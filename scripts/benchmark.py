#! /usr/bin/python

# Stegotorus benchmarking script.
# Several different computers are involved:
#
# - the "client" is the machine you run this script on; the workload
#   generator will run there, as will the StegoTorus and Tor clients.
#
# - the "proxy" is a machine that you can ssh to with no password.
#   It will run the StegoTorus and Tor bridge servers.
#
# - the "target" is the HTTP server that will be contacted in various ways.
#
#   bm-genfiles.py must have been run on this server to create file
#   trees named 'fixed' and 'pareto' which appear as direct children
#   of the root URL. bm-fixedrate-cgi.c must have been compiled for
#   that server and appear as /bm-fixedrate.cgi.
#
# Software you need on the client machine:
#
# bwm-ng: http://www.gropp.org/?id=projects&sub=bwm-ng
# curl: http://curl.haxx.se/
# httperf: http://www.hpl.hp.com/research/linux/httperf/
# tsocks: http://tsocks.sourceforge.net/about.php
# tor: https://torproject.org/
# stegotorus: you already have it :)
#
# Software you need on the proxy machine:
#
# nylon: http://monkey.org/~marius/pages/?page=nylon
# tor, stegotorus
#
# You configure this script by setting variables below.

# Client host

CLIENT_IP     = "99.113.33.155"
CLIENT_IFACE  = "eth0"

# Proxy host

PROXY         = "sandbox03.sv.cmu.edu"
PROXY_IP      = "209.129.244.30" # some things won't do DNS for this
PROXY_PORT    = "1080"
PROXY_SSH_CMD = ("ssh", PROXY)

# Target

TARGET    = "storustest.nfshost.com"

# Fudge factors.  For some reason, bm-fixedrate generates data a
# linear factor slower than it was meant to; this is the quick fix.

FUDGE_FIXEDRATE = 2.5

# Programs we need to run.  Change these if any binary is not in the
# default path or hasn't got the default name.
# C_ - for the client.  P_ - for the proxy.
# You can NOT specify arguments here - if you need to do any
# setup, write a wrapper script.

C_bwm     = "bwm-ng"
C_curl    = "curl"
C_httperf = "httperf"
C_storus  = "stegotorus-wrapper"
C_tor     = "/usr/sbin/tor"
C_tsocks  = "/usr/lib/libtsocks.so"

P_nylon   = "nylon"
P_storus  = "stegotorus-wrapper"
P_tor     = "tor"
P_python  = "/usr/local/bin/python" # this must be an absolute path,
                                    # it goes on a shebang line

# ACTUAL PROGRAM STARTS HERE

from types import MethodType
import os
import os.path
import pickle
import subprocess
import sys
import time

def monitor(report, label, period):
    """Monitor network utilization (bytes/sec up and down) for a
    period of PERIOD seconds, writing the report to REPORT, labeling
    each line with LABEL."""

    bwm = subprocess.Popen((C_bwm, "-o", "csv", "-c", str(period), "-t", "1000",
                            "-u", "bytes", "-T", "rate", "-I", CLIENT_IFACE),
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
    try:
        n = 1
        for line in bwm.stdout:
            (stamp, iface, upbytes, dnbytes, rest) = line.split(';', 4)
            if iface == 'total': continue

            # convert to most compact possible form
            upbytes = str(float(upbytes))
            dnbytes = str(float(dnbytes))

            report.write("%s,%d,%s,%s\n" % (label,n,upbytes,dnbytes))
            n += 1
    except:
        bwm.terminate()
        raise
    finally:
        bwm.wait()

class ProxyProcess(object):
    """A process running on the proxy host.  It has a command line and
    an optional config file. It is not expected to produce any output
    (if it does, it will get dumped to this script's stdout/stderr) or
    require any input (input is redirected from /dev/null).  It is
    expected to run until it is killed."""

    @staticmethod
    def prepare_remote():
        remote_driver=r"""#! %s
import pickle
import signal
import subprocess
import sys
import traceback

wrote_rpid = False

# Remote driver for proxy processes.
try:
    data = pickle.load(sys.stdin)
    sys.stdin.close()
    if data['cfgname']:
        f = open(data['cfgname'], "w")
        f.write(data['cfgdata'])
        f.close()
    proc = subprocess.Popen(data['args'], stdin=open("/dev/null", "r"),
                            stdout=2) # redirect child stdout to our stderr
    sys.stdout.write(str(proc.pid) + "\n")
    wrote_rpid = True
    sys.stdout.close()
    proc.wait()

    # the process being killed by SIGTERM is normal
    if proc.returncode != 0 and proc.returncode != -signal.SIGTERM:
        raise subprocess.CalledProcessError(proc.returncode, data['args'][0])
except:
    traceback.print_exc()
    if not wrote_rpid: sys.stdout.write("X\n")
    sys.exit(1)

sys.exit(0)
""" % P_python
        remote_setup=r"""newdriver=`mktemp ./driver.py.XXXXXX` || exit 1
cat > "$newdriver"
if cmp -s "$newdriver" driver.py
then rm -f "$newdriver"
else set -e; mv -f "$newdriver" driver.py; chmod +x driver.py
fi
"""
        prep_worker = subprocess.Popen(PROXY_SSH_CMD + (remote_setup,),
                                       stdin=subprocess.PIPE,
                                       stdout=2)
        prep_worker.communicate(remote_driver)
        if prep_worker.returncode != 0:
            raise subprocess.CalledProcessError(prep_worker.returncode,
                                                'remote_setup script')

    def __init__(self, args, cfgname=None, cfgdata=None):
        if ((cfgname is None or cfgdata is None) and
            (cfgname is not None or cfgdata is not None)):
            raise TypeError("either both or neither of cfgname and cfgdata"
                            " must be specified")

        self._rpid = "X"

        ProxyProcess.prepare_remote()
        self._proc = subprocess.Popen(PROXY_SSH_CMD + ("./driver.py",),
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     close_fds=True)
        pickle.dump({ 'args'    : args,
                      'cfgname' : cfgname,
                      'cfgdata' : cfgdata },
                    self._proc.stdin, 2)
        self._proc.stdin.close()
        self._rpid = self._proc.stdout.readline().strip()
        if self._rpid == "X" or self._rpid == "":
            self._rpid = "X"
            self._proc.wait()
            raise RuntimeError("failed to execute '%s' on proxy host"
                               % " ".join(args))

    def terminate(self):
        if self._rpid == "X": return
        subprocess.check_call(PROXY_SSH_CMD + ("kill", self._rpid))

    def kill(self):
        if self._rpid == "X": return
        subprocess.check_call(PROXY_SSH_CMD + ("kill", "-9", self._rpid))

    # forward everything else to _proc; logic copied verbatim from
    # http://code.activestate.com/recipes/519639-
    #    true-lieberman-style-delegation-in-python/
    def __getattr__(self, aname):
        target = self._proc
        f = getattr(target, aname)
        if isinstance(f, MethodType):
            return MethodType(f.im_func, self, target.__class__)
        else:
            return f

# Individual proxy-side test runners.
def p_nylon():
    return ProxyProcess((P_nylon, "-f", "-c", "nylon.conf"),
                        "nylon.conf",
                        """\
[General]
No-Simultaneous-Conn=10
Log=0
Verbose=0
PIDfile=nylon.pid

[Server]
Port=%s
Allow-IP=%s/32
""" % (PROXY_PORT, CLIENT_IP))

def p_tor_direct():
    return ProxyProcess((P_tor, "--quiet", "-f", "tor-direct.conf"),
                        "tor-direct.conf",
                        """\
ORPort %s
SocksPort 0
BridgeRelay 1
PublishServerDescriptor 0
ExitPolicy reject *:*
DataDirectory .
Log err stderr
# unfortunately there doesn't seem to be any way to tell Tor to accept
# OR connections from specific IP addresses only.
""" % PROXY_PORT)

class ClientProcess(subprocess.Popen):
    """A process running on the local machine.  This is probably doing
    the meat of the work of some benchmark.  Basically a shim around
    subprocess.Popen to fix constructor arguments."""

    def __init__(self, argv, envp=None):
        if envp is not None:
            env = os.environ.copy()
            env.update(envp)
            subprocess.Popen.__init__(self, argv,
                                      stdin=open("/dev/null", "r"),
                                      stdout=open("/dev/null", "w"),
                                      stderr=subprocess.STDOUT, env=env)
        else:
            subprocess.Popen.__init__(self, argv,
                                      stdin=open("/dev/null", "r"),
                                      stdout=2)

def c_tor_direct():
    fp = open("tor-direct-client.conf", "w")
    fp.write("""\
ORPort 0
SocksPort %s
DataDirectory .
Log err stderr
Bridge %s:%s
UseBridges 1
SafeSocks 0
""" % (PROXY_PORT, PROXY_IP, PROXY_PORT))
    fp.close()
    return ClientProcess((C_tor, "--quiet", "-f", "tor-direct-client.conf"))

def c_curl(url, proxyhost):
    return ClientProcess((C_curl, "-s", "--socks5-hostname",
                          proxyhost + ":" + PROXY_PORT,
                          url, "-o", "/dev/null"))

def c_httperf(prefix, rate, proxyhost):
    fp = open("tsocks.conf", "w")
    fp.write("""\
server = %s
local = %s/255.255.255.255
server_port = %s
server_type = 5
""" % (proxyhost, proxyhost, PROXY_PORT))
    fp.close()
    return ClientProcess((C_httperf, "--hog",
                          "--server=" + TARGET,
                          "--uri=" + prefix,
                          "--period=" + str(rate),
                          "--num-calls=5", "--num-conns=2000",
                          "--wset=10000,1"),
                         { 'LD_PRELOAD' : C_tsocks,
                           'TSOCKS_CONF_FILE' :
                               os.path.join(os.getcwd(), "tsocks.conf") })

# Benchmarks.

def bench_fixedrate_direct(report):
    client = None
    proxy = None
    try:
        proxy = p_nylon()

        for cap in range(10, 810, 10):
            sys.stderr.write("fixedrate,direct,%d\n" % (cap * 1000))
            try:
                client = c_curl('http://' + TARGET + '/bm-fixedrate.cgi/' +
                                str(int(cap * 1000 * FUDGE_FIXEDRATE)),
                                PROXY)
                monitor(report, "fixedrate,direct,%d" % (cap * 1000), 60)
            finally:
                if client is not None:
                    client.terminate()
                    client.wait()
                    client = None
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()

def bench_fixedrate_tor(report):
    client = None
    proxy = None
    proxyl = None
    try:
        proxy = p_tor_direct()
        proxyl = c_tor_direct()
        time.sleep(5) # tor startup is slow

        for cap in range(10,810,10):
            sys.stderr.write("fixedrate,tor,%d\n" % (cap * 1000))
            try:
                client = c_curl('http://' + TARGET + '/bm-fixedrate.cgi/' +
                                str(int(cap * 1000 * FUDGE_FIXEDRATE)),
                                '127.0.0.1')
                monitor(report, "fixedrate,tor,%d" % (cap * 1000), 60)
            finally:
                if client is not None:
                    client.terminate()
                    client.wait()
                    client = None
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()
        if proxyl is not None:
            proxyl.terminate()
            proxyl.wait()

def bench_files_direct(report, prefix):
    client = None
    proxy = None
    try:
        proxy = p_nylon()

        for cps in range(1,81):
            sys.stderr.write("files.%s,direct,%d\n" % (prefix, cps))
            try:
                client = c_httperf(prefix, 1./cps, PROXY_IP)
                monitor(report, "files.%s,direct,%d" % (prefix, cps), 60)
            finally:
                if client is not None:
                    client.terminate()
                    client.wait()
                    client = None
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()

def bench_files_tor(report, prefix):
    client = None
    proxy = None
    proxyl = None
    try:
        proxy = p_tor_direct()
        proxyl = c_tor_direct()
        time.sleep(5) # tor startup is slow

        for cps in range(1,81):
            sys.stderr.write("files.%s,tor,%d\n" % (prefix, cps))
            try:
                client = c_httperf(prefix, 1./cps, '127.0.0.1')
                monitor(report, "files.%s,tor,%d" % (prefix, cps), 60)
            finally:
                if client is not None:
                    client.terminate()
                    client.wait()
                    client = None
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()
        if proxyl is not None:
            proxyl.terminate()
            proxyl.wait()

if __name__ == '__main__':
    sys.stdout.write("benchmark,relay,cap,obs,up,down\n")
    bench_fixedrate_direct(sys.stdout)
    bench_fixedrate_tor(sys.stdout)
    bench_files_direct(sys.stdout, "fixed")
    bench_files_tor(sys.stdout, "fixed")
    bench_files_direct(sys.stdout, "pareto")
    bench_files_tor(sys.stdout, "pareto")
