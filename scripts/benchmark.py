#! /usr/bin/python
# Copyright 2012 Zachary Weinberg
#
# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice
# and this notice are preserved. This file is offered as-is, without any
# warranty.

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
# tor: https://torproject.org/
# stegotorus: you already have it :)
#
# Software you need on the proxy machine:
#
# nylon: http://monkey.org/~marius/pages/?page=nylon
# tor, stegotorus

# CONFIGURATION - ADJUST VARIABLES BELOW AS NECESSARY

# Client host

CLIENT_IP     = "99.113.33.155"
CLIENT_IFACE  = "eth0"

# Proxy host

PROXY         = "sandbox03.sv.cmu.edu"
PROXY_IP      = "209.129.244.30" # some things won't do DNS for this
PROXY_PORT    = 1080
PROXY_SSH_CMD = ("ssh", PROXY)

# Target

TARGET    = "storustest.nfshost.com"

# Programs we need to run.  Change these if any binary is not in the
# default path or hasn't got the default name.
# C_ - for the client.  P_ - for the proxy.
# You can NOT specify arguments here - if you need to do any
# setup, write a wrapper script.

C_bwm     = "bwm-ng"
C_mcurl   = "bm-mcurl"
C_storus  = "stegotorus"
C_tor     = "/usr/sbin/tor"

P_nylon   = "nylon"
P_storus  = "./stegotorus/build/stegotorus"
P_tor     = "tor"
P_python  = "/usr/local/bin/python" # this must be an absolute path,
                                    # it goes on a shebang line

# For some reason, bm-fixedrate generates data a linear factor slower
# than it was meant to; this is the quick fix.  To calibrate this
# number, set it to 1 and run the direct fixedrate test, do a linear
# regression on 'down' as a function of 'cap', and the number you want
# is 1 over the slope of the line.

FUDGE_FIXEDRATE = 1.939

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

            # convert to most compact possible form,
            # scale to decimal kilobytes
            upbytes = str(float(upbytes)/1000)
            dnbytes = str(float(dnbytes)/1000)

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
Port=%d
Allow-IP=%s/32
""" % (PROXY_PORT, CLIENT_IP))

def p_tor():
    return ProxyProcess((P_tor, "--quiet", "-f", "tor.conf"),
                        "tor.conf",
                        """\
ORPort %d
SocksPort 0
BridgeRelay 1
AssumeReachable 1
PublishServerDescriptor 0
ExitPolicy accept *:80
DataDirectory .
Log err stderr
ContactInfo zackw at cmu dot edu
Nickname storustest
AllowSingleHopExits 1
# unfortunately there doesn't seem to be any way to tell Tor to accept
# OR connections from specific IP addresses only.
""" % PROXY_PORT)

def p_storus(smode):
    return ProxyProcess((P_storus, "--log-min-severity=warn",
                         "chop", "server", "127.0.0.1:%d" % PROXY_PORT,
                         "%s:%d" % (PROXY_IP, PROXY_PORT+1), smode,
                         "%s:%d" % (PROXY_IP, PROXY_PORT+2), smode,
                         "%s:%d" % (PROXY_IP, PROXY_PORT+3), smode,
                         "%s:%d" % (PROXY_IP, PROXY_PORT+4), smode))


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
SocksPort %d
DataDirectory .
Log err stderr
Bridge %s:%d
UseBridges 1
SafeSocks 0
ControlPort 9051
AllowSingleHopCircuits 1
ExcludeSingleHopRelays 0
__DisablePredictedCircuits 1
__LeaveStreamsUnattached 1
""" % (PROXY_PORT, PROXY_IP, PROXY_PORT))
    fp.close()
    return ClientProcess((C_tor, "--quiet", "-f", "tor-direct-client.conf"))

def c_tor_storus():
    fp = open("tor-storus-client.conf", "w")
    fp.write("""\
ORPort 0
SocksPort %d
Socks5Proxy 127.0.0.1:%s
DataDirectory .
Log err stderr
Bridge %s:%d
UseBridges 1
SafeSocks 0
ControlPort 9051
AllowSingleHopCircuits 1
ExcludeSingleHopRelays 0
__DisablePredictedCircuits 1
__LeaveStreamsUnattached 1
""" % (PROXY_PORT, PROXY_PORT+1, PROXY_IP, PROXY_PORT))
    fp.close()
    return ClientProcess((C_tor, "--quiet", "-f", "tor-storus-client.conf"))

def c_storus(smode):
    return ClientProcess((C_storus, "--log-min-severity=warn",
                          "chop", "socks", "127.0.0.1:%d" % (PROXY_PORT+1),
                          "%s:%d" % (PROXY_IP, PROXY_PORT+1), smode,
                          "%s:%d" % (PROXY_IP, PROXY_PORT+2), smode,
                          "%s:%d" % (PROXY_IP, PROXY_PORT+3), smode,
                          "%s:%d" % (PROXY_IP, PROXY_PORT+4), smode))

def c_torctl():
    return ClientProcess((os.path.dirname(__file__) + '/bm-tor-controller.py'
                          ))

def c_curl(url, proxyhost):
    return ClientProcess((C_mcurl, '1', '1',
                          proxyhost + ":" + str(PROXY_PORT),
                          url))

def c_mcurl(prefix, cps, proxyhost):
    return ClientProcess((C_mcurl, str(cps), '200',
                          proxyhost + ':' + str(PROXY_PORT),
                          'http://' + TARGET + '/' + prefix +
                          '/[0-9]/[0-9]/[0-9]/[0-9].html'))

# Benchmarks.

def t_direct(report, bench, *args):
    proxy = None
    try:
        proxy = p_nylon()

        bench(report, PROXY_IP, "direct", *args)

    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()

def t_tor(report, bench, *args):
    proxy = None
    proxyl = None
    proxyc = None
    try:
        proxy = p_tor()
        proxyl = c_tor_direct()
        time.sleep(1)
        proxyc = c_torctl()
        time.sleep(4)

        bench(report, '127.0.0.1', "tor", *args)

    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()
        if proxyc is not None:
            proxyc.terminate()
            proxyc.wait()
        if proxyl is not None:
            proxyl.terminate()
            proxyl.wait()

def t_storus(report, bench, smode, *args):
    proxy = None
    proxys = None
    proxyl = None
    proxym = None
    proxyc = None
    try:
        proxy = p_tor()
        proxys = p_storus(smode)
        proxyl = c_tor_storus()
        proxym = c_storus(smode)
        time.sleep(1)
        proxyc = c_torctl()
        time.sleep(4)

        bench(report, '127.0.0.1', "st.http", *args)

    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait()
        if proxyc is not None:
            proxyc.terminate()
            proxyc.wait()
        if proxyl is not None:
            proxyl.terminate()
            proxyl.wait()
        if proxys is not None:
            proxys.terminate()
            proxys.wait()
        if proxym is not None:
            proxym.terminate()
            proxym.wait()

def bench_fixedrate(report, proxyaddr, relay, bmax, bstep, mtime):
    for cap in range(bstep, bmax+bstep, bstep):
        tag = "fixedrate,%s,%d" % (relay, cap)
        sys.stderr.write(tag + "\n")
        try:
            client = c_curl('http://' + TARGET + '/bm-fixedrate.cgi/' +
                            str(int(cap * 1000 * FUDGE_FIXEDRATE)),
                            proxyaddr)
            monitor(report, tag, mtime)
        finally:
            if client is not None:
                client.terminate()
                client.wait()
                client = None

def bench_files(report, proxyaddr, relay, prefix, maxconn, mtime):
    for cps in range(1,maxconn+1):
        tag = "files.%s,%s,%d" % (prefix, relay, cps)
        sys.stderr.write(tag + "\n")
        try:
            client = c_mcurl(prefix, cps, proxyaddr)
            monitor(report, tag, mtime)
        finally:
            if client is not None:
                client.terminate()
                client.wait()
                client = None

if __name__ == '__main__':
    r = sys.stdout
    r.write("benchmark,relay,cap,obs,up,down\n")

    t_direct(r, bench_fixedrate, 700, 10, 20)
    t_direct(r, bench_files, "fixed", 120, 20)
    t_direct(r, bench_files, "pareto", 120, 20)

    t_tor(r, bench_fixedrate, 700, 10, 20)
    t_tor(r, bench_files, "fixed", 120, 20)
    t_tor(r, bench_files, "pareto", 120, 20)

    t_storus(r, bench_fixedrate, "http", 700, 10, 30)
    t_storus(r, bench_files, "http", "fixed", 120, 30)
    t_storus(r, bench_files, "http", "pareto", 120, 30)
