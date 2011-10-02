# Integration tests for obfsproxy - library routines.

import difflib
import errno
import os
import re
import shlex
import signal
import socket
import subprocess
import threading
import time

# Helper: generate unified-format diffs between two named strings.
# Pythonic escaped-string syntax is used for unprintable characters.

def diff(label, expected, received):
    if expected == received:
        return ""
    else:
        return (label + "\n"
                + "\n".join(s.encode("string_escape")
                            for s in
                            difflib.unified_diff(expected.split("\n"),
                                                 received.split("\n"),
                                                 "expected", "received",
                                                 lineterm=""))
                + "\n")

# Helper: Run obfsproxy instances and confirm that they have
# completed without any errors.

# set MALLOC_CHECK_ in subprocess environment; this gets us
# better memory-error behavior from glibc and is harmless
# elsewhere.  Mode 2 is "abort immediately, without flooding
# /dev/tty with useless diagnostics" (the documentation SAYS
# they go to stderr, but they don't).
obfsproxy_env = {}
obfsproxy_env.update(os.environ)
obfsproxy_env['MALLOC_CHECK_'] = '2'

# check for a grinder
if 'GRINDER' in obfsproxy_env:
    obfsproxy_grindv = shlex.split(obfsproxy_env['GRINDER'])
else:
    obfsproxy_grindv = []

class Obfsproxy(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        argv = obfsproxy_grindv[:]
        argv.extend(("./obfsproxy", "--log-min-severity=debug"))

        if len(args) == 1 and (isinstance(args[0], list) or
                               isinstance(args[0], tuple)):
            argv.extend(args[0])
        else:
            argv.extend(args)

        # Windows needs an extra argument passed to parent __init__,
        # but the constant isn't defined on Unix.
        try: kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        except AttributeError: pass
        subprocess.Popen.__init__(self, argv,
                                  stdin=open(os.path.devnull, "r"),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=obfsproxy_env,
                                  **kwargs)

    severe_error_re = re.compile(
        r"\[(?:warn|err(?:or)?)\]|ERROR SUMMARY: [1-9]|LEAK SUMMARY:")

    def check_completion(self, label, force_stderr):
        if self.poll() is None:
            try: signo = signal.CTRL_C_EVENT # Windows
            except AttributeError: signo = signal.SIGINT # Unix

            # subprocess.communicate has no timeout; arrange to blow
            # the process away if it doesn't respond to the original
            # signal in a timely fashion.
            timeout = threading.Thread(target=self.stop, args=(1.0,))
            timeout.daemon = True
            timeout.start()
            self.send_signal(signo)

        (out, err) = self.communicate()

        report = ""
        def indent(s):
            return "| " + "\n| ".join(s.strip().split("\n"))

        # exit status should be zero
        if self.returncode > 0:
            report += label + " exit code: %d\n" % self.returncode
        elif self.returncode < 0:
            report += label + " killed: signal %d\n" % -self.returncode

        # there should be nothing on stdout
        if out != "":
            report += label + " stdout:\n%s\n" % indent(out)

        # there will be debugging messages on stderr, but there should be
        # no [warn], [err], or [error] messages.
        if (force_stderr or
            self.severe_error_re.search(err) or
            self.returncode != 0):
            report += label + " stderr:\n%s\n" % indent(err)

        return report

    def stop(self, delay=None):
        if self.poll() is None:
            if delay is not None:
                time.sleep(delay)
                if self.poll() is not None: return
            self.terminate()


# Helper: Repeatedly try to connect to the specified server socket
# until either it succeeds or one full second has elapsed.  (Surely
# there is a better way to do this?)

def connect_with_retry(addr):
    retry = 0
    if len(obfsproxy_grindv) == 0: maxretries = 20
    else: maxretries = 100 # valgrind is slow, give it some more time
    while True:
        try:
            return socket.create_connection(addr)
        except socket.error, e:
            if e.errno != errno.ECONNREFUSED: raise
            if retry >= maxretries: raise
            retry += 1
            time.sleep(0.05)

# Helper: In a separate thread (to avoid deadlock), listen on a
# specified socket.  The first time something connects to that socket,
# read all available data, stick it in a string, and post the string
# to the output queue.  Then close both sockets and exit.

class ReadWorker(threading.Thread):
    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(0.1)
        listener.bind(self.address)
        listener.listen(1)
        try:
            (conn, remote) = listener.accept()
        except Exception, e:
            self.data = "|ACCEPT ERROR: " + str(e)
            return
        if not self.running: return
        listener.close()
        conn.settimeout(0.1)
        data = ""
        try:
            while True:
                chunk = conn.recv(4096)
                if not self.running: raise socket.timeout
                if chunk == "": break
                data += chunk
        except Exception, e:
            data += "|RECV ERROR: " + str(e)
        conn.close()
        self.data = data

    def __init__(self, address):
        self.address = address
        self.data = ""
        self.running = True
        threading.Thread.__init__(self)
        self.start()

    def get(self):
        self.join(0.5)
        return self.data

    def stop(self):
        self.running = False
        self.join(0.5)

# Globals expected by some of the tests.

ENTRY_PORT  = 4999
SERVER_PORT = 5000
EXIT_PORT   = 5001

TEST_FILE = """\
THIS IS A TEST FILE. IT'S USED BY THE INTEGRATION TESTS.
THIS IS A TEST FILE. IT'S USED BY THE INTEGRATION TESTS.
THIS IS A TEST FILE. IT'S USED BY THE INTEGRATION TESTS.
THIS IS A TEST FILE. IT'S USED BY THE INTEGRATION TESTS.

"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."
"Can entropy ever be reversed?"
"THERE IS AS YET INSUFFICIENT DATA FOR A MEANINGFUL ANSWER."

    In obfuscatory age geeky warfare did I wage
      For hiding bits from nasty censors' sight
    I was hacker to my set in that dim dark age of net
      And I hacked from noon till three or four at night

    Then a rival from Helsinki said my protocol was dinky
      So I flamed him with a condescending laugh,
    Saying his designs for stego might as well be made of lego
      And that my bikeshed was prettier by half.

    But Claude Shannon saw my shame. From his noiseless channel came
       A message sent with not a wasted byte
    "There are nine and sixty ways to disguise communiques
       And RATHER MORE THAN ONE OF THEM IS RIGHT"

		    (apologies to Rudyard Kipling.)
"""
