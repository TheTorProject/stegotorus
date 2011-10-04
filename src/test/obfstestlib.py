# Integration tests for obfsproxy - library routines.

import difflib
import errno
import os
import re
import shlex
import socket
import subprocess
import threading
import time

# Helper: stick "| " at the beginning of each line of |s|.

def indent(s):
    return "| " + "\n| ".join(s.strip().split("\n"))

# Helper: generate unified-format diffs between two named strings.
# Pythonic escaped-string syntax is used for unprintable characters.

def diff(label, expected, received):
    if expected == received:
        return ""
    else:
        return (label + "\n| "
                + "\n| ".join(s.encode("string_escape")
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

        subprocess.Popen.__init__(self, argv,
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=obfsproxy_env,
                                  close_fds=True,
                                  **kwargs)
        # wait for startup completion, which is signaled by
        # the subprocess closing its stdout
        self.stdout.read()

    severe_error_re = re.compile(
        r"\[(?:warn|err(?:or)?)\]|ERROR SUMMARY: [1-9]|LEAK SUMMARY:")

    def check_completion(self, label, force_stderr=False):
        if self.poll() is None:
            # subprocess.communicate has no timeout; arrange to blow
            # the process away if it doesn't respond to the initial
            # shutdown request in a timely fashion.
            timeout = threading.Thread(target=self.stop, args=(1.0,))
            timeout.daemon = True
            timeout.start()

        # this will close the subprocess's stdin as its first act, which
        # will trigger a clean shutdown
        (out, err) = self.communicate()

        report = ""

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

# As above, but for the 'tltester' test helper rather than for
# obfsproxy itself.
class Tltester(subprocess.Popen):
    def __init__(self, timeline, extra_args=(), **kwargs):
        argv = obfsproxy_grindv[:]
        argv.append("./tltester")
        argv.extend(extra_args)

        subprocess.Popen.__init__(self, argv,
                                  stdin=open(timeline, "rU"),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=obfsproxy_env,
                                  close_fds=True,
                                  **kwargs)

    def stop(self, delay=None):
        if self.poll() is None:
            if delay is not None:
                time.sleep(delay)
                if self.poll() is not None: return
            self.terminate()

    def check_completion(self, label):
        if self.poll() is None:
            # subprocess.communicate has no timeout; arrange to blow
            # the process away if it doesn't finish what it's doing in
            # a timely fashion.
            timeout = threading.Thread(target=self.stop, args=(2.0,))
            timeout.daemon = True
            timeout.start()

        (out, err) = self.communicate()

        # exit status should be zero, and there should be nothing on
        # stderr
        if self.returncode != 0 or err != "":
            report = ""
            # exit status should be zero
            if self.returncode > 0:
                report += label + " exit code: %d\n" % self.returncode
            elif self.returncode < 0:
                report += label + " killed: signal %d\n" % -self.returncode
            if err != "":
                report += label + " stderr:\n%s\n" % indent(err)
            raise AssertionError(report)

        # caller will crunch the output
        return out
