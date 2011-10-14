# Integration tests for obfsproxy - "timeline" tests.
#
# These tests use the 'tltester' utility to script a sequence of
# messages sent in both directions across the obfuscated channel.
#
# We synthesize a test matrix of: all 'tl_*' files in src/test/ x
# all supported protocols.

import os
import os.path

from unittest import TestCase, TestSuite
from obfstestlib import Obfsproxy, Tltester, diff

class TimelineTest(object):

    @classmethod
    def setUpClass(cls):
        # Run tltester once in "internal" mode to get the reference
        # for comparison.  This will throw an exception if something
        # goes wrong, and the whole set will then be skipped.
        cls.reftl = Tltester(cls.scriptFile).check_completion(cls.__name__)

    def doTest(self, label, obfs_args):
        obfs = Obfsproxy(obfs_args)
        tester = Tltester(self.scriptFile,
                          ("127.0.0.1:4999", "127.0.0.1:5001"))
        errors = ""
        try:
            testtl = tester.check_completion(label + " tester")
            if testtl != self.reftl:
                errors += diff("errors in transfer:", self.reftl, testtl)

        except AssertionError, e:
            errors += e.message
        except Exception, e:
            errors += repr(e)

        errors += obfs.check_completion(label + " proxy", errors != "")

        if errors != "":
            self.fail("\n" + errors)

    def test_dummy(self):
        self.doTest("dummy",
           ("dummy", "server", "127.0.0.1:5000", "127.0.0.1:5001",
            "dummy", "client", "127.0.0.1:4999", "127.0.0.1:5000"))

    def test_obfs(self):
        self.doTest("obfs2",
           ("obfs2", "--dest=127.0.0.1:5001", "server", "127.0.0.1:5000",
            "obfs2", "--dest=127.0.0.1:5000", "client", "127.0.0.1:4999"))

    def test_xhttp(self):
        self.doTest("xhttp",
           ("x_dsteg", "server", "127.0.0.1:5000", "127.0.0.1:5001",
            "x_dsteg", "client", "127.0.0.1:4999", "127.0.0.1:5000", "x_http"))

    def test_rr(self):
        self.doTest("roundrobin",
           ("roundrobin", "server", "127.0.0.1:5001",
            "127.0.0.1:5010","127.0.0.1:5011","127.0.0.1:5012","127.0.0.1:5013",
            "roundrobin", "client", "127.0.0.1:4999",
            "127.0.0.1:5010","127.0.0.1:5011","127.0.0.1:5012","127.0.0.1:5013"
            ))

# Synthesize TimelineTest+TestCase subclasses for every 'tl_*' file in
# the test directory.
def load_tests(loader, standard_tests, pattern):
    suite = TestSuite()
    testdir = os.path.dirname(__file__)

    for f in sorted(os.listdir(testdir)):
        if f.startswith('tl_'):
            script = os.path.join(testdir, f)
            cls = type(f[3:],
                       (TimelineTest, TestCase),
                       { 'scriptFile': script })
            suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite

if __name__ == '__main__':
    from unittest import main
    main()
