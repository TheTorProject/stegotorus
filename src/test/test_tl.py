# Integration tests for stegotorus - "timeline" tests.
#
# These tests use the 'tltester' utility to script a sequence of
# messages sent in both directions across the obfuscated channel.
#
# We synthesize a test matrix of: all 'tl_*' files in src/test/ x
# all supported protocols.

import os
import os.path

from unittest import TestCase, TestSuite
from itestlib import Stegotorus, Tltester, diff

class TimelineTest(object):

    @classmethod
    def setUpClass(cls):
        # Run tltester once in "internal" mode to get the reference
        # for comparison.  This will throw an exception if something
        # goes wrong, and the whole set will then be skipped.
        cls.reftl = Tltester(cls.scriptFile).check_completion(cls.__name__)

    def doTest(self, label, st_args):
        st = Stegotorus(st_args)
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

        errors += st.check_completion(label + " proxy", errors != "")

        if errors != "":
            self.fail("\n" + errors)

    def test_xnull(self):
        self.doTest("x_null",
           ("x_null", "server", "127.0.0.1:5000", "127.0.0.1:5001",
            "x_null", "client", "127.0.0.1:4999", "127.0.0.1:5000"))

    def test_chop(self):
        self.doTest("chop",
           ("chop", "server", "127.0.0.1:5001",
            "127.0.0.1:5010","127.0.0.1:5011",
            "chop", "client", "127.0.0.1:4999",
            "127.0.0.1:5010","x_http","127.0.0.1:5011","x_http",
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
