# Copyright 2011, 2012 SRI International
# See LICENSE for other credits and copying information

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
from itestlib import Stegotorus, Tltester, TesterProxy, diff

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

    def test_null(self):
        self.doTest("null",
           ("null", "server", "127.0.0.1:5000", "127.0.0.1:5001",
            "null", "client", "127.0.0.1:4999", "127.0.0.1:5000"))

    def test_chop_nosteg(self):
        self.doTest("chop",
           ("chop", "server", "127.0.0.1:5001",
            "nosteg", "127.0.0.1:5010",
            "chop", "client", "127.0.0.1:4999",
            "nosteg", "127.0.0.1:5010",
            ))

    def test_chop_nosteg_2_channels(self):
        self.doTest("chop",
           ("chop", "server", "127.0.0.1:5001",
            "nosteg","127.0.0.1:5010", "nosteg", "127.0.0.1:5011",
            "chop", "client", "127.0.0.1:4999",
            "nosteg","127.0.0.1:5010","nosteg", "127.0.0.1:5011"
            ))

    def test_chop_nosteg_rr(self):
        self.doTest("chop",
           ("chop", "server", "127.0.0.1:5001",
            "nosteg_rr", "127.0.0.1:5010",
            "chop", "client", "127.0.0.1:4999",
            "nosteg_rr", "127.0.0.1:5010",
            ))

    def test_chop_nosteg_rr_2_channels(self):
        ### TODO: take off disable-retransmit
        self.doTest("chop",
           ("chop", "server", "--disable-retransmit", "127.0.0.1:5001",
            "nosteg_rr", "127.0.0.1:5010","nosteg_rr", "127.0.0.1:5011",
            "chop", "client", "--disable-retransmit", "127.0.0.1:4999",
            "nosteg_rr", "127.0.0.1:5010", "nosteg_rr", "127.0.0.1:5011",
            
            ))

    def doProxyTest(self, label, proxy_args, st_args):
        """
        It runs a proxy with proxy_args and then call doTest

        INPUT:
           - ``label``: The test title
           - ``proxy_args``: arguments to be passed to the test proxy
           - ``st_args``: arguments to be passed to Stegotorus
        """
        test_proxy = TesterProxy(proxy_args)

        self.doTest(label, st_args)
        

    # buggy, disabled
    #def no_test_embed(self):
    #    self.doTest("chop",
    #       ("chop", "server", "127.0.0.1:5001",
    #        "127.0.0.1:5010","embed",
    #        "chop", "client", "127.0.0.1:4999",
    #        "127.0.0.1:5010","embed",
    #        ))

    def test_http(self):
        self.doTest("chop",
           ("chop", "server", "--disable-retransmit", "127.0.0.1:5001",
            "http", "127.0.0.1:5010",
            "chop", "client", "--disable-retransmit", "127.0.0.1:4999",
            "http", "127.0.0.1:5010",
            ))

    def test_http_mul_channel(self):
        self.doTest("chop",
           ("chop", "server", "--disable-retransmit", "127.0.0.1:5001",
            "http", "127.0.0.1:5010", "http","127.0.0.1:5011",
            "chop", "client", "--disable-retransmit", "127.0.0.1:4999",
            "http", "127.0.0.1:5010","http","127.0.0.1:5011",
            ))

    def no_ntest_http_apache(self):
        self.doTest("chop",
           ("chop", "server", "--disable-retransmit", "127.0.0.1:5001",
            "http_apache", "127.0.0.1:5010",
            "chop", "client", "--disable-retransmit", "127.0.0.1:4999",
            "http_apache", "127.0.0.1:5010",
            ))

    def no_test_http_apache(self):
        self.doTest("chop",
           ("chop", "server", "127.0.0.1:5001",
            "127.0.0.1:5010","http","127.0.0.1:5011","http_apache",
            "chop", "client", "127.0.0.1:4999",
            "127.0.0.1:5010","http","127.0.0.1:5011","http_apache",
            ))

    def no_test_http_simple_proxy(self):
        self.doProxyTest("chop", 
           ("127.0.0.1:8080", "127.0.0.1:5010"),
           ("chop", "server", "127.0.0.1:5001",
            "127.0.0.1:5010","http","127.0.0.1:5011","http",
            "chop", "client", "127.0.0.1:4999",
            "127.0.0.1:8080","http","127.0.0.1:5011","http",
            ))

    def no_test_http_apache_fail_auth_trans_proxy(self):
        pass
        # self.doTest("chop", 
        #    ("chop", "server",
        #     "--passphrase", "\"correct passphrase\"",
        #     "127.0.0.1:5001",
        #     "http_apache", "127.0.0.1:5011",
        #     "chop", "client",
        #     "--passphrase", "\"wrong passphrase\"",
        #     "127.0.0.1:4999",
        #     "http_apache", "127.0.0.1:5011"
        #    ))

# Synthesize TimelineTest+TestCase subclasses for every 'tl_*' file in
# the test directory.
def load_tests(loader, standard_tests, pattern):
    suite = TestSuite()
    testdir = os.path.dirname(__file__)

    testdir = (testdir == '') and '.' or testdir

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
