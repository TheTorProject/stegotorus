# Copyright 2011, 2012 SRI International
# See LICENSE for other credits and copying information

# Integration tests for steogtorus - "timeline" tests.
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

import pdb

class TimelineTest(TestCase):

    @classmethod
    def setUpClass(cls):
        # Run tltester once in "internal" mode to get the reference
        # for comparison.  This will throw an exception if something
        # goes wrong, and the whole set will then be skipped.
        import pdb
        #pdb.set_trace()
        cls.testdir = os.path.dirname(__file__)

        cls.testdir = (cls.testdir == '') and '.' or cls.testdir

        cls.reftl = Stegotorus("null", "client", "127.0.0.1:4999", "127.0.0.1:5000").check_completion(cls.__name__)
        
        cls.http_reftl = Stegotorus(
            "chop", "server", "127.0.0.1:5001",
            "http", "127.0.0.1:5000",
            "chop", "client", "127.0.0.1:4999",
            "http", "127.0.0.1:5000").check_completion(cls.__name__)

    def doTest(self, label, st_args, reftl = None):
        import pdb
        #pdb.set_trace()
        errors = ""
        st = Stegotorus(st_args)
        try:
            testtl = st.check_completion(label + " tester")
            if ((reftl == None) and (testtl != self.reftl)) or ((reftl != None) and (testtl != reftl)):
                errors += diff("errors in transfer:", self.reftl, testtl)

        except AssertionError, e:
            errors += e.message
        except Exception, e:
            errors += repr(e)

        errors += st.check_completion(label + " proxy", errors != "")

        if errors != "":
            self.fail("\n" + errors)

    def no_test_empty_config_null(self):
        #pdb.set_trace()
        print self.reftl
        self.doTest("null-cl",
           ("--config-file="+ self.testdir + "/test_conf.d/empty.yaml", "null", "server", "127.0.0.1:5000",
            "127.0.0.1:5001", "null", "client", "127.0.0.1:4999", "127.0.0.1:5000"))

    def no_test_null_config(self):
        self.doTest("null", ("--config-file="+ self.testdir + "/test_conf.d/null-client-server.yaml"))

    def no_test_chop_nosteg_config(self):
        self.doTest("chop-nosteg", ("--config-file="+ self.testdir + "/test_conf.d/chop-nosteg-client-server.yaml"))

    def no_test_chop_nosteg_rr_config(self):
        self.doTest("chop-nosteg", ("--config-file="+ self.testdir + "/test_conf.d/chop-nosteg-rr-client-server.yaml"))

    def no_test_chop_http_config(self):
        #pdb.set_trace()
        #print "<<<<<<START>>>>>>"
        #print self.http_reftl
        #print "<<<<<<END>>>>>>"

        #http generate out put so we can't compare with same output
        #so we need to run with cmdline the config and get the output
        #then run with file config and compare the result.
        
        self.doTest("chop-http", ("chop", "server", "127.0.0.1:5001",
            "http", "127.0.0.1:5000",
            "chop", "client", "127.0.0.1:4999",
            "http", "127.0.0.1:5000")
                        , self.reftl)

        raise NotImplementedError

         
if __name__ == '__main__':
    from unittest import main
    main()
