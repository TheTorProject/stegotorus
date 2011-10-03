# Integration tests for obfsproxy: end-to-end communications.

import socket
import unittest
from obfstestlib import *

# Right now this is a direct translation of the former int_test.sh
# (except that I have fleshed out the SOCKS test a bit).
# It will be made more general and parametric Real Soon.

#
# Test base classes.  They do _not_ inherit from unittest.TestCase
# so that they are not scanned directly for test functions (some of
# them do provide test functions, but not in a usable state without
# further code from subclasses).
#

class DirectTest(object):
    def setUp(self):
        self.output_reader = ReadWorker(("127.0.0.1", EXIT_PORT))
        self.obfs = Obfsproxy(self.obfs_args)
        self.input_chan = socket.create_connection(("127.0.0.1", ENTRY_PORT))
        self.input_chan.settimeout(1.0)

    def tearDown(self):
        self.obfs.stop()
        self.output_reader.stop()
        self.input_chan.close()

    def test_direct_transfer(self):
        # Open a server and a simple client (in the same process) and
        # transfer a file.  Then check whether the output is the same
        # as the input.
        self.input_chan.sendall(TEST_FILE)
        self.input_chan.shutdown(socket.SHUT_WR)
        output = self.output_reader.get()

        report = diff("errors in transfer:", TEST_FILE, output)

        report += self.obfs.check_completion("obfsproxy", report!="")

        if report != "":
            self.fail("\n" + report)

#
# Concrete test classes specialize the above base classes for each protocol.
#

class DirectObfs2(DirectTest, unittest.TestCase):
    obfs_args = ("obfs2",
                 "--dest=127.0.0.1:%d" % EXIT_PORT,
                 "server", "127.0.0.1:%d" % SERVER_PORT,
                 "obfs2",
                 "--dest=127.0.0.1:%d" % SERVER_PORT,
                 "client", "127.0.0.1:%d" % ENTRY_PORT)

class DirectDummy(DirectTest, unittest.TestCase):
    obfs_args = ("dummy", "server",
                 "127.0.0.1:%d" % SERVER_PORT,
                 "127.0.0.1:%d" % EXIT_PORT,
                 "dummy", "client",
                 "127.0.0.1:%d" % ENTRY_PORT,
                 "127.0.0.1:%d" % SERVER_PORT)

class DirectXDstegXHttp(DirectTest, unittest.TestCase):
    obfs_args = ("x_dsteg", "server",
                 "127.0.0.1:%d" % SERVER_PORT,
                 "127.0.0.1:%d" % EXIT_PORT,
                 "x_dsteg", "client",
                 "127.0.0.1:%d" % ENTRY_PORT,
                 "127.0.0.1:%d" % SERVER_PORT, "x_http")

if __name__ == '__main__':
    unittest.main()
