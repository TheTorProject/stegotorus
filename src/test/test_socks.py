# Integration tests for obfsproxy - socks mode.

import socket
import struct
import unittest
from obfstestlib import *

class SocksTest(object):
    # 'sequence' is a sequence of SOCKS[45] protocol messages
    # which we will send or receive.  Sends alternate with
    # receives.  Each entry may be a string, which is sent or
    # received verbatim; a pair of a sequence of data items and a
    # struct pack code, which is packed and then sent or received;
    # or the constant False, which means the server is expected to
    # drop the connection at that point.  If we come to the end of
    # the SOCKS sequence without the server having dropped the
    # connection, we transmit the test file and expect to get it
    # back from the far end.
    def socksTestInner(self, sequence, input_chan):
        sending = True
        good = True
        for msg in sequence:
            if msg is False:
                input_chan.shutdown(socket.SHUT_WR)
                # Expect either a clean closedown or a connection reset
                # at this point.
                got = ""
                try:
                    got = input_chan.recv(4096)
                except socket.error, e:
                    if e.errno != errno.ECONNRESET: raise
                self.assertEqual(got, "")
                good = False
                break
            elif isinstance(msg, str):
                exp = msg
            elif isinstance(msg, tuple):
                exp = struct.pack(msg[1], *msg[0])
            else:
                raise TypeError("incomprehensible msg: " + repr(msg))
            if sending:
                input_chan.sendall(exp)
            else:
                got = ""
                try:
                    got = input_chan.recv(4096)
                except socket.error, e:
                    if e.errno != errno.ECONNRESET: raise
                self.assertEqual(got, exp)
            sending = not sending
        if not good: return None

        input_chan.sendall(TEST_FILE)
        input_chan.shutdown(socket.SHUT_WR)
        return self.output_reader.get()

    def socksTest(self, sequence):
        input_chan = socket.create_connection(("127.0.0.1", ENTRY_PORT))
        input_chan.settimeout(1.0)

        try:
            output = self.socksTestInner(sequence, input_chan)
            report = ""
        except Exception:
            output = None
            report = traceback.format_exc()

        input_chan.close()

        if output is not None:
            report += diff("errors in transfer:", TEST_FILE, output)

        fs = report != ""

        report += self.obfs_client.check_completion("obfsproxy client", fs)
        if self.obfs_server is not None:
            report += self.obfs_server.check_completion("obfsproxy server", fs)

        if report != "":
            self.fail("\n" + report)

class GoodSocksTest(SocksTest):
    # Test methods for good SOCKS dialogues; these should be repeated for each
    # protocol.
    def setUp(self):
        self.output_reader = ReadWorker(("127.0.0.1", EXIT_PORT))
        self.obfs_server = Obfsproxy(self.server_args)
        self.obfs_client = Obfsproxy(self.client_args)

    def tearDown(self):
        self.obfs_server.stop()
        self.obfs_client.stop()
        self.output_reader.stop()


    def test_socks4_transfer(self):
        # SOCKS4 connection request - should succeed
        self.socksTest([ ( (4, 1, SERVER_PORT, 127, 0, 0, 1, 0), "!BBH5B" ),
                         ( (0, 90, SERVER_PORT, 127, 0, 0, 1), "!BBH4B" ) ])

    def test_socks5_transfer(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         ( (5, 1, 0, 1, 127, 0, 0, 1, SERVER_PORT), "!8BH" ),
                         ( (5, 0, 0, 1, 127, 0, 0, 1, SERVER_PORT), "!8BH" ) ])

class SocksObfs2(GoodSocksTest, unittest.TestCase):
    server_args = ("obfs2",
                   "--dest=127.0.0.1:%d" % EXIT_PORT,
                   "server", "127.0.0.1:%d" % SERVER_PORT)
    client_args = ("obfs2",
                   "socks", "127.0.0.1:%d" % ENTRY_PORT)

class SocksDummy(GoodSocksTest, unittest.TestCase):
    server_args = ("dummy", "server",
                   "127.0.0.1:%d" % SERVER_PORT,
                   "127.0.0.1:%d" % EXIT_PORT)
    client_args = ("dummy", "socks",
                   "127.0.0.1:%d" % ENTRY_PORT)

class SocksXDstegXHttp(GoodSocksTest, unittest.TestCase):
    server_args = ("x_dsteg", "server",
                   "127.0.0.1:%d" % SERVER_PORT,
                   "127.0.0.1:%d" % EXIT_PORT)
    client_args = ("x_dsteg", "socks",
                   "127.0.0.1:%d" % ENTRY_PORT, "x_http")

#
# Concrete test classes that are not protocol-specific.
#

class SocksBad(SocksTest, unittest.TestCase):
    # We never actually make a connection, so there's no point having a
    # server or an output reader.
    def setUp(self):
        self.obfs_client = Obfsproxy(self.client_args)
        self.obfs_server = None

    def tearDown(self):
        self.obfs_client.stop()

    client_args = ("dummy", "socks",
                   "127.0.0.1:%d" % ENTRY_PORT)

    def test_socks_illformed(self):
        # ill-formed socks message - server should drop connection
        self.socksTest([ "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                         "Connection: close\r\n\r\n",
                         False ])

    def test_socks4_unsupported_method_1(self):
        # SOCKS4 bind request - should fail, presently just drops connection
        self.socksTest([ ( (4, 2, SERVER_PORT, 127, 0, 0, 1, 0), "!BBH5B" ),
                         False ])

    def test_socks5_bad_handshake_1(self):
        self.socksTest([ "\x05", False ])

    def test_socks5_bad_handshake_2(self):
        self.socksTest([ "\x05\x00", False ])

    def test_socks5_bad_handshake_3(self):
        self.socksTest([ "\x05\x01\x01", False ]) # should get "\x05\xFF"

    def test_socks5_bad_handshake_4(self):
        self.socksTest([ "\x05\x01\x080", False ]) # should get "\x05\xFF"

    def test_socks5_bad_handshake_5(self):
        self.socksTest([ "\x05\x02\x01\x02", False ]) # should get "\x05\xFF"

    def test_socks5_no_destination_1(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00", False ])

    def test_socks5_no_destination_2(self):
        self.socksTest([ "\x05\x02\x00\x01", "\x05\x00", False ])

    def test_socks5_unsupported_method_1(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         ( (5, 2, 0, 1, 127, 0, 0, 1, SERVER_PORT), "!8BH" ),
                         "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", False ])

    def test_socks5_unsupported_method_2(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         ( (5, 3, 0, 1, 127, 0, 0, 1, SERVER_PORT), "!8BH" ),
                         "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", False ])

if __name__ == '__main__':
    unittest.main()
