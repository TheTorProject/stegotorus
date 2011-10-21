# Integration tests for obfsproxy - socks mode.

import re
import socket
from errno import ECONNRESET
from obfstestlib import Obfsproxy
from unittest import TestCase

class SocksTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.obfs_client = Obfsproxy("dummy", "socks", "127.0.0.1:4999")

    @classmethod
    def tearDownClass(cls):
        dmsg = cls.obfs_client.check_completion("socks client")
        # We may have gotten a stderr report with [warn]s in it because
        # of intentional connections to ports with nobody listening.
        # Prune those and check again for genuine errors.
        if dmsg != "":
            if ("exit code:" in dmsg
                or "killed:" in dmsg
                or "stdout:" in dmsg):
                raise AssertionError(dmsg)

            pruned = re.sub("^.*Connection refused.*$", "", dmsg)
            if Obfsproxy.severe_error_re.search(pruned):
                raise AssertionError(dmsg)

    def setUp(self):
        self.channel = socket.create_connection(("127.0.0.1", 4999))
        self.channel.settimeout(1.0)

    def tearDown(self):
        self.channel.close()

    # 'sequence' is a sequence of SOCKS[45] protocol messages which we
    # will send or receive.  Sends alternate with receives.  When we
    # come to the end of the sequence, we expect the server to drop
    # the connection.  Note that in none of these tests do we actually
    # make a successful outbound SOCKS connection.
    def socksTest(self, sequence):

        def socksRecv(channel):
            got = ""
            try:
                got = channel.recv(4096)
            except socket.error, e:
                if e.errno != ECONNRESET: raise
            return got

        sending = True
        for msg in sequence:
            if sending:
                self.channel.sendall(msg)
            else:
                got = socksRecv(self.channel)
                self.assertEqual(got, msg)
            sending = not sending

        # Expect the server to drop the connection at this point.
        self.channel.shutdown(socket.SHUT_WR)
        got = socksRecv(self.channel)
        self.assertEqual(got, "")

    def test_socks_illformed(self):
        # ill-formed socks message - server should drop connection
        self.socksTest([ "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                         "Connection: close\r\n\r\n" ])

    def test_socks4_unsupported_method_1(self):
        # SOCKS4 bind request - should fail, presently just drops connection
        self.socksTest([ "\x04\x02\x13\x88\x7f\x00\x00\x01\x00" ])

    def test_socks5_bad_handshake_1(self):
        self.socksTest([ "\x05" ])

    def test_socks5_bad_handshake_2(self):
        self.socksTest([ "\x05\x00" ])

    def test_socks5_bad_handshake_3(self):
        self.socksTest([ "\x05\x01\x01" ]) # should get "\x05\xFF"

    def test_socks5_bad_handshake_4(self):
        self.socksTest([ "\x05\x01\x080" ]) # should get "\x05\xFF"

    def test_socks5_bad_handshake_5(self):
        self.socksTest([ "\x05\x02\x01\x02" ]) # should get "\x05\xFF"

    def test_socks5_no_destination_1(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00" ])

    def test_socks5_no_destination_2(self):
        self.socksTest([ "\x05\x02\x00\x01", "\x05\x00" ])

    def test_socks5_unsupported_method_1(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         "\x05\x02\x00\x01\x7f\x00\x00\x01\x13\x88",
                         "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00" ])

    def test_socks5_unsupported_method_2(self):
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         "\x05\x03\x00\x01\x7f\x00\x00\x01\x13\x88",
                         "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00" ])

    def test_socks4_conn_refused(self):
        # SOCKS4 well-formed connection request - fails with
        # connection refused, since no one is listening
        self.socksTest([ "\x04\x01\x13\x88\x7f\x00\x00\x01\x00",
                         "\x00\x5b\x13\x88\x7f\x00\x00\x01" ])

    def test_socks5_conn_refused(self):
        # ditto, but socks5
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         "\x05\x01\x00\x01\x7f\x00\x00\x01\x13\x88",
                         "\x05\x05\x00\x01\x7f\x00\x00\x01\x13\x88" ])

if __name__ == '__main__':
    from unittest import main
    main()
