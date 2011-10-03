# Integration tests for obfsproxy - socks mode.

import errno
import socket
import traceback
import unittest
from obfstestlib import Obfsproxy

def socksRecv(channel):
    got = ""
    try:
        got = channel.recv(4096)
    except socket.error, e:
        if e.errno != errno.ECONNRESET: raise
    return got

class SocksTest(unittest.TestCase):
    # 'sequence' is a sequence of SOCKS[45] protocol messages which we
    # will send or receive.  Sends alternate with receives.  When we
    # come to the end of the sequence, we expect the server to drop
    # the connection.  Note that in none of these tests do we actually
    # make a successful outbound SOCKS connection.

    def socksTest(self, sequence, expectCR=False):
        input_chan = socket.create_connection(("127.0.0.1", 4999))
        input_chan.settimeout(1.0)

        report = ""
        try:
            sending = True
            for msg in sequence:
                if sending:
                    input_chan.sendall(msg)
                else:
                    got = socksRecv(input_chan)
                    self.assertEqual(got, msg)
                sending = not sending

            # Expect the server to drop the connection at this point.
            input_chan.shutdown(socket.SHUT_WR)
            got = socksRecv(input_chan)
            self.assertEqual(got, "")

        except Exception:
            report = traceback.format_exc()

        client_dmsg = self.obfs_client.check_completion("socks client",
                                                        report != "")
        if (expectCR and report == "" and client_dmsg != ""
            and "exit code:" not in client_dmsg
            and "killed:" not in client_dmsg
            and "stdout:" not in client_dmsg):

            # We may have gotten a client_dmsg with a [warn] in it just
            # because there was a connection refused, which in this case
            # is expected to happen.
            pruned = client_dmsg.replace("| [warn] Connection error: "
                                         "Connection refused\n", "")
            if not Obfsproxy.severe_error_re.search(pruned):
                client_dmsg = ""

        report += client_dmsg
        if report != "":
            self.fail("\n" + report)

    def setUp(self):
        self.obfs_client = Obfsproxy(("dummy", "socks", "127.0.0.1:4999"))

    def tearDown(self):
        self.obfs_client.stop()

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
                         "\x00\x5b\x13\x88\x7f\x00\x00\x01" ], True)

    def test_socks5_conn_refused(self):
        # ditto, but socks5
        self.socksTest([ "\x05\x01\x00", "\x05\x00",
                         "\x05\x01\x00\x01\x7f\x00\x00\x01\x13\x88",
                         "\x05\x05\x00\x01\x7f\x00\x00\x01\x13\x88" ], True)


if __name__ == '__main__':
    unittest.main()
