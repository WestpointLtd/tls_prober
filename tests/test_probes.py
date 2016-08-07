import sys
import os
# Ensure we can see the pytls/tls subdir for the pytls submodule
sys.path.insert(1, os.path.join(os.path.dirname(__file__), '..', 'pytls'))
try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from probes import *


class MockSock(object):
    def __init__(self):
        self.sent_data = []

    def write(self, data):
        self.sent_data.append(data)

    def flush(self):
        pass

DEFAULT_CIPHERS_STR = b'\x00\x04\x00\x05\x00\n\x00/\x005\x00<\x00='


DEFAULT_PFS_CIPHERS_STR = (b"\xc0,"
                           b"\xc0+"
                           b"\xc0$"
                           b"\xc0#"
                           b"\xc0\n"
                           b"\xc0\t"
                           b"\xc00"
                           b"\xc0/"
                           b"\xc0("
                           b"\xc0'"
                           b"\xc0\x14"
                           b"\xc0\x13"
                           b"\x00\x9f"
                           b"\x00\x9e"
                           b"\x00k"
                           b"\x00g"
                           b"\x009"
                           b"\x003"
                           b"\xcc\xa9"
                           b"\xcc\xa2"
                           b"\xcc\x14"
                           b"\xcc\xa8"
                           b"\xcc\xa1"
                           b"\xcc\x13"
                           b"\xcc\xaa"
                           b"\xcc\xa3"
                           b"\xcc\x15"
                           b"\xc0\xad"
                           b"\xc0\xac"
                           b"\xc0\xaf"
                           b"\xc0\xae"
                           b"\xc0\x9f"
                           b"\xc0\x9e"
                           b"\xc0\xa3"
                           b"\xc0\xa2"
                           b"\xc0\x07"
                           b"\xc0\x08"
                           b"\xc0s"
                           b"\xc0H"
                           b"\xc0\x11"
                           b"\xc0\x12"
                           b"\xc0w"
                           b"\xc0M"
                           b"\x00\x88"
                           b"\x00\x16"
                           b"\x00\x9a"
                           b"\xc0D")


DEFAULT_12_CIPHERS_STR = (b'\x00\x04'
                          b'\x00\x05'
                          b'\x00\n'
                          b'\x00/'
                          b'\x005'
                          b'\x00<'
                          b'\x00='
                          b'\x00\x9c'
                          b'\x00\x9d'
                          b'\xcc\xa0'
                          b'\xc0\x9c'
                          b'\xc0\x9d'
                          b'\xc0\xa0'
                          b'\xc0\xa1'
                          b'\x00A'
                          b'\x00\x84'
                          b'\x00\xba'
                          b'\xc0<'
                          b'\x00\x96')


RANDOM_STR = b'01234567890123456789012345678901'


MAKE_HELLO_EMPTY_EXT = (b'\x16\x03\x01\x00;'
                        b'\x01\x00\x007\x03\x01' +
                        RANDOM_STR +
                        b'\x00'
                        b'\x00\x0e' +
                        DEFAULT_CIPHERS_STR +
                        b'\x01\x00'
                        b'\x00\x00')


MAKE_PFS_HELLO_EMPTY_EXT = (b"\x16\x03\x01\x00\x8b"
                            b"\x01\x00\x00\x87"
                            b"\x03\x01" +
                            RANDOM_STR +
                            b"\x00"
                            b"\x00^" +
                            DEFAULT_PFS_CIPHERS_STR +
                            b"\x01\x00"
                            b"\x00\x00")


MAKE_12_HELLO_EMPTY_STR = (b'\x16\x03\x01\x00S'
                           b'\x01\x00\x00O'
                           b'\x03\x03' +
                           RANDOM_STR +
                           b'\x00'
                           b'\x00&' +
                           DEFAULT_12_CIPHERS_STR +
                           b'\x01\x00'
                           b'\x00\x00')


MAKE_12_PFS_HELLO_EMPTY_STR = (b"\x16\x03\x01\x00\x8b"
                               b"\x01\x00\x00\x87"
                               b"\x03\x03" +
                               RANDOM_STR +
                               b"\x00"
                               b"\x00^" +
                               DEFAULT_PFS_CIPHERS_STR +
                               b"\x01\x00"
                               b"\x00\x00")


class TestNormalHandshake(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT])


class TestNormalHandshakePFS(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshakePFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_PFS_HELLO_EMPTY_EXT])


class TestNormalHandshake12(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR])


class TestNormalHandshake12PFS(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR])


class Test(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake12PFSw13()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8b"
                          b"\x01\x00\x00\x87"
                          b"\x03\x04" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b"\x00\x00"])


class TestDoubleClientHello(unittest.TestCase):
    def test_test(self):
        probe = DoubleClientHello()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT, MAKE_HELLO_EMPTY_EXT])


class TestDoubleClientHello12(unittest.TestCase):
    def test_test(self):
        probe = DoubleClientHello12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR,
                          MAKE_12_HELLO_EMPTY_STR])


class TestDoubleClientHello12PFS(unittest.TestCase):
    def test_test(self):
        probe = DoubleClientHello12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR,
                          MAKE_12_PFS_HELLO_EMPTY_STR])


class TestChangeCipherSpec(unittest.TestCase):
    def test_test(self):
        probe = ChangeCipherSpec()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT,
                          b'\x14\x03\x01\x00\x01'
                          b'\x01'])


class TestHelloRequest(unittest.TestCase):
    def test_test(self):
        probe = HelloRequest()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT,
                          b'\x16\x03\x01\x00\x04'
                          b'\x00\x00\x00\x00'])


class TestEmptyChangeCipherSpec(unittest.TestCase):
    def test_test(self):
        probe = EmptyChangeCipherSpec()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT,
                          b'\x14\x03\x01\x00\x00'])


class TestBadHandshakeMessage(unittest.TestCase):
    def test_test(self):
        probe = BadHandshakeMessage()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT,
                          b'\x16\x03\x01\x00\t'
                          b'Something'])


class TestEmptyRecord(unittest.TestCase):
    def test_test(self):
        probe = EmptyRecord()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x00',
                          MAKE_HELLO_EMPTY_EXT])


class TestSplitHelloPackets(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloPackets()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT[:10],
                          MAKE_HELLO_EMPTY_EXT[10:]])

class TestTwoInvalidPackets(unittest.TestCase):
    def test_test(self):
        probe = TwoInvalidPackets()
        sock = MockSock()

        probe.test(sock)

        # this is broken because it is replicating the behaviour of old
        # incorrect code
        self.assertEqual(bytes(sock.sent_data[0])[:32],
                         b'<tls.record.TLSRecord object at ')
        self.assertEqual(bytes(sock.sent_data[1])[:32],
                         b'<tls.record.TLSRecord object at ')

class TestSplitHelloRecords(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloRecords()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\n'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR[:4],
                          b'\x16\x03\x01\x001' +
                          RANDOM_STR[4:] +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestOnlyECCipherSuites(unittest.TestCase):
    def test_test(self):
        probe = OnlyECCipherSuites()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00;"
                          b"\x01\x00\x007"
                          b"\x03\x01" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00\x0e"
                          b"\xc0\x0c\xc0\r\xc0\x0e\xc0\x0f"
                          b"\xc0\x13\xc0\x14\xc0'"
                          b"\x01\x00"
                          b"\x00\x00"])


class TestHeartbeat(unittest.TestCase):
    def test_test(self):
        probe = Heartbeat()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00@'
                          b'\x01\x00\x00<'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x01\x00\x07'
                          b'\x01\x00\x04XXXX'])


class TestHeartbleed(unittest.TestCase):
    def test_test(self):
        probe = Heartbleed()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00@'
                          b'\x01\x00\x00<'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x01\x00\x07'
                          b'\x01@\x00XXXX'])


class TestHighTLSVersion(unittest.TestCase):
    def test_test(self):
        probe = HighTLSVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x04\x00\x00;'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestVeryHighTLSVersion(unittest.TestCase):
    def test_test(self):
        probe = VeryHighTLSVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\xff\xff\x00;'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestZeroTLSVersion(unittest.TestCase):
    def test_test(self):
        probe = ZeroTLSVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x00\x00\x00;'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestSNIWrongName(unittest.TestCase):
    def test_test(self):
        probe = SNIWrongName()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00U'
                          b'\x01\x00\x00Q'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x1a'
                          b'\x00\x00\x00\x16'
                          b'\x00\x14\x00\x00'
                          b'\x11thisisnotyourname'])


class TestSNILongName(unittest.TestCase):
    def test_test(self):
        probe = SNILongName()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x028'
                          b'\x01\x00\x024'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x01\xfd'
                          b'\x00\x00\x01\xf9'
                          b'\x01\xf7\x00\x01\xf4' + b'x'*500])


class TestSNIEmptyName(unittest.TestCase):
    def test_test(self):
        probe = SNIEmptyName()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00D'
                          b'\x01\x00\x00@'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\t'
                          b'\x00\x00\x00\x05'
                          b'\x00\x03\x00\x00\x00'])


class TestSecureRenegoOverflow(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoOverflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00J'
                          b'\x01\x00\x00F'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0f'
                          b'\xff\x01\x00\x0b'
                          b'\x0c0123456789'])


class TestSecureRenegoUnderflow(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoUnderflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00D'
                          b'\x01\x00\x00@'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\t'
                          b'\xff\x01\x00\x05'
                          b'\x00\x00\x00\x00\x00'])


class TestSecureRenegoNonEmpty(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNonEmpty()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00L'
                          b'\x01\x00\x00H'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x11\xff\x01'
                          b'\x00\r\x0c012345678901'])


class TestSecureRenegoNull(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNull()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00?'
                          b'\x01\x00\x00;'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\xff\x01\x00\x00'])
