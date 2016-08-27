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

assert len(MAKE_HELLO_EMPTY_EXT) == 64, len(MAKE_HELLO_EMPTY_EXT)

MAKE_PFS_HELLO_EMPTY_EXT = (b"\x16\x03\x01\x00\x8b"
                            b"\x01\x00\x00\x87"
                            b"\x03\x01" +
                            RANDOM_STR +
                            b"\x00"
                            b"\x00^" +
                            DEFAULT_PFS_CIPHERS_STR +
                            b"\x01\x00"
                            b"\x00\x00")


MAKE_11_HELLO_EMPTY_STR = (b'\x16\x03\x01\x00S'
                           b'\x01\x00\x00O'
                           b'\x03\x02' +
                           RANDOM_STR +
                           b'\x00'
                           b'\x00&' +
                           DEFAULT_12_CIPHERS_STR +
                           b'\x01\x00'
                           b'\x00\x00')


MAKE_11_PFS_HELLO_EMPTY_STR = (b"\x16\x03\x01\x00\x8b"
                               b"\x01\x00\x00\x87"
                               b"\x03\x02" +
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


assert len(MAKE_12_HELLO_EMPTY_STR) == 88, len(MAKE_12_HELLO_EMPTY_STR)


MAKE_12_PFS_HELLO_EMPTY_STR = (b"\x16\x03\x01\x00\x8b"
                               b"\x01\x00\x00\x87"
                               b"\x03\x03" +
                               RANDOM_STR +
                               b"\x00"
                               b"\x00^" +
                               DEFAULT_PFS_CIPHERS_STR +
                               b"\x01\x00"
                               b"\x00\x00")

assert len(MAKE_12_PFS_HELLO_EMPTY_STR) == 144,\
        len(MAKE_12_PFS_HELLO_EMPTY_STR)

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


class TestNormalHandshake11(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake11()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_11_HELLO_EMPTY_STR])


class TestNormalHandshake11PFS(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake11PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_11_PFS_HELLO_EMPTY_STR])


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


class TestInvalidSessionID(unittest.TestCase):
    def test_test(self):
        probe = InvalidSessionID()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00c'
                          b'\x01\x00\x00_'
                          b'\x03\01' +
                          RANDOM_STR +
                          b'\x28' +
                          b'0123456789' * 4 +
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidSessionID12(unittest.TestCase):
    def test_test(self):
        probe = InvalidSessionID12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00{'
                          b'\x01\x00\x00w'
                          b'\x03\03' +
                          RANDOM_STR +
                          b'\x28' +
                          b'0123456789' * 4 +
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidSessionID12PFS(unittest.TestCase):
    def test_test(self):
        probe = InvalidSessionID12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\xb3'
                          b'\x01\x00\x00\xaf'
                          b'\x03\03' +
                          RANDOM_STR +
                          b'\x28' +
                          b'0123456789' * 4 +
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidCiphersLength(unittest.TestCase):
    def test_test(self):
        probe = InvalidCiphersLength()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00<'
                          b'\x01\x00\x008'
                          b'\x03\01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0f' +
                          DEFAULT_CIPHERS_STR + b'\x00'
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidCiphersLength12(unittest.TestCase):
    def test_test(self):
        probe = InvalidCiphersLength12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00T'
                          b'\x01\x00\x00P'
                          b'\x03\03' +
                          RANDOM_STR +
                          b'\x00'
                          b"\x00'" +
                          DEFAULT_12_CIPHERS_STR + b'\x00'
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidCiphersLength12PFS(unittest.TestCase):
    def test_test(self):
        probe = InvalidCiphersLength12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x8c'
                          b'\x01\x00\x00\x88'
                          b'\x03\03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00_' +
                          DEFAULT_PFS_CIPHERS_STR + b'\x00'
                          b'\x01\x00'
                          b'\x00\x00'])


class TestInvalidExtLength(unittest.TestCase):
    def test_test(self):
        probe = InvalidExtLength()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00:'
                          b'\x01\x00\x006'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00'])


class TestInvalidExtLength12(unittest.TestCase):
    def test_test(self):
        probe = InvalidExtLength12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00R'
                           b'\x01\x00\x00N'
                           b'\x03\x03' +
                           RANDOM_STR +
                           b'\x00'
                           b'\x00&' +
                           DEFAULT_12_CIPHERS_STR +
                           b'\x01\x00'
                           b'\x00'])


class TestInvalidExtLength12PFS(unittest.TestCase):
    def test_test(self):
        probe = InvalidExtLength12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8a"
                          b"\x01\x00\x00\x86"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b"\x00"])


class TestExtensionsUnderflow(unittest.TestCase):
    def test_test(self):
        probe = ExtensionsUnderflow()
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
                          b'\x00\x01'
                          b'\xff\x01'
                          b'\x00\x01'
                          b'\x00'])


class TestExtensionsUnderflow12(unittest.TestCase):
    def test_test(self):
        probe = ExtensionsUnderflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00X'
                          b'\x01\x00\x00T'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x01'
                          b'\xff\x01'
                          b'\x00\x01'
                          b'\x00'])


class TestExtensionsUnderflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = ExtensionsUnderflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x90"
                          b"\x01\x00\x00\x8c"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x01'
                          b'\xff\x01'
                          b'\x00\x01'
                          b'\x00'])


class TestEmptyCompression(unittest.TestCase):
    def test_test(self):
        probe = EmptyCompression()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00:'
                          b'\x01\x00\x006'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x00'
                          b'\x00\x00'])


class TestEmptyCompression12(unittest.TestCase):
    def test_test(self):
        probe = EmptyCompression12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00R'
                          b'\x01\x00\x00N'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x00'
                          b'\x00\x00'])


class TestEmptyCompression12PFS(unittest.TestCase):
    def test_test(self):
        probe = EmptyCompression12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8a"
                          b"\x01\x00\x00\x86"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x00"
                          b"\x00\x00"])


class TestCompressOnly(unittest.TestCase):
    def test_test(self):
        probe = CompressOnly()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00<'
                          b'\x01\x00\x008'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x02\x01\x40'
                          b'\x00\x00'])


class TestCompressOnly12(unittest.TestCase):
    def test_test(self):
        probe = CompressOnly12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00T'
                          b'\x01\x00\x00P'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x02\x01\x40'
                          b'\x00\x00'])


class TestCompressOnly12PFS(unittest.TestCase):
    def test_test(self):
        probe = CompressOnly12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8c"
                          b"\x01\x00\x00\x88"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x02\x01\x40"
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


class TestChangeCipherSpec12(unittest.TestCase):
    def test_test(self):
        probe = ChangeCipherSpec12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR,
                          b'\x14\x03\x03\x00\x01'
                          b'\x01'])


class TestChangeCipherSpec12PFS(unittest.TestCase):
    def test_test(self):
        probe = ChangeCipherSpec12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR,
                          b'\x14\x03\x03\x00\x01'
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


class TestHelloRequest12(unittest.TestCase):
    def test_test(self):
        probe = HelloRequest12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR,
                          b'\x16\x03\x03\x00\x04'
                          b'\x00\x00\x00\x00'])


class TestHelloRequest12PFS(unittest.TestCase):
    def test_test(self):
        probe = HelloRequest12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR,
                          b'\x16\x03\x03\x00\x04'
                          b'\x00\x00\x00\x00'])


class TestEmptyChangeCipherSpec(unittest.TestCase):
    def test_test(self):
        probe = EmptyChangeCipherSpec()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT,
                          b'\x14\x03\x01\x00\x00'])


class TestEmptyChangeCipherSpec12(unittest.TestCase):
    def test_test(self):
        probe = EmptyChangeCipherSpec12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR,
                          b'\x14\x03\x03\x00\x00'])


class TestEmptyChangeCipherSpec12PFS(unittest.TestCase):
    def test_test(self):
        probe = EmptyChangeCipherSpec12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR,
                          b'\x14\x03\x03\x00\x00'])


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


class TestSplitHelloPackets12(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloPackets12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_HELLO_EMPTY_STR[:10],
                          MAKE_12_HELLO_EMPTY_STR[10:]])


class TestSplitHelloPackets12PFS(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloPackets12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_12_PFS_HELLO_EMPTY_STR[:10],
                          MAKE_12_PFS_HELLO_EMPTY_STR[10:]])


class TestNoCiphers(unittest.TestCase):
    def test_test(self):
        probe = NoCiphers()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00-'
                          b'\x01\x00\x00)'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x00'
                          b'\x01\x00'
                          b'\x00\x00'])


class TestNoCiphers12(unittest.TestCase):
    def test_test(self):
        probe = NoCiphers12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00-'
                          b'\x01\x00\x00)'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x00'
                          b'\x01\x00'
                          b'\x00\x00'])


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


class TestSplitHelloRecords12(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloRecords12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\n'
                          b'\x01\x00\x00O'
                          b'\x03\x03' +
                          RANDOM_STR[:4],
                          b'\x16\x03\x01\x00I' +
                          RANDOM_STR[4:] +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestSplitHelloRecords12PFS(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloRecords12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\n'
                          b'\x01\x00\x00\x87'
                          b'\x03\x03' +
                          RANDOM_STR[:4],
                          b'\x16\x03\x01\x00\x81' +
                          RANDOM_STR[4:] +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestHeartbeat12(unittest.TestCase):
    def test_test(self):
        probe = Heartbeat12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00X'
                          b'\x01\x00\x00T'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x03\x00\x07'
                          b'\x01\x00\x04XXXX'])


class TestHeartbeat12PFS(unittest.TestCase):
    def test_test(self):
        probe = Heartbeat12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x90'
                          b'\x01\x00\x00\x8c'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x03\x00\x07'
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


class TestHeartbleed12(unittest.TestCase):
    def test_test(self):
        probe = Heartbleed12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00X'
                          b'\x01\x00\x00T'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x03\x00\x07'
                          b'\x01@\x00XXXX'])


class TestHeartbleed12PFS(unittest.TestCase):
    def test_test(self):
        probe = Heartbleed12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x90'
                          b'\x01\x00\x00\x8c'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x0f'
                          b'\x00\x01\x01',
                          b'\x18\x03\x03\x00\x07'
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


class TestHighTLSVersion12(unittest.TestCase):
    def test_test(self):
        probe = HighTLSVersion12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x04\x00\x00S'
                          b'\x01\x00\x00O'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestHighTLSVersion12PFS(unittest.TestCase):
    def test_test(self):
        probe = HighTLSVersion12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x04\x00\x00\x8b'
                          b'\x01\x00\x00\x87'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestVeryHighTLSVersion12(unittest.TestCase):
    def test_test(self):
        probe = VeryHighTLSVersion12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\xff\xff\x00S'
                          b'\x01\x00\x00O'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestVeryHighTLSVersion12PFS(unittest.TestCase):
    def test_test(self):
        probe = VeryHighTLSVersion12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\xff\xff\x00\x8b'
                          b'\x01\x00\x00\x87'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestZeroTLSVersion12(unittest.TestCase):
    def test_test(self):
        probe = ZeroTLSVersion12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x00\x00\x00S'
                          b'\x01\x00\x00O'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestZeroTLSVersion12PFS(unittest.TestCase):
    def test_test(self):
        probe = ZeroTLSVersion12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x00\x00\x00\x8b'
                          b'\x01\x00\x00\x87'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestHighHelloVersion(unittest.TestCase):
    def test_test(self):
        probe = HighHelloVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00;'
                          b'\x01\x00\x007'
                          b'\x04\x00' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestHighHelloVersionNew(unittest.TestCase):
    def test_test(self):
        probe = HighHelloVersionNew()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00S'
                          b'\x01\x00\x00O'
                          b'\x04\x00' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestHighHelloVersionPFS(unittest.TestCase):
    def test_test(self):
        probe = HighHelloVersionPFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x8b'
                          b'\x01\x00\x00\x87'
                          b'\x04\x00' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestVeryHighHelloVersion(unittest.TestCase):
    def test_test(self):
        probe = VeryHighHelloVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00;'
                          b'\x01\x00\x007'
                          b'\xff\xff' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestVeryHighHelloVersionNew(unittest.TestCase):
    def test_test(self):
        probe = VeryHighHelloVersionNew()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00S'
                          b'\x01\x00\x00O'
                          b'\xff\xff' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestVeryHighHelloVersionPFS(unittest.TestCase):
    def test_test(self):
        probe = VeryHighHelloVersionPFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x8b'
                          b'\x01\x00\x00\x87'
                          b'\xff\xff' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestZeroHelloVersion(unittest.TestCase):
    def test_test(self):
        probe = ZeroHelloVersion()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00;'
                          b'\x01\x00\x007'
                          b'\x00\x00' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestBadContentType(unittest.TestCase):
    def test_test(self):
        probe = BadContentType()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x11\x03\x01\x00;'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00'])


class TestRecordLengthOverflow(unittest.TestCase):
    def test_test(self):
        probe = RecordLengthOverflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x01'
                          b'\x01'])


class TestRecordLengthUnderflow(unittest.TestCase):
    def test_test(self):
        probe = RecordLengthUnderflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(len(sock.sent_data[0]), 65540)
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\xff\xff'
                          b'\x01\x00\x007'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x00' +
                          b'\x00' * (65540 - 64)])


class TestEmptyRecord(unittest.TestCase):
    def test_test(self):
        probe = EmptyRecord()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x00',
                          MAKE_HELLO_EMPTY_EXT])


class TestEmptyRecord12(unittest.TestCase):
    def test_test(self):
        probe = EmptyRecord12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x00',
                          MAKE_12_HELLO_EMPTY_STR])


class TestEmptyRecord12PFS(unittest.TestCase):
    def test_test(self):
        probe = EmptyRecord12PFS()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x00',
                          MAKE_12_PFS_HELLO_EMPTY_STR])


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


class TestSNIWrongName12(unittest.TestCase):
    def test_test(self):
        probe = SNIWrongName12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00m'
                          b'\x01\x00\x00i'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x1a'
                          b'\x00\x00\x00\x16'
                          b'\x00\x14\x00\x00'
                          b'\x11thisisnotyourname'])


class TestSNIWrongName12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIWrongName12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\xa5'
                          b'\x01\x00\x00\xa1'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestSNILongName12(unittest.TestCase):
    def test_test(self):
        probe = SNILongName12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x02P'
                          b'\x01\x00\x02L'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x01\xfd'
                          b'\x00\x00\x01\xf9'
                          b'\x01\xf7\x00\x01\xf4' + b'x'*500])


class TestSNIWrongName12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNILongName12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x02\x88'
                          b'\x01\x00\x02\x84'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestSNIEmptyName12(unittest.TestCase):
    def test_test(self):
        probe = SNIEmptyName12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\\'
                          b'\x01\x00\x00X'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\t'
                          b'\x00\x00\x00\x05'
                          b'\x00\x03\x00\x00\x00'])


class TestSNIEmptyName12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIEmptyName12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x94'
                          b'\x01\x00\x00\x90'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\t'
                          b'\x00\x00\x00\x05'
                          b'\x00\x03\x00\x00\x00'])


class TestSNIOneWrong(unittest.TestCase):
    def test_test(self):
        probe = SNIOneWrong()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00c'
                          b'\x01\x00\x00_'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00('
                          b'\x00\x00\x00$'
                          b'\x00"'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x11thisisnotyourname'])


class TestSNIOneWrong12(unittest.TestCase):
    def test_test(self):
        probe = SNIOneWrong12()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00{'
                          b'\x01\x00\x00w'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00('
                          b'\x00\x00\x00$'
                          b'\x00"'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x11thisisnotyourname'])


class TestSNIOneWrong12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIOneWrong12PFS()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\xb3"
                          b"\x01\x00\x00\xaf"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00('
                          b'\x00\x00\x00$'
                          b'\x00"'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x11thisisnotyourname'])


class TestSNIWithDifferentType(unittest.TestCase):
    def test_test(self):
        probe = SNIWithDifferentType()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00_'
                          b'\x01\x00\x00['
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x00\x00\x0bexample.com'
                          b'\x04\x00\r<binary-data>'])


class TestSNIWithDifferentType12(unittest.TestCase):
    def test_test(self):
        probe = SNIWithDifferentType12()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00w'
                          b'\x01\x00\x00s'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x00\x00\x0bexample.com'
                          b'\x04\x00\r<binary-data>'])


class TestSNIWithDifferentType12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIWithDifferentType12PFS()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\xaf"
                          b"\x01\x00\x00\xab"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x00\x00\x0bexample.com'
                          b'\x04\x00\r<binary-data>'])


class TestSNIDifferentTypeRev(unittest.TestCase):
    def test_test(self):
        probe = SNIDifferentTypeRev()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00_'
                          b'\x01\x00\x00['
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x04\x00\r<binary-data>'
                          b'\x00\x00\x0bexample.com'])


class TestSNIDifferentTypeRev12(unittest.TestCase):
    def test_test(self):
        probe = SNIDifferentTypeRev12()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00w'
                          b'\x01\x00\x00s'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x04\x00\r<binary-data>'
                          b'\x00\x00\x0bexample.com'])


class TestSNIDifferentTypeRev12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIDifferentTypeRev12PFS()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\xaf"
                          b"\x01\x00\x00\xab"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00$'
                          b'\x00\x00\x00 '
                          b'\x00\x1e'
                          b'\x04\x00\r<binary-data>'
                          b'\x00\x00\x0bexample.com'])


class TestSNIOverflow(unittest.TestCase):
    def test_test(self):
        probe = SNIOverflow()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00N'
                          b'\x01\x00\x00J'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x13'
                          b'\x00\x00\x00\x0f'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.co'])


class TestSNIOverflow12(unittest.TestCase):
    def test_test(self):
        probe = SNIOverflow12()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00f'
                          b'\x01\x00\x00b'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x13'
                          b'\x00\x00\x00\x0f'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.co'])


class TestSNIOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIOverflow12PFS()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x9e"
                          b"\x01\x00\x00\x9a"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x13'
                          b'\x00\x00\x00\x0f'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.co'])


class TestSNIUnderflow(unittest.TestCase):
    def test_test(self):
        probe = SNIUnderflow()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00R'
                          b'\x01\x00\x00N'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x17'
                          b'\x00\x00\x00\x13'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x00'])


class TestSNIUnderflow12(unittest.TestCase):
    def test_test(self):
        probe = SNIUnderflow12()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00j'
                          b'\x01\x00\x00f'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x17'
                          b'\x00\x00\x00\x13'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x00'])


class TestSNIUnderflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = SNIUnderflow12PFS()
        probe.ipaddress = b'example.com'
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\xa2"
                          b"\x01\x00\x00\x9e"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x17'
                          b'\x00\x00\x00\x13'
                          b'\x00\x0e'
                          b'\x00\x00\x0bexample.com'
                          b'\x00\x00\x00'])


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


class TestSecureRenegoOverflow12(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00b'
                          b'\x01\x00\x00^'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0f'
                          b'\xff\x01\x00\x0b'
                          b'\x0c0123456789'])


class TestSecureRenegoOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x9a'
                          b'\x01\x00\x00\x96'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestSecureRenegoUnderflow12(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoUnderflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\\'
                          b'\x01\x00\x00X'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\t'
                          b'\xff\x01\x00\x05'
                          b'\x00\x00\x00\x00\x00'])


class TestSecureRenegoUnderflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoUnderflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x94'
                          b'\x01\x00\x00\x90'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestSecureRenegoNonEmpty12(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNonEmpty12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00d'
                          b'\x01\x00\x00`'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x11\xff\x01'
                          b'\x00\r\x0c012345678901'])


class TestSecureRenegoNonEmpty12PFS(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNonEmpty12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x9c'
                          b'\x01\x00\x00\x98'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
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


class TestSecureRenegoNull12(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\xff\x01\x00\x00'])


class TestSecureRenegoNonEmpty12PFS(unittest.TestCase):
    def test_test(self):
        probe = SecureRenegoNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x8f'
                          b'\x01\x00\x00\x8b'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\xff\x01\x00\x00'])


class TestMaxFragmentNull(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentNull()
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
                          b'\x00\x01\x00\x00'])


class TestMaxFragmentNull12(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x01\x00\x00'])


class TestMaxFragmentNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x01\x00\x00'])


class TestMaxFragmentInvalid(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentInvalid()
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
                          b'\x00\x01\x00\x01'
                          b'\x08'])


class TestMaxFragmentInvalid12(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentInvalid12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00X'
                          b'\x01\x00\x00T'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x01\x00\x01'
                          b'\x08'])


class TestMaxFragmentInvalid12PFS(unittest.TestCase):
    def test_test(self):
        probe = MaxFragmentInvalid12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x90"
                          b"\x01\x00\x00\x8c"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x05'
                          b'\x00\x01\x00\x01'
                          b'\x08'])


class TestClientCertURLsNotNull(unittest.TestCase):
    def test_test(self):
        probe = ClientCertURLsNotNull()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00A'
                          b'\x01\x00\x00='
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x02\x00\x02'
                          b'\x08\x00'])


class TestClientCertURLsNotNull12(unittest.TestCase):
    def test_test(self):
        probe = ClientCertURLsNotNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Y'
                          b'\x01\x00\x00U'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x02\x00\x02'
                          b'\x08\x00'])


class TestClientCertURLsNotNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = ClientCertURLsNotNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x91"
                          b"\x01\x00\x00\x8d"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x06'
                          b'\x00\x02\x00\x02'
                          b'\x08\x00'])


class TestTrustedCANull(unittest.TestCase):
    def test_test(self):
        probe = TrustedCANull()
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
                          b'\x00\x03\x00\x00'])


class TestTrustedCANull12(unittest.TestCase):
    def test_test(self):
        probe = TrustedCANull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x03\x00\x00'])


class TestTrustedCANull12PFS(unittest.TestCase):
    def test_test(self):
        probe = TrustedCANull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x03\x00\x00'])


class TestTrustedCAOverflow(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAOverflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00A'
                          b'\x01\x00\x00='
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x03\x00\x02'
                          b'\x00\x15'])


class TestTrustedCAOverflow12(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Y'
                          b'\x01\x00\x00U'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x03\x00\x02'
                          b'\x00\x15'])


class TestTrustedCAOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x91"
                          b"\x01\x00\x00\x8d"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x06'
                          b'\x00\x03\x00\x02'
                          b'\x00\x15'])


class TestTrustedCAUnderflow(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAUnderflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x1c'
                          b'\x00\x03\x00\x18'
                          b'\x00\x15\x01' + 'a'*20 + b'\x00'])


class TestTrustedCAUnderflow12(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAUnderflow12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00o'
                          b'\x01\x00\x00k'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x1c'
                          b'\x00\x03\x00\x18'
                          b'\x00\x15\x01' + 'a'*20 + b'\x00'])


class TestTrustedCAUnderflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = TrustedCAUnderflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\xa7"
                          b"\x01\x00\x00\xa3"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x1c'
                          b'\x00\x03\x00\x18'
                          b'\x00\x15\x01' + 'a'*20 + b'\x00'])


class TestTruncatedHMACNotNull(unittest.TestCase):
    def test_test(self):
        probe = TruncatedHMACNotNull()
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
                          b'\x00\x04\x00\x01'
                          b'\x0c'])


class TestTruncatedHMACNotNull12(unittest.TestCase):
    def test_test(self):
        probe = TruncatedHMACNotNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00X'
                          b'\x01\x00\x00T'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x05'
                          b'\x00\x04\x00\x01'
                          b'\x0c'])


class TestTruncatedHMACNotNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = TruncatedHMACNotNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x90"
                          b"\x01\x00\x00\x8c"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x05'
                          b'\x00\x04\x00\x01'
                          b'\x0c'])


class TestOCSPNull(unittest.TestCase):
    def test_test(self):
        probe = OCSPNull()
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
                          b'\x00\x05\x00\x00'])


class TestOCSPNull12(unittest.TestCase):
    def test_test(self):
        probe = OCSPNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x05\x00\x00'])


class TestOCSPNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = OCSPNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x05\x00\x00'])


class TestOCSPOverflow(unittest.TestCase):
    def test_test(self):
        probe = OCSPOverflow()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00C'
                          b'\x01\x00\x00?'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x08'
                          b'\x00\x05\x00\x04'
                          b'\x01\x00\x00\x00'])


class TestOCSPOverflow12(unittest.TestCase):
    def test_test(self):
        probe = OCSPOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00['
                          b'\x01\x00\x00W'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x08'
                          b'\x00\x05\x00\x04'
                          b'\x01\x00\x00\x00'])


class TestOCSPOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = OCSPOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x93"
                          b"\x01\x00\x00\x8f"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x08'
                          b'\x00\x05\x00\x04'
                          b'\x01\x00\x00\x00'])


class TestOCSPUnderflow(unittest.TestCase):
    def test_test(self):
        probe = OCSPUnderflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00F'
                          b'\x01\x00\x00B'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0b'
                          b'\x00\x05\x00\x07'
                          b'\x01\x00\x00\x00\x00\x00\x00'])


class TestOCSPUnderflow12(unittest.TestCase):
    def test_test(self):
        probe = OCSPUnderflow12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00^'
                          b'\x01\x00\x00Z'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0b'
                          b'\x00\x05\x00\x07'
                          b'\x01\x00\x00\x00\x00\x00\x00'])


class TestOCSPUnderflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = OCSPUnderflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x96"
                          b"\x01\x00\x00\x92"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x0b'
                          b'\x00\x05\x00\x07'
                          b'\x01\x00\x00\x00\x00\x00\x00'])


class TestDoubleExtension(unittest.TestCase):
    def test_test(self):
        probe = DoubleExtension()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00E'
                          b'\x01\x00\x00A'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0a'
                          b'\xff\x01\x00\x01'
                          b'\x00'
                          b'\xff\x01\x00\x01'
                          b'\x00'])


class TestDoubleExtension12(unittest.TestCase):
    def test_test(self):
        probe = DoubleExtension12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00]'
                          b'\x01\x00\x00Y'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x0a'
                          b'\xff\x01\x00\x01'
                          b'\x00'
                          b'\xff\x01\x00\x01'
                          b'\x00'])


class TestDoubleExtension12PFS(unittest.TestCase):
    def test_test(self):
        probe = DoubleExtension12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x95"
                          b"\x01\x00\x00\x91"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x0a'
                          b'\xff\x01\x00\x01'
                          b'\x00'
                          b'\xff\x01\x00\x01'
                          b'\x00'])


class TestUserMappingNull(unittest.TestCase):
    def test_test(self):
        probe = UserMappingNull()
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
                          b'\x00\x06\x00\x00'])


class TestUserMappingNull12(unittest.TestCase):
    def test_test(self):
        probe = UserMappingNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x06\x00\x00'])


class TestUserMappingNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = UserMappingNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x06\x00\x00'])


class TestUserMappingOverflow(unittest.TestCase):
    def test_test(self):
        probe = UserMappingOverflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00A'
                          b'\x01\x00\x00='
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x06\x00\x02'
                          b'\x02\x40'])


class TestUserMappingOverflow12(unittest.TestCase):
    def test_test(self):
        probe = UserMappingOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Y'
                          b'\x01\x00\x00U'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x06\x00\x02'
                          b'\x02\x40'])


class TestUserMappingOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = UserMappingOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x91"
                          b"\x01\x00\x00\x8d"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x06'
                          b'\x00\x06\x00\x02'
                          b'\x02\x40'])


class TestClientAuthzNull(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzNull()
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
                          b'\x00\x07\x00\x00'])


class TestClientAuthzNull12(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x07\x00\x00'])


class TestClientAuthzNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x07\x00\x00'])


class TestClientAuthzOverflow(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzOverflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00B'
                          b'\x01\x00\x00>'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x07'
                          b'\x00\x07\x00\x03'
                          b'\x04\x00\x01'])


class TestClientAuthzOverflow12(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Z'
                          b'\x01\x00\x00V'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x07'
                          b'\x00\x07\x00\x03'
                          b'\x04\x00\x01'])


class TestClientAuthzOverflow12FS(unittest.TestCase):
    def test_test(self):
        probe = ClientAuthzOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x92"
                          b"\x01\x00\x00\x8e"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x07'
                          b'\x00\x07\x00\x03'
                          b'\x04\x00\x01'])


class TestServerAuthzNull(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzNull()
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
                          b'\x00\x08\x00\x00'])


class TestServerAuthzNull12(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x08\x00\x00'])


class TestServerAuthzNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x08\x00\x00'])


class TestServerAuthzOverflow(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzOverflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00B'
                          b'\x01\x00\x00>'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x07'
                          b'\x00\x08\x00\x03'
                          b'\x04\x00\x01'])


class TestServerAuthzOverflow12(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Z'
                          b'\x01\x00\x00V'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x07'
                          b'\x00\x08\x00\x03'
                          b'\x04\x00\x01'])


class TestServerAuthzOverflow12FS(unittest.TestCase):
    def test_test(self):
        probe = ServerAuthzOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x92"
                          b"\x01\x00\x00\x8e"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x07'
                          b'\x00\x08\x00\x03'
                          b'\x04\x00\x01'])


class TestCertTypeNull(unittest.TestCase):
    def test_test(self):
        probe = CertTypeNull()
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
                          b'\x00\x09\x00\x00'])


class TestCertTypeNull12(unittest.TestCase):
    def test_test(self):
        probe = CertTypeNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x09\x00\x00'])


class TestCertTypeNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = CertTypeNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x8f"
                          b"\x01\x00\x00\x8b"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x04'
                          b'\x00\x09\x00\x00'])


class TestCertTypeOverflow(unittest.TestCase):
    def test_test(self):
        probe = CertTypeOverflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00A'
                          b'\x01\x00\x00='
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x09\x00\x02'
                          b'\x04\x01'])


class TestCertTypeOverflow12(unittest.TestCase):
    def test_test(self):
        probe = CertTypeOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00Y'
                          b'\x01\x00\x00U'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x06'
                          b'\x00\x09\x00\x02'
                          b'\x04\x01'])


class TestCertTypeOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = CertTypeOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x91"
                          b"\x01\x00\x00\x8d"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x06'
                          b'\x00\x09\x00\x02'
                          b'\x04\x01'])


class TestSupportedGroupsNull(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsNull()
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
                          b'\x00\x0a\x00\x00'])


class TestSupportedGroupsNull12(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsNull12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00W'
                          b'\x01\x00\x00S'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x0a\x00\x00'])


class TestSupportedGroupsNull12PFS(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsNull12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\x8f'
                          b'\x01\x00\x00\x8b'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00^' +
                          DEFAULT_PFS_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x04'
                          b'\x00\x0a\x00\x00'])


class TestSupportedGroupsOddLen(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOddLen()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00D'
                          b'\x01\x00\x00@'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x09'
                          b'\x00\x0a\x00\x05'
                          b'\x00\x03\x00\x17\x00'])


class TestSupportedGroupsOddLen12(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOddLen12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00\\'
                          b'\x01\x00\x00X'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x09'
                          b'\x00\x0a\x00\x05'
                          b'\x00\x03\x00\x17\x00'])


class TestSupportedGroupsOddLen12PFS(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOddLen12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x94"
                          b"\x01\x00\x00\x90"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x09'
                          b'\x00\x0a\x00\x05'
                          b'\x00\x03\x00\x17\x00'])


class TestSupportedGroupsOverflow(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOverflow()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00C'
                          b'\x01\x00\x00?'
                          b'\x03\x01' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00\x0e' +
                          DEFAULT_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x08'
                          b'\x00\x0a\x00\x04'
                          b'\x00\x04\x00\x17'])


class TestSupportedGroupsOverflow12(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOverflow12()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [b'\x16\x03\x01\x00['
                          b'\x01\x00\x00W'
                          b'\x03\x03' +
                          RANDOM_STR +
                          b'\x00'
                          b'\x00&' +
                          DEFAULT_12_CIPHERS_STR +
                          b'\x01\x00'
                          b'\x00\x08'
                          b'\x00\x0a\x00\x04'
                          b'\x00\x04\x00\x17'])


class TestSupportedGroupsOverflow12PFS(unittest.TestCase):
    def test_test(self):
        probe = SupportedGroupsOverflow12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        self.assertEqual(sock.sent_data,
                         [b"\x16\x03\x01\x00\x93"
                          b"\x01\x00\x00\x8f"
                          b"\x03\x03" +
                          RANDOM_STR +
                          b"\x00"
                          b"\x00^" +
                          DEFAULT_PFS_CIPHERS_STR +
                          b"\x01\x00"
                          b'\x00\x08'
                          b'\x00\x0a\x00\x04'
                          b'\x00\x04\x00\x17'])


class TestPadding16384Byte(unittest.TestCase):
    def test_test(self):
        probe = Padding16384Byte()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfc'
                    b'\x03\x01' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00\x0e' +
                    DEFAULT_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3f\xc5'
                    b'\x00\x15\x3f\xc1' +
                    b'\x00' * (16384 - (64-5) - 4))
        self.assertEqual(repr(sock.sent_data[0][:70]),
                         repr(expected[:70]))
        self.assertEqual(sock.sent_data,
                         [expected])


class TestPadding16384Byte12(unittest.TestCase):
    def test_test(self):
        probe = Padding16384Byte12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfc'
                    b'\x03\x03' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00&' +
                    DEFAULT_12_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3f\xad'
                    b'\x00\x15\x3f\xa9' +
                    b'\x00' * (16384 - (88-5) - 4))
        self.assertEqual(repr(sock.sent_data[0][:100]),
                         repr(expected[:100]))
        self.assertEqual(sock.sent_data,
                         [expected])


class TestPadding16384Byte12PFS(unittest.TestCase):
    def test_test(self):
        probe = Padding16384Byte12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfc'
                    b'\x03\x03' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00^' +
                    DEFAULT_PFS_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3fu'
                    b'\x00\x15\x3fq' +
                    b'\x00' * (16384 - (144-5) - 4))
        self.assertEqual(repr(sock.sent_data[0][:160]),
                         repr(expected[:160]))
        self.assertEqual(sock.sent_data,
                         [expected])


class TestPadding16385Byte(unittest.TestCase):
    def test_test(self):
        probe = Padding16385Byte()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfd'
                    b'\x03\x01' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00\x0e' +
                    DEFAULT_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3f\xc6'
                    b'\x00\x15\x3f\xc2' +
                    b'\x00' * (16385 - (64-5) - 4 - 1) +
                    b'\x16\x03\x01\x00\x01'  # second record
                    b'\x00')
        self.assertEqual(repr(sock.sent_data[0][:70]),
                         repr(expected[:70]))
        self.assertEqual(sock.sent_data,
                         [expected])


class TestPadding16385Byte12(unittest.TestCase):
    def test_test(self):
        probe = Padding16385Byte12()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfd'
                    b'\x03\x03' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00&' +
                    DEFAULT_12_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3f\xae'
                    b'\x00\x15\x3f\xaa' +
                    b'\x00' * (16385 - (88-5) - 4 -1 ) +
                    b'\x16\x03\x01\x00\x01'  # second record
                    b'\x00')
        self.assertEqual(repr(sock.sent_data[0][:100]),
                         repr(expected[:100]))
        self.assertEqual(sock.sent_data,
                         [expected])


class TestPadding16385Byte12PFS(unittest.TestCase):
    def test_test(self):
        probe = Padding16385Byte12PFS()
        sock = MockSock()

        probe.test(sock)

        self.maxDiff = None
        expected = (b'\x16\x03\x01\x40\x00'
                    b'\x01\x00\x3f\xfd'
                    b'\x03\x03' +
                    RANDOM_STR +
                    b'\x00'
                    b'\x00^' +
                    DEFAULT_PFS_CIPHERS_STR +
                    b'\x01\x00'
                    b'\x3fv'
                    b'\x00\x15\x3fr' +
                    b'\x00' * (16385 - (144-5) - 4 - 1 ) +
                    b'\x16\x03\x01\x00\x01'  # second record
                    b'\x00')
        self.assertEqual(repr(sock.sent_data[0][:160]),
                         repr(expected[:160]))
        self.assertEqual(sock.sent_data,
                         [expected])
