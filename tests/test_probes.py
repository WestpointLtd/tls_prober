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


MAKE_HELLO_EMPTY_EXT = (b'\x16\x03\x01\x00;'
                        b'\x01\x00\x007\x03\x01'
                        b'01234567890123456789012345678901'
                        b'\x00'
                        b'\x00\x0e'
                        b'\x00\x04\x00\x05\x00\n\x00/\x005\x00<\x00='
                        b'\x01\x00'
                        b'\x00\x00')


class TestNormalHandshake(unittest.TestCase):
    def test_test(self):
        probe = NormalHandshake()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT])


class TestDoubleClientHello(unittest.TestCase):
    def test_test(self):
        probe = DoubleClientHello()
        sock = MockSock()

        probe.test(sock)

        self.assertEqual(sock.sent_data,
                         [MAKE_HELLO_EMPTY_EXT, MAKE_HELLO_EMPTY_EXT])


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

class TestSplitHelloRecords(unittest.TestCase):
    def test_test(self):
        probe = SplitHelloRecords()
        sock = MockSock()

        probe.test(sock)

        # XXX this is broken, but can't change it as it would invalidate
        # probes
        self.assertEqual(bytes(sock.sent_data[0])[:32],
                         b'<tls.record.TLSRecord object at ')
        self.assertEqual(bytes(sock.sent_data[1])[:32],
                         b'<tls.record.TLSRecord object at ')
