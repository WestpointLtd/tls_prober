#!/usr/bin/python

import socket
import errno
import logging
import os
import platform

if platform.system() != 'Java':
    from select import select
else:
    from select import cpython_compatible_select as select

# Disable socks support in Jython
if platform.system() != 'Java':
    import socks
else:
    if os.environ.has_key('socks_proxy'):
        logging.warn('Unable to honour socks_proxy environment variable, unsupported in Jython')

from prober_utils import *

settings = {
    # Note that changing these will invalidate many of the fingerprints
    'default_hello_version': TLSRecord.TLS1_0,
    'default_record_version': TLSRecord.TLS1_0,
    'socket_timeout': 5
}

class Probe(object):

    #
    # Reusable standard elements
    #
    def __init__(self):
        self.ipaddress = None

    def connect(self, ipaddress, port, starttls_mode):
        self.ipaddress = ipaddress
        # Check if we're using socks
        if os.environ.has_key('socks_proxy'):
            socks_host, socks_port = os.environ['socks_proxy'].split(':')
            s = socks.socksocket()
            s.setproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(socks_port))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(settings['socket_timeout'])
        s.connect((ipaddress, port))

        # Do starttls if relevant
        starttls(s, port, starttls_mode)
            
        return s.makefile('rw', 0)

    def test(self, sock):
        pass

    def process_response(self, sock):

        response = ''
        got_done = False

        while True:
            # Check if there is anything following the server done
            if got_done:
                # If no data then we're done (the server hasn't sent anything further)
                # we allow 500ms to give the followup time to arrive
                if not select([sock.fileno(),],[],[],0.5)[0]:
                    break

            try:
                record = read_tls_record(sock)
                response += '*(%x)' % record.version() # TODO: Not sure that recording the record layer version is worth it?
            except socket.timeout, e:
                response += 'error:timeout'
                break
            except socket.error, e:
                response += 'error:%s|' % errno.errorcode[e.errno]
                break
            except IOError, e:
                response += 'error:%s|' % str(e)
                break
        
            if record.content_type() == TLSRecord.Handshake:
                # A single handshake record can contain multiple handshake messages
                processed_bytes = 0
                while processed_bytes < record.message_length():
                    message = HandshakeMessage.from_bytes(record.message()[processed_bytes:])

                    if message.message_type() == message.ServerHello:
                        response += 'handshake:%s(%x)|' % (message.message_types[message.message_type()], message.server_version())
                    else:
                        response += 'handshake:%s|' % (message.message_types[message.message_type()])

                    if message.message_type() == HandshakeMessage.ServerHelloDone:
                        got_done = True

                    processed_bytes += message.message_length() + 4

                if got_done:
                    continue

            elif record.content_type() == TLSRecord.Alert:
                alert = AlertMessage.from_bytes(record.message())

                if alert.alert_level() == AlertMessage.Fatal:
                    response += 'alert:%s:fatal|' % alert.alert_types[alert.alert_type()]
                    break
                else:
                    response += 'alert:%s:warning|' % alert.alert_types[alert.alert_type()]
            else:
                if record.content_types.has_key(record.content_type()):
                    response += 'record:%s|' % record.content_types[record.content_type()]
                else:
                    response += 'record:type(%x)|' % record.content_type()

            if got_done:
                break

        return response
    
    def probe(self, ipaddress, port, starttls):
        sock = self.connect(ipaddress, port, starttls)
        try:
            result = self.test(sock)
        except socket.timeout, e:
            result = 'writeerror:timeout'
            return result
        except socket.error, e:
            result = 'writeerror:%s|' % errno.errorcode[e.errno]
            return result

        if result:
            return result
        return self.process_response(sock)


class NormalHandshake(Probe):
    '''A normal handshake'''

    def __init__(self):
        super(NormalHandshake, self).__init__()
        self.make_hello = make_hello

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())


class NormalHandshakePFS(NormalHandshake):
    '''Normal handshake with PFS ciphersuites'''

    def __init__(self):
        super(NormalHandshakePFS, self).__init__()
        self.make_hello = make_pfs_hello


class NormalHandshake11(NormalHandshake):
    '''Normal TLSv1.1 handshake'''

    def __init__(self):
        super(NormalHandshake11, self).__init__()
        self.make_hello = make_11_hello


class NormalHandshake11PFS(NormalHandshake):
    '''Normal TLSv1.1 handshake'''

    def __init__(self):
        super(NormalHandshake11PFS, self).__init__()
        self.make_hello = make_11_pfs_hello


class NormalHandshake12(NormalHandshake):
    '''Normal TLSv1.2 handshake'''

    def __init__(self):
        super(NormalHandshake12, self).__init__()
        self.make_hello = make_12_hello


class NormalHandshake12PFS(NormalHandshake):
    '''Normal TLSv1.2 handshake with PFS ciphersuites'''

    def __init__(self):
        super(NormalHandshake12PFS, self).__init__()
        self.make_hello = make_12_pfs_hello


class NormalHandshake12PFSw13(Probe):
    '''TLSv1.2 with PFS ciphers with a TLSv1.3 version (invalid TLSv1.3)'''

    def make_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_3,
                                          '01234567890123456789012345678901',
                                          DEFAULT_PFS_CIPHERS)

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())


class InvalidSessionID(Probe):
    '''Send session ID that is too long'''

    def __init__(self):
        self.hello_version = TLSRecord.TLS1_0
        self.ciphers = DEFAULT_CIPHERS

    def make_hello_payload(self, version, cipher_suites):
        session_id = b'0123456789' * 4  # session ID is up to 32 bytes long
        ciphers = struct.pack('>H{0}H'.format(len(cipher_suites)),
                              len(cipher_suites) * 2, *cipher_suites)
        hello = (struct.pack('>H32sB',
                             version,
                             b'01234567890123456789012345678901',
                             len(session_id)) +
                 session_id + ciphers + b'\x01\x00' + b'\x00\x00')

        return hello

    def make_hello(self, version, cipher_suites):
        hello = self.make_hello_payload(version, cipher_suites)

        hello_msg = HandshakeMessage.create(HandshakeMessage.ClientHello,
                                            hello)

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello_msg.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Helo...')
        sock.write(self.make_hello(self.hello_version, self.ciphers))


class InvalidSessionID12(InvalidSessionID):
    '''Send session ID that is too long in TLSv1.2 hello'''

    def __init__(self):
        super(InvalidSessionID12, self).__init__()
        self.hello_version = TLSRecord.TLS1_2
        self.ciphers = DEFAULT_12_CIPHERS


class InvalidSessionID12PFS(InvalidSessionID):
    '''Send session ID that is too long in PFS TLSv1.2 hello'''

    def __init__(self):
        super(InvalidSessionID12PFS, self).__init__()
        self.hello_version = TLSRecord.TLS1_2
        self.ciphers = DEFAULT_PFS_CIPHERS


class InvalidCiphersLength(InvalidSessionID):
    '''Send client hello with length field of ciphers that is invalid (odd)'''

    def make_hello_payload(self, version, cipher_suites):
        cipher_bytes = struct.pack('>{0}H'.format(len(cipher_suites)),
                                   *cipher_suites) + b'\x00'
        ciphers = struct.pack('>H', len(cipher_bytes)) + cipher_bytes
        hello = (struct.pack('>H32sB', version,
                             b'01234567890123456789012345678901',
                             0) +
                 ciphers + b'\x01\x00' + b'\x00\x00')

        return hello


class InvalidCiphersLength12(InvalidCiphersLength, InvalidSessionID12):
    '''As with InvalidCiphersLength but with TLSv1.2 helo'''
    pass


class InvalidCiphersLength12PFS(InvalidCiphersLength, InvalidSessionID12PFS):
    '''As with InvalidCiphersLength but with PFS TLSv1.2 hello'''
    pass


class InvalidExtLength(InvalidSessionID):
    '''Send client hello with length of extensions filed truncated'''

    def make_hello_payload(self, version, cipher_suites):
        ciphers = struct.pack('>H{0}H'.format(len(cipher_suites)),
                              len(cipher_suites) * 2, *cipher_suites)
        hello = (struct.pack('>H32sB',
                             version,
                             b'01234567890123456789012345678901',
                             0) +
                 ciphers + b'\x01\x00' + b'\x00')

        return hello


class InvalidExtLength12(InvalidExtLength, InvalidSessionID12):
    '''As with InvalidExtLength but in TLSv1.2 hello'''
    pass


class InvalidExtLength12PFS(InvalidExtLength, InvalidSessionID12PFS):
    '''As with InvalidExtLength but in PFS TLSv1.2 hello'''
    pass


class ExtensionsUnderflow(InvalidSessionID):
    '''Send hello with data length lower than stated size'''

    def make_hello_payload(self, version, cipher_suites):
        ciphers = struct.pack('>H{0}H'.format(len(cipher_suites)),
                              len(cipher_suites) * 2, *cipher_suites)
        hello = (struct.pack('>H32sB',
                             version,
                             b'01234567890123456789012345678901',
                             0) +
                 ciphers + b'\x01\x00'
                 b'\x00\x01'  # extensions length, just one byte
                 b'\xff\x01'  # extension ID - secure renego indication
                 b'\x00\x01'  # secure renego indication ext length
                 b'\x00')  # valid payload for extension

        return hello


class ExtensionsUnderflow12(ExtensionsUnderflow, InvalidSessionID12):
    '''As in ExtensionsUnderflow but in TLSv1.2 hello'''
    pass


class ExtensionsUnderflow12PFS(ExtensionsUnderflow, InvalidSessionID12PFS):
    '''As in ExtensionsUnderflow but in PFS TLSv1.2 hello'''
    pass


class EmptyCompression(InvalidSessionID):
    '''Send hello with no compression methods'''

    def make_hello_payload(self, version, cipher_suites):
        ciphers = struct.pack('>H{0}H'.format(len(cipher_suites)),
                              len(cipher_suites) * 2, *cipher_suites)
        hello = (struct.pack('>H32sB',
                             version,
                             b'01234567890123456789012345678901',
                             0) +
                 ciphers + b'\x00' + b'\x00\x00')

        return hello


class EmptyCompression12(EmptyCompression, InvalidSessionID12):
    '''As with EmptyCompression but in TLSv1.2 hello'''
    pass


class EmptyCompression12PFS(EmptyCompression, InvalidSessionID12PFS):
    '''As with EmptyCompression but in PFS TLSv1.2 hello'''
    pass


class CompressOnly(InvalidSessionID):
    '''Send hello with no support for uncompressed communication'''

    def make_hello_payload(self, version, cipher_suites):
        ciphers = struct.pack('>H{0}H'.format(len(cipher_suites)),
                              len(cipher_suites) * 2, *cipher_suites)
        hello = (struct.pack('>H32sB',
                             version,
                             b'01234567890123456789012345678901',
                             0) +
                 ciphers + b'\x02\x01\x40' + b'\x00\x00')

        return hello


class CompressOnly12(CompressOnly, InvalidSessionID12):
    '''As with CompressOnly but in TLSv1.2 hello'''
    pass


class CompressOnly12PFS(CompressOnly, InvalidSessionID12PFS):
    '''As with CompressOnly but in PFS TLSv1.2 hello'''
    pass


class DoubleClientHello(NormalHandshake):
    '''Two client hellos'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())


class DoubleClientHello12(DoubleClientHello, NormalHandshake12):
    '''Two client hellos, TLSv1.2'''
    pass


class DoubleClientHello12PFS(DoubleClientHello, NormalHandshake12PFS):
    '''Two client hellos, TLSv1.2 w/PFS ciphers'''
    pass


class ChangeCipherSpec(NormalHandshake):
    '''Send a hello then change cipher spec'''

    def __init__(self):
        super(ChangeCipherSpec, self).__init__()
        self.make_ccs = make_ccs
        self.record_version = TLSRecord.TLS1_0

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())
        logging.debug('Sending ChangeCipherSpec...')
        sock.write(self.make_ccs(self.record_version))


class ChangeCipherSpec12(ChangeCipherSpec, NormalHandshake12):
    '''Send TLSv1.2 hello then change cipher spec'''

    def __init__(self):
        super(ChangeCipherSpec12, self).__init__()
        self.record_version = TLSRecord.TLS1_2


class ChangeCipherSpec12PFS(NormalHandshake12PFS, ChangeCipherSpec12):
    '''Send PFS TLSv1.2 hello then change cipher spec'''
    pass


class HelloRequest(NormalHandshake):
    '''Send a hello then hello request'''

    def __init__(self):
        super(HelloRequest, self).__init__()
        self.make_hello_request = make_hello_request
        self.record_version = TLSRecord.TLS1_0

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())
        logging.debug('Sending Hello Request...')
        sock.write(self.make_hello_request(self.record_version))


class HelloRequest12(HelloRequest, NormalHandshake12):
    '''Send a TLSv1.2 hello then hello request'''

    def __init__(self):
        super(HelloRequest12, self).__init__()
        self.record_version = TLSRecord.TLS1_2


class HelloRequest12PFS(NormalHandshake12PFS, HelloRequest12):
    '''Send a PFS TLSv1.2 hello then hello request'''
    pass


class EmptyChangeCipherSpec(NormalHandshake):
    '''Send a hello then an empty change cipher spec'''

    def __init__(self):
        super(EmptyChangeCipherSpec, self).__init__()
        self.record_version = TLSRecord.TLS1_0

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())
        logging.debug('Sending Empty ChangeCipherSpec...')

        record = TLSRecord.create(content_type=TLSRecord.ChangeCipherSpec,
                                  version=self.record_version,
                                  message='')
        sock.write(record.bytes)


class EmptyChangeCipherSpec12(EmptyChangeCipherSpec, NormalHandshake12):
    '''Send TLSv1.2 hello then an empty change cipher spec'''

    def __init__(self):
        super(EmptyChangeCipherSpec12, self).__init__()
        self.record_version = TLSRecord.TLS1_2


class EmptyChangeCipherSpec12PFS(NormalHandshake12PFS,
                                 EmptyChangeCipherSpec12):
    '''Send PFS TLSv1.2 hello then an empty change cipher spec'''
    pass


class BadHandshakeMessage(Probe):
    '''An invalid handshake message'''
    
    def make_bad_handshake(self):
        content = 'Something'

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=content)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending bad handshake message...')
        sock.write(self.make_bad_handshake())


class OnlyECCipherSuites(Probe):
    '''Try connecting with ECC cipher suites only'''
    
    def make_ec_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          [TLS_ECDH_RSA_WITH_RC4_128_SHA,
                                           TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                                           TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                                           TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                                           TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                           TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                           TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256])
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_ec_hello())


class Heartbeat(NormalHandshake):
    '''Try to send a heartbeat message'''

    def __init__(self):
        super(Heartbeat, self).__init__()
        self.record_version = TLSRecord.TLS1_0

    def make_hb_hello(self):
        hb_extension = HeartbeatExtension.create()
        return self.make_hello([hb_extension])

    def make_heartbeat(self):
        heartbeat = HeartbeatMessage.create(HeartbeatMessage.HeartbeatRequest,
                                            'XXXX')

        record = TLSRecord.create(content_type=TLSRecord.Heartbeat,
                                  version=self.record_version,
                                  message=heartbeat.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hb_hello())
        logging.debug('Sending Heartbeat...')
        sock.write(self.make_heartbeat())


class Heartbeat12(NormalHandshake12, Heartbeat):
    '''Try to send a heartbeat message in TLSv1.2 connection'''

    def __init__(self):
        super(Heartbeat12, self).__init__()
        self.record_version = TLSRecord.TLS1_2


class Heartbeat12PFS(NormalHandshake12PFS, Heartbeat12):
    '''Try to send a hearbeat message in PFS TLSv1.2 connection'''
    pass


class Heartbleed(Heartbeat):
    '''Try to send a heartbleed attack'''

    def make_heartbeat(self):
        heartbeat = HeartbeatMessage.create(HeartbeatMessage.HeartbeatRequest,
                                            'XXXX', 0x4000)

        record = TLSRecord.create(content_type=TLSRecord.Heartbeat,
                                  version=self.record_version,
                                  message=heartbeat.bytes)

        #hexdump(record.bytes)
        return record.bytes


class Heartbleed12(Heartbeat12, Heartbleed):
    '''Try to send a heartbleed attack in TLSv1.2'''
    pass


class Heartbleed12PFS(Heartbeat12PFS, Heartbleed):
    '''Try to send a heartbleed attack in TLSv1.2'''
    pass


class HighTLSVersion(Probe):
    '''Set a high TLS version in the record'''

    def make_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
        return hello

    def make_high_tls_hello(self):
        hello = self.make_hello()

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0x400,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_high_tls_hello())


class HighTLSVersion12(HighTLSVersion):
    '''Set a high TLS version in the record of TLSv1.2 hello'''

    def make_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          '01234567890123456789012345678901',
                                          DEFAULT_12_CIPHERS)
        return hello


class HighTLSVersion12PFS(HighTLSVersion):
    '''Set a high TLS version in the record of PFS TLSv1.2 hello'''

    def make_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          '01234567890123456789012345678901',
                                          DEFAULT_PFS_CIPHERS)
        return hello


class VeryHighTLSVersion(HighTLSVersion):
    '''Set a very high TLS version in the record'''

    def make_high_tls_hello(self):
        hello = self.make_hello()

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0xffff,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes


class VeryHighTLSVersion12(HighTLSVersion12, VeryHighTLSVersion):
    '''Set a very high TLS version in the record of TLSv1.2 hello'''
    pass


class VeryHighTLSVersion12PFS(HighTLSVersion12PFS, VeryHighTLSVersion):
    '''Set a very high TLS version in the record of PFS TLSv1.2 hello'''
    pass


class ZeroTLSVersion(HighTLSVersion):
    '''Set a zero version in the record'''

    def make_high_tls_hello(self):
        hello = self.make_hello()

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0x000,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes


class ZeroTLSVersion12(HighTLSVersion12, ZeroTLSVersion):
    '''Set a zero version in the record of TLSv1.2 hello'''
    pass


class ZeroTLSVersion12PFS(HighTLSVersion12PFS, ZeroTLSVersion):
    '''Set a zero version in the record of PFS TLSv1.2 hello'''
    pass


class HighHelloVersion(Probe):
    '''Set a high version in the hello'''

    def __init__(self):
        super(HighHelloVersion, self).__init__()
        self.hello_version = 0x400
        self.hello_ciphers = DEFAULT_CIPHERS

    def make_high_tls_hello(self):
        hello = ClientHelloMessage.create(self.hello_version,
                                          '01234567890123456789012345678901',
                                          self.hello_ciphers)

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_high_tls_hello())


class HighHelloVersionNew(HighHelloVersion):
    '''Set a high version in a hello with more ciphers'''

    def __init__(self):
        super(HighHelloVersionNew, self).__init__()
        self.hello_ciphers = DEFAULT_12_CIPHERS


class HighHelloVersionPFS(HighHelloVersion):
    '''Set a high version in a hello with PFS ciphers'''

    def __init__(self):
        super(HighHelloVersionPFS, self).__init__()
        self.hello_ciphers = DEFAULT_PFS_CIPHERS


class VeryHighHelloVersion(HighHelloVersion):
    '''Set a very high version in the hello'''

    def __init__(self):
        super(VeryHighHelloVersion, self).__init__()
        self.hello_version = 0xffff


class VeryHighHelloVersionNew(HighHelloVersionNew, VeryHighHelloVersion):
    '''Set a very high version in the hello with more ciphers'''
    pass


class VeryHighHelloVersionPFS(HighHelloVersionPFS, VeryHighHelloVersion):
    '''Set a very high version in the hello with PFS ciphers'''
    pass


class ZeroHelloVersion(Probe):
    '''Set a zero version in the hello'''
    
    def make_zero_tls_hello(self):
        hello = ClientHelloMessage.create(0x000,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_zero_tls_hello())


class BadContentType(Probe):
    '''Use an invalid content type in the record'''
    
    def make_bad_content_type(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=17,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_bad_content_type())


class RecordLengthOverflow(Probe):
    '''Make the record length exceed the stated one'''
    
    def make_record_length_overflow(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes,
                                  length=0x0001)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_record_length_overflow())


class RecordLengthUnderflow(Probe):
    '''Make the record shorter than the specified length'''
    
    def make_record_length_underflow(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes,
                                  length=0xffff)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        try:
            sock.write(self.make_record_length_underflow())
        except socket.timeout, e:
            result = 'writeerror:timeout'
            return result
        except socket.error, e:
            result = 'writeerror:%s|' % errno.errorcode[e.errno]
            return result


class EmptyRecord(NormalHandshake):
    '''Send an empty record then the hello'''

    def make_empty_record(self):
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message='')

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending empty record...')
        sock.write(self.make_empty_record())
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hello())


class EmptyRecord12(NormalHandshake12, EmptyRecord):
    '''Send an empty record then TLSv1.2 hello'''
    pass


class EmptyRecord12PFS(NormalHandshake12PFS, EmptyRecord):
    '''Send and empty record then PFS TLSv1.2 hello'''
    pass


class TwoInvalidPackets(Probe):
    '''Send two invalid messages'''

    def test(self, sock):
        logging.debug('Sending split hello...')
        part_one = '<tls.record.TLSRecord object at 0x7fd2dc0906d0>'
        part_two = '<tls.record.TLSRecord object at 0x7fd2dc090690>'
        sock.write(part_one)
        try:
            sock.write(part_two)
        except socket.timeout, e:
            result = 'writeerror:timeout'
            return result
        except socket.error, e:
            result = 'writeerror:%s|' % errno.errorcode[e.errno]
            return result


class SplitHelloRecords(Probe):
    '''Split the hello over two records'''

    def make_split_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)

        first = hello.bytes[:10]
        second = hello.bytes[10:]
    
        record_one = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=settings['default_record_version'],
                                      message=first)
        record_two = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=0x301,
                                      message=second)

        #hexdump(record.bytes)
        return record_one.bytes, record_two.bytes

    def test(self, sock):
        logging.debug('Sending split hello...')
        part_one, part_two = self.make_split_hello()
        sock.write(part_one)
        try:
            sock.write(part_two)
        except socket.timeout, e:
            result = 'writeerror:timeout'
            return result
        except socket.error, e:
            result = 'writeerror:%s|' % errno.errorcode[e.errno]
            return result


class SplitHelloRecords12(SplitHelloRecords):
    '''Split the TLS1.2 hello over two records'''

    def make_split_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          '01234567890123456789012345678901',
                                          DEFAULT_12_CIPHERS)

        first = hello.bytes[:10]
        second = hello.bytes[10:]

        record_one = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=settings['default_record_version'],
                                      message=first)
        record_two = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=settings['default_record_version'],
                                      message=second)

        #hexdump(record.bytes)
        return record_one.bytes, record_two.bytes


class SplitHelloRecords12PFS(SplitHelloRecords):
    '''Split the TLS1.2 PFS hello over two records'''

    def make_split_hello(self):
        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          '01234567890123456789012345678901',
                                          DEFAULT_PFS_CIPHERS)

        first = hello.bytes[:10]
        second = hello.bytes[10:]

        record_one = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=settings['default_record_version'],
                                      message=first)
        record_two = TLSRecord.create(content_type=TLSRecord.Handshake,
                                      version=settings['default_record_version'],
                                      message=second)

        #hexdump(record.bytes)
        return record_one.bytes, record_two.bytes


class SplitHelloPackets(NormalHandshake):
    '''Split the hello over two packets'''

    def test(self, sock):
        logging.debug('Sending Client Hello part one...')
        record = self.make_hello()
        sock.write(record[:10])
        sock.flush()
        logging.debug('Sending Client Hello part two...')
        sock.write(record[10:])


class SplitHelloPackets12(SplitHelloPackets, NormalHandshake12):
    '''Split the TLS1.2 hello over two packets'''
    pass


class SplitHelloPackets12PFS(SplitHelloPackets, NormalHandshake12PFS):
    '''Split the TLS1.2 PFS hello over two packets'''
    pass


class NoCiphers(Probe):
    '''Send an empty cipher list'''

    def __init__(self):
        super(NoCiphers, self).__init__()
        self.hello_version = settings['default_hello_version']

    def make_no_ciphers_hello(self):
        hello = ClientHelloMessage.create(self.hello_version,
                                          '01234567890123456789012345678901',
                                          [])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending No ciphers Hello...')
        sock.write(self.make_no_ciphers_hello())


class NoCiphers12(NoCiphers):
    '''Send and empty cipher list in TLSv1.2 hello'''

    def __init__(self):
        super(NoCiphers12, self).__init__()
        self.hello_version = TLSRecord.TLS1_2


class SNIWrongName(NormalHandshake):
    '''Send a server name indication for a non-matching name'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        return self.make_hello([sni_extension])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello('thisisnotyourname'))


class SNIWrongName12(NormalHandshake12, SNIWrongName):
    '''Send a server name indication for non-matching name in TLSv1.2 hello'''
    pass


class SNIWrongName12PFS(NormalHandshake12PFS, SNIWrongName):
    '''Send a SNI extension for non-matching name in PFS TLSv1.2 hello'''
    pass


class SNILongName(SNIWrongName):
    '''Send a server name indication with a long name'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello('x'*500))


class SNILongName12(NormalHandshake12, SNILongName):
    '''Send a server name indication with a long name in TLSv1.2 hello'''
    pass


class SNILongName12PFS(NormalHandshake12PFS, SNILongName):
    '''Send a server name indication with a long name in PFS TLSv1.2 hello'''
    pass


class SNIEmptyName(SNIWrongName):
    '''Send a server name indication with an empty name'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(''))


class SNIEmptyName12(NormalHandshake12, SNIEmptyName):
    '''Send a server name indication with an empty name in TLSv1.2 hello'''
    pass


class SNIEmptyName12PFS(NormalHandshake12PFS, SNIEmptyName):
    '''Send a server name indication with an empty name in PFS TLSv1.2 hello'''
    pass


class SNIOneWrong(NormalHandshake):
    '''Send server name indication with two names, one wrong'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(None,
                                                   (name, 'thisisnotyourname'))
        record = self.make_hello([sni_extension])

        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(self.ipaddress))


class SNIOneWrong12(SNIOneWrong, NormalHandshake12):
    '''Send server name indication with two names, one wrong in TLS1.2 hello'''
    pass


class SNIOneWrong12PFS(SNIOneWrong, NormalHandshake12PFS):
    '''As in SNIOneWrong but in PFS TLS1.2 hello'''
    pass


class SNIWithDifferentType(NormalHandshake):
    '''Send server name indication with two names, one not of host_name type'''

    def make_sni_ext(self, server_names):
        encoded_names = ''.join(struct.pack('!BH', name_type, len(name))
                                + name for name_type, name in server_names)
        ext_data = struct.pack('!H', len(encoded_names)) + encoded_names
        return Extension.create(extension_type=Extension.ServerName,
                                data=ext_data)

    def make_sni_hello(self, server_names):
        sni_extension = self.make_sni_ext(server_names)

        record = self.make_hello([sni_extension])

        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        server_names = []
        server_names += [(ServerNameExtension.HostName, self.ipaddress)]
        # only type 0 (HostName) is defined, any other should be ignored
        server_names += [(4, '<binary-data>')]

        sock.write(self.make_sni_hello(server_names))


class SNIWithDifferentType12(SNIWithDifferentType, NormalHandshake12):
    '''As with SNIWithDifferentType but in TLSv1.2 hello'''
    pass


class SNIWithDifferentType12PFS(SNIWithDifferentType, NormalHandshake12PFS):
    '''As with SNIWithDifferentType but in PFS TLSv1.2 hello'''
    pass


class SNIDifferentTypeRev(SNIWithDifferentType):
    '''Send hello like in SNIWithDifferentType but reverse order of names'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        server_names = []
        # only type 0 (HostName) is defined, any other should be ignored
        server_names += [(4, '<binary-data>')]
        server_names += [(ServerNameExtension.HostName, self.ipaddress)]

        sock.write(self.make_sni_hello(server_names))


class SNIDifferentTypeRev12(SNIDifferentTypeRev, NormalHandshake12):
    '''As with SNIDifferentTypeRev but in TLSv1.2 hello'''
    pass


class SNIDifferentTypeRev12PFS(SNIDifferentTypeRev, NormalHandshake12PFS):
    '''As with SNIDifferentTypeRev but in PFS TLSv1.2 hello'''
    pass


class SNIOverflow(NormalHandshake):
    '''Send server name indication with data length exceeding stated size'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        # first four bytes are the header, last one we truncate to exceed size
        ext_data = sni_extension.bytes[4:-1]
        sni_extension = Extension.create(extension_type=Extension.ServerName,
                                         data=ext_data)

        record = self.make_hello([sni_extension])
        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(self.ipaddress))


class SNIOverflow12(SNIOverflow, NormalHandshake12):
    '''as with SNIOverflow but in TLSv1.2 hello'''
    pass


class SNIOverflow12PFS(SNIOverflow, NormalHandshake12PFS):
    '''as with SNIOverflow but in TLSv1.2 hello'''
    pass


class SNIUnderflow(SNIOverflow):
    '''Send server name indication with data length smaller than size inside'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        # first four bytes are the header
        ext_data = sni_extension.bytes[4:] + '\x00\x00\x00'
        sni_extension = Extension.create(extension_type=Extension.ServerName,
                                         data=ext_data)

        record = self.make_hello([sni_extension])

        return record


class SNIUnderflow12(SNIUnderflow, NormalHandshake12):
    '''As with SNIUnderflow, but in TLSv1.2 hello'''
    pass


class SNIUnderflow12PFS(SNIUnderflow, NormalHandshake12PFS):
    '''As with SNIUnderflow, but in PFS TLSv1.2 hello'''
    pass


class SecureRenegoOverflow(NormalHandshake):
    '''Send secure renegotiation with data length exceeding stated size'''

    def make_secure_renego_ext(self, payload):
        secure_renego = Extension.create(
            extension_type=Extension.RenegotiationInfo,
            data=payload)
        return self.make_hello([secure_renego])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # first byte of secure renegotiation extension specifies the
        # length of the array of bytes in it, but don't provide the
        # required amount
        sock.write(self.make_secure_renego_ext('\x0c0123456789'))


class SecureRenegoOverflow12(SecureRenegoOverflow, NormalHandshake12):
    '''As with SecureRenegotOverflow, inside TLSv1.2 hello'''
    pass


class SecureRenegoOverflow12PFS(SecureRenegoOverflow, NormalHandshake12PFS):
    '''As with SecureRenegoOverflow, inside TLSv1.2 PFS hello'''
    pass


class SecureRenegoUnderflow(SecureRenegoOverflow):
    '''Send secure renegotiation with data length lower than stated size'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # again, first byte specifies zero-length array, rest of bytes
        # are just padding to make the extension large
        sock.write(self.make_secure_renego_ext('\x00\x00\x00\x00\x00'))


class SecureRenegoUnderflow12(SecureRenegoUnderflow, NormalHandshake12):
    '''As with SecureRenegoUnderflow, inside TLSv1.2 hello'''
    pass


class SecureRenegoUnderflow12PFS(SecureRenegoUnderflow, NormalHandshake12PFS):
    '''As with SecureRenegoUnderflow, inside PFS TLSv1.2 hello'''
    pass


class SecureRenegoNonEmpty(SecureRenegoOverflow):
    '''Send secure renegotiation with renegotiation payload'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # send a correctly formatted extension, but with a non-empty
        # payload (indicating renegotiated connection)
        sock.write(self.make_secure_renego_ext('\x0c012345678901'))


class SecureRenegoNonEmpty12(SecureRenegoNonEmpty, NormalHandshake12):
    '''Send secure renegotiation with renegotiation payload in TLSv1.2 hello'''
    pass


class SecureRenegoNonEmpty12PFS(SecureRenegoNonEmpty, NormalHandshake12PFS):
    '''As with SecureRenegoNonEmpty12, but with PFS ciphers'''
    pass


class SecureRenegoNull(SecureRenegoOverflow):
    '''Send secure renegotiation extension that is completely empty'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # While the proper formatting is to send an empty array, and not
        # no array, some servers still accept it
        sock.write(self.make_secure_renego_ext(''))


class SecureRenegoNull12(SecureRenegoNull, NormalHandshake12):
    '''As with SecureRenegoNull, but in TLSv1.2 hello'''
    pass


class SecureRenegoNull12PFS(SecureRenegoNull, NormalHandshake12PFS):
    '''As with SecureRenegoNull, but in PFS TLSv1.2 hello'''
    pass


class MaxFragmentNull(NormalHandshake):
    '''Send maximum fragment length extension that is completely empty'''

    def make_fragment_hello(self, payload):
        max_fragment = Extension.create(
            extension_type=Extension.MaxFragmentLength,
            data=payload)

        record = self.make_hello([max_fragment])

        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension needs a single byte value, don't provide it
        sock.write(self.make_fragment_hello(''))


class MaxFragmentNull12(MaxFragmentNull, NormalHandshake12):
    '''As with MaxFragmentNull, but in TLSv1.2 hello'''
    pass


class MaxFragmentNull12PFS(MaxFragmentNull, NormalHandshake12PFS):
    '''As with MaxFragmentNull, but in PFS TLSv1.2 hello'''
    pass


class MaxFragmentInvalid(MaxFragmentNull):
    '''Send maximum fragment length extension with invalid value'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid values are between 1 and 4 inclusive
        sock.write(self.make_fragment_hello('\x08'))


class MaxFragmentInvalid12(MaxFragmentInvalid, NormalHandshake12):
    '''As with MaxFragmentInvalid, but in TLSv1.2 hello'''
    pass


class MaxFragmentInvalid12PFS(MaxFragmentInvalid, NormalHandshake12PFS):
    '''As with MaxFragmentInvalid, but in PFS TLSv1.2 hello'''
    pass


class ClientCertURLsNotNull(NormalHandshake):
    '''Send client certificate URL indication extension that is not empty'''

    def make_cert_urls_hello(self, payload):
        client_cert_url_ext = Extension.create(
            extension_type=Extension.ClientCertificateUrl,
            data=payload)

        record = self.make_hello([client_cert_url_ext])
        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correctly formatted does not include any data
        sock.write(self.make_cert_urls_hello('\x08\x00'))


class ClientCertURLsNotNull12(ClientCertURLsNotNull, NormalHandshake12):
    '''As with ClientCertURLsNotNull, but in TLSv1.2 hello'''
    pass


class ClientCertURLsNotNull12PFS(ClientCertURLsNotNull, NormalHandshake12PFS):
    '''As with ClientCertURLsNotNull, but in PFS TLSv1.2 hello'''
    pass


class TrustedCANull(NormalHandshake):
    '''Send trusted CA keys extension with completely empty payload'''

    def make_trusted_ca_hello(self, payload):
        trusted_ca_ext = Extension.create(
            extension_type=Extension.TrustedCAKeys,
            data=payload)

        record = self.make_hello([trusted_ca_ext])
        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal formatting is a complex structure
        sock.write(self.make_trusted_ca_hello(''))


class TrustedCANull12(TrustedCANull, NormalHandshake12):
    '''As with TrustedCANull but in TLSv1.2 hello'''
    pass


class TrustedCANull12PFS(TrustedCANull, NormalHandshake12PFS):
    '''As with TrustedCANull, but in PFS TLSv1.2 hello'''
    pass


class TrustedCAOverflow(TrustedCANull):
    '''Send trusted CA keys extension smaller than length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # in a normal structure, the first two bytes are the overall length
        # of list with extension data
        # a typical payload includes type (1B) and sha1 hash (20B)
        sock.write(self.make_trusted_ca_hello('\x00\x15'))


class TrustedCAOverflow12(TrustedCAOverflow, NormalHandshake12):
    '''As with TrustedCAOverflow but in TLSv1.2 hello'''
    pass


class TrustedCAOverflow12PFS(TrustedCAOverflow, NormalHandshake12PFS):
    '''As with TrustedCAOverflow but in PFS TLSv1.2 hello'''
    pass


class TrustedCAUnderflow(TrustedCANull):
    '''Send trusted CA keys extension larger than length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')

        # type key_sha1_hash + sha1 hash (20 bytes)
        authority = '\x01' + 'a'*20
        # payload has a 2 byte length and then an array of items,
        # add null byte at end to cause the underflow
        ext_data = struct.pack('!H', len(authority)) + authority + '\x00'

        sock.write(self.make_trusted_ca_hello(ext_data))


class TrustedCAUnderflow12(TrustedCAUnderflow, NormalHandshake12):
    '''As with TrustedCAUnderflow but in TLSv1.2 hello'''
    pass


class TrustedCAUnderflow12PFS(TrustedCAUnderflow, NormalHandshake12PFS):
    '''As with TrustedCAUnderflow but in PFS TLSv1.2 hello'''
    pass


class TruncatedHMACNotNull(NormalHandshake):
    '''Send a truncated HMAC extension with a non empty payload'''

    def make_truncated_hmac_hello(self, payload):
        truncated_hmac = Extension.create(
            extension_type=Extension.TruncateHMAC,
            data=payload)

        record = self.make_hello([truncated_hmac])

        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # properly formatted extension has no data at all
        sock.write(self.make_truncated_hmac_hello('\x0c'))


class TruncatedHMACNotNull12(TruncatedHMACNotNull, NormalHandshake12):
    '''As with TruncatedHMACNotNull but in TLSv1.2 hello'''
    pass


class TruncatedHMACNotNull12PFS(TruncatedHMACNotNull, NormalHandshake12PFS):
    '''As with TruncatedHMACNotNull but in PFS TLSv1.2 hello'''
    pass


class OCSPNull(NormalHandshake):
    '''Send status request extension with empty payload'''

    def make_ocsp_hello(self, payload):
        status_request = Extension.create(
            extension_type=Extension.StatusRequest,
            data=payload)

        record = self.make_hello([status_request])

        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normally the status request is a complex structure, don't include
        # it
        sock.write(self.make_ocsp_hello(''))


class OCSPNull12(OCSPNull, NormalHandshake12):
    '''As with OCSPNull but in TLSv1.2 hello'''
    pass


class OCSPNull12PFS(OCSPNull, NormalHandshake12PFS):
    '''As with OCSPNull but in PFS TLSv1.2 hello'''
    pass


class OCSPOverflow(OCSPNull):
    '''Send status request ext smaller than the length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the request has three fields - type (one byte) and two arrays
        # with 2 byte long headers, truncate the second length header
        sock.write(self.make_ocsp_hello('\x01\x00\x00\x00'))


class OCSPOverflow12(OCSPOverflow, NormalHandshake12):
    '''As with OCSPOverflow but in TLSv1.2 hello'''
    pass


class OCSPOverflow12PFS(OCSPOverflow, NormalHandshake12PFS):
    '''As with OCSPOverflow but in PFS TLSv1.2 hello'''
    pass


class OCSPUnderflow(OCSPNull):
    '''Send status request ext larger than the length inside indicate'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correctly formed request, two extra zero bytes
        sock.write(self.make_ocsp_hello('\x01' + '\x00' * 6))


class OCSPUnderflow12(OCSPUnderflow, NormalHandshake12):
    '''As with OCSPUnderflow but in TLSv1.2 hello'''
    pass


class OCSPUnderflow12PFS(OCSPUnderflow, NormalHandshake12PFS):
    '''As with OCSPUnderflow but in PFS TLSv1.2 hello'''
    pass


class DoubleExtension(NormalHandshake):
    '''Duplicate secure renegotiation extension'''

    def make_double_ext_hello(self):
        secure_renego = Extension.create(
            extension_type=Extension.RenegotiationInfo,
            data='\x00')

        record = self.make_hello([secure_renego,
                                  secure_renego])
        return record

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correct Client Hello messages must not contain two extensions
        # of the same type
        sock.write(self.make_double_ext_hello())


class DoubleExtension12(DoubleExtension, NormalHandshake12):
    '''Duplicate secure renegotiation extension in TLSv1.2 hello'''
    pass


class DoubleExtension12PFS(DoubleExtension, NormalHandshake12PFS):
    '''Duplicate secure renegotiation extension in PFS TLSv1.2 hello'''
    pass


class UserMappingNull(NormalHandshake):
    '''Send empty user mapping extension in hello'''

    def make_user_mapping_ext(self, value):
        user_mapping_ext = Extension.create(
            extension_type=6,
            data=value)
        return self.make_hello([user_mapping_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # extension consists of an array and the array needs at least one
        # element, don't send any
        sock.write(self.make_user_mapping_ext(b''))


class UserMappingNull12(UserMappingNull, NormalHandshake12):
    '''Send empty user mapping extension in TLSv1.2 hello'''
    pass


class UserMappingNull12PFS(UserMappingNull, NormalHandshake12PFS):
    '''Send empty user mapping extension in PFS TLSv1.2 hello'''
    pass


class UserMappingOverflow(UserMappingNull):
    '''Send user mapping extension with length longer than present in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # extension consists of an array and the array needs at least one
        # element, send the length of array (one byte) longer than payload size
        sock.write(self.make_user_mapping_ext(b'\x02\x40'))


class UserMappingOverflow12(UserMappingOverflow, NormalHandshake12):
    '''As with UserMappingOverflow but in TLSv1.2 hello'''
    pass


class UserMappingOverflow12PFS(UserMappingOverflow, NormalHandshake12PFS):
    '''As with UserMappingOverflow but in PFS TLSv1.2 hello'''
    pass


class ClientAuthzNull(NormalHandshake):
    '''Send empty client authz extension in hello'''

    def make_client_authz_hello(self, value):
        client_authz_ext = Extension.create(
            extension_type=7,
            data=value)
        return self.make_hello([client_authz_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_client_authz_hello(b''))


class ClientAuthzNull12(ClientAuthzNull, NormalHandshake12):
    '''Send empty client authz extension in TLSv1.2 hello'''
    pass


class ClientAuthzNull12PFS(ClientAuthzNull, NormalHandshake12PFS):
    '''Send empty client authz extension in PFS TLSv1.2 hello'''
    pass


class ClientAuthzOverflow(ClientAuthzNull):
    '''Send client authz extension with length longer than data in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has one byte length as first element then
        # the array, make the array length longer than real payload
        sock.write(self.make_client_authz_hello(b'\x04\x00\x01'))


class ClientAuthzOverflow12(ClientAuthzOverflow, NormalHandshake12):
    '''As with ClientAuthzOverflow but in TLSv1.2 hello'''
    pass


class ClientAuthzOverflow12PFS(ClientAuthzOverflow, NormalHandshake12PFS):
    '''As with ClientAuthzOverflow but in PFS TLSv1.3 hello'''
    pass


class ServerAuthzNull(ClientAuthzNull):
    '''Send empty server authz extension in hello'''

    def make_client_authz_hello(self, value):
        server_authz_ext = Extension.create(
            extension_type=8,
            data=value)
        return self.make_hello([server_authz_ext])


class ServerAuthzNull12(ServerAuthzNull, NormalHandshake12):
    '''Send empty server authz extension in TLSv1.2 hello'''
    pass


class ServerAuthzNull12PFS(ServerAuthzNull, NormalHandshake12PFS):
    '''Send empty server authz extension in PFS TLSv1.2 hello'''
    pass


class ServerAuthzOverflow(ServerAuthzNull, ClientAuthzOverflow):
    '''Send server authz extension with length longer than data in hello'''
    pass


class ServerAuthzOverflow12(ServerAuthzOverflow, NormalHandshake12):
    '''As with ServerAuthzOverflow but in TLSv1.2 hello'''
    pass


class ServerAuthzOverflow12PFS(ServerAuthzOverflow, NormalHandshake12PFS):
    '''As with ServerAuthzOverflow but in PFS TLSv1.2 hello'''
    pass


class CertTypeNull(NormalHandshake):
    '''Send empty cert type extension in hello'''

    def make_cert_type_hello(self, value):
        cert_type_ext = Extension.create(
            extension_type=9,
            data=value)
        return self.make_hello([cert_type_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_cert_type_hello(b''))


class CertTypeNull12(CertTypeNull, NormalHandshake12):
    '''Send empty cert type extension in TLSv1.2 hello'''
    pass


class CertTypeNull12PFS(CertTypeNull, NormalHandshake12PFS):
    '''Send empty cert type extension in PFS TLSv1.2 hello'''
    pass


class CertTypeOverflow(CertTypeNull):
    '''Send cert type extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # first byte is a length of array, send invalid one
        sock.write(self.make_cert_type_hello(b'\x04\x01'))


class CertTypeOverflow12(CertTypeOverflow, NormalHandshake12):
    '''Send cert type extension with too large length in TLSv1.2 hello'''
    pass


class CertTypeOverflow12PFS(CertTypeOverflow, NormalHandshake12PFS):
    '''Send cert type extension with too large length in PFS TLSv1.2 hello'''
    pass


class SupportedGroupsNull(NormalHandshake):
    '''Send empty supported groups extension in hello'''

    def make_supported_groups_hello(self, value):
        supported_groups_ext = Extension.create(
            extension_type=10,
            data=value)
        return self.make_hello([supported_groups_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_supported_groups_hello(b''))


class SupportedGroupsNull12(SupportedGroupsNull, NormalHandshake12):
    '''Send empty supported groups extension in TLSv1.2 hello'''
    pass


class SupportedGroupsNull12PFS(SupportedGroupsNull, NormalHandshake12PFS):
    '''Send empty supported groups extension in PFS TLSv1.2 hello'''
    pass


class SupportedGroupsOddLen(SupportedGroupsNull):
    '''Send supported groups extension with invalid length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has a two byte length and two byte elements,
        # truncate the second element
        sock.write(self.make_supported_groups_hello(b'\x00\x03\x00\x17\x00'))


class SupportedGroupsOddLen12(SupportedGroupsOddLen, NormalHandshake12):
    '''Send supported groups extension with invalid length in TLSv1.2 hello'''
    pass


class SupportedGroupsOddLen12PFS(SupportedGroupsOddLen, NormalHandshake12PFS):
    '''As with SupportedGroupsOddLen but in PFS TLSv1.2 hello'''
    pass


class SupportedGroupsOverflow(SupportedGroupsNull):
    '''Send supported groups extension with length larger than data'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has a two byte length and two byte elements,
        # truncate the whole second element
        sock.write(self.make_supported_groups_hello(b'\x00\x04\x00\x17'))


class SupportedGroupsOverflow12(SupportedGroupsOverflow, NormalHandshake12):
    '''As with SupportedGroupsOverflow but in TLSv1.2 hello'''
    pass


class SupportedGroupsOverflow12PFS(SupportedGroupsOverflow,
        NormalHandshake12PFS):
    '''As with SupportedGroupsOverflow but in PFS TLSv1.2 hello'''
    pass


class ECPointFormatsNull(NormalHandshake):
    '''Send empty ec point formats extension in hello'''

    def make_point_formats_hello(self, value):
        point_formats_ext = Extension.create(
            extension_type=11,
            data=value)
        return self.make_hello([point_formats_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_point_formats_hello(b''))


class ECPointFormatsNull12(ECPointFormatsNull, NormalHandshake12):
    '''Send empty ec point formats extension in TLSv1.2 hello'''
    pass


class ECPointFormatsNull12PFS(ECPointFormatsNull, NormalHandshake12PFS):
    '''Send empty ec point formats extension in PFS TLSv1.2 hello'''
    pass


class ECPointFormatsOverflow(ECPointFormatsNull):
    '''Send ec point formats extension with length larger than data in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # first byte is the length of array, send too large one
        sock.write(self.make_point_formats_hello(b'\x04\x00'))


class ECPointFormatsOverflow12(ECPointFormatsOverflow, NormalHandshake12):
    '''As with ECPointFormatsOverflow but in TLSv1.2 hello'''
    pass


class ECPointFormatsOverflow12PFS(ECPointFormatsOverflow,
                                   NormalHandshake12PFS):
    '''As with ECPointFormatsOverflow but in PFS TLSv1.2 hello'''
    pass


class ECPointFormatsCompOnly(ECPointFormatsNull):
    '''Send ec point formats extension without uncompressed format'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the uncompressed format is mandatory, send extension without it
        sock.write(self.make_point_formats_hello(b'\x02\x01\x02'))


class ECPointFormatsCompOnly12(ECPointFormatsCompOnly, NormalHandshake12):
    '''As with ECPointFormatsCompOnly but in TLSv1.2 hello'''
    pass


class ECPointFormatsCompOnly12PFS(ECPointFormatsCompOnly,
                                   NormalHandshake12PFS):
    '''As with ECPointFormatsCompOnly but in PFS TLS v1.2 hello'''
    pass


class SRPNull(NormalHandshake):
    '''Send empty srp extension in hello'''

    def make_srp_hello(self, value):
        srp_ext = Extension.create(
            extension_type=12,
            data=value)
        return self.make_hello([srp_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normally the extension has client's identity, don't include any
        sock.write(self.make_srp_hello(b''))


class SRPNull12(SRPNull, NormalHandshake12):
    '''Send empty srp extension in TLSv1.2 hello'''
    pass


class SRPNull12PFS(SRPNull, NormalHandshake12PFS):
    '''Send empty srp extension in PFS TLSv1.2 hello'''
    pass


class SRPOverflow(SRPNull):
    '''Send srp extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # first byte is the length, send too large
        sock.write(self.make_srp_hello(b'\x06test'))


class SRPOverflow12(SRPOverflow, NormalHandshake12):
    '''Send srp extension with too large length in TLSv1.2 hello'''
    pass


class SRPOverflow12PFS(SRPOverflow, NormalHandshake12PFS):
    '''Send srp extension with too large length in PFS TLSv1.2 hello'''
    pass


class SigAlgsNull(NormalHandshake):
    '''Send empty signature algorithms extension in hello'''

    def make_signature_alg_hello(self, value):
        sig_algs_ext = Extension.create(
            extension_type=13,
            data=value)
        return self.make_hello([sig_algs_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_signature_alg_hello(b''))


class SigAlgsNull12(SigAlgsNull, NormalHandshake12):
    '''Send empty signature algorithms extension in TLSv1.2 hello'''
    pass


class SigAlgsNull12PFS(SigAlgsNull, NormalHandshake12PFS):
    '''Send empty signature algorithms extension in PFS TLSv1.2 hello'''
    pass


class SigAlgsOddLen(SigAlgsNull):
    '''Send signature algorithms extensions with invalid length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has two byte long elements, truncate the last one
        sock.write(self.make_signature_alg_hello(b'\x00\x05'
                                                 b'\x04\x01'
                                                 b'\x04\x03\x04'))

class SigAlgsOddLen12(SigAlgsOddLen, NormalHandshake12):
    '''As in SigAlgsOddLen but in TLSv1.2 hello'''
    pass


class SigAlgsOddLen12PFS(SigAlgsOddLen, NormalHandshake12PFS):
    '''As in SigAlgsOddLen but in PFS TLSv1.2 hello'''
    pass


class SigAlgsOverflow(SigAlgsNull):
    '''Send signature algorithms extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the first two bytes are the length of the array, send too large one
        sock.write(self.make_signature_alg_hello(b'\x00\x06'
                                                 b'\x04\x01'
                                                 b'\x04\x03'))


class SigAlgsOverflow12(SigAlgsOverflow, NormalHandshake12):
    '''As in SigAlgsOverflow but in TLSv1.2 hello'''
    pass


class SigAlgsOverflow12PFS(SigAlgsOverflow, NormalHandshake12PFS):
    '''As in SigAlgsOverflow but in PFS TLSv1.2 hello'''
    pass


class UseSrtpNull(NormalHandshake):
    '''Send empty use srtp extension in hello'''

    def make_use_srtp_hello(self, value):
        use_srtp_ext = Extension.create(
            extension_type=14,
            data=value)
        return self.make_hello([use_srtp_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension has an array, don't send anything
        sock.write(self.make_use_srtp_hello(b''))


class UseSrtpNull12(UseSrtpNull, NormalHandshake12):
    '''Send empty use srtp extension in TLSv1.2 hello'''
    pass

class UseSrtpNull12PFS(UseSrtpNull, NormalHandshake12PFS):
    '''Send empty use srtp extension in PFS TLSv1.2 hello'''
    pass

class UseSrtpOddLen(UseSrtpNull):
    '''Send use srtp extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the extension starts with a two byte length of two-byte elements
        # and the second array is optional with a simple binary string
        sock.write(self.make_use_srtp_hello(b'\x00\x05'
                                            b'\x00\x01\x00\x05\x00'
                                            b'\x00'))

class UseSrtpOddLen12(UseSrtpOddLen, NormalHandshake12):
    '''Send use srtp extension with too large length in TLSv1.2 hello'''
    pass


class UseSrtpOddLen12PFS(UseSrtpOddLen, NormalHandshake12PFS):
    '''Send use srtp extension with too large length in PFS TLSv1.2 hello'''
    pass


class UseSrtpOverflow(UseSrtpNull):
    '''Send use srtp extension with length larger than payload'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the extension has two arrays, one has a two byte length the other
        # a one byte length, make the first array longer than payload
        sock.write(self.make_use_srtp_hello(b'\x00\x06'
                                            b'\x00\x01\x00\x05'))


class UseSrtpOverflow12(UseSrtpOverflow, NormalHandshake12):
    '''Send use srtp extension with length larger than payload in TLSv1.2'''
    pass


class UseSrtpOverflow12PFS(UseSrtpOverflow, NormalHandshake12PFS):
    '''As in UseSrtpOverflow but in PFS TLSv1.2 hello'''
    pass


class HeartbeatNull(NormalHandshake):
    '''Send empty heartbeat extension in hello'''

    def make_heartbeat_hello(self, value):
        heartbeat_ext = Extension.create(
            extension_type=15,
            data=value)
        return self.make_hello([heartbeat_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the extension is a single byte value, don't include it
        sock.write(self.make_heartbeat_hello(b''))


class HeartbeatNull12(HeartbeatNull, NormalHandshake12):
    '''Send empty heartbeat extension in TLSv1.2 hello'''
    pass


class HeartbeatNull12PFS(HeartbeatNull, NormalHandshake12PFS):
    '''Send empty heartbeat extension in PFS TLSv1.2 hello'''
    pass


class HeartbeatInvalid(HeartbeatNull):
    '''Send heartbeat extension with invalid value in hello'''

    def test(self, sock):
        # the valid values are 1 and 2, send something else
        sock.write(self.make_heartbeat_hello(b'\x00'))


class HeartbeatInvalid12(HeartbeatInvalid, NormalHandshake12):
    '''Send heartbeat extension with invalid value in TLSv1.2 hello'''
    pass


class HeartbeatInvalid12PFS(HeartbeatInvalid, NormalHandshake12PFS):
    '''Send heartbeat extension with invalid value in PFS TLSv1.2 hello'''
    pass


class ALPNNull(NormalHandshake):
    '''Send empty ALPN extension in hello'''

    def make_alpn_hello(self, value):
        alpn_ext = Extension.create(
            extension_type=16,
            data=value)
        return self.make_hello([alpn_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid extension has an array, don't send anything
        sock.write(self.make_alpn_hello(b''))


class ALPNNull12(ALPNNull, NormalHandshake12):
    '''Send empty APLN extension in TLSv1.2 hello'''
    pass


class ALPNNull12PFS(ALPNNull, NormalHandshake12PFS):
    '''Send empty ALPN extension in PFS TLSv1.2 hello'''
    pass


class ALPNUnknown(ALPNNull):
    '''Send ALPN extension with only unknown protocol in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the extension is an array of arrays, the external array has
        # two byte length header, the internal arrays have one byte length
        sock.write(self.make_alpn_hello(b'\x00\x08'
                                        b'\x07unknown'))


class ALPNUnknown12(ALPNUnknown, NormalHandshake12):
    '''Send ALPN extension with only unknown protocol in TLSv1.2 hello'''
    pass


class ALPNUnknown12PFS(ALPNUnknown, NormalHandshake12PFS):
    '''Send ALPN extension with only unknown protocol in PFS TLSv1.2 hello'''
    pass


class ALPNOverflow(ALPNNull):
    '''Send ALPN extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the extension is an array of arrays, the external array has
        # two byte length header, the internal arrays have one byte length
        # make the external length too large
        sock.write(self.make_alpn_hello(b'\x00\x10'
                                        b'\x08http/1.1'))


class ALPNOverflow12(ALPNOverflow, NormalHandshake12):
    '''Send ALPN extension with too large length in TLSv1.2 hello'''
    pass


class ALPNOverflow12PFS(ALPNOverflow, NormalHandshake12PFS):
    '''Send ALPN extension with too large length in PFS TLSv1.2 hello'''
    pass


class OCSPv2Null(NormalHandshake):
    '''Send empty OCSPv2 staple extension in hello'''

    def make_ocspv2_hello(self, value):
        ocspv2_ext = Extension.create(
            extension_type=17,
            data=value)
        return self.make_hello([ocspv2_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal encoding has a list of complex items, don't include anything
        sock.write(self.make_ocspv2_hello(b''))


class OCSPv2Null12(OCSPv2Null, NormalHandshake12):
    '''Send empty OCSPv2 staple extension in TLSv1.2 hello'''
    pass


class OCSPv2Null12PFS(OCSPv2Null, NormalHandshake12PFS):
    '''Send empty OCSPv2 staple extension in PFS TLSv1.2 hello'''
    pass


class OCSPv2Overflow(OCSPv2Null):
    '''Send OCSPv2 staple extension with too large length in hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        data = (b'\x00\x10'  # overall length of extension (too large)
                b'\x01'  # first request type (ocsp)
                b'\x00\x04'  # request length
                b'\x00\x00'  # responder ID list length
                b'\x00\x00'  # request extensions list length
                b'\x02'  # second request type (ocsp_multi)
                b'\x00\x04'  # request length
                b'\x00\x00'  # responder ID list length
                b'\x00\x00')  # request extensions list length
        sock.write(self.make_ocspv2_hello(data))


class OCSPv2Overflow12(OCSPv2Overflow, NormalHandshake12):
    '''Send OCSPv2 staple extension with too large length in TLSv1.2 hello'''
    pass


class OCSPv2Overflow12PFS(OCSPv2Overflow, NormalHandshake12PFS):
    '''As with OCSPv2Overflow but in PFS TLSv1.2 hello'''
    pass


class SignedCertTSNotNull(NormalHandshake):
    '''Send hello with signed certificate timestamp that is not empty'''

    def make_signed_cert_ts_hello(self, value):
        signed_cert_ts_ext = Extension.create(
            extension_type=18,
            data=value)
        return self.make_hello([signed_cert_ts_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid extension should be empty
        sock.write(self.make_signed_cert_ts_hello(b'\x04'))

class SignedCertTSNotNull12(SignedCertTSNotNull, NormalHandshake12):
    '''As with SignedCertTSNotNull but in TLSv1.2 hello'''
    pass


class SignedCertTSNotNull12PFS(SignedCertTSNotNull, NormalHandshake12PFS):
    '''As with SignedCertTSNotNull but in PFS TLSv1.2 hello'''
    pass


class ClientCertTypeNull(NormalHandshake):
    '''Send empty client certificate type extension in hello'''

    def make_client_cert_type_hello(self, value):
        client_cert_type_ext = Extension.create(
            extension_type=19,
            data=value)
        return self.make_hello([client_cert_type_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid extension has an array
        sock.write(self.make_client_cert_type_hello(b''))


class ClientCertTypeNull12(ClientCertTypeNull, NormalHandshake12):
    '''Send empty client certificate type extension in TLSv1.2 hello'''
    pass


class ClientCertTypeNull12PFS(ClientCertTypeNull, NormalHandshake12PFS):
    '''Send empty client certificate type extension in PFS TLSv1.2 hello'''
    pass


class ClientCertTypeOverflow(ClientCertTypeNull):
    '''Send client certificate type extension with too large length in hello'''

    def test(self, sock):
        logging.debug('sending Client Hello...')
        # first byte is the length of the array, send too large
        sock.write(self.make_client_cert_type_hello(b'\x04\x02\x01\x00'))


class ClientCertTypeOverflow12(ClientCertTypeOverflow, NormalHandshake12):
    '''As with ClientCertTypeOverflow, but in TLSv1.2 hello'''
    pass


class ClientCertTypeOverflow12PFS(ClientCertTypeOverflow,
                                  NormalHandshake12PFS):
    '''As with ClientCertTypeOverflow but in PFS TLSv1.2 hello'''
    pass


class ServerCertTypeNull(NormalHandshake):
    '''Send empty server certificate type extension in hello'''

    def make_server_cert_type_hello(self, value):
        server_cert_type_ext = Extension.create(
            extension_type=20,
            data=value)
        return self.make_hello([server_cert_type_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid extension has an array
        sock.write(self.make_server_cert_type_hello(b''))


class ServerCertTypeNull12(ServerCertTypeNull, NormalHandshake12):
    '''Send empty server certificate type extension in TLSv1.2 hello'''
    pass


class ServerCertTypeNull12PFS(ServerCertTypeNull, NormalHandshake12PFS):
    '''Send empty server certificate type extension in PFS TLSv1.2 hello'''
    pass


class ServerCertTypeOverflow(ServerCertTypeNull):
    '''Send server certificate type extension with too large length in hello'''

    def test(self, sock):
        logging.debug('sending Client Hello...')
        # first byte is the length of the array, send too large
        sock.write(self.make_server_cert_type_hello(b'\x04\x02\x01\x00'))


class ServerCertTypeOverflow12(ServerCertTypeOverflow, NormalHandshake12):
    '''As with ServerCertTypeOverflow, but in TLSv1.2 hello'''
    pass


class ServerCertTypeOverflow12PFS(ServerCertTypeOverflow,
                                  NormalHandshake12PFS):
    '''As with ServerCertTypeOverflow but in PFS TLSv1.2 hello'''
    pass


class PaddingNull(NormalHandshake):
    '''Send empty padding extension in hello'''

    def make_padding_hello(self, value):
        padding_ext = Extension.create(
            extension_type=21,
            data=value)
        return self.make_hello([padding_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # there is no invalid encoding of extension, send an empty one
        sock.write(self.make_padding_hello(b''))


class PaddingNull12(PaddingNull, NormalHandshake12):
    '''Send empty padding extension in TLSv1.2 hello'''
    pass


class PaddingNull12PFS(PaddingNull, NormalHandshake12PFS):
    '''Send empty padding extension in PFS TLSv1.2 hello'''
    pass


class Padding300Byte(PaddingNull):
    '''Use padding extension to send 300 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal hello is 64 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (300 - (64 - 5) - 4)))


class Padding300Byte12(PaddingNull, NormalHandshake12):
    '''Use padding extension to send 300 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # TLSv1.2 hello is 88 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (300 - (88 - 5) - 4)))


class Padding300Byte12PFS(PaddingNull, NormalHandshake12PFS):
    '''Use padding extension to send 300 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # PFS TLSv1.2 hello is 144 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (300 - (144 - 5) - 4)))


class Padding600Byte(PaddingNull):
    '''Use padding extension to send 600 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal hello is 64 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (600 - (64 - 5) - 4)))


class Padding600Byte12(PaddingNull, NormalHandshake12):
    '''Use padding extension to send 600 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # TLSv1.2 hello is 88 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (600 - (88 - 5) - 4)))


class Padding600Byte12PFS(PaddingNull, NormalHandshake12PFS):
    '''Use padding extension to send 600 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # PFS TLSv1.2 hello is 144 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (600 - (144 - 5) - 4)))


class Padding16384Byte(PaddingNull):
    '''Use padding extension to send 16384 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal hello is 64 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        # 16384 is the largest size that can be sent in a single record layer
        sock.write(self.make_padding_hello(b'\x00' * (16384 - (64 - 5) - 4)))


class Padding16384Byte12(PaddingNull, NormalHandshake12):
    '''Use padding extension to send 16384 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # TLSv1.2 hello is 88 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (16384 - (88 - 5) - 4)))


class Padding16384Byte12PFS(PaddingNull, NormalHandshake12PFS):
    '''Use padding extension to send 16384 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # PFS TLSv1.2 hello is 144 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (16384 - (144 - 5) - 4)))


class Padding16385Byte(Probe):
    '''Use padding extension to send 16385 byte large hello'''

    def __init__(self):
        super(Padding16385Byte, self).__init__()
        self.hello_version = TLSRecord.TLS1_0
        self.ciphers = DEFAULT_CIPHERS

    def make_padding_hello(self, value):
        padding_ext = Extension.create(
            extension_type=21,
            data=value)
        RECORD_MAX=16384
        hello = ClientHelloMessage.create(self.hello_version,
                                          b'01234567890123456789012345678901',
                                          self.ciphers,
                                          extensions=[padding_ext])
        hello_bytes = hello.bytes
        records = [TLSRecord.create(content_type=TLSRecord.Handshake,
                                    version=TLSRecord.TLS1_0,
                                    message=hello_bytes[i:i+RECORD_MAX]).bytes
                   for i in range(0, len(hello_bytes), RECORD_MAX)]
        return b''.join(records)

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # hello is 64 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (16385 - (64 - 5) - 4)))


class Padding16385Byte12(Padding16385Byte):
    '''Use padding extension to send 16385 byte large TLSv1.2 hello'''

    def __init__(self):
        super(Padding16385Byte, self).__init__()
        self.hello_version = TLSRecord.TLS1_2
        self.ciphers = DEFAULT_12_CIPHERS

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # TLSv1.2 hello is 88 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (16385 - (88 - 5) - 4)))


class Padding16385Byte12PFS(Padding16385Byte):
    '''Use padding extension to send 16385 byte large PFS TLSv1.2 hello'''

    def __init__(self):
        super(Padding16385Byte, self).__init__()
        self.hello_version = TLSRecord.TLS1_2
        self.ciphers = DEFAULT_PFS_CIPHERS

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # PFS TLSv1.2 hello is 144 byte large with all headers, 5 of which are
        # record layer overhead, extensions length is already included
        # but extension id and extension length is not, totalling 4 bytes
        sock.write(self.make_padding_hello(b'\x00' * (16385 - (144 - 5) - 4)))


class Padding16387Byte(Padding16385Byte):
    '''Use padding extension to send 16387 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16387 - (64 - 5) - 4)))


class Padding16387Byte12(Padding16385Byte12):
    '''Use padding extension to send 16387 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16387 - (88 - 5) - 4)))


class Padding16387Byte12PFS(Padding16385Byte12PFS):
    '''Use padding extension to send 16387 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16387 - (144 - 5) - 4)))


class Padding16389Byte(Padding16385Byte):
    '''Use padding extension to send 16389 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16389 - (64 - 5) - 4)))


class Padding16389Byte12(Padding16385Byte12):
    '''Use padding extension to send 16389 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16389 - (88 - 5) - 4)))


class Padding16389Byte12PFS(Padding16385Byte12PFS):
    '''Use padding extension to send 16389 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (16389 - (144 - 5) - 4)))


class Padding17520Byte(Padding16385Byte):
    '''Use padding extension to send 17520 byte large hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (17520 - (64 - 5) - 4)))


class Padding17520Byte12(Padding16385Byte12):
    '''Use padding extension to send 17520 byte large TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (17520 - (88 - 5) - 4)))


class Padding17520Byte12PFS(Padding16385Byte12PFS):
    '''Use padding extension to send 17520 byte large PFS TLSv1.2 hello'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_padding_hello(b'\x00' * (17520 - (144 - 5) - 4)))


class EtMNotNull(NormalHandshake):
    '''Send not empty encrypt then mac extension in hello'''

    def make_etm_hello(self, value):
        etm_ext = Extension.create(
            extension_type=22,
            data=value)
        return self.make_hello([etm_ext])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension must be empty
        sock.write(self.make_etm_hello(b'\x04'))


class EtMNotNull12(EtMNotNull, NormalHandshake12):
    '''Send not empty encrypt then mac extension in TLSv1.2 hello'''
    pass


class EtMNotNull12PFS(EtMNotNull, NormalHandshake12PFS):
    '''Send not empty encrypt then mac extension in PFS TLSv1.2 hello'''
    pass


class EMSNotNull(NormalHandshake):
    '''Send not empty extended master secret extension in hello'''

    def make_ems_hello(self, value):
        ems_ext = Extension.create(
            extension_type=23,
            data=value)
        return self.make_hello([ems_ext])


    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension must be empty
        sock.write(self.make_ems_hello(b'\x04'))


class EMSNotNull12(EMSNotNull, NormalHandshake12):
    '''Send not empty extended master secret extension in TLSv1.2 hello'''
    pass


class EMSNotNull12PFS(EMSNotNull, NormalHandshake12PFS):
    '''Send not empty extended master secret extension in PFS TLSv1.2 hello'''
    pass
