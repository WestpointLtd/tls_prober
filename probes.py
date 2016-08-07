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
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())


class NormalHandshakePFS(Probe):
    '''Normal handshake with PFS ciphersuites'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_pfs_hello())


class NormalHandshake12(Probe):
    '''Normal TLSv1.2 handshake'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_12_hello())


class NormalHandshake12PFS(Probe):
    '''Normal TLSv1.2 handshake with PFS ciphersuites'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_12_pfs_hello())


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


class DoubleClientHello(Probe):
    '''Two client hellos'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())


class ChangeCipherSpec(Probe):
    '''Send a hello then change cipher spec'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending ChangeCipherSpec...')
        sock.write(make_ccs())


class HelloRequest(Probe):
    '''Send a hello then hello request'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending Hello Request...')
        sock.write(make_hello_request())


class EmptyChangeCipherSpec(Probe):
    '''Send a hello then an empty change cipher spec'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending Empty ChangeCipherSpec...')

        record = TLSRecord.create(content_type=TLSRecord.ChangeCipherSpec,
                                  version=TLSRecord.TLS1_0,
                                  message='')
        sock.write(record.bytes)


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


class Heartbeat(Probe):
    '''Try to send a heartbeat message'''
    
    def make_hb_hello(self):
        hb_extension = HeartbeatExtension.create()
        return make_hello([hb_extension])

    def make_heartbeat(self):
        heartbeat = HeartbeatMessage.create(HeartbeatMessage.HeartbeatRequest,
                                            'XXXX')

        record = TLSRecord.create(content_type=TLSRecord.Heartbeat,
                                  version=TLSRecord.TLS1_0,
                                  message=heartbeat.bytes)
        
        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hb_hello())
        logging.debug('Sending Heartbeat...')
        sock.write(self.make_heartbeat())


class Heartbleed(Heartbeat):
    '''Try to send a heartbleed attack'''

    def make_heartbleed(self):
        heartbeat = HeartbeatMessage.create(HeartbeatMessage.HeartbeatRequest,
                                            'XXXX', 0x4000)

        record = TLSRecord.create(content_type=TLSRecord.Heartbeat,
                                  version=TLSRecord.TLS1_0,
                                  message=heartbeat.bytes)
        
        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_hb_hello())
        logging.debug('Sending Heartbleed...')
        sock.write(self.make_heartbleed())


class HighTLSVersion(Probe):
    '''Set a high TLS version in the record'''
    
    def make_high_tls_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0x400,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_high_tls_hello())


class VeryHighTLSVersion(Probe):
    '''Set a very high TLS version in the record'''
    
    def make_very_high_tls_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0xffff,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_very_high_tls_hello())


class ZeroTLSVersion(Probe):
    '''Set a zero version in the record'''
    
    def make_zero_tls_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=0x000,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_zero_tls_hello())


class HighHelloVersion(Probe):
    '''Set a high version in the hello'''
    
    def make_high_tls_hello(self):
        hello = ClientHelloMessage.create(0x400,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_high_tls_hello())


class VeryHighHelloVersion(Probe):
    '''Set a very high version in the hello'''
    
    def make_high_tls_hello(self):
        hello = ClientHelloMessage.create(0xffff,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS)
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_high_tls_hello())


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


class EmptyRecord(Probe):
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
        sock.write(make_hello())


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

class SplitHelloPackets(Probe):
    '''Split the hello over two packets'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello part one...')
        record = make_hello()
        sock.write(record[:10])
        sock.flush()
        logging.debug('Sending Client Hello part two...')
        sock.write(record[10:])


class NoCiphers(Probe):
    '''Send an empty cipher list'''
    
    def make_no_ciphers_hello(self):
        hello = ClientHelloMessage.create(settings['default_hello_version'],
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


class SNIWrongName(Probe):
    '''Send a server name indication for a non-matching name'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        return make_hello([sni_extension])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello('thisisnotyourname'))


class SNILongName(SNIWrongName):
    '''Send a server name indication with a long name'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello('x'*500))

class SNIEmptyName(SNIWrongName):
    '''Send a server name indication with an empty name'''
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(''))

class SNIOneWrong(Probe):
    '''Send server name indication with two names, one wrong'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(None,
                                                   (name, 'thisisnotyourname'))
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[sni_extension])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(self.ipaddress))

class SNIWithDifferentType(Probe):
    '''Send server name indication with two names, one not of host_name type'''

    def make_sni_ext(self, server_names):
        encoded_names = ''.join(struct.pack('!BH', name_type, len(name))
                                + name for name_type, name in server_names)
        ext_data = struct.pack('!H', len(encoded_names)) + encoded_names
        return Extension.create(extension_type=Extension.ServerName,
                                data=ext_data)

    def make_sni_hello(self, server_names):
        sni_extension = self.make_sni_ext(server_names)

        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[sni_extension])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        server_names = []
        server_names += [(ServerNameExtension.HostName, self.ipaddress)]
        # only type 0 (HostName) is defined, any other should be ignored
        server_names += [(4, '<binary-data>')]

        sock.write(self.make_sni_hello(server_names))


class SNIDifferentTypeRev(SNIWithDifferentType):
    '''Send hello like in SNIWithDifferentType but reverse order of names'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        server_names = []
        # only type 0 (HostName) is defined, any other should be ignored
        server_names += [(4, '<binary-data>')]
        server_names += [(ServerNameExtension.HostName, self.ipaddress)]

        sock.write(self.make_sni_hello(server_names))


class SNIOverflow(Probe):
    '''Send server name indication with data length exceeding stated size'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        # first four bytes are the header, last one we truncate to exceed size
        ext_data = sni_extension.bytes[4:-1]
        sni_extension = Extension.create(extension_type=Extension.ServerName,
                                         data=ext_data)

        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[sni_extension])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(self.ipaddress))


class SNIUnderflow(Probe):
    '''Send server name indication with data length smaller than size inside'''

    def make_sni_hello(self, name):
        sni_extension = ServerNameExtension.create(name)
        # first four bytes are the header
        ext_data = sni_extension.bytes[4:] + '\x00\x00\x00'
        sni_extension = Extension.create(extension_type=Extension.ServerName,
                                         data=ext_data)

        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[sni_extension])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(self.make_sni_hello(self.ipaddress))

class SecureRenegoOverflow(Probe):
    '''Send secure renegotiation with data length exceeding stated size'''

    def make_secure_renego_ext(self, payload):
        secure_renego = Extension.create(
            extension_type=Extension.RenegotiationInfo,
            data=payload)
        return make_hello([secure_renego])

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # first byte of secure renegotiation extension specifies the
        # length of the array of bytes in it, but don't provide the
        # required amount
        sock.write(self.make_secure_renego_ext('\x0c0123456789'))

class SecureRenegoUnderflow(SecureRenegoOverflow):
    '''Send secure renegotiation with data length lower than stated size'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # again, first byte specifies zero-length array, rest of bytes
        # are just padding to make the extension large
        sock.write(self.make_secure_renego_ext('\x00\x00\x00\x00\x00'))

class SecureRenegoNonEmpty(SecureRenegoOverflow):
    '''Send secure renegotiation with renegotiation payload'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # send a correctly formatted extension, but with a non-empty
        # payload (indicating renegotiated connection)
        sock.write(self.make_secure_renego_ext('\x0c012345678901'))

class SecureRenegoNull(SecureRenegoOverflow):
    '''Send secure renegotiation extension that is completely empty'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # While the proper formatting is to send an empty array, and not
        # no array, some servers still accept it
        sock.write(self.make_secure_renego_ext(''))


class MaxFragmentNull(Probe):
    '''Send maximum fragment length extension that is completely empty'''

    def make_hello(self, payload):
        max_fragment = Extension.create(
            extension_type=Extension.MaxFragmentLength,
            data=payload)

        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[max_fragment])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal extension needs a single byte value, don't provide it
        sock.write(self.make_hello(''))


class MaxFragmentInvalid(MaxFragmentNull):
    '''Send maximum fragment length extension with invalid value'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # valid values are between 1 and 4 inclusive
        sock.write(self.make_hello('\x08'))


class ClientCertURLsNotNull(Probe):
    '''Send client certificate URL indication extension that is not empty'''

    def make_hello(self, payload):
        client_cert_url_ext = Extension.create(
            extension_type=Extension.ClientCertificateUrl,
            data=payload)

        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[client_cert_url_ext])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correctly formatted does not include any data
        sock.write(self.make_hello('\x08\x00'))


class TrustedCANull(Probe):
    '''Send trusted CA keys extension with completely empty payload'''

    def make_hello(self, payload):
        trusted_ca_ext = Extension.create(
            extension_type=Extension.TrustedCAKeys,
            data=payload)

        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[trusted_ca_ext])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normal formatting is a complex structure
        sock.write(self.make_hello(''))


class TrustedCAOverflow(TrustedCANull):
    '''Send trusted CA keys extension smaller than length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # in a normal structure, the first two bytes are the overall length
        # of list with extension data
        # a typical payload includes type (1B) and sha1 hash (20B)
        sock.write(self.make_hello('\x00\x15'))


class TrustedCAUnderflow(TrustedCANull):
    '''Send trusted CA keys extension larger than length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')

        # type key_sha1_hash + sha1 hash (20 bytes)
        authority = '\x01' + 'a'*20
        # payload has a 2 byte length and then an array of items,
        # add null byte at end to cause the underflow
        ext_data = struct.pack('!H', len(authority)) + authority + '\x00'

        sock.write(self.make_hello(ext_data))


class TruncatedHMACNotNull(Probe):
    '''Send a truncated HMAC extension with a non empty payload'''

    def make_hello(self, payload):
        truncated_hmac = Extension.create(
            extension_type=Extension.TruncateHMAC,
            data=payload)
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[truncated_hmac])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # properly formatted extension has no data at all
        sock.write(self.make_hello('\x0c'))

class OCSPNull(Probe):
    '''Send status request extension with empty payload'''

    def make_hello(self, payload):
        status_request = Extension.create(
            extension_type=Extension.StatusRequest,
            data=payload)
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[status_request])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # normally the status request is a complex structure, don't include
        # it
        sock.write(self.make_hello(''))


class OCSPOverflow(OCSPNull):
    '''Send status request ext smaller than the length inside indicates'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # the request has three fields - type (one byte) and two arrays
        # with 2 byte long headers, truncate the second length header
        sock.write(self.make_hello('\x01\x00\x00\x00'))


class OCSPUnderflow(OCSPNull):
    '''Send status request ext larger than the length inside indicate'''

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correctly formed request, two extra zero bytes
        sock.write(self.make_hello('\x01' + '\x00' * 6))


class DoubleExtension(Probe):
    '''Duplicate secure renegotiation extension'''

    def make_hello(self):
        secure_renego = Extension.create(
            extension_type=Extension.RenegotiationInfo,
            data='\x00')
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[secure_renego,
                                                      secure_renego])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

    def test(self, sock):
        logging.debug('Sending Client Hello...')
        # correct Client Hello messages must not contain two extensions
        # of the same type
        sock.write(self.make_hello())
