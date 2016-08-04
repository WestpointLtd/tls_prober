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

    def connect(self, ipaddress, port, starttls_mode):
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
        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions = [ hb_extension ])

    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

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


class Heartbleed(Probe):
    '''Try to send a heartbleed attack'''
    
    def make_hb_hello(self):
        hb_extension = HeartbeatExtension.create()
        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions = [ hb_extension ])

    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

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
        return record_one, record_two

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
        hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions = [ sni_extension ])
    
        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        #hexdump(record.bytes)
        return record.bytes

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

class SecureRenegoOverflow(Probe):
    '''Send secure renegotiation with data length exceeding stated size'''

    def make_secure_renego_ext(self, payload):
        secure_renego = Extension.create(
            extension_type=Extension.RenegotiationInfo,
            data=payload)
        hello = ClientHelloMessage.create(settings['default_hello_version'],
                                          '01234567890123456789012345678901',
                                          DEFAULT_CIPHERS,
                                          extensions=[secure_renego])

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=settings['default_record_version'],
                                  message=hello.bytes)

        return record.bytes

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
