#!/usr/bin/python

import sys
import socket
import select
import errno
import logging
import socks
import os

from optparse import OptionParser

# Ensure we can see the pytls/tls subdir for the pytls submodule
sys.path.insert(1, 'pytls')
from tls import *

from prober_utils import *
import probe_db

__version__ = '0.0.2'
__author__ = 'Richard J. Moore'
__email__ = 'rich@kde.org'

settings = {
    'default_hello_version': 0x301,
    'default_record_version': 0x301
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

        s.settimeout(5)
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
                if not select.select([sock.fileno(),],[],[],0.5)[0]:
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
        result = self.test(sock)
        if result:
            return result
        return self.process_response(sock)


class NormalHandshake(Probe):
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())


class DoubleClientHello(Probe):
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())


class ChangeCipherSuite(Probe):
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending ChangeCipherSpec...')
        sock.write(make_ccs())


class EmptyChangeCipherSuite(Probe):
    
    def test(self, sock):
        logging.debug('Sending Client Hello...')
        sock.write(make_hello())
        logging.debug('Sending Empty ChangeCipherSpec...')

        record = TLSRecord.create(content_type=TLSRecord.ChangeCipherSpec,
                                  version=TLSRecord.TLS1_0,
                                  message='')
        sock.write(record.bytes)


class BadHandshakeMessage(Probe):
    
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
    
    def test(self, sock):
        logging.debug('Sending Client Hello part one...')
        record = make_hello()
        sock.write(record[:10])
        sock.flush()
        logging.debug('Sending Client Hello part two...')
        sock.write(record[10:])


class NoCiphers(Probe):
    
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


# List all the probes we have
probes = [
    NormalHandshake(),
    ChangeCipherSuite(),
    OnlyECCipherSuites(),
    HighTLSVersion(),
    VeryHighTLSVersion(),
    ZeroTLSVersion(),
    HighHelloVersion(),
    VeryHighHelloVersion(),
    ZeroHelloVersion(),
    BadContentType(),
    RecordLengthOverflow(),
    RecordLengthUnderflow(),
    Heartbeat(),
    Heartbleed(),
    BadHandshakeMessage(),
    DoubleClientHello(),
    EmptyRecord(),
    SplitHelloRecords(),
    SplitHelloPackets(),
    NoCiphers(),
    EmptyChangeCipherSuite()
]

def probe(ipaddress, port, starttls, specified_probe):

    results = {}

    for probe in probes:
        if specified_probe and specified_probe != type(probe).__name__:
            continue

        logging.info('Probing... %s', type(probe).__name__)
        result = probe.probe(ipaddress, port, starttls)
        results[type(probe).__name__] = result

    return results

def list_probes():
    for probe in probes:
        print type(probe).__name__

def main():
    options = OptionParser(usage='%prog server [options]',
                           description='A tool to fingerprint SSL/TLS servers')
    options.add_option('-p', '--port',
                       type='int', default=443,
                       help='TCP port to test (default: 443)')
    options.add_option('-d', '--debug', action='store_true', dest='debug',
                       default=False,
                       help='Print debugging messages')
    options.add_option( '-s', '--starttls', dest='starttls',
                       type='choice', action='store', default='auto',
                       choices=['auto','smtp','ftp','pop3','imap','none'],
                       help=('Enable a starttls mode. '
                             'The available modes are: auto, smtp, ftp, pop3, imap, none') )
    options.add_option('-t', '--probe', dest='probe',
                       type='string',
                       help='Run the specified probe')
    options.add_option('-a', '--add', dest='add', type='string',
                       help='Add the specified fingerprint to the database')
    options.add_option('-l', '--list', dest='list', action='store_true',
                       help='List the fingerprints of the target')
    options.add_option('--list-probes', dest='list_probes', action='store_true',
                       help='List the available probes')
    options.add_option('-v', '--version', dest='version', action='store_true',
                       help='Display the version information')

    opts, args = options.parse_args()

    if opts.version:
        print 'TLS Prober version %s, %s <%s>' % (__version__, __author__, __email__)
        return

    if opts.list_probes:
        list_probes()
        return

    if len(args) < 1:
        options.print_help()
        return

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)

    # Probe the server
    results = probe(args[0], opts.port, opts.starttls, opts.probe)

    # Add a fingerprint to the db
    if opts.add:
        probe_db.add_fingerprint(opts.add, results)
        print 'Added %s to the database' % opts.add
        print 'Please submit your new fingerprint for inclusion in the next release!'
        return
    
    # Print the results of the probe
    if opts.list:
        for key in results.keys():
            print '%20s\t%s' % (key, results[key])
        return
    
    # Print the matches
    matches = probe_db.find_matches(results)
    for server, score in matches:
        print '%20s\t%s' % (server, score)

if __name__ == '__main__':
    main()
