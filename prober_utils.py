#!/bin/python

from tls import *

DEFAULT_CIPHERS = [TLS_RSA_WITH_RC4_128_MD5,
                   TLS_RSA_WITH_RC4_128_SHA,
                   TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                   TLS_RSA_WITH_AES_128_CBC_SHA,
                   TLS_RSA_WITH_AES_256_CBC_SHA,
                   TLS_RSA_WITH_AES_128_CBC_SHA256,
                   TLS_RSA_WITH_AES_256_CBC_SHA256]

                   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                   # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                   # TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                   # TLS_ECDH_RSA_WITH_RC4_128_SHA,
                   # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                   # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                   # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]

def make_hello():
    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      DEFAULT_CIPHERS)
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes

def make_hello_request():
    hello_req = HandshakeMessage.create(HandshakeMessage.HelloRequest,
                                        b'')
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello_req.bytes)
    return record.bytes

def make_ccs():
    ccs = '\1'

    record = TLSRecord.create(content_type=TLSRecord.ChangeCipherSpec,
                              version=TLSRecord.TLS1_0,
                              message=ccs)

    return record.bytes
