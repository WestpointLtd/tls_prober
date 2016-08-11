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

# DEFAULT_CIPHERS extended for non-PFS TLSv1.2-only connections
DEFAULT_12_CIPHERS = [TLS_RSA_WITH_RC4_128_MD5,
                      TLS_RSA_WITH_RC4_128_SHA,
                      TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                      TLS_RSA_WITH_AES_128_CBC_SHA,
                      TLS_RSA_WITH_AES_256_CBC_SHA,
                      TLS_RSA_WITH_AES_128_CBC_SHA256,
                      TLS_RSA_WITH_AES_256_CBC_SHA256,
                      TLS_RSA_WITH_AES_128_GCM_SHA256,
                      TLS_RSA_WITH_AES_256_GCM_SHA384,
                      # ChaCha20
                      0xCCA0,  # RSA [nmav]
                      # IoT
                      TLS_RSA_WITH_AES_128_CCM,
                      TLS_RSA_WITH_AES_256_CCM,
                      TLS_RSA_WITH_AES_128_CCM_8,
                      TLS_RSA_WITH_AES_256_CCM_8,
                      # uncommon stuff:
                      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
                      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
                      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                      TLS_RSA_WITH_ARIA_128_CBC_SHA256,
                      TLS_RSA_WITH_SEED_CBC_SHA
                     ]

DEFAULT_PFS_CIPHERS = [TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                       TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                       TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                       TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                       TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       # ChaCha20
                       0xCCA9,  # ECDHE_ECDSA [ietf]
                       0xCCA2,  # ECDHE_ECDSA [nmav]
                       0xCC14,  # ECDHE_ECDSA [agl]
                       0xCCA8,  # ECDHE_RSA [ietf]
                       0xCCA1,  # ECDHE_RSA [nmav]
                       0xCC13,  # ECDHE_RSA [agl]
                       0xCCAA,  # DHE_RSA [ietf]
                       0xCCA3,  # DHE_RSA [nmav]
                       0xCC15,  # DHE_RSA [agl]
                       # IoT stuff (maybe)
                       TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
                       TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                       TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                       TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                       TLS_DHE_RSA_WITH_AES_256_CCM,
                       TLS_DHE_RSA_WITH_AES_128_CCM,
                       TLS_DHE_RSA_WITH_AES_256_CCM_8,
                       TLS_DHE_RSA_WITH_AES_128_CCM_8,
                       # uncommon stuff:
                       TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                       TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                       TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                       TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
                       TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                       TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                       TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
                       TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
                       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
                       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                       TLS_DHE_RSA_WITH_SEED_CBC_SHA,
                       TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
                       ]


def make_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      DEFAULT_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_pfs_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      DEFAULT_PFS_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_11_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_1,
                                      '01234567890123456789012345678901',
                                      DEFAULT_12_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_11_pfs_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_1,
                                      '01234567890123456789012345678901',
                                      DEFAULT_PFS_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_12_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                      '01234567890123456789012345678901',
                                      DEFAULT_12_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_12_pfs_hello(extensions=tuple()):
    hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                      '01234567890123456789012345678901',
                                      DEFAULT_PFS_CIPHERS,
                                      extensions=extensions)

    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def make_hello_request(version=TLSRecord.TLS1_0):
    hello_req = HandshakeMessage.create(HandshakeMessage.HelloRequest,
                                        b'')
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=version,
                              message=hello_req.bytes)
    return record.bytes


def make_ccs(version=TLSRecord.TLS1_0):
    ccs = '\1'

    record = TLSRecord.create(content_type=TLSRecord.ChangeCipherSpec,
                              version=version,
                              message=ccs)

    return record.bytes

class Extension(TLSExtension):
    @classmethod
    def create(cls, extension_type, data, length=-1):
        self = cls()

        if length < 0:
            length = len(data)

        self.bytes = struct.pack('!HH%ds' % (len(data)),
                                 extension_type,
                                 length,
                                 data)
        return self
