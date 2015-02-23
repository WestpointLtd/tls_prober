Description: openssl-0.9.8o default source build (no-ec)

HighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroHelloVersion: error:Unexpected EOF receiving record header - server closed connection|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
BadContentType: error:Unexpected EOF receiving record header - server closed connection|
VeryHighTLSVersion: error:Unexpected EOF receiving record header - server closed connection|
RecordLengthOverflow: error:timeout
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
VeryHighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ChangeCipherSuite: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroTLSVersion: error:Unexpected EOF receiving record header - server closed connection|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: error:Unexpected EOF receiving record header - server closed connection|
RecordLengthUnderflow: *(301)alert:RecordOveflow:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
