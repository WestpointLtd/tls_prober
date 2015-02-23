Description: VMware Horizon View

HighHelloVersion: *(302)handshake:ServerHello(302)|handshake:Certificate|handshake:ServerHelloDone|
ZeroHelloVersion: *(301)alert:HandshakeFailure:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
BadContentType: *(301)alert:UnexpectedMesage:fatal|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
RecordLengthOverflow: error:timeout
Heartbleed: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
VeryHighHelloVersion: *(302)handshake:ServerHello(302)|handshake:Certificate|handshake:ServerHelloDone|
ChangeCipherSuite: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
ZeroTLSVersion: *(301)alert:UnexpectedMesage:fatal|
OnlyECCipherSuites: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerKeyExchange|handshake:ServerHelloDone|
HighTLSVersion: *(301)alert:UnexpectedMesage:fatal|
RecordLengthUnderflow: *(301)alert:UnexpectedMesage:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|*(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
