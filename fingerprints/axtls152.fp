Description: axTLS-1.5.2

HighHelloVersion: *(302)handshake:ServerHello(302)|*(302)handshake:Certificate|*(302)handshake:ServerHelloDone|
ZeroHelloVersion: *(300)alert:ProtocolVersion:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
NoCiphers: *(301)alert:IllegalParameter:fatal|
BadContentType: *(300)alert:HandshakeFailure:fatal|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthOverflow: *(300)alert:HandshakeFailure:fatal|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
TwoInvalidPackets: writeerror:EPIPE|
VeryHighHelloVersion: *(302)handshake:ServerHello(302)|*(302)handshake:Certificate|*(302)handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
EmptyRecord: error:Unexpected EOF receiving record header - server closed connection|
ZeroTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:IllegalParameter:fatal|
HighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthUnderflow: writeerror:EPIPE|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
