Description: axTLS 1.5.2

BadContentType: *(300)alert:HandshakeFailure:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
EmptyRecord: error:Unexpected EOF receiving record header - server closed connection|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
HighHelloVersion: *(302)handshake:ServerHello(302)|*(302)handshake:Certificate|*(302)handshake:ServerHelloDone|
HighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
NoCiphers: *(301)alert:IllegalParameter:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:IllegalParameter:fatal|
RecordLengthOverflow: *(300)alert:HandshakeFailure:fatal|
RecordLengthUnderflow: writeerror:EPIPE|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
TwoInvalidPackets: writeerror:EPIPE|
VeryHighHelloVersion: *(302)handshake:ServerHello(302)|*(302)handshake:Certificate|*(302)handshake:ServerHelloDone|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroHelloVersion: *(300)alert:ProtocolVersion:fatal|
ZeroTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
