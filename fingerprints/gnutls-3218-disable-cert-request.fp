Description: GnuTLS 3.2.18 disable cert request

BadContentType: *(303)alert:UnexpectedMessage:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
EmptyRecord: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
HighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
HighTLSVersion: *(303)alert:ProtocolVersion:fatal|
NoCiphers: *(301)alert:HandshakeFailure:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
RecordLengthOverflow: *(303)alert:RecordOveflow:fatal|
RecordLengthUnderflow: writeerror:EPIPE|
SNIEmptyName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNILongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNIWrongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
TwoInvalidPackets: *(303)alert:UnexpectedMessage:fatal|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
VeryHighTLSVersion: *(303)alert:ProtocolVersion:fatal|
ZeroHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
ZeroTLSVersion: *(303)alert:ProtocolVersion:fatal|
