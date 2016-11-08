Description: MatrixSSL 3.1.2

BadContentType: *(0)alert:UnexpectedMessage:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
EmptyRecord: *(0)alert:IllegalParameter:fatal|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
HighHelloVersion: *(400)handshake:ServerHello(400)|*(400)handshake:Certificate|*(400)handshake:ServerHelloDone|
HighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
NoCiphers: *(301)alert:DecodeError:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
RecordLengthOverflow: *(0)alert:DecodeError:fatal|
RecordLengthUnderflow: writeerror:EPIPE|
SNIEmptyName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNILongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNIWrongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
TwoInvalidPackets: *(0)alert:UnexpectedMessage:fatal|
VeryHighHelloVersion: *(ff01)handshake:ServerHello(ff01)|*(ff01)handshake:Certificate|*(ff01)handshake:ServerHelloDone|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroHelloVersion: *(0)alert:ProtocolVersion:fatal|
ZeroTLSVersion: *(0)alert:IllegalParameter:fatal|
