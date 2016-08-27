Description: MatrixSSL 3.1.2

ZeroHelloVersion: *(0)alert:ProtocolVersion:fatal|
BadContentType: *(0)alert:UnexpectedMesage:fatal|
SNIEmptyName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
TwoInvalidPackets: *(0)alert:UnexpectedMesage:fatal|
EmptyRecord: *(0)alert:IllegalParameter:fatal|
RecordLengthUnderflow: writeerror:EPIPE|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
NoCiphers: *(301)alert:DecodeError:fatal|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
VeryHighHelloVersion: *(ff01)handshake:ServerHello(ff01)|*(ff01)handshake:Certificate|*(ff01)handshake:ServerHelloDone|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
HighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
HighHelloVersion: *(400)handshake:ServerHello(400)|*(400)handshake:Certificate|*(400)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
RecordLengthOverflow: *(0)alert:DecodeError:fatal|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
SNIWrongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNILongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroTLSVersion: *(0)alert:IllegalParameter:fatal|
