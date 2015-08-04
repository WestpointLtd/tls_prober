Description: MatrixSSL 3.7.2b

ZeroHelloVersion: *(0)alert:ProtocolVersion:fatal|
BadContentType: *(0)alert:UnexpectedMesage:fatal|
SNIEmptyName: *(301)alert:IllegalParameter:fatal|
SplitHelloRecords: *(0)alert:UnexpectedMesage:fatal|
EmptyRecord: *(0)alert:IllegalParameter:fatal|
RecordLengthUnderflow: *(0)alert:IllegalParameter:fatal|
Heartbleed: *(301)alert:HandshakeFailure:fatal|
BadHandshakeMessage: *(301)alert:DecodeError:fatal|
NormalHandshake: *(301)alert:DecodeError:fatal|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
NoCiphers: *(301)alert:DecodeError:fatal|
VeryHighTLSVersion: *(301)alert:DecodeError:fatal|
VeryHighHelloVersion: *(ff02)alert:DecodeError:fatal|
DoubleClientHello: *(301)alert:DecodeError:fatal|
Heartbeat: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: *(301)alert:DecodeError:fatal|
HighHelloVersion: *(400)alert:ProtocolVersion:fatal|
SplitHelloPackets: *(301)alert:DecodeError:fatal|
EmptyChangeCipherSpec: *(301)alert:DecodeError:fatal|
RecordLengthOverflow: *(0)alert:DecodeError:fatal|
ChangeCipherSpec: *(301)alert:DecodeError:fatal|
SNIWrongName: *(301)alert:HandshakeFailure:fatal|
SNILongName: *(301)alert:IllegalParameter:fatal|
ZeroTLSVersion: *(0)alert:IllegalParameter:fatal|
