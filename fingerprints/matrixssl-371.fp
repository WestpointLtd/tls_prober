Description: MatrixSSL 3.7.1

HighHelloVersion: *(400)alert:ProtocolVersion:fatal|
ZeroHelloVersion: *(0)alert:ProtocolVersion:fatal|
BadHandshakeMessage: *(301)alert:DecodeError:fatal|
SplitHelloPackets: *(301)alert:DecodeError:fatal|
NoCiphers: *(301)alert:DecodeError:fatal|
BadContentType: *(0)alert:UnexpectedMesage:fatal|
VeryHighTLSVersion: *(301)alert:DecodeError:fatal|
RecordLengthOverflow: *(0)alert:DecodeError:fatal|
Heartbleed: *(301)alert:HandshakeFailure:fatal|
SplitHelloRecords: *(0)alert:UnexpectedMesage:fatal|
VeryHighHelloVersion: *(ff02)alert:DecodeError:fatal|
EmptyChangeCipherSuite: *(301)alert:DecodeError:fatal|
ChangeCipherSuite: *(301)alert:DecodeError:fatal|
NormalHandshake: *(301)alert:DecodeError:fatal|
Heartbeat: *(301)alert:HandshakeFailure:fatal|
EmptyRecord: *(0)alert:IllegalParameter:fatal|
ZeroTLSVersion: *(0)alert:IllegalParameter:fatal|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: *(301)alert:DecodeError:fatal|
RecordLengthUnderflow: writeerror:ECONNRESET|
DoubleClientHello: *(301)alert:DecodeError:fatal|
