Description: Apache Tomcat 7.0.54 (Tomcat Native 1.1.30; APR 1.4.8)

ZeroHelloVersion: *(301)alert:ProtocolVersion:fatal|
BadContentType: error:timeout
SNIEmptyName: *(301)alert:DecodeError:fatal|
TwoInvalidPackets: error:ECONNRESET|
EmptyRecord: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthUnderflow: writeerror:ECONNRESET|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerKeyExchange|*(301)handshake:ServerHelloDone|
NoCiphers: *(301)alert:IllegalParameter:fatal|
VeryHighTLSVersion: error:ECONNRESET|
VeryHighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
HighTLSVersion: error:ECONNRESET|
HighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthOverflow: error:timeout
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNIWrongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNILongName: *(301)alert:UnrecognizedName:fatal|
ZeroTLSVersion: error:ECONNRESET|
