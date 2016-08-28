Description: Apache Tomcat 7.0.54 (JSSE; BIO; Java 1.8.0_40)

ZeroHelloVersion: *(303)alert:HandshakeFailure:fatal|
BadContentType: *(303)alert:UnexpectedMessage:fatal|
SNIEmptyName: *(303)alert:UnexpectedMessage:fatal|
TwoInvalidPackets: *(303)alert:UnexpectedMessage:fatal|
EmptyRecord: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
RecordLengthUnderflow: writeerror:ECONNRESET|
Heartbleed: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
NormalHandshake: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerKeyExchange|handshake:ServerHelloDone|
NoCiphers: *(301)alert:HandshakeFailure:fatal|
VeryHighTLSVersion: *(303)alert:UnexpectedMessage:fatal|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|handshake:Certificate|handshake:ServerHelloDone|
DoubleClientHello: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
Heartbeat: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
HighTLSVersion: *(303)alert:UnexpectedMessage:fatal|
HighHelloVersion: *(303)handshake:ServerHello(303)|handshake:Certificate|handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
RecordLengthOverflow: error:timeout
ChangeCipherSpec: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
SNIWrongName: *(301)handshake:ServerHello(301)|handshake:Certificate|handshake:ServerHelloDone|
SNILongName: *(303)alert:UnexpectedMessage:fatal|
ZeroTLSVersion: *(303)alert:UnexpectedMessage:fatal|
