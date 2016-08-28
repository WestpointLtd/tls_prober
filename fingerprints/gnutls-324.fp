Description: gnutls 3.2.4

HighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:CertificateRequest|*(303)handshake:ServerHelloDone|
ZeroHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:CertificateRequest|*(303)handshake:ServerHelloDone|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|
NoCiphers: *(301)alert:HandshakeFailure:fatal|
BadContentType: *(303)alert:UnexpectedMessage:fatal|
VeryHighTLSVersion: *(303)alert:ProtocolVersion:fatal|
RecordLengthOverflow: *(303)alert:RecordOveflow:fatal|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
TwoInvalidPackets: writeerror:EPIPE|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:CertificateRequest|*(303)handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
EmptyRecord: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|
ZeroTLSVersion: *(303)alert:ProtocolVersion:fatal|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: *(303)alert:ProtocolVersion:fatal|
RecordLengthUnderflow: writeerror:EPIPE|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:CertificateRequest|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMessage:fatal|
