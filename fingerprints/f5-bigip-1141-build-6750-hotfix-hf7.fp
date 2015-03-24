Description: F5 BIG-IP 11.4.1 Build 675.0 Hotfix HF7

ZeroHelloVersion: *(0)alert:HandshakeFailure:fatal|
BadContentType: error:Unexpected EOF receiving record header - server closed connection|
SNIEmptyName: *(301)alert:HandshakeFailure:fatal|
SplitHelloRecords: error:Unexpected EOF receiving record header - server closed connection|
EmptyRecord: error:Unexpected EOF receiving record header - server closed connection|
RecordLengthUnderflow: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
NoCiphers: *(301)alert:HandshakeFailure:fatal|
VeryHighTLSVersion: *(0)alert:HandshakeFailure:fatal|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
HighTLSVersion: *(0)alert:HandshakeFailure:fatal|
HighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
EmptyChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthOverflow: error:timeout
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNIWrongName: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
SNILongName: *(301)alert:HandshakeFailure:fatal|
ZeroTLSVersion: *(0)alert:HandshakeFailure:fatal|
