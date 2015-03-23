Description: Nessus 5.2.8

HighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroHelloVersion: error:timeout
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
BadContentType: error:timeout
VeryHighTLSVersion: error:timeout
RecordLengthOverflow: error:timeout
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
VeryHighHelloVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroTLSVersion: error:timeout
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: error:timeout
RecordLengthUnderflow: *(301)alert:RecordOveflow:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
