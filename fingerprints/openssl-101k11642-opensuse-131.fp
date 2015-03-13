Description: openssl 1.0.1k-11.64.2 openSUSE 13.1

HighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
ZeroHelloVersion: error:ECONNRESET|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:IllegalParameter:fatal|
BadContentType: error:ECONNRESET|
VeryHighTLSVersion: error:ECONNRESET|
RecordLengthOverflow: error:timeout
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
ChangeCipherSuite: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
ZeroTLSVersion: error:ECONNRESET|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: error:ECONNRESET|
RecordLengthUnderflow: *(301)alert:RecordOveflow:fatal|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:HandshakeFailure:fatal|
