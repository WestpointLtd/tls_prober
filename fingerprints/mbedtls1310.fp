Description: mbedtls-1.3.10

HighHelloVersion: *(400)alert:ProtocolVersion:fatal|
ZeroHelloVersion: *(0)alert:ProtocolVersion:fatal|
BadHandshakeMessage: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|error:Unexpected EOF receiving record header - server closed connection|
SplitHelloPackets: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
BadContentType: error:Unexpected EOF receiving record header - server closed connection|
VeryHighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthOverflow: error:Unexpected EOF receiving record header - server closed connection|
Heartbleed: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
SplitHelloRecords: writeerror:EPIPE|
VeryHighHelloVersion: *(303)handshake:ServerHello(303)|*(303)handshake:Certificate|*(303)handshake:ServerHelloDone|
ChangeCipherSpec: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|error:Unexpected EOF receiving record header - server closed connection|
NormalHandshake: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
Heartbeat: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|*(301)alert:UnexpectedMesage:fatal|
EmptyRecord: error:Unexpected EOF receiving record header - server closed connection|
ZeroTLSVersion: error:Unexpected EOF receiving record header - server closed connection|
OnlyECCipherSuites: *(301)alert:HandshakeFailure:fatal|
HighTLSVersion: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|
RecordLengthUnderflow: writeerror:EPIPE|
DoubleClientHello: *(301)handshake:ServerHello(301)|*(301)handshake:Certificate|*(301)handshake:ServerHelloDone|error:Unexpected EOF receiving record header - server closed connection|
