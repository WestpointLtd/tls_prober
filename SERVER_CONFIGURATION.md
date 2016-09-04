Server configuration
====================


OpenSSL
-------

Key/cert generation:

    openssl ocsp -index ca/index.txt -port 8888 -rsigner ca/cert.pem -rkey ca/key.pem -CA ca/cert.pem
    touch srpfile.bin
    openssl srp -add -srpvfile srpfile.bin -gn 2048 -passin pass:test user

Server start:

    openssl s_server -key localhost/key.pem -cert localhost/cert.pem -www \
    -nextprotoneg 'http/1.1,h2' -status -servername example -cert2 example/cert.pem \
    -key2 example/key.pem -status_url http://localhost:8888 -alpn 'http/1.1,h2' \
    -CAfile ca/cert.pem -psk_hint example-hint -psk 0fbacdf271823b -srpvfile srpfile.bin \
    -use_srtp SRTP_AES128_CM_SHA1_80


NSS
---

Key/cert setup:

    openssl pkcs12 -export -passout pass: -out localhost.p12 -inkey localhost/key.pem -in localhost/cert.pem -name localhost
    openssl pkcs12 -export -passout pass: -out example.p12 -inkey example/key.pem -in example/cert.pem -name example
    openssl pkcs12 -export -passout pass: -out ca.p12 -inkey ca/key.pem -in ca/cert.pem -name ca
    mkdir nssdb
    certutil -N --empty-password -d sql:nssdb
    pk12util -i localhost.p12 -d sql:nssdb -W ''
    pk12util -i ca.p12 -d sql:nssdb -W ''
    pk12util -i example.p12 -d sql:nssdb -W ''

Server start:

    selfserv -d sql:./nssdb -p 4433 -V tls1.0: -H 1 -z -n localhost -T good -A ca -a example -c :c013:0033:002F -u -G -Q


GnuTLS
------

Setup:

    echo garbage > ocsp.der

Server start:

    gnutls-serv --http -p 4433 --x509keyfile localhost/key.pem \
    --x509certfile localhost/cert.pem --disable-client-cert \
    --srtp-profiles SRTP_AES128_CM_HMAC_SHA1_80 --ocsp-response ocsp.der --heartbeat
