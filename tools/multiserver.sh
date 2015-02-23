#!/bin/bash

#openssl=openssl
port=5678
cert=~/src/westpoint/pyssl/test-ocsp-good-cert.pem
key=~/src/westpoint/pyssl/test-ocsp-good-key.pem
ip=127.0.0.1

function probe
{
    name=`basename $1`
    command="$1 s_server -www -accept $port -cert $cert -key $key"

    $command &
    pid=$!

    ./prober.py -a "$name default source build (no-ec)" -p $port $ip

    kill $pid
}

for openssl in ~/src/all-openssl-versions/binaries/openssl-*
do
    probe $openssl
done
