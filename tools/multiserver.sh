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

    echo "Launching $command"

    $command &
    pid=$!

    sleep 1

    ./prober.py -a "$name default source build" -p $port $ip

    kill $pid
}

for openssl in ~/src/all-openssl-versions/binaries/openssl-*
do
    echo "Trying $openssl"
    probe $openssl
    sleep 1
done

