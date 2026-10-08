#!/bin/bash
# Entry point inside the image (quic-network-simulator convention): set up routing, let a client wait for the
# simulator, then run the endpoint, which reads ROLE, TESTCASE, REQUESTS and SSLKEYLOGFILE itself.
set -e

/setup.sh

if [ "$ROLE" == "client" ]; then
    /wait-for-it.sh sim:57832 -s -t 30
fi

exec /neton-quic-endpoint
