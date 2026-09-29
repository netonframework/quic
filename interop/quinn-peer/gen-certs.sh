#!/bin/bash
# A throwaway test CA and a server certificate it issues for localhost / 127.0.0.1 (ECDSA P-256), for the interop
# runs only. Both peers trust the CA explicitly.
set -euo pipefail
mkdir -p certs && cd certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/O=neton quic interop/CN=interop test CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=neton quic interop/CN=localhost" \
  -keyout server.key -out server.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile server.ext -out server.pem
# A second CA nobody's certificate chains to, for the rejection runs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/O=neton quic interop/CN=unrelated CA" -keyout other-ca.key -out other-ca.pem
openssl x509 -in server.pem -noout -subject -issuer -ext subjectAltName
