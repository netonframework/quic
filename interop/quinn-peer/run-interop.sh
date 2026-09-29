#!/bin/bash
# Interop between neton quic (the Kotlin test binary's InteropTest) and quinn 0.11 (target/release/{server,client}),
# both directions, then the rejection cases. Usage: run-interop.sh <neton test.kexe> <port base>
# Only processes started here are stopped (by their recorded PIDs).
set -u
K=$1
P=${2:-24433}
C=$(pwd)/certs
Q=$(pwd)/target/release
F='neton.quic.InteropTest.*'
mkdir -p logs
result() { echo "== $*"; }

# 1. neton client -> quinn server
RUST_LOG=quinn_proto::connection=trace $Q/server 127.0.0.1:$P $C/server.pem $C/server.key 1 > logs/1-quinn-server.log 2>&1 &
QPID=$!
sleep 1
NETON_QUIC_INTEROP=client NETON_QUIC_INTEROP_ADDR=127.0.0.1:$P NETON_QUIC_INTEROP_CA=$C/ca.pem \
  $K --ktest_filter="$F" > logs/1-neton-client.log 2>&1
R1=$?
for i in $(seq 1 30); do kill -0 $QPID 2>/dev/null || break; sleep 1; done
kill $QPID 2>/dev/null
result "1. neton client -> quinn server: neton exit $R1"
grep -h "interop\]" logs/1-neton-client.log logs/1-quinn-server.log
echo "quinn 'executing key update' traces: $(grep -c 'executing key update' logs/1-quinn-server.log)"

# 2. quinn client -> neton server
NETON_QUIC_INTEROP=server NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+1)) NETON_QUIC_INTEROP_CERT=$C/server.pem \
  NETON_QUIC_INTEROP_KEY=$C/server.key NETON_QUIC_INTEROP_CONNS=1 $K --ktest_filter="$F" > logs/2-neton-server.log 2>&1 &
NPID=$!
sleep 2
RUST_LOG=quinn_proto::connection=trace $Q/client 127.0.0.1:$((P+1)) localhost $C/ca.pem 8 > logs/2-quinn-client.log 2>&1
R2=$?
wait $NPID
R2N=$?
result "2. quinn client -> neton server: quinn exit $R2, neton exit $R2N"
grep -h "interop\]" logs/2-quinn-client.log logs/2-neton-server.log
grep -h "OK \]\|FAILED \]" logs/2-neton-server.log | head -2
echo "quinn 'executing key update' traces: $(grep -c 'executing key update' logs/2-quinn-client.log)"

# 3. rejections against the neton server: quinn client trusting another CA; quinn client with another ALPN
NETON_QUIC_INTEROP=server NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+2)) NETON_QUIC_INTEROP_CERT=$C/server.pem \
  NETON_QUIC_INTEROP_KEY=$C/server.key NETON_QUIC_INTEROP_CONNS=3 $K --ktest_filter="$F" > logs/3-neton-server.log 2>&1 &
NPID=$!
sleep 2
$Q/client 127.0.0.1:$((P+2)) localhost $C/other-ca.pem 1 > logs/3a-quinn-client.log 2>&1
result "3a. quinn client trusting another CA -> neton server: exit $?"; grep -h "interop\]" logs/3a-quinn-client.log
$Q/client 127.0.0.1:$((P+2)) localhost $C/ca.pem 1 other-alpn > logs/3b-quinn-client.log 2>&1
result "3b. quinn client with ALPN other-alpn -> neton server: exit $?"; grep -h "interop\]" logs/3b-quinn-client.log
$Q/client 127.0.0.1:$((P+2)) localhost $C/ca.pem 2 > logs/3c-quinn-client.log 2>&1
result "3c. the neton server still serves a good client afterwards: exit $?"; grep -h "interop\]" logs/3c-quinn-client.log
wait $NPID
echo "neton server exit $?"; grep -h "interop\]" logs/3-neton-server.log

# 4. neton client trusting another CA -> quinn server
$Q/server 127.0.0.1:$((P+3)) $C/server.pem $C/server.key 1 > logs/4-quinn-server.log 2>&1 &
QPID=$!
sleep 1
NETON_QUIC_INTEROP=client NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+3)) NETON_QUIC_INTEROP_CA=$C/other-ca.pem \
  $K --ktest_filter="$F" > logs/4-neton-client.log 2>&1
result "4. neton client trusting another CA -> quinn server: neton exit $? (expected to fail)"
grep -h "ConnectionError\|Transport\|interop\]" logs/4-neton-client.log | head -3
grep -h "interop\]" logs/4-quinn-server.log
kill $QPID 2>/dev/null
exit 0
