#!/bin/bash
# Interop between neton quic (the Kotlin test binary's InteropTest) and quinn 0.11 (target/release/{server,client}),
# both directions, then the rejection cases. Usage: run-interop.sh <neton test.kexe> <port base>
# Only processes started here are stopped (by their recorded PIDs). Exits non-zero if any case has an unexpected result.
set -u
K=$1
P=${2:-24433}
C=$(pwd)/certs
Q=$(pwd)/target/release
F='neton.quic.InteropTest.*'
mkdir -p logs
FAILS=0
# expect ok <exit code> <case>: a case passes when its exit code is zero.
expect() {
  if [ "$2" = 0 ]; then echo "== PASS $3 (exit $2)"
  else echo "== FAIL $3 (exit $2, expected $1)"; FAILS=$((FAILS + 1)); fi
}
# rejected <exit code> <log> <reason> <case>: a rejection case passes when it fails for the expected reason, so a peer
# that never started does not count as a rejection.
rejected() {
  if [ "$1" != 0 ] && grep -q "$3" "$2"; then echo "== PASS $4 (exit $1: $3)"
  else echo "== FAIL $4 (exit $1, expected a failure with '$3' in $2)"; FAILS=$((FAILS + 1)); fi
}

# logged <log> <text> <case>: the log of a case that exited 0 must also show <text> (e.g. that 0-RTT was accepted).
logged() {
  if grep -q "$2" "$1"; then echo "== PASS $3"; else echo "== FAIL $3 (no '$2' in $1)"; FAILS=$((FAILS + 1)); fi
}

# 1. neton client -> quinn server; then the neton client again, with a ticket, in 0-RTT
RUST_LOG=quinn_proto::connection=trace $Q/server 127.0.0.1:$P $C/server.pem $C/server.key 2 > logs/1-quinn-server.log 2>&1 &
QPID=$!
sleep 1
NETON_QUIC_INTEROP=client NETON_QUIC_INTEROP_ADDR=127.0.0.1:$P NETON_QUIC_INTEROP_CA=$C/ca.pem NETON_QUIC_INTEROP_ZERO_RTT=1 \
  $K --ktest_filter="$F" > logs/1-neton-client.log 2>&1
R1=$?
for i in $(seq 1 30); do kill -0 $QPID 2>/dev/null || break; sleep 1; done
kill $QPID 2>/dev/null
expect ok $R1 "1. neton client -> quinn server"
logged logs/1-neton-client.log "0-RTT accepted true" "1. neton client -> quinn server: 0-RTT with a quinn ticket"
grep -h "interop\]" logs/1-neton-client.log logs/1-quinn-server.log
echo "quinn 'executing key update' traces: $(grep -c 'executing key update' logs/1-quinn-server.log)"

# 2. quinn client -> neton server; then the quinn client again, with a ticket, in 0-RTT
NETON_QUIC_INTEROP=server NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+1)) NETON_QUIC_INTEROP_CERT=$C/server.pem \
  NETON_QUIC_INTEROP_KEY=$C/server.key NETON_QUIC_INTEROP_CONNS=2 $K --ktest_filter="$F" > logs/2-neton-server.log 2>&1 &
NPID=$!
sleep 2
ZERO_RTT=1 RUST_LOG=quinn_proto::connection=trace $Q/client 127.0.0.1:$((P+1)) localhost $C/ca.pem 8 > logs/2-quinn-client.log 2>&1
R2=$?
wait $NPID
R2N=$?
expect ok $R2 "2. quinn client -> neton server (quinn)"
expect ok $R2N "2. quinn client -> neton server (neton)"
logged logs/2-quinn-client.log "0-RTT accepted true" "2. quinn client -> neton server: 0-RTT with a neton ticket (quinn)"
logged logs/2-neton-server.log "0-RTT accepted true" "2. quinn client -> neton server: 0-RTT with a neton ticket (neton)"
grep -h "interop\]" logs/2-quinn-client.log logs/2-neton-server.log
grep -h "OK \]\|FAILED \]" logs/2-neton-server.log | head -2
echo "quinn 'executing key update' traces: $(grep -c 'executing key update' logs/2-quinn-client.log)"

# 3. rejections against the neton server: quinn client trusting another CA; quinn client with another ALPN
NETON_QUIC_INTEROP=server NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+2)) NETON_QUIC_INTEROP_CERT=$C/server.pem \
  NETON_QUIC_INTEROP_KEY=$C/server.key NETON_QUIC_INTEROP_CONNS=3 $K --ktest_filter="$F" > logs/3-neton-server.log 2>&1 &
NPID=$!
sleep 2
$Q/client 127.0.0.1:$((P+2)) localhost $C/other-ca.pem 1 > logs/3a-quinn-client.log 2>&1
rejected $? logs/3a-quinn-client.log UnknownIssuer "3a. quinn client trusting another CA -> neton server"; grep -h "interop\]" logs/3a-quinn-client.log
$Q/client 127.0.0.1:$((P+2)) localhost $C/ca.pem 1 other-alpn > logs/3b-quinn-client.log 2>&1
rejected $? logs/3b-quinn-client.log "no application protocol" "3b. quinn client with ALPN other-alpn -> neton server"; grep -h "interop\]" logs/3b-quinn-client.log
$Q/client 127.0.0.1:$((P+2)) localhost $C/ca.pem 2 > logs/3c-quinn-client.log 2>&1
expect ok $? "3c. the neton server still serves a good client afterwards"; grep -h "interop\]" logs/3c-quinn-client.log
wait $NPID
expect ok $? "3. neton server"; grep -h "interop\]" logs/3-neton-server.log

# 4. neton client trusting another CA -> quinn server
$Q/server 127.0.0.1:$((P+3)) $C/server.pem $C/server.key 1 > logs/4-quinn-server.log 2>&1 &
QPID=$!
sleep 1
NETON_QUIC_INTEROP=client NETON_QUIC_INTEROP_ADDR=127.0.0.1:$((P+3)) NETON_QUIC_INTEROP_CA=$C/other-ca.pem \
  $K --ktest_filter="$F" > logs/4-neton-client.log 2>&1
rejected $? logs/4-neton-client.log "certificate verify failed" "4. neton client trusting another CA -> quinn server"
grep -h "ConnectionError\|Transport\|interop\]" logs/4-neton-client.log | head -3
grep -h "interop\]" logs/4-quinn-server.log
kill $QPID 2>/dev/null
echo "== $FAILS unexpected result(s)"
[ $FAILS = 0 ]
