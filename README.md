# quic

QUIC (RFC 9000 / 9001 / 9002) for Kotlin/Native on top of `com.netonstream:io`. The first version replicates quinn
0.11.12 (quinn-proto). Release coordinate `com.netonstream:quic:0.1.0` (test double: `com.netonstream:quic-testkit:0.1.0`), built
against `com.netonstream:io:0.3.0` and `com.netonstream:openssl:4.0.2`; package `neton.quic`.

Specification and implementation record: [SPEC.md](SPEC.md).

## Status

Real TLS works and quinn interop passes in both directions (SPEC §11.9), including session resumption and 0-RTT
(SPEC §11.14), so the QUIC protocol and its TLS layer are complete for this version. Tested in CI on macOS (kqueue),
Linux x64 (epoll, io_uring) and Windows (IOCP, WSAPoll).

What exists (SPEC §11.1–11.10):
- varint and frame codecs, and packet protection and header protection on openssl-kotlin primitives;
- streams, flow control and datagrams;
- congestion control (NewReno, Cubic, BBR), pacing, RTT estimation, MTU discovery, packet spaces and ACKs;
- the connection state machine (quinn's `connection/mod.rs`) and the endpoint (routing, Retry and tokens, version
  negotiation, stateless reset);
- **real TLS 1.3** (SPEC §4, §11.9): `TlsSession`, `TlsClientConfig` and `TlsServerConfig`, implemented in this
  library on OpenSSL 4.0.2's third-party QUIC TLS interface through openssl-kotlin's raw bindings — certificate
  chain and host name / IP verification against explicitly given trust anchors (no insecure default; the operating
  system's roots through `Certificates.system()`, SPEC §11.19), optional client authentication, ALPN, the QUIC transport
  parameters extension, TLS alerts as CRYPTO_ERROR, 1-RTT key updates, the exporter, session resumption and 0-RTT, a key
  log (`KeyLogFile`, `SSLKEYLOGFILE`), with explicit exactly-once release of every native object and a GC cleaner only as
  a backstop;
- deterministic release of native key contexts and TLS sessions: explicit ownership and release points;
- the driver layer (SPEC §3, §11.8): the endpoint, connection and stream API on neton-io UDP sockets on one reactor,
  with receive and send budgets, the lifecycle rules as explicit `close()`, streams as neton-io `IoStream`;
- quinn's connection, token and driver tests (the TLS-dependent ones on real TLS; the rest run on either the real
  session or the test double, `NETON_QUIC_TEST_TLS=real`); the whole suite passes on both (SPEC §11.11), the 0-RTT
  tests included (SPEC §11.14);
- session tickets and 0-RTT on the real TLS session: clients keep tickets per server name (single use) and send 0-RTT
  when a ticket allows it (`TlsClientConfig(enableEarlyData = true)`, the default); servers accept 0-RTT
  (`TlsServerConfig(earlyData = true)`, the default) with OpenSSL's replay protection (single-use tickets);
- verification under an impaired network (SPEC §11.10): seeded loss, reordering, duplication and delay in the
  protocol-level simulation and through a UDP relay for the real driver — bulk transfer at 1/5/20% loss, lost handshake
  flights, key updates, resets and stops, closes under loss, exhausted flow-control credit, chaos soaks; two bugs found
  and fixed (both also in quinn 0.11.12); a third, found running the suite on real TLS: a server connection taken
  before the handshake completed could not open streams when the ClientHello spanned two datagrams (also in quinn
  0.11.12, SPEC §11.11); 606 tests, run on macOS arm64 and on Linux x64 with both drivers (SPEC §11.12).
- two-way interop with quinn 0.11 (`interop/quinn-peer`): handshake with certificate verification and ALPN,
  bidirectional stream echo, key updates initiated by each side, 0-RTT with each side's tickets, application close,
  and the rejection cases; run in CI on Linux with both drivers.

What is missing:
- The server sends no 0.5-RTT data: OpenSSL yields the server's 1-RTT read secret only after the client's Finished.
- Tests have run on macOS arm64 and Linux x64 only; the other targets are compile-checked.
- `FairnessTest` has latency bounds that a heavily loaded host can exceed (seen at a load average above 100 on the
  development Mac); SPEC §11.11 records the measurements.
- quic-interop-runner and the performance comparison with quinn (SPEC §6).

`quic-testkit` (test-only) holds the TLS test double (`MockTls`) and a test PKI (`TestPki`) that generates
certificates with OpenSSL at test time. Neither may be used by production code.

## Building and testing

```
./gradlew :quic:macosArm64Test               # or linuxX64Test
NETON_QUIC_TEST_TLS=real quic/build/bin/macosArm64/debugTest/test.kexe   # the whole suite on real TLS
```
