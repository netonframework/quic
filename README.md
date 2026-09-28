# quic

QUIC (RFC 9000 / 9001 / 9002) for Kotlin/Native on top of `com.netonstream:io`. The first version replicates quinn
0.11.12 (quinn-proto). Maven coordinate `com.netonstream:quic`, package `neton.quic`.

Specification and implementation record: [SPEC.md](SPEC.md).

## Status: not finished

The protocol core runs against a **test double for TLS**. QUIC is not complete, and nothing here is fit for use yet.

What exists (SPEC §11.1–11.6):
- varint and frame codecs, and packet protection and header protection on openssl-kotlin primitives;
- streams, flow control and datagrams;
- congestion control (NewReno, Cubic, BBR), pacing, RTT estimation, MTU discovery, packet spaces and ACKs;
- the connection state machine (quinn's `connection/mod.rs`) and the endpoint (routing, Retry and tokens, version
  negotiation, stateless reset);
- deterministic release of native key contexts: explicit ownership and release points, and an exactly-once release
  shared with the GC cleaner, which is only a backstop;
- quinn's connection and token tests, run against the test double; 437 tests in all.

What is missing, and blocks the first version:
- **Real TLS.** The handshake, certificate verification, advancing key levels and 1-RTT key updates on a real TLS
  stack, and two-way interop with quinn, are all unverified and may expose state-machine bugs.
  - TLS comes from openssl-kotlin. Its QUIC TLS callback interface (batch 1 of the requests in SPEC §11.7) has not
    been delivered yet.
  - Interpreting transport parameters, reassembling and retransmitting CRYPTO data, and scheduling connections stay
    in this library.
- **The driver layer (SPEC §3):** sockets, timers, and the endpoint and connection tasks on neton-io datagrams.
- **0-RTT on real TLS.** It is a separate later batch with its own acceptance.

## Building and testing

```
./gradlew :quic:macosArm64Test               # or linuxX64Test
```
