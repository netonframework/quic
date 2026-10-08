#!/usr/bin/env python3
"""Summarise the runner's results-*.json files: one line per server/client pair and test case, then the totals.

Usage: summary.py results-*.json. Prints Markdown. Exits non-zero when a test case marked as expected in
EXPECTED_NETON fails between neton and itself, so that a regression of a supported case fails CI.
"""
import json
import sys

# The cases the neton endpoint supports; between neton and neton every one of them must succeed.
EXPECTED_NETON = {
    "handshake", "transfer", "longrtt", "chacha20", "multiplexing", "retry", "resumption", "zerortt", "blackhole",
    "keyupdate", "ecn", "amplificationlimit", "handshakeloss", "transferloss", "handshakecorruption",
    "transfercorruption", "ipv6", "rebind-port", "rebind-addr",
}

regressions = []
for path in sys.argv[1:]:
    data = json.load(open(path))
    servers, clients = data["servers"], data["clients"]
    i = 0
    for client in clients:
        for server in servers:
            results = data["results"][i]
            i += 1
            counts = {}
            for r in results:
                counts[r["result"]] = counts.get(r["result"], 0) + 1
            print(f"### server {server}, client {client}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=str)))
            print()
            print("| test | result |")
            print("|---|---|")
            for r in results:
                print(f"| {r['name']} | {r['result']} |")
                if server == "neton" and client == "neton" and r["name"] in EXPECTED_NETON and r["result"] != "succeeded":
                    regressions.append(r["name"])
            print()

if regressions:
    print(f"**neton ↔ neton failures: {', '.join(regressions)}**")
    sys.exit(1)
