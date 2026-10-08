#!/bin/bash
# Run the QUIC Interop Runner's test cases between the neton endpoint image and one peer, both directions (once when the
# peer is neton itself). Usage: run.sh <quic-interop-runner checkout> <neton image> <peer> [tests]
# Writes results-<server>_<client>.json and logs-<server>_<client>/ here; summary.py turns them into a table.
set -u
RUNNER=$1
IMAGE=$2
PEER=$3
TESTS=${4:-onlyTests}
HERE=$(pwd)

# Register the neton image with the runner (its implementation list is the only way to name an endpoint)
python3 - "$RUNNER/implementations_quic.json" "$IMAGE" <<'PY'
import json, sys
path, image = sys.argv[1], sys.argv[2]
impls = json.load(open(path))
impls["neton"] = {"image": image, "url": "https://github.com/netonframework/quic", "role": "both"}
json.dump(impls, open(path, "w"), indent=2)
PY

pair() {
  local server=$1 client=$2
  echo "== server $server, client $client"
  (cd "$RUNNER" && python3 run.py -s "$server" -c "$client" -t "$TESTS" \
    -l "$HERE/logs-${server}_${client}" -j "$HERE/results-${server}_${client}.json" -i neton) 2>&1 | tail -40
}

pair neton "$PEER"
if [ "$PEER" != neton ]; then pair "$PEER" neton; fi
