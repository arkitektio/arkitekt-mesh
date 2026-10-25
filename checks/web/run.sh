#!/usr/bin/env bash
# Run the web driver's test under node against the Go harness or the lab.
#   ./run.sh harness     (needs go and wasm-pack)
#   ./run.sh lab         (eval "$(testing/mesh-lab/lab.sh env)" first)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

case "${1:-harness}" in
  harness)
    harness="$here/../../crates/mesh/tests/harness"
    bin="$here/target/mesh-harness"
    mkdir -p target
    (cd "$harness" && go test -c -o "$bin" .)
    out="$here/target/harness.out"
    : > "$out"
    # Its stdin stays open (it exits on EOF); nothing of it holds our output.
    MESH_HARNESS=1 "$bin" -test.run TestHarness < <(exec sleep 100000 2>/dev/null) > "$out" 2>/dev/null &
    pid=$!
    trap 'kill $pid 2>/dev/null || true; pkill -P $$ sleep 2>/dev/null || true' EXIT
    for _ in $(seq 1 600); do grep -q '^{' "$out" && break; sleep 0.1; done
    ready="$(grep -m1 '^{' "$out")" || { echo "the harness did not start" >&2; exit 1; }
    field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$ready" "$1"; }
    export MESH_WEB_CONTROL_URL="$(field control_url)" MESH_WEB_AUTH_KEY="$(field auth_key)"
    export MESH_WEB_PEER="$(field peer_name)" MESH_WEB_PEER_IP="$(field peer_ip)"
    # The harness's DERP certificate is self-signed (InsecureForTests).
    export NODE_TLS_REJECT_UNAUTHORIZED=0
    ;;
  lab)
    : "${ARKITEKT_TEST_MESH_URL:?load the lab: eval \"\$(testing/mesh-lab/lab.sh env)\"}"
    export MESH_WEB_CONTROL_URL="$ARKITEKT_TEST_MESH_URL" MESH_WEB_AUTH_KEY="$ARKITEKT_TEST_MESH_KEY"
    export MESH_WEB_PEER="$ARKITEKT_TEST_MESH_PEER" MESH_WEB_PEER_IP="$ARKITEKT_TEST_MESH_PEER_IP"
    # The lab CA, for wss:// to ionskale (DERP certificates are checked).
    export NODE_EXTRA_CA_CERTS="$ARKITEKT_MESH_CA_FILE"
    ;;
  *) echo "usage: $0 harness|lab" >&2; exit 2 ;;
esac
export MESH_WEB_REQUIRED=1
wasm-pack test --node -- -- --nocapture
