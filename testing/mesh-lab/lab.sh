#!/usr/bin/env bash
# The local mesh lab: our ionskale fork plus a tsnet peer, for the mesh
# integration tests (Rust, meshd, Python, ESP32).
#
#   ./lab.sh up                 build and start ionskale + the peer, write .lab/env
#   ./lab.sh env                print the test environment (source it: eval "$(./lab.sh env)")
#   ./lab.sh test [--python]    run every lab test suite (Rust; with --python, the bindings too)
#   ./lab.sh key [--ephemeral] [--tag tag:x] [--expiry 1h]
#                               mint a pre-authorized key on the lab tailnet (tag:lab:
#                               a test node; tag:probe: may reach boards)
#   ./lab.sh machines           list the tailnet's machines
#   ./lab.sh expire NAME        expire a machine's key (by name)
#   ./lab.sh delete NAME        delete a machine (by name)
#   ./lab.sh prune              delete the machines tests left behind (t-*)
#   ./lab.sh restart            restart ionskale (clients should reconnect)
#   ./lab.sh netem SPEC...|off  shape what the peer sends (tc netem, e.g. `delay 20ms`,
#                               `delay 100ms loss 1%`): a round trip for the benchmarks
#   ./lab.sh ionscale ARGS...   any ionscale CLI command against the lab
#   ./lab.sh livekit            start a LiveKit server that is only on the mesh
#                               (lab-livekit:7880, dev keys; for the lovekit tests)
#   ./lab.sh lock               lock the `lab-lock` tailnet (tailnet lock), with a
#                               tailscaled admin holding the trusted key
#   ./lab.sh lock-sign NODEKEY  sign a node key in `lab-lock` (nodekey:<hex>)
#   ./lab.sh esp32-env FILE     write a mesh.env for the ESP32 firmware (fresh key, the
#                               lab CA, the lab NTP; keeps WIFI_*/MESH_LINK/PPP/DIRECT)
#   ./lab.sh esp32-watch [--udp PORT | --serial DEV] [--timeout S]
#                               wait for the board's "MESH-TEST ok" line (PPP logs
#                               arrive over UDP, 5514 by default; Wi-Fi boards on serial)
#   ./lab.sh down [-v]          stop (and with -v, forget all state)
#
# Environment:
#   MESH_LAB_ADDR       the address everything reaches ionskale at (default:
#                       this machine's LAN address, so an ESP32 can join too)
#   MESH_LAB_PORT       its HTTPS/DERP port (8443); MESH_LAB_STUN_PORT (3478)
#   MESH_LAB_TS_VERSION the tailscale version the peer is built with (v1.102.5)
#   IONSKALE_SRC        the fork's source (../../../../deployments/next/mounts/ionskale)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab="$here/.lab"
# Paths given on the command line are the caller's, not the script's.
caller="$PWD"
cd "$here"

# A path relative to where lab.sh was run from.
from_caller() { case "$1" in /*) echo "$1" ;; *) echo "$caller/$1" ;; esac; }

export IONSKALE_SRC="${IONSKALE_SRC:-$(cd "$here/../../../../deployments/next/mounts/ionskale" 2>/dev/null && pwd || true)}"
export MESH_LAB_PORT="${MESH_LAB_PORT:-8443}"
export MESH_LAB_STUN_PORT="${MESH_LAB_STUN_PORT:-3478}"
TAILNET=lab

die() { echo "lab: $*" >&2; exit 1; }
compose() { docker compose -f "$here/compose.yml" "$@"; }

lan_addr() {
  ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1
}

addr() {
  if [ -n "${MESH_LAB_ADDR:-}" ]; then echo "$MESH_LAB_ADDR"
  elif [ -f "$lab/addr" ]; then cat "$lab/addr"
  else lan_addr; fi
}

admin_key() { cat "$lab/admin-key"; }

# The ionscale CLI, run inside the ionskale container against itself.
ionscale() {
  compose exec -T \
    -e IONSCALE_ADDR=https://localhost:443 \
    -e IONSCALE_SKIP_VERIFY=true \
    -e IONSCALE_SYSTEM_ADMIN_KEY="$(admin_key)" \
    ionskale /usr/local/bin/ionscale "$@"
}

gen_tls() {
  local host="$1"
  mkdir -p "$lab/tls"
  if [ -f "$lab/tls/ca.pem" ] && grep -qx "$host" "$lab/tls/host" 2>/dev/null; then return; fi
  TLS_CHANGED=1
  echo "lab: generating a CA and a certificate for $host"
  # ECDSA P-256: cheap to verify on an ESP32 too.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/CN=mesh-lab CA" \
    -keyout "$lab/tls/ca.key" -out "$lab/tls/ca.pem" 2>/dev/null
  local san="DNS:localhost,DNS:ionskale,IP:127.0.0.1"
  if [[ "$host" =~ ^[0-9.]+$ ]]; then san="$san,IP:$host"; else san="$san,DNS:$host"; fi
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" \
    -keyout "$lab/tls/ionskale.key" -out "$lab/tls/ionskale.csr" 2>/dev/null
  openssl x509 -req -in "$lab/tls/ionskale.csr" -CA "$lab/tls/ca.pem" -CAkey "$lab/tls/ca.key" \
    -CAcreateserial -days 825 -out "$lab/tls/ionskale.pem" \
    -extfile <(printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth" "$san") 2>/dev/null
  chmod 644 "$lab/tls/"*.pem "$lab/tls/ionskale.key"
  echo "$host" > "$lab/tls/host"
}

write_config() {
  local host="$1"
  [ -f "$lab/admin-key" ] || openssl rand -hex 32 > "$lab/admin-key"
  cat > "$lab/config.yaml" <<YAML
listen_addr: ":443"
public_addr: "$host:$MESH_LAB_PORT"
stun_listen_addr: ":3478"
stun_public_addr: "$host:$MESH_LAB_STUN_PORT"
tls:
  disable: false
  cert_file: /etc/ionscale/tls/ionskale.pem
  key_file: /etc/ionscale/tls/ionskale.key
keys:
  system_admin_key: "$(admin_key)"
database:
  type: sqlite
  url: /data/ionscale.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)
logging:
  level: info
YAML
}

wait_healthy() {
  local url="https://$(addr):$MESH_LAB_PORT/healthz"
  for _ in $(seq 1 90); do
    if curl -fsS --cacert "$lab/tls/ca.pem" "$url" >/dev/null 2>&1; then return; fi
    sleep 1
  done
  compose logs --tail 40 ionskale >&2
  die "ionskale did not become healthy at $url"
}

# A second tailnet with lok's ACL shape, for the packet-filter tests
# (docs/rfc8-packet-filter.md): tag:app may reach tag:hub on port 80, and
# nothing else is allowed, so the hub never initiates.
ACL_TAILNET=lab-acl

ensure_acl_tailnet() {
  if ! ionscale tailnets list | awk 'NR > 1 { print $2 }' | grep -qx "$ACL_TAILNET"; then
    ionscale tailnets create -n "$ACL_TAILNET" >/dev/null
  fi
  printf '%s' '{"tagOwners":{"tag:app":[],"tag:hub":[]},"acls":[{"action":"accept","src":["tag:app"],"dst":["tag:hub:80"]}]}' > "$lab/acl-lab-acl.json"
  compose cp "$lab/acl-lab-acl.json" ionskale:/tmp/acl-lab-acl.json >/dev/null
  ionscale tailnets set-acl-policy --tailnet "$ACL_TAILNET" --file /tmp/acl-lab-acl.json >/dev/null
  [ -s "$lab/acl-app-key" ] || ionscale auth-keys create --tailnet "$ACL_TAILNET" --pre-authorized --tag tag:app \
    | awk 'NF { key = $NF } END { print key }' > "$lab/acl-app-key"
  [ -s "$lab/acl-hub-key" ] || ionscale auth-keys create --tailnet "$ACL_TAILNET" --pre-authorized --tag tag:hub \
    | awk 'NF { key = $NF } END { print key }' > "$lab/acl-hub-key"
}

mint_key() {
  # The fork wants at least one tag on every key; lab keys carry tag:lab
  # unless others are given. ionscale prints the key last.
  local args=("$@")
  [[ " ${args[*]} " == *" --tag "* ]] || args+=(--tag tag:lab)
  ionscale auth-keys create --tailnet "$TAILNET" --pre-authorized "${args[@]}" \
    | awk 'NF { key = $NF } END { print key }'
}

machine_id() {
  ionscale machines list --tailnet "$TAILNET" \
    | awk -v name="$1" 'NR > 1 && $3 == name { print $1 }' | head -1
}

cmd_up() {
  [ -d "$IONSKALE_SRC" ] || die "no ionskale source at '$IONSKALE_SRC' (set IONSKALE_SRC)"
  command -v openssl >/dev/null || die "openssl is needed"
  local host; host="$(addr)"
  [ -n "$host" ] || die "could not work out a LAN address; set MESH_LAB_ADDR"
  mkdir -p "$lab"
  echo "$host" > "$lab/addr"
  gen_tls "$host"
  write_config "$host"
  export MESH_LAB_URL="https://$host:$MESH_LAB_PORT"
  compose up -d --build ionskale
  # Mounted files changed under a running container: pick them up.
  if [ -n "${TLS_CHANGED:-}" ]; then compose restart ionskale >/dev/null; fi
  wait_healthy
  if ! ionscale tailnets list | awk 'NR > 1 { print $2 }' | grep -qx "$TAILNET"; then
    ionscale tailnets create -n "$TAILNET" >/dev/null
  fi
  # Test nodes (tag:lab) reach each other, the peer and LiveKit, but never
  # a board (tag:esp32), which reaches only the peer; probes (tag:probe)
  # reach boards. A netmap lists only peers a node can reach or be reached
  # by, so test runs never grow a board's netmap (its heap is tight).
  printf '%s' '{"tagOwners":{"tag:lab":[],"tag:peer":[],"tag:esp32":[],"tag:probe":[]},"acls":[{"action":"accept","src":["tag:lab"],"dst":["tag:lab:*","tag:peer:*"]},{"action":"accept","src":["tag:esp32"],"dst":["tag:peer:*"]},{"action":"accept","src":["tag:probe"],"dst":["tag:esp32:*","tag:peer:*"]}]}' > "$lab/acl.json"
  compose cp "$lab/acl.json" ionskale:/tmp/acl.json >/dev/null
  ionscale tailnets set-acl-policy --tailnet "$TAILNET" --file /tmp/acl.json >/dev/null
  # The peer carries tag:peer (older labs keyed it tag:lab: re-key it once).
  if [ -s "$lab/peer-key" ] && [ "$(cat "$lab/peer-tag" 2>/dev/null)" != "tag:peer" ]; then
    rm -f "$lab/peer-key"
    compose --profile peer rm -sf peer >/dev/null 2>&1 || true
    docker volume rm mesh-lab_peer-state >/dev/null 2>&1 || true
    id="$(machine_id lab-peer)"; [ -n "$id" ] && ionscale machines delete --machine-id "$id" >/dev/null </dev/null
  fi
  if [ ! -s "$lab/peer-key" ]; then
    mint_key --tag tag:peer > "$lab/peer-key"
    echo "tag:peer" > "$lab/peer-tag"
  fi
  [ -s "$lab/peer-key" ] || die "could not mint a key for the peer"
  export MESH_LAB_PEER_KEY; MESH_LAB_PEER_KEY="$(cat "$lab/peer-key")"
  compose --profile peer up -d --build ${TLS_CHANGED:+--force-recreate} peer
  for _ in $(seq 1 60); do
    if compose --profile peer logs peer 2>/dev/null | grep -q '"event":"ready"'; then break; fi
    sleep 1
  done
  compose --profile peer logs peer | grep -q '"event":"ready"' \
    || { compose --profile peer logs --tail 40 peer >&2; die "the peer did not come up"; }
  [ -s "$lab/test-key" ] || mint_key > "$lab/test-key"
  ensure_acl_tailnet
  write_env
  echo "lab: up at $MESH_LAB_URL (tailnet '$TAILNET'); test environment in $lab/env"
}

write_env() {
  local host; host="$(addr)"
  local livekit_lines=""
  [ -f "$lab/env" ] && livekit_lines="$(grep -E 'ARKITEKT_TEST_LIVEKIT|ARKITEKT_TEST_MESH_LOCK' "$lab/env" || true)"
  local peer_ip
  peer_ip="$(compose --profile peer logs peer | grep -o '"ip":"[^"]*"' | tail -1 | cut -d'"' -f4)"
  cat > "$lab/env" <<ENV
export ARKITEKT_TEST_MESH_URL=https://$host:$MESH_LAB_PORT
export ARKITEKT_TEST_MESH_KEY=$(cat "$lab/test-key")
export ARKITEKT_TEST_MESH_PEER=lab-peer
export ARKITEKT_TEST_MESH_PEER_IP=$peer_ip
export ARKITEKT_MESH_CA_FILE=$lab/tls/ca.pem
export ARKITEKT_MESH_LAB=$here/lab.sh
export ARKITEKT_TEST_MESH_ACL_APP_KEY=$(cat "$lab/acl-app-key")
export ARKITEKT_TEST_MESH_ACL_HUB_KEY=$(cat "$lab/acl-hub-key")
ENV
  [ -n "$livekit_lines" ] && echo "$livekit_lines" >> "$lab/env" || true
}

cmd_env() {
  [ -f "$lab/env" ] || die "the lab is not up (./lab.sh up)"
  cat "$lab/env"
}

cmd_livekit() {
  [ -f "$lab/env" ] || die "the lab is not up (./lab.sh up)"
  export MESH_LAB_URL; MESH_LAB_URL="https://$(addr):$MESH_LAB_PORT"
  [ -s "$lab/livekit-key" ] || mint_key > "$lab/livekit-key"
  export MESH_LAB_LIVEKIT_KEY; MESH_LAB_LIVEKIT_KEY="$(cat "$lab/livekit-key")"
  # LiveKit reads its interfaces once, at start: start it only when
  # tailscale0 has its tailnet address (else it offers no candidates, e.g.
  # after a reboot, when docker starts both at once), then restart it.
  compose --profile livekit up -d ts-livekit
  for _ in $(seq 1 60); do
    compose --profile livekit exec -T ts-livekit tailscale ip -4 >/dev/null 2>&1 && break
    sleep 1
  done
  compose --profile livekit up -d livekit
  compose --profile livekit restart livekit >/dev/null
  for _ in $(seq 1 60); do
    if ionscale machines list --tailnet "$TAILNET" | awk 'NR > 1 { print $3 }' | grep -qx lab-livekit; then
      break
    fi
    sleep 1
  done
  ionscale machines list --tailnet "$TAILNET" | awk 'NR > 1 { print $3 }' | grep -qx lab-livekit \
    || { compose --profile livekit logs --tail 30 ts-livekit >&2; die "lab-livekit did not join"; }
  grep -q ARKITEKT_TEST_LIVEKIT "$lab/env" || cat >> "$lab/env" <<ENV
export ARKITEKT_TEST_LIVEKIT_HOST=lab-livekit
export ARKITEKT_TEST_LIVEKIT_KEY=devkey
export ARKITEKT_TEST_LIVEKIT_SECRET=devsecret_devsecret_devsecret_devsecret
ENV
  echo "lab: LiveKit at lab-livekit:7880 on the mesh (media on 7882/udp over tailscale0)"
}

LOCK_TAILNET=lab-lock

lock_admin() { compose --profile lock exec -T lock-admin tailscale "$@"; }

cmd_lock() {
  [ -f "$lab/env" ] || die "the lab is not up (./lab.sh up)"
  if ! ionscale tailnets list | awk 'NR > 1 { print $2 }' | grep -qx "$LOCK_TAILNET"; then
    ionscale tailnets create -n "$LOCK_TAILNET" >/dev/null
  fi
  printf '%s' '{"tagOwners":{"tag:lab":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}' > "$lab/acl-lock.json"
  compose cp "$lab/acl-lock.json" ionskale:/tmp/acl-lock.json >/dev/null
  ionscale tailnets set-acl-policy --tailnet "$LOCK_TAILNET" --file /tmp/acl-lock.json >/dev/null
  # Nodes may run `tailscale lock init` (ionskale gates it on this).
  ionscale tailnets enable-tailnet-lock --tailnet "$LOCK_TAILNET" >/dev/null 2>&1 || true
  lock_key() {
    ionscale auth-keys create --tailnet "$LOCK_TAILNET" --pre-authorized --tag tag:lab \
      | awk 'NF { key = $NF } END { print key }'
  }
  [ -s "$lab/lock-admin-key" ] || lock_key > "$lab/lock-admin-key"
  [ -s "$lab/lock-test-key" ] || lock_key > "$lab/lock-test-key"
  export MESH_LAB_URL; MESH_LAB_URL="https://$(addr):$MESH_LAB_PORT"
  export MESH_LAB_LOCK_ADMIN_KEY; MESH_LAB_LOCK_ADMIN_KEY="$(cat "$lab/lock-admin-key")"
  compose --profile lock up -d lock-admin >/dev/null
  for _ in $(seq 1 60); do
    lock_admin status >/dev/null 2>&1 && break
    sleep 1
  done
  local status; status="$(lock_admin lock status --json)"
  if ! echo "$status" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["Enabled"] else 1)'; then
    local tlpub
    tlpub="$(echo "$status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["PublicKey"])')"
    lock_admin lock init --gen-disablements 1 --confirm "$tlpub" >/dev/null
    for _ in $(seq 1 30); do
      lock_admin lock status --json | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["Enabled"] else 1)' && break
      sleep 1
    done
  fi
  grep -q ARKITEKT_TEST_MESH_LOCK "$lab/env" || cat >> "$lab/env" <<ENV
export ARKITEKT_TEST_MESH_LOCK_KEY=$(cat "$lab/lock-test-key")
ENV
  echo "lab: tailnet '$LOCK_TAILNET' is locked; sign node keys with ./lab.sh lock-sign nodekey:…"
}

cmd_lock_sign() {
  local nodekey="${1:?usage: lab.sh lock-sign nodekey:<hex>}"
  export MESH_LAB_URL; MESH_LAB_URL="https://$(addr):$MESH_LAB_PORT"
  export MESH_LAB_LOCK_ADMIN_KEY; MESH_LAB_LOCK_ADMIN_KEY="$(cat "$lab/lock-admin-key")"
  lock_admin lock sign "$nodekey"
}

cmd_esp32_env() {
  local out; out="$(from_caller "${1:?usage: lab.sh esp32-env FILE}")"
  [ -f "$lab/env" ] || die "the lab is not up (./lab.sh up)"
  # The board sets its clock from the lab (it may have no internet).
  compose --profile esp32 up -d --build ntp >/dev/null
  # tag:esp32: the board sees only the peer (and probes), never test nodes.
  local key; key="$(mint_key --tag tag:esp32)"
  [ -n "$key" ] || die "could not mint a key"
  {
    echo "# written by testing/mesh-lab/lab.sh esp32-env"
    echo "MESH_CONTROL_URL=https://$(addr):$MESH_LAB_PORT"
    echo "MESH_AUTH_KEY=$key"
    echo "MESH_PEER=lab-peer"
    echo "MESH_CA_PEM_FILE=$lab/tls/ca.pem"
    echo "MESH_SNTP_SERVER=$(addr)"
    if [ -f "$out" ]; then grep -E '^(WIFI_|MESH_LINK|MESH_PPP|MESH_DIRECT|MESH_CA_ONLY)' "$out" || true; fi
  } > "$out.tmp"
  mv "$out.tmp" "$out"
  echo "lab: wrote $out (a fresh key; your WIFI_*/MESH_LINK/PPP/DIRECT lines kept)"
}

cmd_esp32_watch() {
  local source="udp" where="5514" timeout=180
  while [ $# -gt 0 ]; do
    case "$1" in
      --udp) source=udp; where="$2"; shift 2 ;;
      --serial) source=serial; where="$(from_caller "$2")"; shift 2 ;;
      --timeout) timeout="$2"; shift 2 ;;
      *) die "usage: lab.sh esp32-watch [--udp PORT | --serial DEV] [--timeout S]" ;;
    esac
  done
  python3 - "$source" "$where" "$timeout" <<'PY'
import socket, sys, time
source, where, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
deadline = time.monotonic() + timeout

def lines():
    if source == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", int(where)))
        while True:
            s.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data = s.recv(4096)
            except socket.timeout:
                return
            yield from data.decode(errors="replace").splitlines()
    else:
        with open(where, "rb", buffering=0) as port:
            buf = b""
            while time.monotonic() < deadline:
                chunk = port.read(256)
                buf += chunk or b""
                *done, buf = buf.split(b"\n")
                for line in done:
                    yield line.decode(errors="replace")

for line in lines():
    print(line, flush=True)
    if "MESH-TEST ok" in line:
        print("lab: the board is on the mesh and reached lab-peer", file=sys.stderr)
        sys.exit(0)
    if time.monotonic() > deadline:
        break
print(f"lab: no MESH-TEST ok line within {timeout:.0f} s", file=sys.stderr)
sys.exit(1)
PY
}

cmd_test() {
  [ -f "$lab/env" ] || die "the lab is not up (./lab.sh up)"
  # shellcheck disable=SC1091
  source "$lab/env"
  local root; root="$(cd "$here/../.." && pwd)"
  (cd "$root" \
    && cargo test -p arkitekt-mesh --features session,relay --test lab --test lab_restart --test lab_firmware_tls --test lab_acl --test lab_lock \
    && cargo test -p arkitekt-meshd --test lab \
    && if [ -n "${ARKITEKT_TEST_LIVEKIT_HOST:-}" ]; then
         cargo test -p arkitekt-lovekit --features livekit --test lab_livekit
       fi)
  if [ "${1:-}" = "--python" ]; then
    (cd "$root/crates/mesh-py" && uv run --with maturin --with pytest sh -c \
      'maturin develop --uv -q && pytest -q tests/test_lab.py')
  fi
  cmd_prune
}

cmd_prune() {
  # Collect first: docker compose exec would swallow a piped id list.
  mapfile -t ids < <(for t in "$TAILNET" "$ACL_TAILNET" lab-lock; do
    ionscale machines list --tailnet "$t" 2>/dev/null | awk 'NR > 1 && $3 ~ /^t-/ { print $1 }'
  done)
  for id in "${ids[@]}"; do ionscale machines delete --machine-id "$id" >/dev/null </dev/null; done
  echo "lab: pruned ${#ids[@]} test machine(s)"
}

case "${1:-}" in
  up) cmd_up ;;
  test) shift; cmd_test "$@" ;;
  env) cmd_env ;;
  key) shift; mint_key "$@" ;;
  machines) ionscale machines list --tailnet "$TAILNET" ;;
  expire)
    id="$(machine_id "${2:?usage: lab.sh expire NAME}")"; [ -n "$id" ] || die "no machine named $2"
    ionscale machines expire --machine-id "$id" ;;
  delete)
    id="$(machine_id "${2:?usage: lab.sh delete NAME}")"; [ -n "$id" ] || die "no machine named $2"
    ionscale machines delete --machine-id "$id" ;;
  prune) cmd_prune ;;
  restart) compose restart ionskale && wait_healthy ;;
  netem)
    shift; [ $# -gt 0 ] || die "usage: lab.sh netem SPEC...|off"
    if [ "$1" = off ]; then
      compose --profile peer exec -T peer tc qdisc del dev eth0 root 2>/dev/null || true
    else
      compose --profile peer exec -T peer tc qdisc replace dev eth0 root netem "$@"
    fi ;;
  ionscale) shift; ionscale "$@" ;;
  livekit) cmd_livekit ;;
  lock) cmd_lock ;;
  lock-sign) shift; cmd_lock_sign "$@" ;;
  esp32-env) shift; cmd_esp32_env "$@" ;;
  esp32-watch) shift; cmd_esp32_watch "$@" ;;
  down) shift; compose --profile peer --profile esp32 --profile livekit --profile lock down "$@"; [ "${1:-}" = "-v" ] && rm -rf "$lab" || true ;;
  *) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 1 ;;
esac
