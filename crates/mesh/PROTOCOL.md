# Protocol notes

This crate implements, from the protocol up, what a Tailscale client needs to dial peers. These notes describe the wire formats it relies on.

They were taken from the Go source (`tailscale.com` v1.102.5). The end-to-end tests check every one of them against that implementation. Where these notes and the Go code disagree, the Go code is right.

## Endianness, at a glance

| Item | Width | Order |
|---|---|---|
| Control Noise frame length | u16 | big |
| Control Noise nonce | `[0;4] ‖ u64 counter` | **big** (WireGuard's is little) |
| Control early payload length | u32 | big |
| Map response frame length | u32 | **little** |
| DERP frame length | u32 | big |
| WireGuard indices and counters | u32 / u64 | little |
| Disco and STUN ports | u16 | big |

## Control (`control/`)

- **Server key.** `GET /key?v=142` returns `{"publicKey":"mkey:…"}`. Always send `?v=`: without it, the server replies with the *legacy* key as plain text.
- **Handshake.** The pattern is `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The prologue is `"Tailscale Control Protocol v142"`, with the version in decimal.
  - The initiation is 101 bytes: `u16 BE version ‖ 0x01 ‖ u16 BE 96 ‖ e ‖ enc(s) ‖ tag`.
  - The response is 51 bytes: `0x02 ‖ u16 BE 48 ‖ e ‖ tag`.
  - Type `0x03` means an unauthenticated error string.
  - The `ee` step updates only the chaining key.
  - Split: the client sends with k1 and receives with k2.
- **Upgrade.** Send `POST /ts2021` with these headers and an empty body:
  - `Upgrade: tailscale-control-protocol`
  - `Connection: upgrade`
  - `X-Tailscale-Handshake: base64(initiation)`

  Expect `101`. The server corks its writes, so the Noise response may arrive in the same read as the HTTP head.

  Over TLS, offer **no ALPN** and ignore certificate errors; Noise authenticates the server.
- **Records.** `0x04 ‖ u16 BE len ‖ ciphertext`, with at most 4096 bytes per record including the header. Associated data is empty.
- **Early payload.** The server may send `FF FF FF 'T' 'S' ‖ u32 BE len ‖ JSON` before HTTP/2 starts, possibly split across records. Sniff the first 9 plaintext bytes. If they aren't this magic, they are the start of HTTP/2.
- **HTTP/2.** Use prior knowledge (h2c) over the Noise stream, with `:scheme https`. Send `Ts-Lb: nodekey:…` as a load-balancer hint.
- **Register.** `POST /machine/register`. `Version` must be non-zero, and `Hostinfo` is required.
  - An `Error` string means refused.
  - `AuthURL` means interactive login is needed.
  - Re-registering a known node key works without an auth key on ionscale.
- **Map.** `POST /machine/map`. Omit `Compress` to get uncompressed frames.
  - With `Stream:true` and capver ≥ 68, the server **ignores** DiscoKey, Endpoints and Hostinfo. So also send a non-streaming update with `OmitPeers:true` that carries them, and `Hostinfo.NetInfo.PreferredDERP`, which sets our home DERP.
  - Deltas are applied in this order: `Peers` (a full replace), `PeersRemoved`, `PeersChanged`, `OnlineChange`, `PeersChangedPatch`.
  - Go writes nil slices and maps as `null`.
- **Keys.** `prefix ‖ 64 lowercase hex`. The prefixes are `mkey:`, `nodekey:`, `discokey:`, and `privkey:` for private keys. Never send `""` for a key field, because Go servers panic on it; send the zero key instead.

## DERP (`derp.rs`)

- Send `GET /derp` with `Upgrade: DERP` over TLS, expect `101`, and offer no ALPN. `InsecureForTests` only disables certificate verification. It does not mean plain HTTP.
- Frames are `type ‖ u32 BE len ‖ payload`. The magic is `"DERP🔑"`.
- **Handshake:**
  1. ServerKey `0x01`: `magic ‖ key`.
  2. ClientInfo `0x02`: `our node key ‖ box({"version":2,"CanAckPings":true})`.
  3. ServerInfo `0x03`: a sealed box from the server.
  4. NotePreferred `0x07`: send `1` on the home region.
- **Traffic:**
  - Send `0x04`: `dst key ‖ packet`.
  - Receive `0x05`: `src key ‖ packet`.
  - Answer Ping `0x12` with Pong `0x13` carrying the same 8 bytes.
  - Payloads are raw WireGuard or disco packets.

## NaCl box (`nacl.rs`)

The box is X25519 plus XSalsa20-Poly1305, laid out as `nonce(24) ‖ tag(16) ‖ ciphertext`; the tag comes *before* the ciphertext. A test checks this against Go.

## Disco (`disco.rs`, `paths.rs`)

- **Packet:** `"TS💬" ‖ sender disco key ‖ box(type ‖ 0 ‖ payload)`.
- **Messages:**
  - Ping `0x01`: `txid(12) ‖ node key`.
  - Pong `0x02`: `txid ‖ ip16 ‖ port`.
  - CallMeMaybe `0x03`: `(ip16 ‖ port)*`.
  - IPv4 addresses are written v4-mapped.
- Answer every ping with a pong on the path it arrived on. For a ping over DERP, the pong's source is `127.3.3.40:<region>`. A Go peer only switches to a direct path after we pong it over UDP.
- Accept CallMeMaybe only via DERP, and only from the peer that the disco key belongs to.
- **Timers:**

  | What | Value |
  |---|---|
  | Heartbeat | 3 s |
  | Trust a pong | 6.5 s |
  | Ping timeout | 5 s |
  | Minimum time between pings to one endpoint | 5 s |
  | Session counts as active after the last send | 45 s |

## STUN (`stun.rs`)

- The request is **40 bytes**: header, `SOFTWARE="tailnode"`, then `FINGERPRINT` (CRC-32 XOR `0x5354554e`). Tailscale's STUN servers drop requests without both.
- The reply's address comes from `XOR-MAPPED-ADDRESS`, falling back to `MAPPED-ADDRESS`.

## WireGuard (`wg.rs`)

- WireGuard is used unmodified: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, a zero PSK, and the node key as the static key.
- Message sizes:

  | Message | Bytes |
  |---|---|
  | Initiation | 148 |
  | Response | 92 |
  | Cookie reply | 64 |
  | Transport header | 16 |

- The timers are the standard ones. There is no persistent keepalive. The MTU is 1280.
