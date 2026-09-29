# RFC-6: macOS and Windows are built and tested, not assumed

**Status:** Tests pass on Linux, macOS and Windows (September 2026, PR #1).
Release signing and a real-machine lab run are still open.

## Problem

The Rust node, `arkitekt-meshd` and the Python bindings have only ever been
built and run on Linux (and the ESP32). The release workflow ships macOS and
Windows binaries and wheels that nobody has run. Known risk areas:
- **Windows UDP:** an ICMP port-unreachable makes the next `recv_from` fail
  with `WSAECONNRESET` (Go sets `SIO_UDP_CONNRESET` off). `run_loop`
  ignores receive errors, so it would not stop, but it may spin or drop a
  datagram. Verify, and set the socket option.
- **Paths and locks:** `identity.json` with `0o600`, the directory with
  `0o700`, and `File::try_lock` on `mesh.lock` are all cfg'd or portable, but
  unverified on Windows ACLs.
- **The stdin-close shutdown** of meshd works with Windows pipes, as it must
  for the fakts sidecar and the Python `Popen`. Needs a test.
- **Local interface enumeration** for endpoints (`probe` in `node.rs`), and
  the default gateway for port mapping (RFC-3). Only Linux reads it
  (`/proc/net/route`); macOS and Windows map nothing without an override.
- **The port-mapping tests** use 127.0.0.2, so they run on Linux only.
- **macOS:** the application firewall prompts for incoming UDP on unsigned
  binaries. Document it, and sign and notarize the release binaries.

## Proposal

1. **The matrix,** added: the Go harness, the Rust tests and the Python
   bindings on `macos-14` and `windows-latest`, on every PR that touches
   the mesh.
2. **Fix what it finds.** Expected first: `SIO_UDP_CONNRESET`, and Windows
   path and permission handling.
3. **Release artifacts get a smoke test:** run each built `arkitekt-meshd`
   binary once, `--version` and a `needs_login` start, on its own runner before
   publishing.
4. **Sign and notarize** the macOS binaries. Sign the Windows ones
   (Authenticode) if the SmartScreen prompts become a problem.

## Done when

- The matrix is green on all three operating systems.
- The release smoke test is in place.
- One manual run of the mesh lab tests against a Windows and a macOS
  machine, since the lab is Linux Docker; its address is reachable from both.

## Done

- **CI matrix, green in `meshd.yml`:** the Rust node, `arkitekt-meshd` and
  fakts' native mesh run against tailscale's test control server, DERP and a
  tsnet peer on `ubuntu-latest`, `macos-14` and `windows-latest`, and so do
  the Python bindings. That covers UDP, the relay, IPv6, netcheck, tailnet
  lock, the packet filter and meshd's stdin shutdown. On Windows, no UDP
  connection-reset errors showed up in these tests.
- **Builds:** Linux and Windows ARM64 build (`check-arm`). `ci.yml` builds
  and unit-tests the native mesh on six runners, including macOS Intel and
  Windows ARM.
- **Skipped:** the `lab_*` suites (they need the local ionskale lab) and the
  port-mapping tests (Linux-only, since they need 127.0.0.2).
- **`ci.yml`'s workspace job** needed clang 21 (from apt.llvm.org) and
  GLib/X11 headers for `webrtc-sys` (lovekit's `livekit` feature).

- **Release builds** (`meshd.yml`, also on a manual run):
  - The macOS binaries are signed (Developer ID, hardened runtime) and
    notarized from the organization's secrets, as konstruktor does.
  - Each natively runnable binary is smoke-tested: `--version`, and a start
    that must report `needs_login`.
  - The `arkitekt-mesh` wheels (`release.yaml`) are installed and run on
    every platform they are built for, the architecture asserted, before
    they are published.

## Still open

- **Windows Authenticode signing:** there are no secrets for it.
- **A mesh-lab run from a real macOS or Windows machine.**
- **Gateway discovery for port mapping** on macOS and Windows.
- **The ESP32 firmware** moved to its own repo,
  [arkitekt-mesh-esp32](https://github.com/arkitektio/arkitekt-mesh-esp32).
  This repo only checks that the mesh builds without its default features
  (`ci.yml`, `mesh-embedded`).
