# arkitekt-mesh-smoltcp

arkitekt-mesh's fork of [smoltcp](https://github.com/smoltcp-rs/smoltcp) 0.13.1,
used by `arkitekt-mesh-core` with its `fast-tcp` feature (the desktop builds).
Without that feature the mesh uses upstream smoltcp, as a board does.

Everything the fork adds is off until asked for, so a socket behaves as
upstream's does by default. What it adds is in [FORK.md](FORK.md).

Licensed 0BSD, as smoltcp is.
