# Releasing `arkitekt-mesh` to PyPI

`.github/workflows/release.yaml` builds and publishes the Python bindings
(`crates/mesh-py`). Every release of the workspace publishes them:
`release-plz.yml` starts `release.yaml` on the release's `vX.Y.Z` tag once the
crates are on crates.io. It publishes with PyPI trusted publishing from this
workflow, without a GitHub environment. The meshd binaries are separate:
`meshd.yml` attaches them to a GitHub release on a `meshd-vX.Y.Z` tag.

What goes to PyPI (abi3: one wheel per platform covers every CPython from 3.9 on):

| platform | wheel |
|---|---|
| Linux glibc x86_64 / aarch64 | manylinux |
| Linux musl x86_64 / aarch64 | musllinux_1_2 |
| macOS x86_64 + arm64 | universal2 |
| Windows x64 / arm64 | win_amd64, win_arm64 |
| anything else | sdist (needs Rust) |

Each wheel and the sdist carries `LICENSE` and `LICENSE-THIRD-PARTY`
(cargo-about). `smoke` installs every wheel on its platform, asserts the
interpreter's architecture and runs `crates/mesh-py/tests/smoke_installed.py`.
`sdist` checks what the sdist contains, then builds it from source and runs
it. `publish` runs only after both have passed.

## One-time setup

On PyPI, add a trusted publisher for `arkitekt-mesh`: owner `arkitektio`,
repository `arkirust`, workflow `release.yaml`, no environment.

## Each release

1. Run `release.yaml` by hand on main (Actions → release → Run workflow). On a
   branch it builds and smoke-tests everything and publishes nothing. It must
   be green.
2. Release the workspace: bump `workspace.package.version` (and the versions
   in `workspace.dependencies`) on main, or merge the release-plz PR.
   `release-plz.yml` publishes the crates, tags `vX.Y.Z` and starts
   `release.yaml` on that tag, which publishes `arkitekt-mesh X.Y.Z`.

release-plz's tag starts no workflow by itself (it is pushed with
`GITHUB_TOKEN`), which is why `release-plz.yml` dispatches `release.yaml`.
To publish outside of a release, push a `mesh-vX.Y.Z` tag: `X.Y.Z` must be the
workspace version, which the `version` job checks.

PyPI never takes the same version twice, even after a deletion. If the upload
stops partway, re-run `publish`: it skips what is already there.
If a release is broken, fix it and release the next patch version.
