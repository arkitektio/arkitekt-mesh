# Releasing `arkitekt-mesh` to PyPI

`.github/workflows/release.yaml` builds and publishes the Python bindings
(`crates/mesh-py`) on a `mesh-vX.Y.Z` tag. `X.Y.Z` must be the workspace
version, which the `version` job checks. It publishes with PyPI trusted
publishing from this workflow, without a GitHub environment. The meshd
binaries are separate: `meshd.yml` attaches them to a GitHub release on a
`meshd-vX.Y.Z` tag.

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

1. Merge the release-plz PR. It bumps the workspace version and tags `vX.Y.Z`.
2. Run `release.yaml` by hand on main (Actions → release → Run workflow). It
   builds and smoke-tests everything and publishes nothing. It must be green.
3. Push the tag yourself. release-plz's tags don't trigger workflows.
   ```sh
   git checkout main && git pull
   git tag mesh-vX.Y.Z && git push origin mesh-vX.Y.Z
   ```

PyPI never takes the same version twice, even after a deletion. If the upload
stops partway, re-run `publish` (add `skip-existing: true` if it complains).
If a release is broken, fix it and release the next patch version.
