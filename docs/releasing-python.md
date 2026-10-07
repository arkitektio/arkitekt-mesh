# Releasing `arkitekt-mesh` to PyPI

`.github/workflows/release.yaml` builds and publishes the Python bindings
(`crates/mesh-py`). Every release of the workspace publishes them: the
`release` job in `ci.yml` starts `release.yaml` on the release's `vX.Y.Z` tag
once the crates are on crates.io. It publishes with PyPI trusted publishing
from this workflow, without a GitHub environment. The meshd binaries go the
same way: `meshd.yml`, started on the same tag, attaches them to the GitHub
release.

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

Nothing by hand. A push to main that carries a `feat`, `fix` or `perf` (or a
breaking change) is a release once CI is green: semantic-release
(`releaserc.toml`) bumps the workspace version, commits, tags `vX.Y.Z` and
creates the GitHub release; the same job publishes the crates and starts
`release.yaml` on the tag, which publishes `arkitekt-mesh X.Y.Z`. The bump
commit is pushed back to main, so pull before the next push.

The tag starts no workflow by itself (it is pushed with `GITHUB_TOKEN`), which
is why the job dispatches `release.yaml`.

To try the build without releasing, run `release.yaml` by hand on main
(Actions → release → Run workflow): on a branch it builds and smoke-tests
everything and publishes nothing. To publish outside of a release, push a
`mesh-vX.Y.Z` tag: `X.Y.Z` must be the workspace version, which the `version`
job checks.

PyPI never takes the same version twice, even after a deletion. If the upload
stops partway, re-run `publish`: it skips what is already there.
If a release is broken, fix it and release the next patch version.
