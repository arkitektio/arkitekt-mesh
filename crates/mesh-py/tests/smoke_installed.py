"""Smoke test for an installed wheel (not collected by pytest): the native
module loads and a node starts, then stops with NeedsLogin as there is no
control server. .github/workflows/release.yaml runs it on every shipped wheel;
SMOKE_MACHINE, if set, is the architecture the interpreter must have (so a
row cannot pass on another platform's wheel)."""

import asyncio
import os
import platform
import sys
import sysconfig
import tempfile
from pathlib import Path

import arkitekt_mesh
from arkitekt_mesh import NeedsLogin, Node


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        statedir = str(Path(tmp) / "node")
        try:
            await Node.start(statedir, "smoke", control_url="http://127.0.0.1:1")
        except NeedsLogin:
            pass
        else:
            sys.exit("the node started without a key")


machine = platform.machine().lower()
print(f"arkitekt_mesh from {Path(arkitekt_mesh.__file__).parent}")
print(f"Python {sys.version.split()[0]} on {sysconfig.get_platform()} ({machine})")
expected = os.environ.get("SMOKE_MACHINE")
if expected and machine != expected:
    sys.exit(f"expected a {expected} interpreter, got {machine}")
asyncio.run(main())
print("ok")
