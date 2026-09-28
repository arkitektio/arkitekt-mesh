"""Starts the Go harness from crates/mesh/tests/harness: tailscale's test
control server, DERP/STUN and a tsnet peer (HTTP on :80, TCP and UDP echo on
:7). Tests are skipped without Go."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[2] / "mesh" / "tests" / "harness"


@pytest.fixture(scope="session")
def harness_binary(tmp_path_factory) -> Path:
    if shutil.which("go") is None:
        pytest.skip("go is not available")
    out = tmp_path_factory.mktemp("harness") / "mesh-harness"
    subprocess.run(["go", "test", "-c", "-o", str(out), "."], cwd=HARNESS, check=True)
    return out


@pytest.fixture
def tailnet(harness_binary):
    """A fresh tailnet; control takes restarts of joined nodes without a key."""
    env = {**os.environ, "MESH_HARNESS": "1", "MESH_HARNESS_OPEN": "1"}
    proc = subprocess.Popen(
        [str(harness_binary), "-test.run", "TestHarness"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        for line in proc.stdout:
            if line.startswith(b"{"):
                yield json.loads(line)
                break
        else:
            pytest.fail("the harness exited before it was ready")
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
