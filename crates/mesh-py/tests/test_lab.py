"""The Python node against the local mesh lab (our ionskale fork and a
tsnet peer); skipped unless ``eval "$(testing/mesh-lab/lab.sh env)"``."""

import asyncio
import os
import time
import urllib.request

import pytest

from arkitekt_mesh import Node

LAB = {k: os.environ.get(k) for k in ("ARKITEKT_TEST_MESH_URL", "ARKITEKT_TEST_MESH_KEY", "ARKITEKT_TEST_MESH_PEER")}
pytestmark = pytest.mark.skipif(not all(LAB.values()), reason="the mesh lab is not up (testing/mesh-lab/lab.sh up)")


def fetch(url: str, proxy: str | None = None) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy} if proxy else {}))
    deadline = time.monotonic() + 30
    while True:
        try:
            with opener.open(url, timeout=10) as response:
                return response.read().decode()
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def test_python_node_over_ionskale(tmp_path):
    peer = LAB["ARKITEKT_TEST_MESH_PEER"]

    async def run():
        node = await Node.start(
            str(tmp_path / "node"), f"t-py-{os.getpid()}",
            control_url=LAB["ARKITEKT_TEST_MESH_URL"], auth_key=LAB["ARKITEKT_TEST_MESH_KEY"],
        )
        try:
            assert await asyncio.to_thread(fetch, f"http://{peer}/", node.proxy_url) == "hello from peer"
            local = await node.forward(peer, 80)
            assert await asyncio.to_thread(fetch, f"http://{local}/") == "hello from peer"
            turn = await node.turn()
            assert turn.urls[0].startswith("turn:127.0.0.1:")
        finally:
            node.close()

    asyncio.run(run())
