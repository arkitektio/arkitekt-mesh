"""The Python node against the Go harness: proxy, TURN relay and forwards."""

import asyncio
import socket
import struct
import urllib.request

import pytest

from arkitekt_mesh import Locked, NeedsLogin, Node


def fetch(url: str, proxy: str | None = None) -> str:
    handlers = [urllib.request.ProxyHandler({"http": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    with opener.open(url, timeout=10) as response:
        return response.read().decode()


def test_needs_a_key_to_join(tmp_path):
    async def start():
        await Node.start(str(tmp_path / "node"), "py", control_url="http://127.0.0.1:1")

    with pytest.raises(NeedsLogin):
        asyncio.run(start())
    assert not Node.has_state(str(tmp_path / "node"))


def test_proxy_forward_and_restart(tmp_path, tailnet):
    statedir = str(tmp_path / "node")

    async def first():
        node = await Node.start(
            statedir, "py-node", control_url=tailnet["control_url"], auth_key=tailnet["auth_key"]
        )
        assert node.proxy_url.startswith("http://127.0.0.1:")
        assert node.addresses
        peer = f"http://{tailnet['peer_name']}/"
        body = await asyncio.to_thread(fetch, peer, node.proxy_url)
        assert body == "hello from peer"

        local = await node.forward(tailnet["peer_name"], 80)
        assert local == await node.forward(tailnet["peer_name"], 80), "one forward per target"
        assert await asyncio.to_thread(fetch, f"http://{local}/") == "hello from peer"

        with pytest.raises(Locked):
            await Node.start(statedir, "py-node", control_url=tailnet["control_url"])
        node.close()

    asyncio.run(first())
    assert Node.has_state(statedir)

    async def again():
        # Joined once: neither key nor control url.
        node = await Node.start(statedir, "py-node")
        node.close()

    asyncio.run(again())


# --- TURN, spoken by hand (RFC 5389/8656) -----------------------------------

MAGIC = 0x2112A442


def attr(kind: int, value: bytes) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return struct.pack("!HH", kind, len(value)) + value + b"\0" * pad


def message(kind: int, attrs: bytes, txid: bytes, key: bytes | None = None) -> bytes:
    import hmac

    if key is not None:
        # MESSAGE-INTEGRITY over the message with its length covering it.
        head = struct.pack("!HHI", kind, len(attrs) + 24, MAGIC) + txid
        mac = hmac.new(key, head + attrs, "sha1").digest()
        attrs += attr(0x0008, mac)
    return struct.pack("!HHI", kind, len(attrs), MAGIC) + txid + attrs


def parse(data: bytes) -> tuple[int, dict]:
    kind, length = struct.unpack("!HH", data[:4])
    attrs, i = {}, 20
    while i < 20 + length:
        t, n = struct.unpack("!HH", data[i : i + 4])
        attrs[t] = data[i + 4 : i + 4 + n]
        i += 4 + n + (4 - n % 4) % 4
    return kind, attrs


def xor_addr(ip: str, port: int) -> bytes:
    xport = port ^ (MAGIC >> 16)
    xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ MAGIC
    return struct.pack("!BBHI", 0, 1, xport, xip)


def test_turn_relays_udp_over_the_mesh(tmp_path, tailnet):
    import hashlib
    import os

    async def run():
        node = await Node.start(
            str(tmp_path / "node"), "py-turn",
            control_url=tailnet["control_url"], auth_key=tailnet["auth_key"],
        )
        turn = await node.turn()
        host, port = turn.urls[0].removeprefix("turn:").split("?")[0].split(":")
        server = (host, int(port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        def call(kind, attrs, key=None):
            txid = os.urandom(12)
            sock.sendto(message(kind, attrs, txid, key), server)
            return parse(sock.recv(2048))

        transport = attr(0x0019, bytes([17, 0, 0, 0]))  # REQUESTED-TRANSPORT: UDP
        kind, attrs = call(0x0003, transport)  # Allocate, unauthenticated
        assert kind == 0x0113, "401 first"
        realm, nonce = attrs[0x0014], attrs[0x0015]
        key = hashlib.md5(f"{turn.username}:{realm.decode()}:{turn.credential}".encode()).digest()
        auth = attr(0x0006, turn.username.encode()) + attr(0x0014, realm) + attr(0x0015, nonce)
        kind, attrs = call(0x0003, transport + auth, key)
        assert kind == 0x0103, f"allocated ({kind:#x})"

        peer_ip = tailnet["peer_ip"]
        kind, _ = call(0x0008, attr(0x0012, xor_addr(peer_ip, 7)) + auth, key)  # CreatePermission
        assert kind == 0x0108

        # A Send indication out, a Data indication back from the UDP echo.
        for _ in range(20):
            txid = os.urandom(12)
            send = attr(0x0012, xor_addr(peer_ip, 7)) + attr(0x0013, b"through the relay")
            sock.sendto(message(0x0016, send, txid), server)
            try:
                kind, attrs = parse(sock.recv(2048))
            except socket.timeout:
                continue
            if kind == 0x0017:
                assert attrs[0x0013] == b"through the relay"
                break
        else:
            pytest.fail("no Data indication from the echo")
        node.close()

    asyncio.run(run())
