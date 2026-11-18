from typing import List, Literal, Optional

class MeshError(Exception): ...
class NeedsLogin(MeshError):
    """The node is not on the mesh and no auth key was given."""
class KeyExpired(NeedsLogin):
    """The node's key expired; a new one is ready, and the next start with
    an auth key registers it."""
class Locked(MeshError):
    """Another node is already running in the state directory."""
class Refused(MeshError):
    """The coordination server refused the node (e.g. a bad auth key)."""
class Timeout(MeshError):
    """The mesh did not connect in time."""
class LockedOut(MeshError):
    """The tailnet is locked and this node's key is not signed (the message
    names the ``nodekey:`` to sign with ``tailscale lock sign``)."""

class TurnInfo:
    """One ICE server entry for a WebRTC client."""
    urls: List[str]
    username: str
    credential: str

class PeerPath:
    """How packets to a peer travel right now (see ``Node.path``)."""
    kind: Literal["direct", "relay", "idle"]
    """``idle``: nothing was sent to the peer lately (the next packet probes
    again)."""
    via: Optional[str]
    """The peer's UDP address when direct; when relayed the DERP region code
    (e.g. ``waw``), or ``peer relay <address>`` for a node of the tailnet that
    forwards UDP for the two; else ``None``."""

class ControlStatus:
    """How the node stands with the coordination server (see ``Node.control``)."""
    state: Literal["connected", "reconnecting", "key_expired", "needs_login", "refused"]
    """``reconnecting``: it tries again by itself, and runs on with the peers
    it knows. The last three take a new login (the node still retries, but
    its view of the mesh goes stale meanwhile)."""
    reason: Optional[str]
    """Why, unless connected."""

class Node:
    """A mesh node with its state directory; stop it with ``close``."""

    proxy_url: str
    """The local HTTP proxy into the mesh, e.g. ``http://127.0.0.1:41234``;
    with ``proxy_auth``, ``http://mesh:<token>@127.0.0.1:41234`` (a secret:
    keep it out of logs)."""
    addresses: List[str]
    """This node's addresses on the mesh."""
    statedir: str

    @staticmethod
    async def start(
        statedir: str,
        hostname: str,
        control_url: Optional[str] = None,
        auth_key: Optional[str] = None,
        timeout: float = 90,
        ephemeral: bool = False,
        listen: str = "127.0.0.1:0",
        *,
        tcp_buffer: Optional[int] = None,
        proxy_auth: bool = False,
    ) -> "Node":
        """Start (or join) the node. ``tcp_buffer`` is the bytes of buffer per
        connection, each way: what a connection can have in flight, so its
        throughput is at most this per round trip (default: 1 MiB).
        ``proxy_auth`` has the proxy ask every request for credentials that
        ``proxy_url`` then carries: without them any user of this machine
        reaches the mesh as this node."""
    @staticmethod
    def has_state(statedir: str) -> bool:
        """Whether a node was already joined in ``statedir``."""
    async def turn(self) -> TurnInfo:
        """Start the TURN relay (once): its relayed traffic goes over the mesh."""
    async def forward(self, host: str, port: int) -> str:
        """A local ``127.0.0.1:P`` forwarding TCP to ``host:port`` on the mesh."""
    def path(self, host: str) -> PeerPath:
        """How packets to the peer ``host`` (a mesh name or address) travel
        right now. A path starts out relayed and turns direct once one is
        found, usually seconds after the first packet."""
    def control(self) -> ControlStatus:
        """How the node stands with the coordination server right now."""
    async def control_changed(self) -> ControlStatus:
        """Wait for the next change of ``control()``."""
    def rebind(self) -> None:
        """The network changed (another Wi-Fi, back from sleep): reconnect and
        find paths again now. Open connections carry on."""
    def close(self) -> None: ...
