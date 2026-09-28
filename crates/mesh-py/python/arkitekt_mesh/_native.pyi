from typing import List, Optional

class MeshError(Exception): ...
class NeedsLogin(MeshError):
    """The node is not on the mesh and no auth key was given."""
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

class Node:
    """A mesh node with its state directory; stop it with ``close``."""

    proxy_url: str
    """The local HTTP proxy into the mesh, e.g. ``http://127.0.0.1:41234``."""
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
    ) -> "Node": ...
    @staticmethod
    def has_state(statedir: str) -> bool:
        """Whether a node was already joined in ``statedir``."""
    async def turn(self) -> TurnInfo:
        """Start the TURN relay (once): its relayed traffic goes over the mesh."""
    async def forward(self, host: str, port: int) -> str:
        """A local ``127.0.0.1:P`` forwarding TCP to ``host:port`` on the mesh."""
    def close(self) -> None: ...
