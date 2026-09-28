"""The bundled arkitekt-meshd binary.

``fakts`` looks it up with :func:`binary_path` to run the mesh sidecar; the
``arkitekt-meshd`` console script runs it directly.
"""

import sys
from pathlib import Path

__version__ = "0.0.0"


def binary_path() -> Path:
    """The path of the bundled ``arkitekt-meshd`` executable."""
    name = "arkitekt-meshd.exe" if sys.platform == "win32" else "arkitekt-meshd"
    return Path(__file__).parent / "bin" / name
