"""Bundle the prebuilt meshd binary and tag the wheel for its platform.

MESHD_BINARY is the Go build for the target, MESHD_PLATFORM the wheel
platform tag (``manylinux2014_x86_64``, ``macosx_11_0_arm64``, ``win_amd64``,
...). The binary is static, so one build serves every Python version.
"""

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class MeshdBinaryHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return
        binary = os.environ.get("MESHD_BINARY")
        platform = os.environ.get("MESHD_PLATFORM")
        if not binary or not platform:
            raise RuntimeError("set MESHD_BINARY and MESHD_PLATFORM to build an arkitekt-meshd wheel")
        name = "arkitekt-meshd.exe" if platform.startswith("win") else "arkitekt-meshd"
        build_data["force_include"][binary] = f"arkitekt_meshd/bin/{name}"
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{platform}"
