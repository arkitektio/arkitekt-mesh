import os
import subprocess
import sys

from arkitekt_meshd import binary_path


def main() -> None:
    binary = str(binary_path())
    if sys.platform == "win32":
        sys.exit(subprocess.call([binary, *sys.argv[1:]]))
    os.execv(binary, [binary, *sys.argv[1:]])


if __name__ == "__main__":
    main()
