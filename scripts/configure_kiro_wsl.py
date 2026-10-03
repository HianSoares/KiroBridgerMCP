"""Configure Kiro for Windows to start this bridge inside WSL 2, without storing credentials.

Run inside the WSL distribution with this project's Linux .venv Python, after
``pip install -e .``. For Kiro running on Linux, use configure_kiro.py instead.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

try:
    from soc_bridge.wsl_setup import configure_wsl, launch_args, linux_python, powershell_command, windows_folder
except ImportError:
    print("Kiro WSL configuration failed: soc_bridge is not installed in this Python; "
          "run ./.venv/bin/python -m pip install -e . first", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--distribution", default=os.environ.get("WSL_DISTRO_NAME", ""),
                        help="WSL distribution name as shown by wsl.exe --list --verbose (default: current)")
    options = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    try:
        if os.name == "nt":
            raise ValueError("Run this script inside WSL, not with Windows Python")
        if not options.distribution:
            raise ValueError("WSL_DISTRO_NAME is not set; run inside WSL or pass --distribution")
        if os.geteuid() == 0:
            raise ValueError("Do not run as root/sudo: Kiro reads the file as your WSL user")
        if Path(sys.prefix).resolve() != (project / ".venv").resolve():
            raise ValueError("Run with the project's .venv/bin/python, not system Python")
        path = configure_wsl(project, options.distribution)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Kiro WSL configuration failed: {exc}", file=sys.stderr)
        return 1
    args = launch_args(options.distribution, project.as_posix(), linux_python(project.as_posix()))
    check = [*args[:-2], "scripts/wsl_preflight.py", "--from-windows"]
    print(f"Configurado {path} (soc-bridge-readonly via wsl.exe, distribuicao {options.distribution}).")
    print(f"Pasta para abrir no Kiro do Windows: {windows_folder(options.distribution, project.as_posix())}")
    print("Teste no PowerShell do Windows (mesmo caminho que o Kiro usa):")
    print(f"  {powershell_command(check)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
