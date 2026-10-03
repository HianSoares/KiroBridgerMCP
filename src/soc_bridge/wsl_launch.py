"""MCP entry point when Kiro for Windows starts the bridge through wsl.exe.

stdout carries only MCP JSON-RPC. The single diagnostic line goes to stderr
(Kiro shows it in its MCP logs) and names variable states, never values.
"""

from __future__ import annotations

import os
import sys
from typing import MutableMapping

from .wsl_setup import BRIDGE_ENV, env_state


def prepare_environment(environ: MutableMapping[str, str]) -> list[str]:
    """Drop empty values (WSLENV turns undefined Windows variables into "") and
    literal ${VAR} references so the bridge applies its own defaults."""
    notes = []
    for name in BRIDGE_ENV:
        state = env_state(environ.get(name))
        if state in ("empty", "unexpanded reference"):
            del environ[name]
            state += " (ignored)"
        notes.append(f"{name}={state}")
    return notes


def main() -> None:
    notes = prepare_environment(os.environ)
    distro = os.environ.get("WSL_DISTRO_NAME") or "unknown distribution"
    print(f"SOC Bridge via wsl.exe ({distro}): " + ", ".join(notes), file=sys.stderr, flush=True)
    from .kiro_server import main as serve
    serve()


if __name__ == "__main__":
    main()
