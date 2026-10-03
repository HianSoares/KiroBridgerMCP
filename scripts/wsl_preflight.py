"""Preflight for Kiro for Windows -> wsl.exe -> SOC Bridge in WSL 2. Read-only; prints no secrets.

Inside WSL:      ./.venv/bin/python scripts/wsl_preflight.py [--check-qradar-mcp]
From PowerShell: the wsl.exe line printed by configure_kiro_wsl.py (adds --from-windows)
"""

from pathlib import Path
import sys

project = Path(__file__).resolve().parent.parent
try:
    from soc_bridge.wsl_preflight import main
except ImportError:
    print(f"[FALHA] soc_bridge nao importa com {sys.executable} (Python {sys.version.split()[0]})", file=sys.stderr)
    print("        -> Use ./.venv/bin/python (Python 3.11+) e rode ./.venv/bin/python -m pip install -e . "
          "na raiz do projeto", file=sys.stderr)
    raise SystemExit(1)

raise SystemExit(main(project=project))
