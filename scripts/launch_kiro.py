"""Start the installed project MCP server from its project-local virtualenv."""

from pathlib import Path
import os
import subprocess
import sys


root = Path(__file__).resolve().parent.parent
if os.name == "nt":
    interpreter = root / ".venv" / "Scripts" / "python.exe"
else:
    interpreter = root / ".venv" / "bin" / "python"

if not interpreter.is_file():
    print("SOC Bridge: create .venv and run pip install -e . first", file=sys.stderr)
    raise SystemExit(1)

raise SystemExit(subprocess.run([str(interpreter), "-m", "soc_bridge.kiro_server"],
                                cwd=root, env=os.environ, check=False).returncode)
