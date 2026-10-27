"""Update this Git checkout, reinstall its .venv package and run synthetic checks.

The Windows wrapper runs Python directly instead of a pip-installed console launcher:
pip does not have to replace an updater .exe that Windows is still running.
Only the standard library is imported, so a broken MCP dependency does not block repair.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]
REMOTE = "refs/remotes/origin/master"
ORIGIN = re.compile(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
                    r"HianSoares/KiroBridgerMCP(?:\.git)?/?", re.IGNORECASE)


class UpdateError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def _command(root: Path, args: list[str], *, capture: bool = True, timeout: int = 300):
    try:
        return subprocess.run(args, cwd=root, check=False, capture_output=capture,
                              text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise UpdateError("Tempo limite atingido. Confira o estado local antes de repetir.") from None
    except OSError:
        raise UpdateError("Nao foi possivel iniciar o comando. Confira Git e a .venv.") from None


def _git(root: Path, *args: str, allowed: tuple[int, ...] = (0,)) -> str:
    result = _command(root, ["git", *args])
    if result.returncode not in allowed:
        # Git may include authenticated remote URLs in errors. Do not echo them.
        raise UpdateError(f"Git falhou na etapa '{args[0]}' (codigo {result.returncode}). "
                          "Confira git status e o acesso ao origin; nenhum reset/stash sera feito.")
    return result.stdout.strip()


def _ancestor(root: Path, before: str, after: str) -> bool:
    result = _command(root, ["git", "merge-base", "--is-ancestor", before, after])
    if result.returncode not in (0, 1):
        raise UpdateError("Nao foi possivel verificar o historico Git.")
    return result.returncode == 0


def _path(root: Path, name: str) -> Path:
    value = Path(_git(root, "rev-parse", "--git-path", name))
    return value if value.is_absolute() else root / value


@contextmanager
def _lock(root: Path):
    path = _path(root, "bridger-update.lock")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise UpdateError("Outra atualizacao esta em andamento ou deixou bridger-update.lock. "
                          "So remova esse lock apos confirmar que o processo terminou.") from None
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        path.unlink(missing_ok=True)


def _clean(root: Path) -> None:
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise UpdateError("Ha alteracoes locais em arquivos rastreados. Revise git status; "
                          "salve seu trabalho antes de atualizar. Nada foi descartado.")


def _python_step(root: Path, python: str, label: str, *args: str) -> None:
    print(label, flush=True)
    result = _command(root, [python, *args], capture=False, timeout=1800)
    if result.returncode:
        raise UpdateError(f"Etapa interrompida: {label} (codigo {result.returncode}).", result.returncode)


def update(root: Path, python: str) -> None:
    """Fast-forward only; never reset, stash, clean, push, edit MCP config or start services."""
    if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root.resolve():
        raise UpdateError("Execute o atualizador de um checkout Git completo do projeto.")
    with _lock(root):
        for state in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "BISECT_LOG"):
            if _path(root, state).exists():
                raise UpdateError("Ha merge/rebase/cherry-pick/revert/bisect em andamento. Resolva-o primeiro.")
        _clean(root)
        branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD", allowed=(0, 1))
        if not branch:
            raise UpdateError("HEAD destacado. Escolha uma branch antes de atualizar.")
        if not ORIGIN.fullmatch(_git(root, "remote", "get-url", "origin")):
            raise UpdateError("origin deve apontar para HianSoares/KiroBridgerMCP no GitHub (HTTPS ou SSH).")
        before = _git(root, "rev-parse", "HEAD")
        print("[1/5] Buscando a master do origin...", flush=True)
        _git(root, "fetch", "--no-tags", "origin", f"refs/heads/master:{REMOTE}")
        target = _git(root, "rev-parse", REMOTE)
        if not _ancestor(root, "HEAD", target):
            raise UpdateError("Sua branch tem commits fora de origin/master. Revise-os manualmente; "
                              "o atualizador nao troca a branch nem descarta commits.")
        master = _command(root, ["git", "show-ref", "--verify", "--quiet", "refs/heads/master"])
        if master.returncode not in (0, 1):
            raise UpdateError("Nao foi possivel verificar a master local.")
        if master.returncode == 0 and not _ancestor(root, "refs/heads/master", target):
            raise UpdateError("A master local tem commits fora de origin/master. Nada sera sobrescrito.")
        # Recheck before changing the worktree; Git also guards untracked/ignored collisions.
        _clean(root)
        print("[2/5] Atualizando a master por fast-forward...", flush=True)
        if branch != "master":
            if master.returncode == 0:
                _git(root, "checkout", "--no-overwrite-ignore", "master")
            else:
                _git(root, "checkout", "--no-overwrite-ignore", "-b", "master", REMOTE)
        _git(root, "-c", "merge.autostash=false", "merge", "--ff-only", "--no-overwrite-ignore", target)
        after = _git(root, "rev-parse", "HEAD")
        print(f"Git: {before[:12]} -> {after[:12]}", flush=True)
        try:
            _python_step(root, python, "[3/5] Instalando na .venv...", "-m", "pip", "install", "--no-input", "-e", ".")
            _python_step(root, python, "[4/5] Rodando testes sinteticos...", "-m", "unittest", "discover", "-s", "tests", "-q")
            print("[5/5] Conferindo registro e matriz...", flush=True)
            _python_step(root, python, "Registro upstream", "scripts/build_upstream_registry.py", "--check")
            _python_step(root, python, "Matriz de cobertura", "scripts/build_coverage_matrix.py", "--check")
        except UpdateError:
            print(f"A master esta em {after[:12]}; instalacao/validacao nao terminou. "
                  "Nao houve rollback automatico.", file=sys.stderr)
            raise
        print("Atualizacao e verificacoes concluidas. Reabra o Kiro ou reconecte o MCP em um chat novo.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], prog="bridger")
    parser.add_argument("--update", action="store_true", help="update master, reinstall and run synthetic checks")
    args = parser.parse_args(argv)
    if not args.update:
        parser.print_help()
        return 2
    if Path(sys.prefix).resolve() != (PROJECT / ".venv").resolve():
        print("Use a .venv deste projeto: .\\bridger --update (Windows) ou "
              "./.venv/bin/python scripts/update_bridge.py --update (Linux/WSL).", file=sys.stderr)
        return 1
    try:
        update(PROJECT, sys.executable)
    except UpdateError as exc:
        print(f"Atualizacao interrompida: {exc}", file=sys.stderr)
        return exc.code if 0 < exc.code < 256 else 1
    except KeyboardInterrupt:
        print("Atualizacao interrompida pelo usuario. Confira git status e a instalacao antes de repetir.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
