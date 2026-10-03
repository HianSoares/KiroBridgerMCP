"""Read-only preflight for Kiro for Windows -> wsl.exe -> bridge in WSL 2 -> Docker/QRadar MCP.

Run inside WSL with the project's Linux .venv Python. It never prints credential
values and never queries QRadar or Vision One: the optional --check-qradar-mcp only
opens a local MCP session and lists tools. Output is ASCII so it also reads well
in Windows PowerShell when started through wsl.exe.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable
from urllib.parse import urlparse

from .wsl_setup import BRIDGE_ENV, LAUNCH_MODULE, SECRET_ENV, SERVER, env_state

OK, WARN, FAIL, SKIP, INFO = "OK", "AVISO", "FALHA", "PULADO", "INFO"
PROBE = "SOC_BRIDGE_PROBE"
DEFAULT_URL = "http://127.0.0.1:5001/mcp"
QRADAR_CORE = {"get_offense", "list_offenses", "validate_aql", "create_ariel_search",
               "get_ariel_search_status", "get_ariel_search_results"}


class Report:
    def __init__(self) -> None:
        self.items: list[tuple[str, str, str]] = []

    def add(self, status: str, title: str, fix: str = "") -> None:
        self.items.append((status, title, fix))

    @property
    def failed(self) -> bool:
        return any(status == FAIL for status, _, _ in self.items)

    def render(self) -> str:
        lines = []
        for status, title, fix in self.items:
            lines.append(f"[{status}] {title}")
            if fix:
                lines.append(f"        -> {fix}")
        verdict = "Ha falhas: corrija a primeira FALHA antes de continuar." if self.failed else \
            "Nenhuma FALHA. Leia os AVISOS: alguns so importam para casos reais."
        return "\n".join(lines + ["", verdict])


def wsl_kind(release: str) -> str:
    text = release.lower()
    if "microsoft-standard" in text or "wsl2" in text:
        return "WSL 2"
    if "microsoft" in text:
        return "WSL 1"
    return "not WSL"


def check_platform(report: Report, release: str, environ: dict, os_release: str) -> None:
    kind = wsl_kind(release)
    distro = environ.get("WSL_DISTRO_NAME")
    if kind == "WSL 2":
        report.add(OK, f"WSL 2 (kernel {release}), distribuicao {distro or 'desconhecida'}")
    elif kind == "WSL 1":
        report.add(FAIL, "Distribuicao em WSL 1", "No PowerShell: wsl --set-version <distro> 2 (Docker Desktop exige WSL 2)")
    else:
        report.add(FAIL, "Nao esta dentro do WSL",
                   "Para Kiro executando no proprio Linux use scripts/configure_kiro.py; este preflight e do caminho WSL")
    if kind != "not WSL" and not distro:
        report.add(WARN, "WSL_DISTRO_NAME ausente", "Abra o terminal da distribuicao (ou wsl.exe -d <distro>)")
    pretty = next((line.split("=", 1)[1].strip('"') for line in os_release.splitlines()
                   if line.startswith("PRETTY_NAME=")), "")
    if pretty:
        report.add(INFO, f"Sistema: {pretty}")


def check_project(report: Report, project: Path, prefix: str, version: tuple) -> bool:
    if not (project / "pyproject.toml").is_file():
        report.add(FAIL, f"pyproject.toml nao encontrado em {project}", "Execute a partir do clone do KiroBridgerMCP")
        return False
    report.add(OK, f"Projeto em {project}")
    if " " in str(project):
        report.add(INFO, "O caminho tem espacos: suportado, cada argumento do wsl.exe e separado no mcp.json")
    if str(project).startswith("/mnt/"):
        report.add(WARN, "Projeto no disco do Windows (/mnt/...)",
                   "Funciona, mas e mais lento; prefira ~/projetos no filesystem Linux")
    if (project / ".venv" / "Scripts" / "python.exe").exists():
        report.add(FAIL, "Esta pasta tem uma .venv do Windows",
                   "Nao misture .venv Windows e Linux: use um clone separado em ~/projetos")
        return False
    if version < (3, 11):
        report.add(FAIL, f"Python {version[0]}.{version[1]} na .venv; o projeto exige 3.11+",
                   "Use Ubuntu 24.04 (Python 3.12) ou outra distro com Python 3.11+, e recrie a .venv")
        return False
    if Path(prefix).resolve() != (project / ".venv").resolve():
        report.add(FAIL, "Executado fora da .venv Linux do projeto", "Use ./.venv/bin/python scripts/wsl_preflight.py")
        return False
    report.add(OK, f"Python {version[0]}.{version[1]} da .venv Linux do projeto")
    return True


def check_tools(report: Report) -> int | None:
    try:
        from .kiro_server import mcp
        tools = asyncio.run(mcp.list_tools())
    except ImportError as exc:
        report.add(FAIL, f"Importacao de soc_bridge falhou ({type(exc).__name__})",
                   "Na raiz do projeto: ./.venv/bin/python -m pip install -e .")
        return None
    readonly = all(tool.annotations and tool.annotations.readOnlyHint for tool in tools)
    report.add(OK if readonly else FAIL, f"soc_bridge importado: {len(tools)} tools, todas read-only: {readonly}")
    return len(tools)


def _reader(stream: Any, lines: "queue.Queue[bytes | None]") -> None:
    for line in iter(stream.readline, b""):
        lines.put(line)
    lines.put(None)


def stdio_probe(command: list[str], cwd: str | None = None, env: dict | None = None,
                timeout: float = 60.0) -> dict:
    """Raw MCP handshake: every stdout line must be JSON-RPC, so any banner fails."""
    from mcp.types import LATEST_PROTOCOL_VERSION
    result: dict = {"ok": False, "tools": None, "readonly": None, "error": None, "stderr": ""}
    with tempfile.TemporaryFile() as errlog:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=errlog)
        except OSError as exc:
            result["error"] = f"could not start ({type(exc).__name__})"
            return result
        lines: "queue.Queue[bytes | None]" = queue.Queue()
        reader = threading.Thread(target=_reader, args=(process.stdout, lines), daemon=True)
        reader.start()

        def send(message: dict) -> None:
            process.stdin.write((json.dumps(message) + "\n").encode())
            process.stdin.flush()

        def parse(line: bytes) -> dict:
            try:
                message = json.loads(line)
            except ValueError:
                raise ValueError(line[:60].decode("utf-8", "replace").strip()) from None
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("not JSON-RPC")
            return message

        def receive(request_id: int) -> dict:
            while True:
                line = lines.get(timeout=timeout)
                if line is None:
                    raise EOFError
                message = parse(line)
                if message.get("id") == request_id:
                    return message

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "soc-bridge-preflight", "version": "1"}}})
            if "result" not in receive(1):
                raise RuntimeError("initialize rejected")
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tools = receive(2).get("result", {}).get("tools", [])
            process.stdin.close()
            # Text flushed only at exit (a buffered print) would also corrupt Kiro's stream.
            while (line := lines.get(timeout=timeout)) is not None:
                parse(line)
            result.update(ok=True, tools=len(tools),
                          readonly=all((t.get("annotations") or {}).get("readOnlyHint") for t in tools))
        except queue.Empty:
            result["error"] = "no MCP response before timeout"
        except EOFError:
            result["error"] = "process closed stdout before answering"
        except ValueError as exc:
            result["error"] = f"stdout contaminated by non JSON-RPC text: {exc}"
        except (RuntimeError, OSError) as exc:
            result["error"] = str(exc) or type(exc).__name__
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            process.stdout.close()
            errlog.seek(0)
            # Only the launcher's own line: it names variable states, never values.
            result["stderr"] = next((line for line in errlog.read().decode("utf-8", "replace").splitlines()
                                     if line.startswith("SOC Bridge via wsl.exe")), "")
    return result


def _probe_env(environ: dict) -> dict:
    return {key: value for key, value in environ.items() if key not in SECRET_ENV}


def check_stdio(report: Report, python: str, project: Path, environ: dict) -> None:
    probe = stdio_probe([python, "-m", LAUNCH_MODULE], cwd=str(project), env=_probe_env(environ))
    if probe["ok"]:
        report.add(OK, f"Servidor MCP por stdio: handshake limpo, {probe['tools']} tools")
    else:
        report.add(FAIL, f"Servidor MCP por stdio falhou: {probe['error']}",
                   "Nada pode escrever em stdout alem do protocolo MCP; veja o erro acima")


def load_entry(report: Report, project: Path) -> dict | None:
    path = project / ".kiro" / "settings" / "mcp.json"
    if not path.is_file():
        report.add(FAIL, "Sem .kiro/settings/mcp.json", "Execute ./.venv/bin/python scripts/configure_kiro_wsl.py")
        return None
    try:
        entry = json.loads(path.read_text(encoding="utf-8-sig"))["mcpServers"][SERVER]
        if not isinstance(entry, dict):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        report.add(FAIL, f"mcp.json sem entrada {SERVER} valida", "Execute scripts/configure_kiro_wsl.py")
        return None
    return entry


def check_entry(report: Report, entry: dict, project: Path, distro: str | None) -> list[str] | None:
    command, args = entry.get("command"), entry.get("args")
    if isinstance(command, str) and command.replace("\\", "/").endswith("/bin/python"):
        report.add(WARN, "mcp.json aponta para um Python Linux diretamente",
                   "Kiro do Windows nao executa esse caminho; rode scripts/configure_kiro_wsl.py "
                   "(mantenha assim apenas se o Kiro roda no proprio Linux)")
        return None
    if not isinstance(command, str) or command.lower().replace("\\", "/").rsplit("/", 1)[-1] != "wsl.exe" \
            or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        report.add(FAIL, "mcp.json: command/args nao iniciam o wsl.exe", "Execute scripts/configure_kiro_wsl.py")
        return None
    expected = {"--distribution": distro, "--cd": project.as_posix(),
                "--exec": (project / ".venv" / "bin" / "python").as_posix()}
    problems = []
    for flag, value in expected.items():
        actual = args[args.index(flag) + 1] if flag in args and args.index(flag) + 1 < len(args) else None
        if value and actual != value:
            problems.append(f"{flag} difere deste ambiente")
    if args[-2:] != ["-m", LAUNCH_MODULE]:
        problems.append(f"modulo final deveria ser -m {LAUNCH_MODULE}")
    if problems:
        report.add(FAIL, "mcp.json: " + "; ".join(problems),
                   "Rode scripts/configure_kiro_wsl.py nesta distribuicao e neste clone")
        return None
    report.add(OK, "mcp.json: wsl.exe com distribuicao, pasta e Python absolutos deste clone")
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    listed = {item.split("/", 1)[0]: item.partition("/")[2] for item in str(env.get("WSLENV", "")).split(":") if item}
    # Only /u (or no flag) passes the raw value from Windows to Linux; /p, /l and /w alter or block it.
    missing = [name for name in BRIDGE_ENV if name not in listed or set(listed[name]) - {"u"}]
    if missing:
        report.add(FAIL, "WSLENV do mcp.json nao repassa: " + ", ".join(missing), "Rode scripts/configure_kiro_wsl.py")
    else:
        report.add(OK, "WSLENV do mcp.json repassa as variaveis da ponte (Windows -> Linux, /u)")
    for name in SECRET_ENV:
        if env_state(env.get(name)) == "set":
            report.add(WARN, f"{name} tem valor literal no mcp.json",
                       f"Troque por ${{{name}}} e guarde o segredo fora de arquivos")
    approved = entry.get("autoApprove")
    if isinstance(approved, list) and set(approved) - {"investigate_demo"}:
        report.add(INFO, "autoApprove inclui mais que investigate_demo (escolha existente preservada)")
    return args


def check_through_wsl_exe(report: Report, args: list[str] | None, environ: dict) -> None:
    executable = shutil.which("wsl.exe")
    if args is None:
        report.add(SKIP, "Handshake via wsl.exe: mcp.json ainda nao esta pronto")
        return
    if not executable:
        report.add(SKIP, "Handshake via wsl.exe: interop do Windows indisponivel neste terminal",
                   "Faca o teste equivalente no PowerShell, como descrito no guia")
        return
    probe = stdio_probe([executable, *args], env=_probe_env(environ), timeout=90)
    if probe["ok"]:
        report.add(OK, f"Mesmo comando do mcp.json via wsl.exe: handshake limpo, {probe['tools']} tools")
    else:
        report.add(FAIL, f"Comando do mcp.json via wsl.exe falhou: {probe['error']}",
                   "Confira distribuicao, caminhos e se algo imprime em stdout")


def _run(command: list[str], timeout: float = 25) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def check_docker(report: Report, run: Callable[..., Any] = _run, which: Callable[[str], str | None] = shutil.which,
                 home: Path | None = None) -> None:
    if not which("docker"):
        report.add(WARN, "docker nao encontrado neste WSL (o demo nao precisa)",
                   "Docker Desktop > Settings > Resources > WSL Integration: habilite esta distribuicao e reabra o terminal")
        return
    try:
        info = run(["docker", "info", "--format", "{{.OperatingSystem}}|{{.ServerVersion}}"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add(WARN, f"docker info nao respondeu ({type(exc).__name__})", "Abra o Docker Desktop e aguarde o motor")
        return
    if info.returncode != 0:
        text = (info.stderr or "").strip().splitlines()
        first = text[0][:160] if text else "sem detalhe"
        hint = "Adicione seu usuario ao grupo docker ou use o Docker Desktop" if "permission denied" in first.lower() \
            else "Inicie o Docker Desktop e confira a WSL Integration desta distribuicao"
        report.add(WARN, f"Docker sem daemon acessivel: {first}", hint)
    else:
        system, _, version = info.stdout.strip().partition("|")
        if system == "Docker Desktop":
            report.add(OK, f"Daemon: Docker Desktop {version} (o mesmo do Windows)")
        else:
            report.add(WARN, f"Daemon: motor Docker proprio desta distro ({system} {version})",
                       "Se voce escolheu Docker Desktop, isso e um segundo daemon: conteineres e portas nao sao os "
                       "mesmos do Windows. A Docker recomenda remover o Engine instalado dentro da distro")
    try:
        compose = run(["docker", "compose", "version", "--short"])
        if compose.returncode == 0:
            report.add(OK, f"docker compose {compose.stdout.strip()}")
        else:
            report.add(WARN, "docker compose indisponivel neste WSL",
                       "Com Docker Desktop ele vem pela WSL Integration; so e preciso para subir o QRadar MCP")
    except (OSError, subprocess.TimeoutExpired):
        report.add(WARN, "docker compose nao respondeu")
    config = (home or Path.home()) / ".docker" / "config.json"
    try:
        store = json.loads(config.read_text(encoding="utf-8")).get("credsStore")
    except (OSError, ValueError, AttributeError):
        store = None
    if isinstance(store, str) and store and not which(f"docker-credential-{store}"):
        report.add(WARN, f"credsStore '{store}' configurado, mas docker-credential-{store} nao esta no PATH",
                   "docker pull pode falhar; reative a WSL Integration ou a inclusao do PATH do Windows no WSL")


def check_environment(report: Report, environ: dict, from_windows: bool) -> None:
    states = {name: env_state(environ.get(name)) for name in BRIDGE_ENV}
    summary = ", ".join(f"{name}={state}" for name, state in states.items())
    if not from_windows:
        report.add(INFO, "Variaveis neste terminal (nao sao as do Kiro): " + summary)
        return
    probe = env_state(environ.get(PROBE))
    if probe == "set":
        report.add(OK, f"WSLENV entregou {PROBE} do PowerShell ao Linux")
    elif probe == "absent":
        report.add(INFO, f"{PROBE} nao recebido: teste de WSLENV nao foi preparado neste PowerShell")
    else:
        report.add(WARN, f"{PROBE} chegou {probe}", "Defina-o com um valor no PowerShell antes de chamar wsl.exe")
    report.add(INFO, "Variaveis recebidas do Windows: " + summary)
    for name in SECRET_ENV:
        if states[name] == "unexpanded reference":
            report.add(WARN, f"{name} chegou como referencia ${{...}} sem expansao",
                       "No Kiro, aprove a variavel em 'Mcp Approved Env Vars'")


def qradar_url(environ: dict, entry: dict | None) -> str:
    value = environ.get("QRADAR_MCP_URL")
    if env_state(value) == "set":
        return value
    env = entry.get("env") if entry and isinstance(entry.get("env"), dict) else {}
    configured = env.get("QRADAR_MCP_URL")
    return configured if env_state(configured) == "set" else DEFAULT_URL


def local_endpoint(url: str) -> tuple[str, int] | None:
    parsed = urlparse(url)
    try:
        port = parsed.port or 80
    except ValueError:
        return None
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.path != "/mcp" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        return None
    return parsed.hostname, port


def check_port(report: Report, url: str, timeout: float = 3.0) -> bool:
    endpoint = local_endpoint(url)
    if endpoint is None:
        report.add(FAIL, "QRADAR_MCP_URL nao e um endpoint http de loopback terminado em /mcp",
                   "A ponte so aceita http://127.0.0.1:<porta>/mcp; nao publique o MCP em 0.0.0.0")
        return False
    host, port = endpoint
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        report.add(WARN, f"Porta {host}:{port} inacessivel a partir deste WSL ({type(exc).__name__}); "
                         "o demo nao precisa dela",
                   "Veja no guia: QRadar MCP parado, porta publicada so no Windows ou rede NAT do WSL")
        return False
    report.add(OK, f"Porta {host}:{port} aberta a partir deste WSL (isso nao prova autenticacao MCP)")
    return True


async def _qradar_session(url: str, token: str | None) -> list[str]:
    from contextlib import AsyncExitStack
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    async with AsyncExitStack() as stack:
        http = await stack.enter_async_context(httpx.AsyncClient(headers={"SEC": token} if token else {},
                                                                 timeout=30.0, trust_env=False))
        streams = await stack.enter_async_context(streamable_http_client(url, http_client=http))
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        await session.initialize()
        return [tool.name for tool in (await session.list_tools()).tools]


def check_qradar_mcp(report: Report, url: str, token: str | None) -> None:
    from .diagnostics import failure_reason
    try:
        names = asyncio.run(asyncio.wait_for(_qradar_session(url, token), 45))
    except Exception as exc:  # report a category only; never the response body
        report.add(FAIL, f"Sessao MCP do QRadar falhou: {failure_reason(exc)}",
                   "Porta aberta nao basta: confira token/config.json do QRadar MCP e os logs do conteiner")
        return
    missing = sorted(QRADAR_CORE - set(names))
    if missing:
        report.add(WARN, f"Sessao MCP do QRadar aberta ({len(names)} tools), faltam: {', '.join(missing)}")
    else:
        report.add(OK, f"Sessao MCP do QRadar autenticada: initialize e tools/list ok ({len(names)} tools)")


def main(argv: list[str] | None = None, project: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight do caminho Kiro (Windows) -> wsl.exe -> ponte no WSL 2")
    parser.add_argument("--from-windows", action="store_true", help="executado pelo PowerShell via wsl.exe")
    parser.add_argument("--check-qradar-mcp", action="store_true",
                        help="abre sessao MCP local e lista tools (sem AQL, sem leitura de offense)")
    options = parser.parse_args(argv)
    project = project or Path.cwd()
    environ = dict(os.environ)
    report = Report()
    release = os.uname().release if hasattr(os, "uname") else ""
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        os_release = ""
    check_platform(report, release, environ, os_release)
    python = str(project / ".venv" / "bin" / "python")
    if check_project(report, project, sys.prefix, sys.version_info[:2]) and check_tools(report) is not None:
        check_stdio(report, python, project, environ)
    entry = load_entry(report, project)
    args = check_entry(report, entry, project, environ.get("WSL_DISTRO_NAME")) if entry else None
    check_through_wsl_exe(report, args, environ)
    check_docker(report)
    check_environment(report, environ, options.from_windows)
    url = qradar_url(environ, entry)
    if check_port(report, url) and options.check_qradar_mcp:
        token = environ.get("QRADAR_MCP_TOKEN")
        check_qradar_mcp(report, url, token if env_state(token) == "set" else None)
    print(report.render())
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
