"""Kiro for Windows -> wsl.exe -> bridge in WSL 2: config merge, launcher, stdio and preflight.

Everything here is synthetic: no WSL, Docker, QRadar or Vision One is contacted.
"""

from __future__ import annotations

import asyncio
import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from soc_bridge import wsl_preflight as pre
from soc_bridge.kiro_server import mcp
from soc_bridge.wsl_launch import prepare_environment
from soc_bridge.wsl_setup import (BRIDGE_ENV, configure_wsl, env_state, launch_args, merge_wslenv,
                                  powershell_command, windows_folder)

ROOT = "/home/analista/meus projetos/KiroBridgerMCP"
SECRET = "synthetic-secret-value-7f3a"
OURS = ":".join(f"{name}/u" for name in BRIDGE_ENV)


def project_dir(base: str, windows_venv: bool = False) -> Path:
    project = Path(base) / "meus projetos" / "KiroBridgerMCP"
    (project / ".venv" / ("Scripts" if windows_venv else "bin")).mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (project / ".venv" / ("Scripts/python.exe" if windows_venv else "bin/python")).touch()
    return project


def child_env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in BRIDGE_ENV}
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra)
    return env


class WslenvAndArgumentsTests(unittest.TestCase):
    def test_merge_keeps_other_entries_normalizes_ours_and_is_idempotent(self):
        merged = merge_wslenv("WT_SESSION:TREND_VISION_ONE_API_KEY/p:HTTPS_PROXY/u")
        self.assertEqual(merged, "WT_SESSION:HTTPS_PROXY/u:" + OURS)
        self.assertEqual(merge_wslenv(merged), merged)
        self.assertEqual(merge_wslenv(None), OURS)
        with self.assertRaises(ValueError):
            merge_wslenv(["not", "a", "string"])  # type: ignore[arg-type]

    def test_launch_args_are_separate_items_and_keep_spaces(self):
        args = launch_args("Ubuntu-24.04", ROOT, ROOT + "/.venv/bin/python")
        self.assertEqual(args, ["--distribution", "Ubuntu-24.04", "--cd", ROOT, "--exec", ROOT + "/.venv/bin/python",
                                "-m", "soc_bridge.wsl_launch"])
        for distro, path in [("Ubuntu 24.04", ROOT), ("", ROOT), ("Ubuntu", "relative/path"),
                             ("Ubuntu", '/home/a"b'), ("Ubuntu", "/home/a\nb")]:
            with self.subTest(distro=distro, path=path), self.assertRaises(ValueError):
                launch_args(distro, path, "/usr/bin/python3")

    def test_powershell_line_and_windows_folder(self):
        line = powershell_command(["--cd", "/home/o'neil/meus projetos"])
        self.assertEqual(line, "wsl.exe '--cd' '/home/o''neil/meus projetos'")
        self.assertEqual(windows_folder("Ubuntu-24.04", ROOT),
                         "\\\\wsl.localhost\\Ubuntu-24.04\\home\\analista\\meus projetos\\KiroBridgerMCP")
        self.assertEqual(windows_folder("Ubuntu-24.04", "/mnt/d/SOC tools/KiroBridgerMCP"),
                         "D:\\SOC tools\\KiroBridgerMCP")


class ConfigureWslTests(unittest.TestCase):
    def test_new_config_uses_wsl_exe_and_stores_no_secret(self):
        with tempfile.TemporaryDirectory() as base, \
                mock.patch.dict(os.environ, {"TREND_VISION_ONE_API_KEY": SECRET, "QRADAR_MCP_TOKEN": SECRET}):
            path = configure_wsl(project_dir(base), "Ubuntu-24.04", ROOT)
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(SECRET, text)
            self.assertTrue(text.endswith("}\n"))
            bridge = json.loads(text)["mcpServers"]["soc-bridge-readonly"]
            self.assertEqual(bridge["command"], "wsl.exe")
            self.assertEqual(bridge["args"], launch_args("Ubuntu-24.04", ROOT, ROOT + "/.venv/bin/python"))
            self.assertEqual(bridge["autoApprove"], ["investigate_demo"])
            self.assertEqual(bridge["env"]["TREND_VISION_ONE_API_KEY"], "${TREND_VISION_ONE_API_KEY}")
            self.assertEqual(bridge["env"]["QRADAR_MCP_TOKEN"], "${QRADAR_MCP_TOKEN}")
            self.assertEqual(bridge["env"]["WSLENV"], OURS)

    def test_preserves_servers_preferences_and_existing_wslenv(self):
        with tempfile.TemporaryDirectory() as base:
            project = project_dir(base)
            path = project / ".kiro" / "settings" / "mcp.json"
            path.parent.mkdir(parents=True)
            original = {"customSetting": True, "mcpServers": {
                "other": {"command": "other-server", "args": ["--flag"], "autoApprove": ["x"]},
                "soc-bridge-readonly": {"command": "C:\\old\\python.exe", "args": ["-m", "old"], "disabled": False,
                                        "autoApprove": ["investigate_demo", "investigate_case"],
                                        "disabledTools": ["qradar_run_aql"],
                                        "env": {"TREND_VISION_ONE_REGION": "eu", "WSLENV": "HTTPS_PROXY/u",
                                                "QRADAR_AQL_UTC_OFFSET_HOURS": "0"}}}}
            path.write_text(json.dumps(original), encoding="utf-8")
            configure_wsl(project, "Debian", ROOT)
            first = path.read_text(encoding="utf-8")
            configure_wsl(project, "Debian", ROOT)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            config = json.loads(first)
            self.assertTrue(config["customSetting"])
            self.assertEqual(config["mcpServers"]["other"], original["mcpServers"]["other"])
            bridge = config["mcpServers"]["soc-bridge-readonly"]
            self.assertEqual(bridge["autoApprove"], ["investigate_demo", "investigate_case"])
            self.assertEqual(bridge["disabledTools"], ["qradar_run_aql"])
            self.assertIs(bridge["disabled"], False)
            self.assertEqual(bridge["env"]["TREND_VISION_ONE_REGION"], "eu")
            self.assertEqual(bridge["env"]["QRADAR_AQL_UTC_OFFSET_HOURS"], "0")
            self.assertEqual(bridge["env"]["WSLENV"], "HTTPS_PROXY/u:" + OURS)
            self.assertEqual(bridge["args"][1], "Debian")

    def test_rejects_windows_venv_missing_python_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as base:
            with self.assertRaisesRegex(ValueError, "Windows Python"):
                configure_wsl(project_dir(base, windows_venv=True), "Ubuntu", ROOT)
        with tempfile.TemporaryDirectory() as base:
            project = Path(base)
            (project / "pyproject.toml").touch()
            with self.assertRaisesRegex(ValueError, "Linux .venv Python is missing"):
                configure_wsl(project, "Ubuntu", ROOT)
        with tempfile.TemporaryDirectory() as base:
            project = project_dir(base)
            path = project / ".kiro" / "settings" / "mcp.json"
            path.parent.mkdir(parents=True)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mcpServers"):
                configure_wsl(project, "Ubuntu", ROOT)
            self.assertEqual(path.read_text(encoding="utf-8"), "[]")


class LauncherTests(unittest.TestCase):
    def test_empty_and_unexpanded_values_are_dropped_and_never_echoed(self):
        environ = {"QRADAR_MCP_URL": "http://127.0.0.1:5001/mcp", "QRADAR_MCP_TOKEN": "",
                   "TREND_VISION_ONE_API_KEY": "${TREND_VISION_ONE_API_KEY}", "TREND_VISION_ONE_REGION": SECRET,
                   "QRADAR_AQL_UTC_OFFSET_HOURS": ""}
        notes = prepare_environment(environ)
        self.assertEqual(set(environ), {"QRADAR_MCP_URL", "TREND_VISION_ONE_REGION"})
        text = " ".join(notes)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("127.0.0.1", text)
        self.assertIn("QRADAR_MCP_TOKEN=empty (ignored)", text)
        self.assertIn("TREND_VISION_ONE_API_KEY=unexpanded reference (ignored)", text)
        self.assertIn("QRADAR_AQL_TIMEZONE_VERIFIED=absent", text)
        self.assertEqual(env_state("  ${X}  "), "unexpanded reference")

    def test_stdout_carries_only_json_rpc_and_stderr_has_no_secret(self):
        tools = asyncio.run(mcp.list_tools())
        expected = len(tools)
        probe = pre.stdio_probe([sys.executable, "-m", "soc_bridge.wsl_launch"],
                                env=child_env(TREND_VISION_ONE_API_KEY=SECRET, TREND_VISION_ONE_REGION="",
                                              QRADAR_MCP_TOKEN="${QRADAR_MCP_TOKEN}"),
                                expected=pre.expected_surface(tools))
        self.assertTrue(probe["ok"], probe["error"])
        self.assertEqual(probe["tools"], expected)
        self.assertTrue(probe["readonly"])
        self.assertIn("TREND_VISION_ONE_API_KEY=set", probe["stderr"])
        self.assertIn("TREND_VISION_ONE_REGION=empty (ignored)", probe["stderr"])
        self.assertNotIn(SECRET, probe["stderr"])

    def test_probe_detects_a_banner_on_stdout(self):
        with tempfile.TemporaryDirectory() as base:
            script = Path(base) / "noisy.py"
            script.write_text("print('Welcome to the shell profile', flush=True)\n"
                              "from soc_bridge.wsl_launch import main\nmain()\n", encoding="utf-8")
            probe = pre.stdio_probe([sys.executable, str(script)], env=child_env())
        self.assertFalse(probe["ok"])
        self.assertIn("stdout contaminated", probe["error"])
        self.assertNotIn("Welcome", probe["error"])


def entry(**env: str) -> dict:
    return {"command": "wsl.exe", "args": launch_args("Ubuntu-24.04", ROOT, ROOT + "/.venv/bin/python"),
            "env": {"WSLENV": OURS, **env}, "autoApprove": ["investigate_demo"]}


class PreflightTests(unittest.TestCase):
    def statuses(self, report: pre.Report) -> list[str]:
        return [status for status, _, _ in report.items]

    def test_platform_distinguishes_wsl2_wsl1_and_plain_linux(self):
        for release, status in [("5.15.167.4-microsoft-standard-WSL2", pre.OK), ("4.4.0-19041-Microsoft", pre.FAIL),
                                ("6.8.0-45-generic", pre.FAIL)]:
            report = pre.Report()
            pre.check_platform(report, release, {"WSL_DISTRO_NAME": "Ubuntu-24.04"}, "PRETTY_NAME=\"Ubuntu\"\n")
            self.assertEqual(report.items[0][0], status, release)

    def test_project_rejects_windows_venv_and_old_python(self):
        with tempfile.TemporaryDirectory() as base:
            project = project_dir(base, windows_venv=True)
            report = pre.Report()
            self.assertFalse(pre.check_project(report, project, str(project / ".venv"), (3, 12)))
            self.assertIn("venv do Windows", report.render())
        with tempfile.TemporaryDirectory() as base:
            project = project_dir(base)
            report = pre.Report()
            self.assertFalse(pre.check_project(report, project, str(project / ".venv"), (3, 10)))
            self.assertIn("3.11+", report.render())
            report = pre.Report()
            self.assertTrue(pre.check_project(report, project, str(project / ".venv"), (3, 12)))

    def test_entry_checks_layout_wslenv_and_literal_secrets_without_values(self):
        project = Path(ROOT)
        report = pre.Report()
        self.assertIsNotNone(pre.check_entry(report, entry(), project, "Ubuntu-24.04"))
        self.assertNotIn(pre.FAIL, self.statuses(report))

        report = pre.Report()
        pre.check_entry(report, entry(TREND_VISION_ONE_API_KEY=SECRET), project, "Ubuntu-24.04")
        self.assertIn(pre.WARN, self.statuses(report))
        self.assertNotIn(SECRET, report.render())

        bad = entry()
        bad["env"]["WSLENV"] = OURS.replace("TREND_VISION_ONE_API_KEY/u", "TREND_VISION_ONE_API_KEY/p")
        report = pre.Report()
        pre.check_entry(report, bad, project, "Ubuntu-24.04")
        self.assertIn("nao repassa: TREND_VISION_ONE_API_KEY", report.render())

        report = pre.Report()
        self.assertIsNone(pre.check_entry(report, entry(), project, "Debian"))
        self.assertIn("--distribution difere", report.render())

        report = pre.Report()
        linux_command = {"command": ROOT + "/.venv/bin/python", "args": ["-m", "soc_bridge.kiro_server"]}
        self.assertIsNone(pre.check_entry(report, linux_command, project, "Ubuntu-24.04"))
        self.assertIn("Kiro do Windows nao executa", report.render())

    def test_docker_engine_classification(self):
        def runner(outputs):
            def run(command, **_):
                code, out, err = outputs[command[1]]
                return subprocess.CompletedProcess(command, code, out, err)
            return run
        cases = [({"info": (0, "Docker Desktop|28.3.2\n", ""), "compose": (0, "2.39.1\n", "")}, [pre.OK, pre.OK]),
                 ({"info": (0, "Ubuntu 24.04.3 LTS|27.5.1\n", ""), "compose": (1, "", "unknown command")},
                  [pre.WARN, pre.WARN]),
                 ({"info": (1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n"),
                   "compose": (0, "2.39.1\n", "")}, [pre.WARN, pre.OK])]
        for outputs, expected in cases:
            report = pre.Report()
            with tempfile.TemporaryDirectory() as home:
                pre.check_docker(report, run=runner(outputs), which=lambda name: "/usr/bin/docker", home=Path(home))
            self.assertEqual(self.statuses(report), expected, outputs)
        report = pre.Report()
        pre.check_docker(report, which=lambda name: None)
        self.assertEqual(self.statuses(report), [pre.WARN])
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".docker").mkdir()
            (Path(home) / ".docker" / "config.json").write_text('{"credsStore": "desktop.exe"}', encoding="utf-8")
            report = pre.Report()
            outputs = {"info": (0, "Docker Desktop|28.3.2\n", ""), "compose": (0, "2.39.1\n", "")}
            pre.check_docker(report, run=runner(outputs), which=lambda name: None if "credential" in name else "/d",
                             home=Path(home))
            self.assertIn("docker-credential-desktop.exe", report.render())

    def test_environment_report_shows_states_only(self):
        report = pre.Report()
        pre.check_environment(report, {pre.PROBE: "ok", "TREND_VISION_ONE_API_KEY": SECRET,
                                       "QRADAR_MCP_TOKEN": "${QRADAR_MCP_TOKEN}"}, from_windows=True)
        text = report.render()
        self.assertNotIn(SECRET, text)
        self.assertIn("WSLENV entregou", text)
        self.assertIn("Mcp Approved Env Vars", text)
        report = pre.Report()
        pre.check_environment(report, {"TREND_VISION_ONE_API_KEY": SECRET}, from_windows=False)
        self.assertIn("nao sao as do Kiro", report.render())
        self.assertNotIn(SECRET, report.render())

    def test_url_must_stay_on_loopback(self):
        self.assertEqual(pre.qradar_url({}, entry(QRADAR_MCP_URL="http://127.0.0.1:5002/mcp")),
                         "http://127.0.0.1:5002/mcp")
        self.assertEqual(pre.qradar_url({"QRADAR_MCP_URL": ""}, None), pre.DEFAULT_URL)
        for url in ["http://0.0.0.0:5001/mcp", "http://172.30.96.1:5001/mcp", "https://127.0.0.1:5001/mcp",
                    "http://127.0.0.1:5001/other", "http://user:pw@127.0.0.1:5001/mcp"]:
            report = pre.Report()
            self.assertFalse(pre.check_port(report, url), url)
            self.assertEqual(self.statuses(report), [pre.FAIL], url)

    def test_open_port_is_not_a_valid_mcp_session(self):
        class Reject(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_GET = do_POST

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Reject)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
            report = pre.Report()
            self.assertTrue(pre.check_port(report, url))
            pre.check_qradar_mcp(report, url, SECRET)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(self.statuses(report), [pre.OK, pre.FAIL])
        self.assertIn("HTTP 401", report.render())
        self.assertNotIn(SECRET, report.render())

    def test_closed_port_is_a_warning(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        report = pre.Report()
        self.assertFalse(pre.check_port(report, f"http://127.0.0.1:{port}/mcp", timeout=1))
        self.assertEqual(self.statuses(report), [pre.WARN])


def closed_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"


FAKE = str(Path(__file__).with_name("fake_stdio_mcp.py"))
FAKE_SURFACE = {"investigate_demo": {"type": "object", "properties": {}}}


def fake_probe(mode: str, timeout: float = 20.0, expected: dict | None = FAKE_SURFACE) -> dict:
    """Run the probe in a daemon thread so a regression shows up as a failure, not a hung suite."""
    box: dict = {}
    thread = threading.Thread(target=lambda: box.update(pre.stdio_probe(
        [sys.executable, FAKE, mode], env=child_env(), timeout=timeout, expected=expected)), daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout + 15)
    box["elapsed"] = time.monotonic() - started
    box["finished"] = not thread.is_alive()
    return box


class ProbeRegressionTests(unittest.TestCase):
    def assert_rejected(self, mode: str, fragment: str, **kwargs) -> dict:
        probe = fake_probe(mode, **kwargs)
        self.assertTrue(probe["finished"], f"{mode}: probe did not return")
        self.assertFalse(probe["ok"], mode)
        self.assertIn(fragment, probe["error"], mode)
        self.assertNotIn(SECRET, json.dumps(probe), mode)
        return probe

    def test_fake_server_baseline_is_accepted(self):
        probe = fake_probe("ok")
        self.assertTrue(probe["ok"], probe.get("error"))
        self.assertEqual(probe["tools"], 1)

    def test_json_rpc_error_in_tools_list_is_a_failure_without_upstream_message(self):
        probe = self.assert_rejected("tools_error", "tools/list returned a JSON-RPC error (code -32603)")
        self.assertIsNone(probe["tools"])

    def test_invalid_formats_are_rejected(self):
        for mode, fragment in [("bad_initialize", "initialize result has an invalid format"),
                               ("tools_not_list", "tools/list result has an invalid format"),
                               ("tool_without_schema", "tools/list result has an invalid format"),
                               ("not_readonly", "1 tool(s) not marked read-only")]:
            with self.subTest(mode=mode):
                self.assert_rejected(mode, fragment)

    def test_surface_must_match_the_bridge_and_foreign_names_are_not_echoed(self):
        probe = self.assert_rejected("other_surface", "missing investigate_demo; 1 unexpected")
        self.assertNotIn("tool_", probe["error"])

    def test_secret_on_stdout_is_detected_but_never_reported(self):
        self.assert_rejected("secret_stdout", "stdout contaminated")

    def test_arbitrary_stderr_is_not_copied(self):
        probe = fake_probe("secret_stderr")
        self.assertTrue(probe["ok"], probe.get("error"))
        self.assertEqual(probe["stderr"], "")
        self.assertEqual(pre.launcher_line(b"SOC Bridge via wsl.exe (Ubuntu-24.04): QRADAR_MCP_TOKEN=set, "
                                           b"TREND_VISION_ONE_REGION=empty (ignored)\r\nnoise\n"),
                         "SOC Bridge via wsl.exe (Ubuntu-24.04): QRADAR_MCP_TOKEN=set, "
                         "TREND_VISION_ONE_REGION=empty (ignored)")

    def test_continuous_notifications_cannot_extend_the_deadline(self):
        probe = self.assert_rejected("notifications", "before the deadline", timeout=1.0)
        self.assertLess(probe["elapsed"], 10)

    def test_continuous_notifications_hit_the_message_cap(self):
        probe = self.assert_rejected("notifications", "too many stdout messages", timeout=60.0)
        self.assertLess(probe["elapsed"], 20)

    def test_oversized_output_is_bounded_and_the_process_is_stopped(self):
        probe = self.assert_rejected("huge_line", "stdout exceeded the size limit")
        self.assertLess(probe["elapsed"], 15)


class ExplicitQRadarCheckTests(unittest.TestCase):
    def test_closed_port_is_a_failure_only_when_the_check_was_requested(self):
        url = closed_port_url()
        report = pre.Report()
        pre.check_qradar(report, {"QRADAR_MCP_URL": url}, None, explicit=False)
        self.assertEqual([s for s, _, _ in report.items], [pre.WARN])
        self.assertFalse(report.failed)
        report = pre.Report()
        pre.check_qradar(report, {"QRADAR_MCP_URL": url}, None, explicit=True)
        self.assertEqual([s for s, _, _ in report.items], [pre.FAIL])
        self.assertIn("handshake MCP pedido nao foi feito", report.render())

    def test_main_exit_code_follows_the_explicit_option(self):
        noop = lambda *args, **kwargs: None
        patches = dict(check_platform=noop, check_project=lambda *a: False, load_entry=lambda *a: None,
                       check_through_wsl_exe=noop, check_docker=noop, check_environment=noop)
        environ = {"QRADAR_MCP_URL": closed_port_url()}
        with mock.patch.multiple(pre, **patches), mock.patch.dict(os.environ, environ), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pre.main([], project=Path(ROOT)), 0)
            self.assertEqual(pre.main(["--check-qradar-mcp"], project=Path(ROOT)), 1)


if __name__ == "__main__":
    unittest.main()
