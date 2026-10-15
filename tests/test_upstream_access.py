"""Registry-bound access to every audited upstream tool: policy, gate, normalization, live path, change control.

All data is synthetic. The upstream servers are tests/fake_upstream_mcp.py, which announces the audited
contracts (docs/coverage/*-tools-list.json) and reproduces only a few behaviors in each product's real
response format; any other call fails. No QRadar or Vision One is contacted.
"""

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from mcp import types

from soc_bridge import change_control, upstream_access as access, upstream_live as live
from soc_bridge.upstream_policy import EFFECTS, QUERY_EFFECTS, callable_for_change, callable_for_query

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_upstream_mcp.py"
sys.path.insert(0, str(FAKE.parent))
import fake_upstream_mcp  # noqa: E402
SETTINGS = {"url": "http://127.0.0.1:5001/mcp", "token": "synthetic-token", "api_key": "synthetic-key",
            "region": "us"}


def snapshot(name):
    return json.loads((ROOT / "docs" / "coverage" / name).read_text(encoding="utf-8"))


def run(coro):
    return asyncio.run(coro)


class FakeUpstream:
    """Replaces the transport only. "memory" runs the fake server in-process over the SDK memory streams
    (same JSON-RPC session, fast and deterministic for timeouts); "stdio" spawns it as a subprocess."""

    def __init__(self, transport="memory", **env):
        self.transport = transport
        self.opened = []
        handle, name = tempfile.mkstemp(prefix="fake-upstream-", suffix=".jsonl")
        os.close(handle)
        self.log = Path(name)
        self.env = {"FAKE_UPSTREAM_LOG": str(self.log), "FAKE_UPSTREAM_HIDE": "", "FAKE_UPSTREAM_DRIFT": "",
                    "FAKE_UPSTREAM_EXTRA": "", **env}

    async def open(self, stack, platform, toolset="", readonly=True, settings=None):
        self.opened.append({"platform": platform, "toolset": toolset, "readonly": readonly})
        if self.transport == "memory":
            return await stack.enter(fake_upstream_mcp.connect(platform), platform, "fake memory session")
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        params = StdioServerParameters(command=sys.executable, args=[str(FAKE), platform],
                                       env={**os.environ, **self.env})
        stream = await stack.enter(stdio_client(params), platform, "fake stdio")
        return await stack.enter(ClientSession(stream[0], stream[1]), platform, "fake session")

    async def open_all(self, stack, settings=None):
        return await self.open(stack, "vision_one", "all", True, settings)

    def calls(self):
        text = self.log.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    @contextlib.contextmanager
    def patch(self):
        with mock.patch.dict(os.environ, self.env),                 mock.patch.multiple(live, open_session=self.open, _open_all_toolsets=self.open_all):
            yield


def query(fake, platform, tool, arguments=None, **kw):
    with fake.patch():
        return run(live.live_upstream_query(platform, tool, arguments, settings=SETTINGS, **kw))


class RegistryTests(unittest.TestCase):
    def test_registry_covers_every_announced_tool_of_both_audited_servers(self):
        reg = access.registry()
        for platform, name in (("qradar", "qradar-tools-list.json"), ("vision_one", "vision-one-tools-list.json")):
            listed = snapshot(name)
            names = {t["name"] for t in listed["tools"]}
            audited = {t["name"] for t in reg["tools"] if t["platform"] == platform}
            self.assertEqual(audited, names)
            self.assertEqual(listed["source"]["commit"], reg["sources"][platform]["commit"])
        totals = access.counts()
        self.assertEqual((totals["qradar"]["total"], totals["vision_one"]["total"]), (83, 349))
        self.assertEqual((totals["qradar"]["query"], totals["qradar"]["change"]), (53, 30))
        self.assertEqual((totals["vision_one"]["query"], totals["vision_one"]["change"],
                          totals["vision_one"]["unsupported"]), (202, 137, 10))
        self.assertEqual(totals["qradar"]["pending_review"] + totals["vision_one"]["pending_review"], 0)

    def test_every_tool_has_a_route_or_a_precise_reason(self):
        for t in access.registry()["tools"]:
            with self.subTest(tool=t["name"]):
                routed = callable_for_query(t) or callable_for_change(t)
                self.assertTrue(routed or (t["support"] == "unsupported" and t["unsupported_reason"]))
                self.assertIn(t["effect"], EFFECTS)
                self.assertTrue(t["basis"])

    def test_query_access_never_includes_a_state_change(self):
        for t in access.registry()["tools"]:
            if t["access"] != "query":
                continue
            with self.subTest(tool=t["name"]):
                self.assertIn(t["effect"], QUERY_EFFECTS)
                if t["platform"] == "vision_one":
                    self.assertEqual((t["http"]["methods"], t["upstream_registration"]["registered_as"]),
                                     (["GET"], "read"))
                    self.assertTrue(t["server_flags"]["readonly"])
                elif t["name"] not in ("validate_aql", "create_ariel_search"):
                    self.assertEqual(t["http"]["methods"], ["GET"])

    def test_read_registered_generators_and_annotations_do_not_decide_alone(self):
        e = access.entry
        self.assertEqual(e("vision_one", "container_security_generate_service_gateway_password")["effect"],
                         "credential_generation")
        self.assertEqual(e("vision_one", "aisecurity_guardrails_apply")["access"], "change")
        # Annotated destructive by the upstream, but the handler is a plain GET.
        self.assertEqual(e("vision_one", "endpoint_security_endpoints_list")["effect"], "read")
        self.assertEqual(e("qradar", "create_ariel_search")["effect"], "query_job")
        self.assertEqual(e("qradar", "dns_lookup")["access"], "change")
        self.assertEqual(e("vision_one", "sandbox_files_analyze")["support"], "unsupported")

    def test_generated_registry_and_matrix_are_current(self):
        for script in ("scripts/build_upstream_registry.py", "scripts/build_coverage_matrix.py"):
            with self.subTest(script=script):
                done = subprocess.run([sys.executable, str(ROOT / script), "--check"], capture_output=True,
                                      text=True, encoding="utf-8")
                self.assertEqual(done.returncode, 0, done.stderr)

    def test_contract_tested_list_matches_the_fake_upstream_behaviors(self):
        import re
        from soc_bridge.coverage import CONTRACT_TESTED
        source = FAKE.read_text(encoding="utf-8")
        behaviors = set()
        for platform, function in (("qradar", "async def qradar"), ("vision_one", "async def vision_one")):
            body = source.split(function, 1)[1].split("\nasync def ", 1)[0].split("\ndef ", 1)[0]
            behaviors |= {(platform, n) for n in re.findall(r'if name == "([a-z0-9_]+)"', body)}
        behaviors.add(("qradar", "list_rules"))  # exercised by hiding it from tools/list
        self.assertEqual(set(CONTRACT_TESTED), behaviors)
        test_source = Path(__file__).read_text(encoding="utf-8")
        for platform, tool in CONTRACT_TESTED:
            self.assertIn(f'"{tool}"', test_source)

    def test_qradar_validation_schema_is_the_handler_schema_with_the_announced_structure(self):
        for t in access.registry()["tools"]:
            if t["platform"] == "qradar":
                self.assertEqual(set(t["input_schema"]["properties"]), set(t["announced_schema"]["properties"]))
                self.assertFalse(t["input_schema"]["additionalProperties"])

    def test_registry_reads_as_utf8_without_utf8_mode(self):
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
        code = ("from soc_bridge.upstream_access import registry, search; r = registry(); "
                "print(len(r['tools']), search(query='endpoint', limit=1)['total_matches'] > 0)")
        done = subprocess.run([sys.executable, "-X", "utf8=0", "-c", code], capture_output=True, text=True,
                              encoding="utf-8", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split(), ["432", "True"])


class GateTests(unittest.TestCase):
    def test_every_change_tool_is_refused_before_any_upstream_contact(self):
        for t in access.registry()["tools"]:
            if t["access"] == "query":
                continue
            with self.subTest(tool=t["name"]):
                with self.assertRaises(access.Refused) as caught:
                    access.gate_query(t["platform"], t["name"], {})
                self.assertIn(caught.exception.category, ("policy_blocked", "unsupported"))

    def test_names_are_exact_and_never_normalized(self):
        for tool in ("Set_Offense_Status", "set_offense_status ", "qradar/set_offense_status", "list_offenses;",
                     "list_offensеs", "", "../list_offenses"):
            with self.subTest(tool=tool), self.assertRaises(access.Refused) as caught:
                access.gate_query("qradar", tool, {})
            self.assertIn(caught.exception.category, ("invalid_arguments", "unknown_tool"))
        with self.assertRaises(access.Refused):
            access.gate_query("splunk", "list_offenses", {})

    def test_arguments_follow_the_audited_schema(self):
        cases = [("qradar", "list_offenses", {"status": "OPEN"}), ("qradar", "list_offenses", {"limit": 0}),
                 ("qradar", "list_offenses", {"limit": "5"}), ("qradar", "get_offense", {}),
                 ("vision_one", "search_endpoint_activities_list", {"query": "x", "mode": "everything"}),
                 ("qradar", "list_offenses", ["not", "an", "object"])]
        for platform, tool, args in cases:
            with self.subTest(args=args), self.assertRaises(access.Refused) as caught:
                access.gate_query(platform, tool, args)
            self.assertEqual(caught.exception.category, "invalid_arguments")
        with self.assertRaises(access.Refused) as caught:  # declared upstream, dropped by the handler
            access.gate_query("vision_one", "workbench_alert_notes_list", {"alertId": "WB-1", "skipToken": "abc"})
        self.assertIn("does not send it", str(caught.exception))
        _, args = access.gate_query("vision_one", "search_endpoint_activities_list",
                                    {"query": "endpointHostName:ws-001", "mode": "countOnly", "top": "50"})
        self.assertEqual(args["mode"], "countOnly")

    def test_readonly_server_never_exposes_or_imports_change_control(self):
        from soc_bridge.capabilities import public_tools
        tools = run(public_tools())
        self.assertFalse({n for n in tools if n.startswith("change_")})
        source = (ROOT / "src" / "soc_bridge" / "kiro_server.py").read_text(encoding="utf-8")
        self.assertNotIn("change_control", source)
        self.assertNotIn("change_server", source)
        self.assertTrue(tools["upstream_query"]["read_only"])


def result(*content, error=False, structured=None):
    return types.CallToolResult(content=list(content), isError=error, structuredContent=structured)


def txt(value):
    return types.TextContent(type="text", text=value if isinstance(value, str) else json.dumps(value))


class NormalizeTests(unittest.TestCase):
    def test_errors_are_classified_without_copying_bodies(self):
        cases = {
            "failed to list audit logs (HTTP 403): {\"message\":\"not entitled\",\"apiKey\":\"synthetic-secret\"}":
                "permission_or_license",
            "Error executing list_users: Client error '403 Forbidden' for url 'https://x' token=synthetic-secret":
                "permission",
            "Error executing get_offense: Client error '404 Not Found' synthetic-secret": "not_found",
            "x (HTTP 401): synthetic-secret": "authentication", "x (HTTP 429): slow down": "rate_limited",
            "x (HTTP 503): down synthetic-secret": "upstream_unavailable",
            "missing required parameter: alertId": "invalid_arguments", "something odd synthetic-secret": "upstream_error"}
        t = access.entry("vision_one", "audit_logs_list")
        for message, category in cases.items():
            with self.subTest(category=category):
                out = access.normalize(t, {}, result(txt(message), error=True))
                self.assertEqual(out["error"]["category"], category)
                self.assertNotIn("synthetic-secret", json.dumps(out))

    def test_trend_headers_block_binary_and_untrusted_marking(self):
        t = access.entry("vision_one", "sandbox_analysis_result_report_get")
        raw = b"%PDF synthetic"
        out = access.normalize(t, {"id": "r1"}, result(types.EmbeddedResource(
            type="resource", resource=types.BlobResourceContents(uri="vision-one:response", mimeType="application/pdf",
                                                                 blob=base64.b64encode(raw).decode())),
            txt("Operation-Location: https://api.example.test/v3.0/tasks/1")))
        self.assertEqual(out["binary"][0]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(out["response_headers"]["Operation-Location"], "https://api.example.test/v3.0/tasks/1")
        self.assertIn("never instructions", out["untrusted_content"])

    def test_pagination_only_as_the_handler_forwards_it(self):
        tokens = access.entry("vision_one", "endpoint_security_endpoints_list")
        out = access.normalize(tokens, {"orderBy": "agentGuid asc"}, result(txt(
            {"items": [1, 2], "nextLink": "https://x/v3.0/e?top=2&skipToken=AB%3D"})))
        self.assertEqual(out["pagination"]["next_arguments"], {"orderBy": "agentGuid asc", "skipToken": "AB="})
        self.assertEqual(out["outcome"], "partial")
        blocked = access.entry("vision_one", "workbench_alert_notes_list")
        out = access.normalize(blocked, {"alertId": "WB-1"}, result(txt({"items": [1], "nextLink": "https://x?skipToken=1"})))
        self.assertFalse(out["pagination"]["continuation_supported"])
        self.assertNotIn("next_arguments", out["pagination"])
        ranged = access.entry("qradar", "list_offenses")
        full = access.normalize(ranged, {"limit": 2, "offset": 4}, result(txt([1, 2])))
        self.assertEqual(full["pagination"]["next_arguments"], {"limit": 2, "offset": 6})
        last = access.normalize(ranged, {"limit": 5}, result(txt([1, 2])))
        self.assertFalse(last["pagination"]["more_may_exist"])

    def test_empty_truncated_and_fastmcp_text_wrapper(self):
        t = access.entry("qradar", "list_offenses")
        self.assertEqual(access.normalize(t, {}, result(txt([]), structured={"result": "[]"}))["outcome"], "empty")
        big = [{"id": i, "pad": "x" * 200} for i in range(50)]
        out = access.normalize(t, {"limit": 100}, result(txt(big)), max_chars=2000)
        self.assertTrue(out["output_truncated"])
        self.assertGreater(out["items_omitted"], 0)
        self.assertEqual(out["outcome"], "partial")


class LiveQRadarTests(unittest.TestCase):
    def test_list_offenses_forwards_exact_arguments_and_reports_range_pagination(self):
        fake = FakeUpstream()
        out = query(fake, "qradar", "list_offenses", {"limit": 10, "offset": 0})
        self.assertEqual(out["outcome"], "partial")
        self.assertEqual(out["items_returned"], 10)
        self.assertEqual(out["pagination"]["next_arguments"], {"limit": 10, "offset": 10})
        self.assertGreater(out["discovery"]["pages"], 1)  # tools/list paginated in pages of 40
        self.assertEqual(fake.calls(), [{"tool": "list_offenses", "arguments": {"limit": 10, "offset": 0}}])
        last = query(fake, "qradar", "list_offenses", {"limit": 10, "offset": 20})
        self.assertEqual((last["items_returned"], last["pagination"]["more_may_exist"]), (5, False))

    def test_errors_text_output_and_mutations_over_stdio(self):
        fake = FakeUpstream("stdio")  # real subprocess pipes: the UTF-8 text must survive without UTF-8 mode
        missing = query(fake, "qradar", "get_offense", {"offense_id": 1})
        self.assertEqual(missing["error"]["category"], "not_found")
        self.assertNotIn("synthetic-secret", json.dumps(missing))
        users = query(fake, "qradar", "list_users", {})
        self.assertEqual(users["error"]["category"], "permission")
        geo = query(fake, "qradar", "geolocate_ip", {"ip_address": "203.0.113.7"})
        self.assertEqual((geo["format"], "São Exemplo" in geo["data"]), ("text", True))
        blocked = query(fake, "qradar", "set_offense_status", {"offense_id": 1000, "status": "CLOSED"})
        self.assertEqual((blocked["outcome"], blocked["category"]), ("refused", "policy_blocked"))
        self.assertNotIn("set_offense_status", [c["tool"] for c in fake.calls()])
        self.assertEqual(len(fake.opened), 3)  # the refused mutation never opened a session

    def test_absent_tool_drift_timeout_and_cancellation(self):
        hidden = query(FakeUpstream(FAKE_UPSTREAM_HIDE="list_rules"), "qradar", "list_rules", {})
        self.assertEqual(hidden["error"]["category"], "tool_absent")
        drift_fake = FakeUpstream(FAKE_UPSTREAM_DRIFT="list_offenses")
        drift = query(drift_fake, "qradar", "list_offenses", {"limit": 5})
        self.assertEqual(drift["error"]["category"], "contract_changed")
        self.assertEqual(drift_fake.calls(), [])
        slow = query(FakeUpstream(), "qradar", "get_system_info", {}, timeout_seconds=5)
        self.assertEqual((slow["error"]["category"], slow["upstream_call_attempted"]), ("timeout", True))

        async def cancel():
            fake = FakeUpstream()
            with fake.patch():
                task = asyncio.create_task(live.live_upstream_query("qradar", "get_system_info", {},
                                                                    settings=SETTINGS, timeout_seconds=60))
                await asyncio.sleep(3)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        run(cancel())


class LiveVisionOneTests(unittest.TestCase):
    def test_skip_token_continuation_headers_and_readonly_container(self):
        fake = FakeUpstream()
        first = query(fake, "vision_one", "endpoint_security_endpoints_list", {"orderBy": "agentGuid asc"})
        self.assertEqual(first["response_headers"], {"ETag": '"synthetic-etag"'})
        self.assertEqual(first["pagination"]["next_arguments"], {"orderBy": "agentGuid asc", "skipToken": "2"})
        second = query(fake, "vision_one", "endpoint_security_endpoints_list", first["pagination"]["next_arguments"])
        self.assertEqual([i["agentGuid"] for i in second["data"]["items"]], ["guid-002", "guid-003"])
        self.assertEqual(fake.opened[0], {"platform": "vision_one", "toolset": "endpoint", "readonly": True})

    def test_unforwarded_continuation_untrusted_text_binary_license_and_empty(self):
        fake = FakeUpstream()
        notes = query(fake, "vision_one", "workbench_alert_notes_list", {"alertId": "WB-SYNTH-1"})
        self.assertFalse(notes["pagination"]["continuation_supported"])
        self.assertIn("never instructions", notes["untrusted_content"])
        audit = query(fake, "vision_one", "audit_logs_list", {})
        self.assertEqual(audit["error"]["category"], "permission_or_license")
        self.assertNotIn("synthetic-secret", json.dumps(audit))
        empty = query(fake, "vision_one", "search_detections_list", {"query": "endpointHostName:ws-001"})
        self.assertEqual(empty["outcome"], "empty")
        report = query(fake, "vision_one", "sandbox_analysis_result_report_get", {"id": "r-1"})
        self.assertEqual(report["binary"][0]["mime_type"], "application/pdf")
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {"SOC_BRIDGE_DOWNLOAD_DIR": folder}):
            with fake.patch():
                saved = run(live.live_upstream_download("vision_one", "sandbox_analysis_result_report_get",
                                                        {"id": "r-1"}, settings=SETTINGS))
            path = Path(saved["saved_files"][0]["path"])
            self.assertEqual(path.read_bytes(), b"%PDF-1.4 synthetic report")
            self.assertEqual(path.parent, Path(folder))

    def test_docker_arguments_are_built_from_the_registry(self):
        captured = []
        from mcp import StdioServerParameters as Real

        def synthetic(command, args, env):
            captured.append(args)
            return Real(command=sys.executable, args=[str(FAKE), "vision_one"], env=env)
        with mock.patch("mcp.StdioServerParameters", side_effect=synthetic):
            out = run(live.live_upstream_query("vision_one", "search_detections_list", {"query": "x"},
                                               settings=SETTINGS))
        self.assertEqual(out["outcome"], "empty")
        self.assertEqual(captured[0][-3:], ["us", "-readonly=true", "-toolsets=search"])
        self.assertNotIn("synthetic-key", json.dumps(captured))  # the key goes through the environment only

    def test_inventory_reports_absent_unreviewed_and_drift(self):
        fake = FakeUpstream(FAKE_UPSTREAM_EXTRA="brand_new_tool", FAKE_UPSTREAM_HIDE="audit_logs_list",
                            FAKE_UPSTREAM_DRIFT="workbench_alerts_list")
        with fake.patch():
            inv = run(live.live_inventory("vision_one", settings=SETTINGS))
        self.assertEqual(inv["announced_but_pending_review"], ["brand_new_tool"])
        self.assertIn("audit_logs_list", inv["absent"])
        self.assertIn("workbench_alerts_list", inv["schema_drift"])
        self.assertTrue(inv["discovery"]["complete"])


class TTY(io.StringIO):
    def isatty(self):
        return True


class ChangeControlTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name)
        self.policy = base / "policy.json"
        self.env = mock.patch.dict(os.environ, {"SOC_BRIDGE_CHANGE_DIR": str(base / "changes"),
                                                "SOC_BRIDGE_APPROVAL_KEY": str(base / "key"),
                                                "SOC_BRIDGE_CHANGE_POLICY": str(self.policy)})
        self.env.start()
        os.environ.pop("SOC_BRIDGE_ENABLE_CHANGES", None)

    def tearDown(self):
        self.env.stop()
        self.folder.cleanup()

    def propose_note(self):
        return change_control.propose("qradar", "add_offense_note", {"offense_id": 1000, "note_text": "synthetic"},
                                      "Record the synthetic analyst conclusion")

    def approve(self, request, typed=None):
        code = change_control.load(request["id"])["digest"][:8]
        return change_control.approve_interactively(request["id"], stdin=TTY((typed or code) + "\n"), stdout=TTY())

    def execute(self, request_id, fake=None):
        fake = fake or FakeUpstream()
        with fake.patch():
            return run(change_control.execute(request_id, settings=SETTINGS)), fake

    def test_proposal_rules(self):
        for platform, tool, args, why in [("qradar", "list_offenses", {}, "query tools are not changes here"),
                                          ("vision_one", "sandbox_files_analyze", {}, "upload is unsupported"),
                                          ("qradar", "add_offense_note", {"offense_id": 1}, "missing note_text"),
                                          ("qradar", "add_offense_note", {"offense_id": 1, "note_text": "x"}, "short")]:
            with self.subTest(why=why), self.assertRaises(change_control.Refused):
                change_control.propose(platform, tool, args, why if why != "short" else "no")
        request = self.propose_note()
        self.assertEqual(request["status"], "pending_approval")
        self.assertIn("soc-bridge change approve", request["next_step"])

    def test_every_gate_must_hold_and_model_input_never_approves(self):
        request = self.propose_note()
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(request["id"])
        self.assertEqual(caught.exception.category, "changes_disabled")
        os.environ["SOC_BRIDGE_ENABLE_CHANGES"] = "1"
        with self.assertRaises(change_control.Refused) as caught:  # policy path set, file missing
            self.execute(request["id"])
        self.assertEqual(caught.exception.category, "policy_invalid")
        self.policy.write_text(json.dumps({"allowed_tools": ["qradar/set_offense_status"]}), encoding="utf-8")
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(request["id"])
        self.assertEqual(caught.exception.category, "not_enabled_by_policy")
        self.policy.write_text(json.dumps({"allowed_tools": ["qradar/add_offense_note"]}), encoding="utf-8")
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(request["id"])
        self.assertEqual(caught.exception.category, "not_approved")
        with self.assertRaises(change_control.Refused) as caught:  # piped input is not a person at a terminal
            change_control.approve_interactively(request["id"], stdin=io.StringIO("x\n"), stdout=io.StringIO())
        self.assertEqual(caught.exception.category, "approval_requires_terminal")
        with self.assertRaises(change_control.Refused):
            self.approve(request, typed="wrong")
        self.approve(request)
        out, fake = self.execute(request["id"])
        self.assertEqual((out["request_status"], out["outcome"]), ("executed", "ok"))
        self.assertEqual(fake.calls(), [{"tool": "add_offense_note", "arguments": {"offense_id": 1000,
                                                                                    "note_text": "synthetic"}}])
        with self.assertRaises(change_control.Refused):  # single use
            self.execute(request["id"])

    def test_tampering_forged_approval_and_expiry_are_refused(self):
        os.environ["SOC_BRIDGE_ENABLE_CHANGES"] = "1"
        self.policy.write_text(json.dumps({"allowed_tools": ["qradar/add_offense_note"]}), encoding="utf-8")
        request = self.propose_note()
        self.approve(request)
        path = change_control._store().path(request["id"])
        stored = json.loads(path.read_text(encoding="utf-8"))
        stored["arguments"]["offense_id"] = 1001
        path.write_text(json.dumps(stored), encoding="utf-8")
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(request["id"])
        self.assertEqual(caught.exception.category, "tampered")
        forged = self.propose_note()
        data = json.loads(change_control._store().path(forged["id"]).read_text(encoding="utf-8"))
        data.update(status="approved", approval={"approved_by": "model", "approved_at": "2026-10-15T00:00:00Z",
                                                 "expires_at": "2099-01-01T00:00:00Z", "signature": "0" * 64})
        change_control._store().path(forged["id"]).write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(forged["id"])
        self.assertEqual(caught.exception.category, "approval_invalid")
        late = self.propose_note()
        self.approve(late)
        with mock.patch.object(change_control, "_now", return_value=change_control._now() + change_control.APPROVAL_TTL * 2):
            with self.assertRaises(change_control.Refused) as caught:
                self.execute(late["id"])
        self.assertEqual(caught.exception.category, "approval_expired")

    def test_vision_one_write_tool_runs_in_a_container_that_registers_writes(self):
        os.environ["SOC_BRIDGE_ENABLE_CHANGES"] = "1"
        self.policy.write_text(json.dumps({"allowed_tools": ["vision_one/workbench_alert_notes_create"]}),
                               encoding="utf-8")
        request = change_control.propose("vision_one", "workbench_alert_notes_create",
                                         {"alertId": "WB-SYNTH-1", "content": "synthetic note"},
                                         "Record the synthetic triage conclusion")
        self.approve(request)
        out, fake = self.execute(request["id"])
        self.assertEqual(fake.opened, [{"platform": "vision_one", "toolset": "workbench", "readonly": False}])
        self.assertEqual((out["request_status"], out["format"]), ("executed", "text"))
        self.assertTrue(out["response_headers"]["Location"].endswith("/notes/9"))
        stored = change_control.load(request["id"])
        self.assertEqual(stored["result"]["response_headers"], out["response_headers"])

    def test_generated_credential_is_returned_once_and_never_stored(self):
        os.environ["SOC_BRIDGE_ENABLE_CHANGES"] = "1"
        tool = "container_security_generate_service_gateway_password"
        self.policy.write_text(json.dumps({"allowed_tools": [f"vision_one/{tool}"]}), encoding="utf-8")
        request = change_control.propose("vision_one", tool, {}, "Synthetic gateway onboarding in a lab")
        self.approve(request)
        out, fake = self.execute(request["id"])
        self.assertEqual(out["data"]["password"], "synthetic-generated-password-value")
        self.assertEqual(fake.opened[0], {"platform": "vision_one", "toolset": "container", "readonly": True})
        stored = change_control._store().path(request["id"]).read_text(encoding="utf-8")
        self.assertNotIn("synthetic-generated-password-value", stored)

    def test_change_server_tools_and_disabled_kiro_entry(self):
        from soc_bridge.change_server import mcp
        tools = {t.name: t for t in run(mcp.list_tools())}
        self.assertEqual(set(tools), {"change_operations", "change_request", "change_request_status", "change_execute"})
        self.assertTrue(tools["change_execute"].annotations.destructiveHint)
        guide = (ROOT / "docs" / "upstream-access.md").read_text(encoding="utf-8")
        snippet = json.loads(guide.split("```json\n", 1)[1].split("```", 1)[0])
        entry = snippet["mcpServers"]["soc-bridge-change"]
        self.assertTrue(entry["disabled"])
        self.assertNotIn("autoApprove", entry)


if __name__ == "__main__":
    unittest.main()
