"""Regressions for the PR #20 review: discovery gate, recursive contracts, output limit and partial pages,
pinned image, uncertain change outcomes and staged uploads. Synthetic servers and files only."""

import asyncio
import copy
import io
import json
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mcp import types

from soc_bridge import change_control, upstream_access as access, upstream_live as live
from soc_bridge.upstream_policy import callable_for_change, callable_for_query

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_upstream_access import FAKE, SETTINGS, TTY, FakeUpstream, query, result, run, snapshot, txt


def first_page_query_tool():
    names = [t["name"] for t in snapshot("qradar-tools-list.json")["tools"]][:40]
    for name in names:
        t = access.entry("qradar", name)
        if t["access"] == "query" and not t["input_schema"].get("required"):
            return name
    raise AssertionError("no argument-free query tool on the first tools/list page")


class DiscoveryGateTests(unittest.TestCase):
    def test_incomplete_discovery_blocks_a_tool_seen_on_the_first_page(self):
        tool = first_page_query_tool()
        fake = FakeUpstream(FAKE_UPSTREAM_FAIL_PAGE="1")
        out = query(fake, "qradar", tool, {})
        self.assertEqual(out["error"]["category"], "discovery_incomplete")
        self.assertFalse(out["upstream_call_attempted"])
        self.assertFalse(out["discovery"]["complete"])
        self.assertEqual(fake.calls(), [])  # tools/call counter stays at zero


class ContractTests(unittest.TestCase):
    def patched(self, t, path, value):
        schema = copy.deepcopy(t.get("announced_schema") or t["input_schema"])
        node = schema
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
        return access.contract_drift(t, {"inputSchema": schema})

    def test_changes_inside_anyof_and_nested_objects_are_detected(self):
        offenses = access.entry("qradar", "list_offenses")
        self.assertTrue(self.patched(offenses, ["properties", "limit", "anyOf", 0, "type"], "string"))
        self.assertTrue(self.patched(offenses, ["properties", "limit", "default"], 1000))
        nested = access.entry("vision_one", "aisecurity_guardrails_apply")
        item = ["properties", "messages", "items", "properties", "role"]
        self.assertTrue(self.patched(nested, item + ["type"], "integer"))
        self.assertTrue(self.patched(nested, ["properties", "messages", "items", "required"], ["content"]))

    def test_relevant_keywords_are_compared_and_descriptions_ignored(self):
        t = access.entry("vision_one", "search_endpoint_activities_list")
        for path, value in [(["properties", "mode", "enum"], ["default"]), (["required"], []),
                            (["properties", "query", "pattern"], "^x$"), (["properties", "query", "maxLength"], 10),
                            (["properties", "top", "minimum"], 1), (["properties", "extra"], {"type": "string"}),
                            (["properties", "query", "$ref"], "#/$defs/q")]:
            with self.subTest(path=path):
                self.assertTrue(self.patched(t, path, value))
        self.assertEqual(self.patched(t, ["properties", "query", "description"], "reworded"), [])
        self.assertEqual(self.patched(t, ["properties", "mode", "enum"],
                                      list(reversed(t["input_schema"]["properties"]["mode"]["enum"]))), [])
        offenses = access.entry("qradar", "list_offenses")
        swapped = list(reversed(offenses["announced_schema"]["properties"]["limit"]["anyOf"]))
        self.assertEqual(self.patched(offenses, ["properties", "limit", "anyOf"], swapped), [])

    def test_parameter_named_description_is_a_real_parameter(self):
        t = access.entry("qradar", "create_reference_set")
        self.assertIn("description", t["announced_schema"]["properties"])
        removed = copy.deepcopy(t["announced_schema"])
        removed["properties"].pop("description")
        self.assertIn("properties.description: removed", access.contract_drift(t, {"inputSchema": removed}))
        self.assertTrue(self.patched(t, ["properties", "description", "anyOf"], [{"type": "integer"}]))
        # The documentation of that parameter is still only documentation.
        reworded = self.patched(t, ["properties", "description", "description"], "reworded")
        self.assertEqual(reworded, [])

    def synthetic(self, schema):
        return {"platform": "qradar", "name": "synthetic", "input_schema": schema, "announced_schema": schema}

    def test_parameters_named_like_annotations_are_compared(self):
        base = {"type": "object", "description": "doc", "title": "Doc", "properties": {
            "title": {"type": "string"}, "examples": {"type": "array", "items": {"type": "string"}},
            "x-custom": {"type": "integer", "minimum": 1}}, "required": ["title"],
            "$defs": {"description": {"type": "string"}}, "patternProperties": {"^x-": {"type": "string"}}}
        t = self.synthetic(base)
        for path, value in [(["properties", "title", "type"], "integer"),
                            (["properties", "examples", "items", "type"], "number"),
                            (["properties", "x-custom", "minimum"], 5),
                            (["$defs", "description", "type"], "integer"),
                            (["patternProperties", "^x-", "type"], "integer"),
                            (["required"], ["examples"])]:
            with self.subTest(path=path):
                self.assertTrue(self.patched(t, path, value))
        for name in ("title", "examples", "x-custom"):
            with self.subTest(removed=name):
                changed = copy.deepcopy(base)
                changed["properties"].pop(name)
                self.assertIn(f"properties.{name}: removed", access.contract_drift(t, {"inputSchema": changed}))

    def test_data_values_with_annotation_like_keys_are_kept(self):
        base = {"type": "object", "properties": {
            "filter": {"type": "object", "default": {"description": "a", "x-mode": 1, "title": "t"}},
            "kind": {"const": {"examples": [1], "$comment": "c"}},
            "choice": {"enum": [{"title": "a"}, {"title": "b"}]}}}
        t = self.synthetic(base)
        for path, value in [(["properties", "filter", "default", "description"], "b"),
                            (["properties", "filter", "default", "x-mode"], 2),
                            (["properties", "kind", "const", "examples"], [2]),
                            (["properties", "kind", "const", "$comment"], "other"),
                            (["properties", "choice", "enum"], [{"title": "a"}, {"title": "c"}])]:
            with self.subTest(path=path):
                self.assertTrue(self.patched(t, path, value))
        self.assertEqual(self.patched(t, ["properties", "choice", "enum"], [{"title": "b"}, {"title": "a"}]), [])

    def test_schema_documentation_alone_is_still_ignored(self):
        base = {"type": "object", "description": "doc", "properties": {
            "description": {"type": "string", "description": "the free text", "title": "Description",
                            "examples": ["x"], "x-ui": "textarea"},
            "items": {"type": "array", "items": {"type": "object", "description": "item doc",
                                                 "properties": {"id": {"type": "string", "$comment": "c"}}}}}}
        t = self.synthetic(base)
        for path, value in [(["description"], "new doc"), (["properties", "description", "description"], "changed"),
                            (["properties", "description", "title"], "Text"),
                            (["properties", "description", "examples"], ["y"]),
                            (["properties", "description", "x-ui"], "input"),
                            (["properties", "items", "items", "description"], "changed"),
                            (["properties", "items", "items", "properties", "id", "$comment"], "d")]:
            with self.subTest(path=path):
                self.assertEqual(self.patched(t, path, value), [])
        self.assertTrue(self.patched(t, ["properties", "items", "items", "properties", "id", "type"], "integer"))

    def test_anyof_change_in_a_running_server_blocks_the_call(self):
        patch = {"tool": "list_offenses", "path": ["properties", "limit", "anyOf", 0, "type"], "value": "string"}
        fake = FakeUpstream(FAKE_UPSTREAM_SCHEMA_PATCH=json.dumps(patch))
        out = query(fake, "qradar", "list_offenses", {"limit": 5})
        self.assertEqual(out["error"]["category"], "contract_changed")
        self.assertTrue(any("anyOf" in d for d in out["differences"]))
        self.assertEqual(fake.calls(), [])


def items_result(items, **extra):
    return result(txt({"items": items, **extra}))


class OutputLimitTests(unittest.TestCase):
    def test_data_never_exceeds_the_limit_and_keeps_continuation_fields(self):
        t = access.entry("vision_one", "endpoint_security_endpoints_list")
        body = {"items": [{"agentGuid": f"g{i}"} for i in range(3)], "nextLink": "https://x/e?skipToken=T2",
                "totalCount": 99, "summary": "s" * 5000}
        out = access.normalize(t, {}, result(txt(body)), max_chars=1000)
        self.assertLessEqual(len(json.dumps(out["data"], ensure_ascii=False)), 1000)
        self.assertEqual(out["data"]["nextLink"], body["nextLink"])
        self.assertEqual(out["data"]["totalCount"], 99)
        self.assertIn("summary", out["fields_omitted"])
        self.assertEqual(out["output_limit"], {"max_chars": 1000, "applies_to": "data"})

    def test_limit_holds_for_arbitrary_shapes(self):
        rng = random.Random(7)
        t = access.entry("vision_one", "search_detections_list")
        for case in range(200):
            items = [{"k": "é" * rng.randint(0, 900), "n": i} for i in range(rng.randint(0, 30))]
            shape = rng.choice(["list", "dict", "text", "nested"])
            body = (items if shape == "list" else {"items": items, "blob": "\"q\"" * rng.randint(0, 3000)}
                    if shape == "dict" else "z" * rng.randint(0, 9000) if shape == "text"
                    else {"a": {"b": "c" * rng.randint(0, 5000)}, "d": "e" * rng.randint(0, 5000)})
            limit = rng.randint(1000, 4000)
            out = access.normalize(t, {}, result(txt(body)), max_chars=limit)
            with self.subTest(case=case, shape=shape):
                self.assertLessEqual(len(json.dumps(out["data"], ensure_ascii=False)), limit)

    def test_range_continuation_after_local_cut_starts_at_the_first_undelivered_item(self):
        fake = FakeUpstream()
        first = query(fake, "qradar", "list_offenses", {"limit": 25, "offset": 0}, max_output_chars=1000)
        self.assertTrue(first["output_truncated"])
        delivered = first["items_delivered"]
        self.assertLess(delivered, 25)
        self.assertEqual(first["pagination"]["next_arguments"], {"limit": 25, "offset": delivered})
        ids = [o["id"] for o in first["data"]]
        nxt = first["pagination"]["next_arguments"]
        while nxt:
            page = query(fake, "qradar", "list_offenses", nxt, max_output_chars=1000)
            ids += [o["id"] for o in page["data"]]
            nxt = page["pagination"].get("next_arguments")
        self.assertEqual(ids, [1000 + i for i in range(25)])  # nothing skipped, nothing repeated

    def test_token_page_cut_locally_offers_recovery_before_the_next_page(self):
        t = access.entry("vision_one", "endpoint_security_endpoints_list")
        items = [{"agentGuid": f"g{i}", "pad": "p" * 300} for i in range(6)]
        page = items_result(items, nextLink="https://x/e?skipToken=NEXT")
        first = access.normalize(t, {"orderBy": "agentGuid asc"}, page, max_chars=1000)
        pag = first["pagination"]
        self.assertNotIn("next_arguments", pag)
        self.assertEqual(pag["next_page_arguments"], {"orderBy": "agentGuid asc", "skipToken": "NEXT"})
        self.assertEqual(pag["recover"]["skip_items"], first["items_delivered"])
        seen = [i["agentGuid"] for i in first["data"]["items"]]
        skip = pag["recover"]["skip_items"]
        while True:
            again = access.normalize(t, {"orderBy": "agentGuid asc"}, page, max_chars=1000, skip_items=skip)
            seen += [i["agentGuid"] for i in again["data"]["items"]]
            if "recover" not in again["pagination"]:
                self.assertEqual(again["pagination"]["next_arguments"]["skipToken"], "NEXT")
                break
            skip = again["pagination"]["recover"]["skip_items"]
        self.assertEqual(seen, [f"g{i}" for i in range(6)])

    def test_skip_items_is_validated(self):
        out = query(FakeUpstream(), "qradar", "list_offenses", {}, skip_items=-1)
        self.assertEqual(out["category"], "invalid_arguments")


class EmptyPageTests(unittest.TestCase):
    def test_empty_page_with_token_is_partial_and_continuable(self):
        t = access.entry("vision_one", "endpoint_security_endpoints_list")
        out = access.normalize(t, {}, items_result([], nextLink="https://x/e?skipToken=MORE"))
        self.assertEqual(out["outcome"], "partial")
        self.assertEqual(out["pagination"]["next_arguments"], {"skipToken": "MORE"})
        oat = access.entry("vision_one", "workbench_observed_attack_techniques_list")
        out = access.normalize(oat, {}, items_result([], nextBatchToken="B2"))
        self.assertEqual((out["outcome"], out["pagination"]["next_arguments"]["nextBatchToken"]), ("partial", "B2"))

    def test_empty_terminal_page_is_empty(self):
        t = access.entry("vision_one", "endpoint_security_endpoints_list")
        self.assertEqual(access.normalize(t, {}, items_result([]))["outcome"], "empty")
        self.assertEqual(access.normalize(access.entry("qradar", "list_offenses"), {"limit": 5},
                                          result(txt([])))["outcome"], "empty")

    def test_empty_page_with_unfollowable_link_is_not_exhausted(self):
        t = access.entry("vision_one", "search_detections_list")
        out = access.normalize(t, {"query": "x"}, items_result([], nextLink="https://x/s?skipToken=Z"))
        self.assertEqual(out["outcome"], "partial")
        self.assertFalse(out["pagination"]["continuation_supported"])
        self.assertIn("not exhausted", out["empty_meaning"])


class PinnedImageTests(unittest.TestCase):
    def capture(self, coro_factory):
        captured = []
        from mcp import StdioServerParameters as Real

        def synthetic(command, args, env):
            captured.append(args)
            return Real(command=sys.executable, args=[str(FAKE), "vision_one"], env=env)
        with mock.patch("mcp.StdioServerParameters", side_effect=synthetic):
            out = run(coro_factory())
        return captured, out

    def test_queries_and_inventory_start_the_audited_digest(self):
        image = access.registry()["sources"]["vision_one"]["image"]
        self.assertEqual(image["label_revision"], access.registry()["sources"]["vision_one"]["commit"])
        reference = access.trend_image()
        self.assertRegex(reference, r"^ghcr\.io/trendmicro/vision-one-mcp-server@sha256:[0-9a-f]{64}$")
        args, out = self.capture(lambda: live.live_upstream_query("vision_one", "search_detections_list",
                                                                  {"query": "x"}, settings=SETTINGS))
        self.assertIn(reference, args[0])
        self.assertEqual(out["version_binding"]["image"], reference)
        args, inv = self.capture(lambda: live.live_inventory("vision_one", settings=SETTINGS))
        self.assertIn(reference, args[0])

    def test_curated_workflows_and_diagnostics_use_the_same_image(self):
        for module in ("transports.py", "diagnose.py", "upstream_live.py"):
            source = (Path(access.__file__).parent / module).read_text(encoding="utf-8")
            self.assertNotIn('"ghcr.io/trendmicro/vision-one-mcp-server"', source, module)
            self.assertIn("trend_image()", source, module)

    def test_qradar_version_is_not_claimed_as_verified(self):
        out = query(FakeUpstream(), "qradar", "list_offenses", {"limit": 1})
        self.assertFalse(out["version_binding"]["verified"])
        self.assertIn("not verifiable", out["version_binding"]["basis"])


class ChangeEnv(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.base = Path(self.folder.name)
        self.policy = self.base / "policy.json"
        self.env = mock.patch.dict(os.environ, {"SOC_BRIDGE_CHANGE_DIR": str(self.base / "changes"),
                                                "SOC_BRIDGE_APPROVAL_KEY": str(self.base / "key"),
                                                "SOC_BRIDGE_CHANGE_POLICY": str(self.policy),
                                                "SOC_BRIDGE_ENABLE_CHANGES": "1"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.folder.cleanup()

    def allow(self, *names):
        self.policy.write_text(json.dumps({"allowed_tools": list(names)}), encoding="utf-8")

    def approved(self, platform, tool, args, why="Synthetic lab change for regression tests"):
        request = change_control.propose(platform, tool, args, why)
        code = change_control.load(request["id"])["digest"][:8]
        change_control.approve_interactively(request["id"], stdin=TTY(code + "\n"), stdout=TTY())
        return request

    def execute(self, request_id, fake, timeout=30):
        with fake.patch():
            return run(change_control.execute(request_id, timeout_seconds=timeout, settings=SETTINGS))


NOTE = {"offense_id": 1000, "note_text": "synthetic"}


class UncertainOutcomeTests(ChangeEnv):
    def test_server_that_applies_then_breaks_the_connection_is_uncertain(self):
        self.allow("qradar/add_offense_note")
        request = self.approved("qradar", "add_offense_note", NOTE)
        fake = FakeUpstream("stdio", FAKE_UPSTREAM_INTERRUPT="add_offense_note")
        out = self.execute(request["id"], fake)
        self.assertEqual([c["tool"] for c in fake.calls()], ["add_offense_note"])  # applied upstream
        self.assertEqual(out["request_status"], "outcome_uncertain")
        self.assertIn("Reconcile in the product", out["note"])
        self.assertTrue(out["upstream_call_attempted"])
        with self.assertRaises(change_control.Refused):  # single use survives the uncertain outcome
            self.execute(request["id"], FakeUpstream())

    def test_timeout_after_sending_is_uncertain(self):
        self.allow("qradar/add_offense_note")
        request = self.approved("qradar", "add_offense_note", NOTE)
        fake = FakeUpstream(FAKE_UPSTREAM_SLOW="add_offense_note")
        out = self.execute(request["id"], fake, timeout=5)
        self.assertEqual((out["error"]["category"], out["request_status"]), ("timeout", "outcome_uncertain"))
        self.assertEqual(change_control.load(request["id"])["status"], "outcome_uncertain")

    def test_cancellation_after_sending_is_recorded_as_uncertain(self):
        self.allow("qradar/add_offense_note")
        request = self.approved("qradar", "add_offense_note", NOTE)
        fake = FakeUpstream(FAKE_UPSTREAM_SLOW="add_offense_note")

        async def scenario():
            task = asyncio.create_task(change_control.execute(request["id"], timeout_seconds=60, settings=SETTINGS))
            deadline = time.monotonic() + 20
            while not fake.calls() and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        with fake.patch():
            run(scenario())
        stored = change_control.load(request["id"])
        self.assertEqual(stored["status"], "outcome_uncertain")
        self.assertTrue(stored["result"]["upstream_call_attempted"])

    def test_explicit_rejection_server_error_and_unsent_request(self):
        self.allow("qradar/add_offense_note")
        rejected = self.approved("qradar", "add_offense_note", NOTE)
        out = self.execute(rejected["id"], FakeUpstream(FAKE_UPSTREAM_ERROR="add_offense_note:409"))
        self.assertEqual((out["request_status"], out["error"]["http_status"]), ("rejected_by_upstream", 409))
        failed = self.approved("qradar", "add_offense_note", NOTE)
        out = self.execute(failed["id"], FakeUpstream(FAKE_UPSTREAM_ERROR="add_offense_note:500"))
        self.assertEqual(out["request_status"], "outcome_uncertain")
        unsent = self.approved("qradar", "add_offense_note", NOTE)
        fake = FakeUpstream(FAKE_UPSTREAM_HIDE="add_offense_note")
        out = self.execute(unsent["id"], fake)
        self.assertEqual((out["request_status"], fake.calls()), ("not_sent", []))


class UploadTests(ChangeEnv):
    def source(self, content=b"synthetic sample bytes\n", name="sample.txt"):
        folder = self.base / "src"
        folder.mkdir(exist_ok=True)
        path = folder / name
        path.write_bytes(content)
        return path

    def test_upload_sends_exactly_the_approved_bytes_and_cleans_up(self):
        self.allow("vision_one/sandbox_files_analyze")
        src = self.source()
        request = self.approved("vision_one", "sandbox_files_analyze", {"file": str(src)})
        upload = change_control.load(request["id"])["upload"]
        src.write_bytes(b"changed after approval")  # the source is not read again
        fake = FakeUpstream()
        out = self.execute(request["id"], fake)
        self.assertEqual(out["request_status"], "executed")
        self.assertEqual(out["data"]["sha256"], upload["sha256"])
        self.assertEqual(fake.calls()[0]["arguments"]["file"], "/approved/sample.txt")
        self.assertEqual(fake.opened[0]["readonly"], False)
        self.assertEqual(fake.opened[0]["mounts"], [(upload["staged_path"], "/approved/sample.txt")])
        self.assertFalse(change_control.staging_dir(request["id"]).exists())
        self.assertIn("verified before and after", out["upload_integrity"])

    def test_replaced_staged_file_is_refused_before_sending(self):
        self.allow("vision_one/sandbox_files_analyze")
        request = self.approved("vision_one", "sandbox_files_analyze", {"file": str(self.source())})
        staged = Path(change_control.load(request["id"])["upload"]["staged_path"])
        os.chmod(staged, 0o600)
        staged.write_bytes(b"swapped")
        fake = FakeUpstream()
        with self.assertRaises(change_control.Refused) as caught:
            self.execute(request["id"], fake)
        self.assertEqual(caught.exception.category, "file_changed")
        self.assertEqual(fake.calls(), [])
        self.assertEqual(change_control.load(request["id"])["status"], "not_sent")

    def test_unsafe_sources_are_refused(self):
        folder = self.base / "src"
        folder.mkdir(exist_ok=True)
        cases = {"relative": "sample.txt", "directory": str(folder), "missing": str(folder / "none.bin")}
        try:
            link = folder / "link.txt"
            os.symlink(self.source(), link)
            cases["symlink"] = str(link)
        except (OSError, NotImplementedError):
            pass  # creating symlinks needs a privilege on some Windows hosts
        for why, path in cases.items():
            with self.subTest(why=why), self.assertRaises(change_control.Refused):
                change_control.propose("vision_one", "sandbox_files_analyze", {"file": path}, "Synthetic upload test")
        with mock.patch.object(change_control, "MAX_UPLOAD_BYTES", 4), self.assertRaises(change_control.Refused):
            change_control.propose("vision_one", "sandbox_files_analyze", {"file": str(self.source())},
                                   "Synthetic upload test")
        self.assertFalse(any((self.base / "changes" / "staged").glob("*/*")))

    def test_approval_shows_destination_and_hash_and_reject_cleans_staging(self):
        request = change_control.propose("vision_one", "sandbox_files_analyze", {"file": str(self.source())},
                                         "Synthetic upload test")
        stored = change_control.load(request["id"])
        screen = TTY()
        with self.assertRaises(change_control.Refused):
            change_control.approve_interactively(request["id"], stdin=TTY("wrong\n"), stdout=screen)
        self.assertIn(stored["upload"]["sha256"], screen.getvalue())
        self.assertIn("vision_one/sandbox_files_analyze", screen.getvalue())
        change_control.reject(request["id"])
        self.assertFalse(change_control.staging_dir(request["id"]).exists())

    def test_expired_requests_lose_their_staged_files(self):
        request = change_control.propose("vision_one", "sandbox_files_analyze", {"file": str(self.source())},
                                         "Synthetic upload test")
        self.assertTrue(change_control.staging_dir(request["id"]).exists())
        later = change_control._now() + change_control.REQUEST_TTL * 2
        with mock.patch.object(change_control, "_now", return_value=later):
            self.assertEqual(change_control.sweep_expired(), [request["id"]])
        self.assertFalse(change_control.staging_dir(request["id"]).exists())
        self.assertEqual(change_control.load(request["id"])["status"], "expired")

    def test_upload_tools_never_run_on_the_read_path(self):
        with self.assertRaises(access.Refused) as caught:
            access.gate_query("vision_one", "sandbox_files_analyze", {"file": "/etc/hostname"})
        self.assertEqual(caught.exception.category, "policy_blocked")

    def test_docker_mounts_only_the_staged_file_read_only(self):
        self.allow("vision_one/sandbox_files_analyze")
        request = self.approved("vision_one", "sandbox_files_analyze", {"file": str(self.source())})
        upload = change_control.load(request["id"])["upload"]
        captured = []
        from mcp import StdioServerParameters as Real

        def synthetic(command, args, env):
            captured.append(args)
            return Real(command=sys.executable, args=[str(FAKE), "vision_one"],
                        env={**env, "FAKE_UPSTREAM_MOUNTS": json.dumps({upload["container_path"]: upload["staged_path"]})})
        with mock.patch("mcp.StdioServerParameters", side_effect=synthetic):
            out = run(change_control.execute(request["id"], timeout_seconds=60, settings=SETTINGS))
        args = captured[0]
        mount = args[args.index("--mount") + 1]
        self.assertEqual(mount, f"type=bind,source={upload['staged_path']},target=/approved/sample.txt,readonly")
        self.assertEqual(args.count("--mount"), 1)
        self.assertIn("-readonly=false", args)
        self.assertIn(access.trend_image(), args)
        self.assertEqual(out["request_status"], "executed")
        with self.assertRaises(access.Refused):
            live._mount_args([("/tmp/a,b", "/approved/x")])
        with self.assertRaises(access.Refused):
            live._mount_args([("/tmp/a", "/etc/passwd")])


class ContractCheckAllToolsTests(unittest.TestCase):
    def test_every_routable_tool_has_a_valid_schema_and_one_route(self):
        import jsonschema
        for t in access.registry()["tools"]:
            with self.subTest(tool=t["name"]):
                jsonschema.validators.validator_for(t["input_schema"]).check_schema(t["input_schema"])
                self.assertEqual(access.contract_drift(t, {"inputSchema": t.get("announced_schema")
                                                           or t["input_schema"]}), [])
                self.assertTrue(callable_for_query(t) != callable_for_change(t))


if __name__ == "__main__":
    unittest.main()
