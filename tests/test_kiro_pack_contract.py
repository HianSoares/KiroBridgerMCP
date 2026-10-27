"""Offline contract of the Kiro pack against Kiro IDE 1.4.26 (see docs/kiro-pack-compatibility.md).

What this checks: front matter against the IDE agent schema, resource resolution the way the
installed version resolves it, tool lists and delegation boundaries, skill/tool compatibility,
routing, the handoff contract, steering inclusion, spec traceability, and the synthetic
scenarios that existing bridge code can execute.

What this does not check: whether Kiro activates the skills, delegates, or answers as the rules
say. Those are model behaviors and stay pending until a real Kiro session evaluates them.
"""

import asyncio
import glob
import json
import os
import re
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

from soc_bridge.capabilities import LOCAL_WRITE_TOOLS, public_tools

ROOT = Path(__file__).resolve().parents[1]
KIRO = ROOT / ".kiro"
# Agent front-matter fields of the IDE 1.4.26 schema (extension.js, object `Sjr`).
IDE_AGENT_FIELDS = {"name", "description", "tools", "excludedTools", "model", "effortLevel", "includeMcpJson",
                    "includePowers", "mcpServers", "resources", "permissions", "welcomeMessage", "dispatchKind", "hooks"}
CLI_ONLY_FIELDS = {"allowedTools", "toolsSettings", "toolAliases", "keyboardShortcut"}
# Broad selectors that would hand an agent generic built-ins or every MCP tool.
BROAD_SELECTORS = {"*", "@builtin", "@mcp", "@powers", "read", "write", "shell", "web", "subagent", "@subagent",
                   "fs_read", "fs_write", "knowledge", "context", "spec"}
REVIEWED_BUILTINS = {"disclose_context"}
SKILL_SECTIONS = ("Quando usar", "Quando não usar", "Entradas mínimas e descoberta automática", "Procedimento",
                  "Evidência esperada e falhas", "Continuação, escalonamento e parada", "Saída", "Tools permitidas")
TOOL_NAME = re.compile(r"`((?:investigate|qradar|trend|bridge|upstream)_[a-z_]+|list_cases|get_case|reassess_case)`")
# Routing entries write calls with arguments, e.g. `investigate_demo()`.
TOOL_CALL = re.compile(r"`((?:investigate|qradar|trend|bridge|upstream)_[a-z_]+|list_cases|get_case|reassess_case)"
                       r"(?:\([^`]*\))?`")
# Owner words that stand for every agent; they are expanded, never skipped.
GENERIC_OWNERS = {"qualquer", "qualquer agente", "todos", "todos os agentes"}


def front_matter(path: Path) -> tuple[dict, str]:
    """Strict reader for the YAML subset used by the pack; anything else fails the test."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: front matter must be the first content")
    head, body = text[4:].split("\n---\n", 1)
    data: dict = {}
    current = None
    for line in head.splitlines():
        if not line.strip():
            continue
        item = re.fullmatch(r"  - (.+)", line)
        if item:
            if current is None or not isinstance(data[current], list):
                raise ValueError(f"{path}: list item without a list key: {line}")
            data[current].append(item.group(1).strip())
            continue
        pair = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*):(?: (.*))?", line)
        if not pair:
            raise ValueError(f"{path}: unsupported front-matter line: {line}")
        key, raw = pair.group(1), (pair.group(2) or "").strip()
        current = key
        if raw == "":
            data[key] = []
        elif raw.startswith("["):
            data[key] = json.loads(raw)
        elif raw.startswith('"'):
            data[key] = json.loads(raw)
        elif raw in ("true", "false"):
            data[key] = raw == "true"
        else:
            if ": " in raw or " #" in raw or raw[0] in "[]{}&*!|>%@`'":
                raise ValueError(f"{path}: plain scalar would not parse as YAML: {key}")
            data[key] = raw
    return data, body


def resolve(uri: str) -> list[Path]:
    """Kiro IDE 1.4.26 resolver (rFs): absolute as is, ~ from home, else joined to the workspace root."""
    scheme, sep, path = uri.partition("://")
    if not sep or scheme not in ("file", "skill") or not path:
        raise ValueError(f"unsupported resource URI: {uri}")
    if path.startswith("/"):
        target = path
    elif path.startswith("~"):
        target = str(Path.home()) + path[1:]
    else:
        target = os.path.join(str(ROOT), path)
    if any(c in target for c in "*?["):
        return [Path(p) for p in glob.glob(target.replace("\\", "/"), recursive=True) if Path(p).is_file()]
    return [Path(target)]


def agents() -> dict[str, tuple[dict, str]]:
    return {p.stem: front_matter(p) for p in sorted((KIRO / "agents").glob("*.md"))}


def skills() -> dict[str, tuple[dict, str]]:
    return {p.parent.name: front_matter(p) for p in sorted((KIRO / "skills").glob("*/SKILL.md"))}


def section(body: str, title: str) -> str:
    marker = f"\n## {title}\n"
    return body.split(marker, 1)[1].split("\n## ", 1)[0] if marker in body else ""


def bridge_tools(front: dict) -> set[str]:
    return {t.split("/", 1)[1] for t in front.get("tools", []) if t.startswith("@soc-bridge-readonly/")}


def routing_rows(table: str) -> list[list[str]]:
    rows = [r for r in table.splitlines() if r.startswith("| ") and not r.startswith("| Pedido") and "---" not in r]
    return [[c.strip() for c in r.strip("|").split("|")] for r in rows]


def routing_violations(rows: list[list[str]], agent_tools: dict[str, set[str]]) -> list[str]:
    """Every owner of a row, generic owners expanded to all agents, must expose every tool of its entry."""
    problems = []
    for request, agent_cell, entry, _ in rows:
        owners = []
        for owner in (a.strip() for a in re.split(r" ou |, ", agent_cell) if a.strip()):
            owners += sorted(agent_tools) if owner in GENERIC_OWNERS else [owner]
        for owner in owners:
            if owner not in agent_tools:
                problems.append(f"{request}: unknown agent {owner}")
                continue
            for tool in TOOL_CALL.findall(entry):
                if tool not in agent_tools[owner]:
                    problems.append(f"{request}: {owner} does not expose {tool}")
    return problems


class PackContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = asyncio.run(public_tools())
        cls.agents = agents()
        cls.skills = skills()

    def test_front_matter_uses_ide_schema_only(self):
        for name, (front, _) in self.agents.items():
            with self.subTest(agent=name):
                self.assertLessEqual(set(front), IDE_AGENT_FIELDS)
                self.assertFalse(set(front) & CLI_ONLY_FIELDS)
                self.assertEqual(front["name"], name)
                self.assertIsInstance(front["tools"], list)
                self.assertIsInstance(front["includeMcpJson"], bool)
                self.assertTrue(front["description"])

    def test_resources_resolve_like_kiro_1_4_26(self):
        self.assertEqual(resolve("skill://offense-investigation"), [ROOT / "offense-investigation"])
        self.assertFalse((ROOT / "offense-investigation").exists())  # why a bare skill name does not load
        for name, (front, _) in self.agents.items():
            for uri in front.get("resources", []):
                with self.subTest(agent=name, resource=uri):
                    found = resolve(uri)
                    self.assertTrue(found and all(p.is_file() for p in found), uri)
                    if uri.startswith("skill://"):
                        for path in found:
                            self.assertEqual(path.name, "SKILL.md")
                            meta, _ = front_matter(path)
                            self.assertEqual(meta["name"], path.parent.name)
                            self.assertRegex(meta["name"], r"^[a-z0-9-]{1,64}$")
                            self.assertTrue(0 < len(meta["description"]) <= 1024)

    def test_tools_are_bridge_tools_or_reviewed_builtins(self):
        names = set(self.agents)
        for name, (front, _) in self.agents.items():
            for tool in front["tools"]:
                with self.subTest(agent=name, tool=tool):
                    self.assertNotIn(tool, BROAD_SELECTORS)
                    if tool.startswith("@soc-bridge-readonly/"):
                        self.assertIn(tool.split("/", 1)[1], self.public)
                    elif tool.startswith("subagent/"):
                        target = tool.split("/", 1)[1]
                        self.assertEqual(name, "case-investigator", "only the orchestrator delegates")
                        self.assertIn(target, names - {name})
                    else:
                        self.assertIn(tool, REVIEWED_BUILTINS)
            if any(r.startswith("skill://") for r in front.get("resources", [])):
                self.assertIn("disclose_context", front["tools"], f"{name} references skills")
        delegated = {t.split("/", 1)[1] for t in self.agents["case-investigator"][0]["tools"] if t.startswith("subagent/")}
        self.assertEqual(delegated, {"threat-hunter", "report-writer", "response-advisor"})

    def test_agent_boundaries(self):
        tools = {name: bridge_tools(front) for name, (front, _) in self.agents.items()}
        advisor, _ = self.agents["response-advisor"]
        self.assertEqual(advisor["tools"], [])
        self.assertFalse(advisor["includeMcpJson"])
        self.assertTrue(all(r.startswith("file://") for r in advisor["resources"]))
        self.assertEqual(tools["report-writer"], {"list_cases", "get_case", "investigate_demo"})
        self.assertIn("únicas tools MCP são `list_cases`, `get_case` e `investigate_demo`", self.agents["report-writer"][1])
        self.assertIn("`disclose_context` é uma tool interna do Kiro", self.agents["report-writer"][1])
        hunter = tools["threat-hunter"]
        self.assertFalse(hunter & LOCAL_WRITE_TOOLS)
        self.assertNotIn("qradar_assess_closure", hunter)
        self.assertLessEqual(LOCAL_WRITE_TOOLS, tools["case-investigator"])
        writers = [n for n, t in tools.items() if t & {"investigate_offense_case", "reassess_case"}]
        self.assertEqual(writers, ["case-investigator"])

    def test_skills_have_sections_and_compatible_tools(self):
        referenced: dict[str, set[str]] = {}
        for agent, (front, _) in self.agents.items():
            for uri in front.get("resources", []):
                if uri.startswith("skill://"):
                    referenced.setdefault(Path(uri.split("://", 1)[1]).parent.name, set()).add(agent)
        self.assertEqual(set(referenced), set(self.skills), "every skill is loaded by some agent")
        for name, (meta, body) in self.skills.items():
            with self.subTest(skill=name):
                for title in SKILL_SECTIONS:
                    self.assertTrue(section(body, title).strip(), f"{name}: section {title}")
                self.assertIn("soc-core.md", body)
                listed = section(body, "Tools permitidas")
                for line in listed.splitlines():
                    for tool in TOOL_NAME.findall(line):
                        self.assertIn(tool, self.public, f"{name}: {tool}")
                        for agent in referenced[name]:
                            if "(somente case-investigator)" in line and agent != "case-investigator":
                                continue
                            self.assertIn(tool, bridge_tools(self.agents[agent][0]), f"{name} → {agent}: {tool}")

    def test_routing_table_maps_requests_to_existing_components(self):
        core = (KIRO / "steering" / "soc-core.md").read_text(encoding="utf-8")
        table = section(core, "Roteamento")
        rows = routing_rows(table)
        self.assertGreaterEqual(len(rows), 15)
        agent_tools = {name: bridge_tools(front) for name, (front, _) in self.agents.items()}
        self.assertEqual(routing_violations(rows, agent_tools), [])
        seen_skills = set()
        for request, _, entry, skill in rows:
            with self.subTest(request=request):
                for tool in TOOL_CALL.findall(entry):
                    self.assertIn(tool, self.public)
                if skill not in ("—", "conforme a origem"):
                    self.assertIn(skill, self.skills)
                    seen_skills.add(skill)
        self.assertEqual(seen_skills, set(self.skills))
        demo = [r for r in rows if "investigate_demo" in r[2]]
        self.assertTrue(demo and all("response-advisor" not in r[1] for r in demo))
        for request in ("offense X", "WB-X", "View event", "UacAudit", "Reputação web", "AD", "Hipótese", "Relatório",
                        "Plano de resposta", "Backup", "Dado que as entradas curadas não coletam"):
            self.assertIn(request, table)

    def test_routing_check_rejects_owners_without_the_tool(self):
        agent_tools = {name: bridge_tools(front) for name, (front, _) in self.agents.items()}
        contradictory = routing_rows("| Treino sem credenciais | qualquer | `investigate_demo()` | — |\n"
                                     "| Plano de resposta | response-advisor | `get_case(case_id)` | — |\n"
                                     "| Relatório | report-witer | caso | incident-report |")
        self.assertEqual(routing_violations(contradictory, agent_tools), [
            "Treino sem credenciais: response-advisor does not expose investigate_demo",
            "Plano de resposta: response-advisor does not expose get_case",
            "Relatório: unknown agent report-witer",
        ])

    def test_handoff_contract_is_defined_and_consumed(self):
        core = section((KIRO / "steering" / "soc-core.md").read_text(encoding="utf-8"), "Delegação e contrato de passagem")
        fields = ("pergunta", "entidades", "janela", "referências", "fatos_confirmados", "vínculos_candidatos",
                  "contradições", "cobertura", "pendências", "orçamento", "formato_de_retorno")
        for field in fields:
            self.assertIn(f"`{field}`", core)
        self.assertIn("O subagente não recebe o histórico", core)
        self.assertIn("nunca diga que um subagente executou sem o retorno da delegação", core)
        for agent in ("threat-hunter", "report-writer", "response-advisor"):
            self.assertIn("contrato de passagem", self.agents[agent][1], agent)
        investigator = self.agents["case-investigator"][1]
        self.assertIn("fração explícita do orçamento", investigator)
        self.assertIn("Sem retorno da delegação, nada foi executado por ele", investigator)

    def test_steering_inclusion_and_main_source(self):
        steering = {p.name: front_matter(p)[0] for p in (KIRO / "steering").glob("*.md")}
        always = sorted(n for n, f in steering.items() if f.get("inclusion") == "always")
        self.assertEqual(always, ["soc-core.md"])
        loaded = {Path(r.split("://", 1)[1]).name for front, _ in self.agents.values() for r in front.get("resources", [])
                  if r.startswith("file://")}
        for name, meta in steering.items():
            with self.subTest(steering=name):
                self.assertIn(meta.get("inclusion"), ("always", "auto", "fileMatch", "manual"))
                if meta["inclusion"] == "auto":
                    self.assertTrue(meta.get("name") and meta.get("description"))
                    self.assertIn("soc-core.md", (KIRO / "steering" / name).read_text(encoding="utf-8")[:1200])
                    self.assertIn(name, loaded, "domain steering must reach the custom agents")
                if meta["inclusion"] == "fileMatch":
                    self.assertTrue(meta.get("fileMatchPattern"))
                    self.assertNotIn(name, loaded)
        self.assertTrue(all(f"file://.kiro/steering/soc-core.md" in front.get("resources", [])
                            for front, _ in self.agents.values()))

    def test_scenarios_have_rules_and_code_checks(self):
        catalog = json.loads((ROOT / "tests" / "fixtures" / "kiro_scenarios.json").read_text(encoding="utf-8"))
        kinds = {"code": 0, "existing_test": 0, "rule_only": 0}
        for scenario in catalog["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                rule = scenario["rule"]
                self.assertIn(rule["phrase"], (ROOT / rule["file"]).read_text(encoding="utf-8"))
                check = scenario["verification"]
                kinds[check["type"]] += 1
                if check["type"] == "code":
                    CHECKS[check["check"]](self)
                elif check["type"] == "existing_test":
                    module, cls, method = check["test"].split(".")
                    sys.path.insert(0, str(ROOT / "tests"))
                    loaded = __import__(module)
                    self.assertTrue(callable(getattr(getattr(loaded, cls), method)))
                else:
                    self.assertTrue(check["pending"])
                    if "partial" in check:  # code covers one part; the rest of the scenario stays pending
                        self.assertTrue(check["partial"]["covers"])
                        CHECKS[check["partial"]["check"]](self)
        self.assertEqual(len(catalog["scenarios"]), 16)
        self.assertGreater(kinds["rule_only"], 0)  # model behaviors stay pending, never claimed as tested

    def test_specs_are_traceable_and_pending_is_explained(self):
        base = KIRO / "specs" / "kiro-operational-pack"
        requirements = (base / "requirements.md").read_text(encoding="utf-8")
        design = (base / "design.md").read_text(encoding="utf-8")
        for line in (base / "tasks.md").read_text(encoding="utf-8").splitlines():
            if line.startswith("- [ ]"):
                self.assertRegex(line, r"_Pending: .+_")
        for row in section(design, "Traceability").splitlines()[2:]:
            if not row.startswith("|"):
                continue
            cells = [c.strip() for c in row.strip("|").split("|")]
            for req in re.findall(r"(\d+\.\d+)", cells[0]):
                self.assertIn(req, requirements)
            for test in re.findall(r"`(test_[a-z0-9_]+)`", cells[2]):
                self.assertTrue(hasattr(PackContractTests, test), test)


# ------------------------------------------------------------------ code-verifiable scenarios

def _run(coro):
    return asyncio.run(coro)


def _digest(rows, tool="search_endpoint_activities_list"):
    from soc_bridge.xdr_followup import digest
    return digest([{"data": r} for r in rows], tool, "q", True, 0)


GUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
HOST = "ws-synth-01.example.test"


def xdr_plan_follows_listed_endpoint_order(test):
    """Only the XDR plan order: phases of each endpoint come in the order the alert lists them.

    The bridge does not tell the main endpoint from a contextual one, and it does not account for budget
    or for Ariel/QRadar priority; that part of the scenario is an agent decision (see BRIDGE-BACKLOG.md).
    """
    sys.path.insert(0, str(ROOT / "tests"))
    from trend_fixtures import NOW, T0, FakeVision, z
    from soc_bridge.alert_investigation import investigate_vision_alert
    other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    hosts = {GUID: {"name": HOST, "guid": GUID}, other: {"name": "ctx-server.example.test", "guid": other}}

    class NoQRadar:
        async def call(self, name, args):
            raise AssertionError("QRadar is not used")
    for listed in ([GUID, other], [other, GUID]):
        alert = {"id": "WB-SYNTH-CTX-0001", "model": "Synthetic Detection", "createdDateTime": z(T0),
                 "impactScope": {"entities": [{"entityType": "host", "entityId": g, "entityValue": hosts[g]}
                                              for g in listed]},
                 "matchedRules": [{"id": "r", "name": "Synthetic", "matchedFilters": [
                     {"id": "f", "name": "f", "matchedDateTime": z(T0), "matchedEvents": []}]}]}
        report = _run(investigate_vision_alert(NoQRadar(), FakeVision(alert=alert, search=lambda t, a: []),
                                               alert["id"], enable_vision_search=True, qradar_correlation=False,
                                               now=NOW))
        phases = report["xdr_followup"]["phases"]
        owners = [g for p in phases for g in listed if g in p["parameters"]["query"]]
        test.assertEqual(len(owners), len(phases))  # every phase names exactly one listed endpoint
        test.assertEqual(phases[0]["kind"], "command_series")
        test.assertEqual(owners, sorted(owners, key=listed.index))  # all phases of the first, then the next


def remote_name_is_kept_as_command_text_only(test):
    cmd = "rclone.exe copy C:\\Data\\Reports Google_Drive:archive"
    d = _digest([{"uuid": "u1", "endpointGuid": GUID, "endpointHostName": HOST, "processHashId": "inst-1",
                  "processFilePath": "C:\\Tools\\rclone.exe", "processCmd": cmd}])
    test.assertEqual([c["cmd"] for c in d["commands"]], [cmd])
    text = json.dumps(d).lower()
    for claim in ("personal", "corporate", "backend", "pessoal", "corporativ"):
        test.assertNotIn(claim, text)
    test.assertIsNone(d["volume"]["total"])


def transfer_stages_are_ordered_and_distinct(test):
    from soc_bridge.xdr_followup import TRANSFER_STAGES
    names = [s["stage"] for s in TRANSFER_STAGES]
    test.assertEqual(names, ["binary_present", "configuration_accessed", "command_started", "connection_attributed",
                             "traffic_observed", "operation_completed"])
    completion = TRANSFER_STAGES[-1]["established_by"]
    test.assertNotIn("counter", completion)


def pid_reuse_and_large_ids_stay_distinct(test):
    base = {"endpointGuid": GUID, "endpointHostName": HOST, "processFilePath": "C:\\Tools\\tool.exe", "processPid": 4242}
    big = -(2 ** 62) - 5
    d = _digest([dict(base, uuid="a", processHashId=big, logonUser=["EXAMPLE\\user.a"]),
                 dict(base, uuid="b", processHashId=big - 2, logonUser=["EXAMPLE\\user.b"])])
    test.assertEqual([a["instance"] for a in d["actors"]], [str(big), str(big - 2)])
    test.assertEqual([a["users"] for a in d["actors"]], [["EXAMPLE\\user.a"], ["EXAMPLE\\user.b"]])


def identifier_match_is_not_linked(test):
    from soc_bridge.alert_discovery import classify
    sha = "ab" * 32
    parsed = {"matched_event_uuids": ["ev-linked"], "observables": {"hash": [{"value": sha}], "path": [], "command": []}}
    record = {"uuid": "ev-other", "endpoint_guid": GUID, "endpoint_host": HOST,
              "process": {"fileHashSha256": sha, "filePath": "C:\\Tools\\tool.exe"}}
    label, reasons = classify(record, parsed, [{"guid": GUID, "name": HOST}])
    test.assertEqual(label, "identifier_match")
    test.assertNotEqual(label, "linked")


def host_level_network_record_is_not_process_attributed(test):
    d = _digest([{"uuid": "n1", "endpointHostName": HOST, "src": "192.0.2.10", "dst": "198.51.100.20", "dpt": 443,
                  "bytesSent": 1000}], tool="search_network_activities_list")
    connection = d["connections"][0]
    test.assertIsNone(connection["actor_instance"])
    test.assertIn("not attributable", connection["attribution"])
    test.assertEqual(d["transfer_counters"], [])  # unverified counter semantics never become volume


def repeated_session_counters_are_never_summed(test):
    from soc_bridge import xdr_followup
    tool = "search_endpoint_activities_list"
    row = {"uuid": "c1", "endpointGuid": GUID, "endpointHostName": HOST, "processHashId": "inst-1", "src": "192.0.2.10",
           "spt": 50000, "dst": "198.51.100.20", "dpt": 443, "flowId": "flow-1", "bytesSent": 100}
    with mock.patch.dict(xdr_followup.NETWORK_COUNTERS, {(tool, "bytesSent"): {"unit": "bytes", "direction": "sent"}}):
        d = _digest([row, dict(row, uuid="c2", bytesSent=900), dict(row, uuid="c3", spt=50001, bytesSent=50)])
    test.assertEqual([c["value"] for c in d["transfer_counters"]], [100, 900, 50])
    test.assertEqual(d["volume"]["repeated_sessions"][0]["readings"], 2)
    test.assertIsNone(d["volume"]["total"])
    test.assertNotIn("1000", json.dumps(d["volume"]))


def empty_search_is_bounded_to_its_window(test):
    from soc_bridge.trend_search import collect, parameters
    selection = parameters(f'endpointGuid:"{GUID}"', start_date_time="2026-10-01T00:00:00Z",
                           end_date_time="2026-10-01T01:00:00Z")
    result = _run(collect(SimpleNamespace(call=AsyncMock(return_value={"items": []})), selection))
    test.assertEqual(result["outcome"], "empty")
    test.assertIn("does not prove complete endpoint logging", result["coverage_note"])
    test.assertEqual(result["errors"], [])


CHECKS = {f.__name__: f for f in (xdr_plan_follows_listed_endpoint_order, remote_name_is_kept_as_command_text_only,
                                  transfer_stages_are_ordered_and_distinct, pid_reuse_and_large_ids_stay_distinct,
                                  identifier_match_is_not_linked, host_level_network_record_is_not_process_attributed,
                                  repeated_session_counters_are_never_summed, empty_search_is_bounded_to_its_window)}


if __name__ == "__main__":
    unittest.main()
