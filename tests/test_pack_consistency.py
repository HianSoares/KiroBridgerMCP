"""Code, Kiro pack (agents, steering, skills, specs) and documentation must agree."""

import asyncio
import re
import unittest
from pathlib import Path

from soc_bridge.capabilities import LOCAL_WRITE_TOOLS, public_tools

ROOT = Path(__file__).resolve().parents[1]
TOOL_LIKE = re.compile(r"`((?:investigate|qradar|trend|bridge)_[a-z_]+|list_cases|get_case|reassess_case)\b")
# Identifiers with a tool-like prefix that are report fields, parameters or pivot actions.
NOT_TOOLS = {"qradar_correlation", "qradar_utc_offset_hours", "investigate_related_alert", "bridge_findings",
             "trend_link", "trend_state", "trend_finding_refuted",
             "qradar_link", "trend_finding_reinstated", "trend_hash_states",
             "qradar_instance_key"}  # functions, modules and record types
SPECS = ["capability-discovery-diagnostics", "case-persistence-resume", "investigation-orchestration-pivots",
         "evidence-decisions-closure", "kiro-pack-quality"]


def texts():
    files = list((ROOT / ".kiro").rglob("*.md")) + [ROOT / "README.md", ROOT / "README-kiro-pack.md"]
    files += [p for p in (ROOT / "docs").glob("*.md") if p.name != "coverage-matrix.md"]
    return {p: p.read_text(encoding="utf-8") for p in files}


class PackConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = asyncio.run(public_tools())

    def test_every_referenced_bridge_tool_exists(self):
        for path, text in texts().items():
            for name in re.findall(r"@soc-bridge-readonly/([A-Za-z0-9_]+)", text):
                self.assertIn(name, self.tools, f"{path.name}: {name}")
            for name in TOOL_LIKE.findall(text):
                if name not in NOT_TOOLS:
                    self.assertIn(name, self.tools, f"{path.relative_to(ROOT)}: `{name}`")

    def test_documented_tool_counts_match_the_registry(self):
        count = len(self.tools)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual([int(n) for n in re.findall(r"exposes \*\*(\d+) tools\*\*", readme)], [count])
        for path, text in texts().items():
            for number in re.findall(r"(?:São \*{0,2}|totalizando |now |Entre as |carregar as )(\d+) tools", text):
                self.assertEqual(int(number), count, f"{path.name} states {number} tools")

    def test_agent_responsibilities_and_tool_boundaries(self):
        agents = {p.stem: p.read_text(encoding="utf-8") for p in (ROOT / ".kiro" / "agents").glob("*.md")}

        def tools_of(name):
            header = agents[name].split("\n---", 1)[0]
            return set(re.findall(r"@soc-bridge-readonly/([a-z_]+)", header))
        self.assertRegex(agents["response-advisor"], r"(?m)^tools: \[\]$")
        self.assertIn("includeMcpJson: false", agents["response-advisor"])
        self.assertEqual(tools_of("report-writer"), {"list_cases", "get_case", "investigate_demo"})
        self.assertFalse(tools_of("threat-hunter") & LOCAL_WRITE_TOOLS)
        self.assertTrue(LOCAL_WRITE_TOOLS <= tools_of("case-investigator"))
        for name in agents:
            self.assertNotIn("toolsSettings", agents[name])  # only the documented tools-list syntax

    def test_specs_are_complete_and_tasks_verified(self):
        for spec in SPECS:
            base = ROOT / ".kiro" / "specs" / spec
            for file in ("requirements.md", "design.md", "tasks.md"):
                self.assertTrue((base / file).is_file(), f"{spec}/{file}")
            requirements = (base / "requirements.md").read_text(encoding="utf-8")
            self.assertIn("THE SYSTEM SHALL", requirements)
            self.assertIn("#### Acceptance Criteria", requirements)
            tasks = (base / "tasks.md").read_text(encoding="utf-8")
            self.assertRegex(tasks, r"- \[x\] 1\.")
            self.assertNotIn("- [ ]", tasks, f"{spec} has unchecked tasks")
            for ref in re.findall(r"_Requirements: ([^_]+)_", tasks):
                for item in re.findall(r"(\d+)\.\d+", ref):
                    self.assertIn(f"### Requirement {item}", requirements, f"{spec}: requirement {item}")

    def test_case_workflow_steering_is_loaded_by_the_investigator(self):
        steering = (ROOT / ".kiro" / "steering" / "case-workflow.md").read_text(encoding="utf-8")
        self.assertIn("inclusion: always", steering)
        self.assertIn("investigate_offense_case", steering)
        self.assertIn("case-workflow.md", (ROOT / ".kiro" / "agents" / "case-investigator.md").read_text(encoding="utf-8"))
        product = (ROOT / ".kiro" / "steering" / "product.md").read_text(encoding="utf-8")
        self.assertNotIn("never assigns a final", product)

    def test_case_rules_match_the_implemented_behavior(self):
        steering = (ROOT / ".kiro" / "steering" / "case-workflow.md").read_text(encoding="utf-8")
        for phrase in ("verify_alert_link", "processes", "fuso explícito", "pertence a uma offense", "uncovered_instances",
                       "instances_not_evaluated", "breadth_basis", "trend_finding_refuted", "não apaga fatos anteriores",
                       "trend_finding_reinstated", "ParentProcessGuid", "link_conflict", "link_contradicted",
                       "observations_after_refutation"):
            self.assertIn(phrase, steering)
        self.assertIn("UUID de evento Trend é proveniência", steering)
        self.assertIn("vínculos atuais e históricos", steering)
        self.assertIn("fora da tolerância temporal", steering)
        # Superseded promise: a shared hash/command line alone no longer demonstrates the link.
        self.assertNotIn("hash completo ou linha de comando exata compartilhados", steering)
        store = (ROOT / "docs" / "case-store.md").read_text(encoding="utf-8")
        for phrase in ("bloqueio exclusivo entre processos", "Checkpoints", "Isolamento por offense",
                       "não têm identidade suficiente"):
            self.assertIn(phrase, store)
        self.assertNotIn("o progresso do QRadar é salvo antes da etapa Trend", store)  # superseded promise
        self.assertNotIn("cada registro aparece uma vez", store)


if __name__ == "__main__":
    unittest.main()
