# Design

## Evidence about the target version

Kiro IDE 1.4.26 (`resources/app/product.json`, build date 2026-10-22) was inspected offline in `extensions/kiro.kiro-agent/dist/extension.js`:

- **Resource resolution:**
  - A resource is a `file://` or `skill://` prefix plus a path.
  - The path is resolved by `path.join(workspaceFolder, path)` unless it is absolute or starts with `~`. Globs are expanded.
  - A `skill://` path is read directly as the `SKILL.md` file and needs `name` and `description` front matter.
  - So `skill://<name>` alone resolves to `<workspace>/<name>`, which does not exist, and the skill does not load.
- **Front-matter schema:** `name`, `description`, `tools`, `excludedTools`, `model`, `effortLevel`, `includeMcpJson`, `includePowers`, `mcpServers`, `resources`, `permissions`, `welcomeMessage`, `dispatchKind` and `hooks`. `allowedTools` and `toolsSettings` are flagged as CLI-only fields.
- **Tool filtering:** a tool is kept when an entry equals its id, an alias or a tag.
  - Each custom agent becomes a delegation tool tagged `subagent`, `@subagent` and `subagent/<id>`.
  - `disclose_context`, which loads skills and `inclusion: auto` steering on demand, has no tags and is matched by id.
- **Steering inclusion modes:** `always`, `fileMatch`, `manual` and `auto` (with `name` and `description`).

The documentation (kiro.dev, see `docs/kiro-pack-compatibility.md`) confirms:

- the `subagent` tool;
- `skill://` paths and globs;
- `toolsSettings.subagent.availableAgents` for the CLI;
- that subagents have isolated history and their own `tools`.

Per-agent `subagent/<id>` entries are taken from the installed code, not from the documentation.

## Structure

| Component | Change |
| --- | --- |
| `steering/soc-core.md` (always) | Main source: scope and reads vs local writes, routing table, autonomy/budget/stop, job continuity, collection states, evidence rules, delegation contract, safety. Replaces soc-principles, operational-execution, safety-guardrails and evidence-and-limits. |
| Domain steering | `inclusion: auto` with name/description and a pointer to soc-core: case-workflow, offense-verification, qradar-aql-conventions, trend-search-conventions, upstream-access, investigation-methodology. `product.md` and `tech.md` become `fileMatch` on source files. `investigation.md` (legacy, manual) is removed; its unique EPM, web-reputation and Ariel rules moved to skills and qradar-aql-conventions. |
| Agents | Path-form `skill://`; `disclose_context`; case-investigator delegates through `subagent/threat-hunter`, `subagent/report-writer` and `subagent/response-advisor`; threat-hunter loses `qradar_assess_closure` (decision belongs to the investigator); report-writer works without a case. |
| Skills | Uniform sections. New sections: authentication/identity and Linux/Windows privilege (offense-investigation), process↔network attribution (exfiltration-assessment), handoff-based hunting, report from received evidence. |
| Tests | `tests/test_kiro_pack_contract.py` re-implements the 1.4.26 resolver and the front-matter schema. It checks permissions, the skill↔tool compatibility, routing and the handoff contract, and runs the code-verifiable scenarios from `tests/fixtures/kiro_scenarios.json`. |

## Traceability

| Requirement | Implementation | Test | Validation evidence |
| --- | --- | --- | --- |
| 1.1 | agent `resources` | `test_resources_resolve_like_kiro_1_4_26` | offline resolver; real activation pending |
| 1.2 | agent front matter | `test_front_matter_uses_ide_schema_only` | 1.4.26 schema |
| 1.3 | `tools` lists | `test_tools_are_bridge_tools_or_reviewed_builtins` | installed code; real delegation pending |
| 1.4 | soc-core routing table | `test_routing_table_maps_requests_to_existing_components` | structural |
| 2.1–2.4 | agents | `test_agent_boundaries` | structural |
| 2.5 | soc-core contract, agents | `test_handoff_contract_is_defined_and_consumed` | structural; real behavior pending |
| 3.1–3.2 | steering | `test_steering_inclusion_and_main_source` | structural |
| 3.3 | skills | `test_skills_have_sections_and_compatible_tools` | structural |
| 3.4 | soc-core, skills | `test_scenarios_have_rules_and_code_checks` | code checks for verifiable scenarios; the rest pending |
| 4.1–4.3 | tests, tasks | `test_specs_are_traceable_and_pending_is_explained` | CI |

## Out of scope

No change to the MCP server, credentials, launcher, change-server isolation or upstream access rules. Core Python improvements found during the review are listed in `BRIDGE-BACKLOG.md`.
