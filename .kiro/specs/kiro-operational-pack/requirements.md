# Requirements: Kiro operational pack (agents, skills, steering, specs)

## Introduction

A request such as "investigue a offense X" or "investigue o alerta WB-X" must start a coherent, bounded investigation in Kiro:

- specialized procedures are selected;
- entities are discovered;
- QRadar and Trend are correlated;
- the pertinent leads are deepened;
- the report is traceable.

The compatibility target is Kiro IDE 1.4.26 (installed build 2026-10-22) and the kiro.dev documentation pages updated between 2026-10-10 and 2026-10-24 (see `docs/kiro-pack-compatibility.md`).

### Requirement 1 — Loading and routing

#### Acceptance Criteria

1.1 THE SYSTEM SHALL declare agent resources in forms that the target version resolves: `file://` and `skill://` paths relative to the workspace root, with `skill://` pointing at a `SKILL.md` that has valid `name` and `description` front matter.
1.2 THE SYSTEM SHALL use only agent front-matter fields of the target IDE schema and SHALL NOT use CLI-only fields (`allowedTools`, `toolsSettings`).
1.3 THE SYSTEM SHALL list `disclose_context` for agents that reference skills, and SHALL restrict delegation to named agents through `subagent/<name>` entries of the orchestrator only.
1.4 THE SYSTEM SHALL route representative requests (offense, WB alert, XDR, transfer, EPM, web reputation, AD count, upstream data, hunting, report, response) to an existing agent, entry tool and skill.

### Requirement 2 — Responsibilities and boundaries

#### Acceptance Criteria

2.1 THE SYSTEM SHALL give case-investigator the objective, plan, budget, skill selection, case writes, delegation and consolidation.
2.2 THE SYSTEM SHALL give threat-hunter hypothesis tests from a handoff, without case writes, local file writes or delegation.
2.3 THE SYSTEM SHALL give report-writer writing from received evidence or the persisted case, including Workbench investigations without a case, without collection tools.
2.4 THE SYSTEM SHALL keep response-advisor without tools or MCP and make recommendations proportional to risk, impact, confidence and reversibility, where high confidence alone does not justify disruptive containment.
2.5 THE SYSTEM SHALL define a handoff contract (question, entities, window, references, facts, candidate links, contradictions, coverage, pending items, budget, return format) and SHALL NOT claim subagent execution without a delegation result.

### Requirement 3 — Steering and skills

#### Acceptance Criteria

3.1 THE SYSTEM SHALL keep common rules in one always-included source (`soc-core.md`) and load domain steering on demand (`inclusion: auto`) or through agent resources, with developer context limited to source files.
3.2 THE SYSTEM SHALL state autonomy, question limits, shared budget, progress and stop criteria, job resumption, distinct collection states and the difference between product reads and local writes.
3.3 THE SYSTEM SHALL give each skill when to use, when not to use, minimum inputs and automatic discovery, procedure, expected evidence and failures, continuation and stop, output, and allowed tools that exist in the profiles that reference it.
3.4 THE SYSTEM SHALL encode the observed failure scenarios as rules without concluding benignity, policy violation or malice from names, accounts, paths, internal destinations or absent bytes.

### Requirement 4 — Validation levels

#### Acceptance Criteria

4.1 THE SYSTEM SHALL test configuration structure, resolvable references, permissions, skill and tool compatibility, routing and handoff contract offline.
4.2 THE SYSTEM SHALL run the synthetic scenarios that existing code can execute and mark the remaining ones as rule-only, pending a real Kiro evaluation.
4.3 THE SYSTEM SHALL keep pending real-Kiro validation as unchecked tasks with a recorded reason, instead of marking it complete.
