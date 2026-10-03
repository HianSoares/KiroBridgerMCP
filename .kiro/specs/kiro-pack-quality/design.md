# Design — Kiro pack and automated quality

## Agents

The front-matter `tools` lists use the existing `@soc-bridge-readonly/<tool>` syntax. No other permission syntax is introduced.

| Agent | Responsibility | Tools |
| --- | --- | --- |
| case-investigator | Investigation and interpretation | All bridge tools, including `investigate_offense_case` and `reassess_case` (local case writes) |
| threat-hunter | Hunting by hypothesis | Read tools plus `list_cases`, `get_case` and `bridge_diagnostics`; no case writes |
| report-writer | Writing from the consolidated case | `list_cases`, `get_case`, `investigate_demo` |
| response-advisor | Response recommendations for human execution | `tools: []` with `includeMcpJson: false`, unchanged |

## Steering and skills

- `case-workflow.md` (always included) defines the professional flow, when to ask, resume and reassess, and the prohibitions.
- `product.md` is corrected to describe sustained recommendations instead of "never assigns a verdict".
- `evidence-and-limits.md` adds the scoped-confirmation and contradiction rules.
- `tech.md` documents local writes, paginated discovery and CI.
- The `offense-investigation`, `incident-report` and `hypothesis-hunting` skills use the case tools.

## Consistency tests (`tests/test_pack_consistency.py`)

The tests check that:
- every `@soc-bridge-readonly/<name>` reference and every backticked tool-like name in `.kiro` and the docs exists in the registry;
- the README tool count matches the registry;
- each spec has its three files, uses EARS `WHEN/THE SYSTEM SHALL` criteria and has only checked tasks;
- `response-advisor` has no tools;
- `report-writer` cannot write cases.

## CI (`.github/workflows/ci.yml`)

- **Matrix:** `ubuntu-latest` and `windows-latest` × Python 3.11, 3.12 and 3.13.
- **Steps:** `pip install -e .`, `python -m unittest discover -s tests` (includes the schema snapshots and pack consistency), and `python scripts/build_coverage_matrix.py --check`.
- **Scope:** CI contacts no QRadar or Vision One instance.

## Limitations

The tests check references and structure, not whether Kiro interprets the text as intended. Behavior in the Kiro UI still needs a manual check after updates.
