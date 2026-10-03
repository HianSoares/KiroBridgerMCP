# Requirements Document

## Introduction

The Kiro pack (agents, steering, skills, specs) and the documentation must match the code, give each agent a clear responsibility with compatible tools, and be checked automatically on Windows and Linux.

## Requirements

### Requirement 1 — Agent responsibilities

**User Story:** As a team lead, I want each agent profile to do one job with the tools that job needs.

#### Acceptance Criteria

1. THE SYSTEM SHALL give `case-investigator` investigation and interpretation, including the only case-writing tools.
2. THE SYSTEM SHALL give `threat-hunter` hypothesis-driven hunting with read tools and case reads only.
3. THE SYSTEM SHALL give `report-writer` only `list_cases`, `get_case` and `investigate_demo`, writing from the consolidated case.
4. THE SYSTEM SHALL keep `response-advisor` with `tools: []` and no MCP loaded.

### Requirement 2 — Steering and skills

**User Story:** As an analyst, I want rules in steering and procedures in skills, without contradictions with the code.

#### Acceptance Criteria

1. THE SYSTEM SHALL provide a common case workflow steering for "investigue a offense X".
2. THE SYSTEM SHALL remove statements that contradict the current behavior (for example "never assigns a verdict").
3. THE SYSTEM SHALL keep guarantees that can be enforced in code (read-only allowlists, scoped confirmations, no recreation of uncertain jobs) implemented and tested, not only described.

### Requirement 3 — Automated consistency and CI

**User Story:** As a maintainer, I want CI to catch drift between code, schemas, pack and docs.

#### Acceptance Criteria

1. THE SYSTEM SHALL fail tests when an agent, steering, skill or spec references a bridge tool that does not exist.
2. THE SYSTEM SHALL fail tests when the documented tool count differs from the registry, when a spec task is unchecked, or when a spec lacks requirements, design or tasks.
3. THE SYSTEM SHALL run the full suite, the schema snapshots and the coverage-matrix check on Windows and Linux with Python 3.11 to 3.13.
4. THE SYSTEM SHALL use only synthetic data in public tests.
