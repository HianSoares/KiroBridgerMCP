# Requirements Document

## Introduction

Decisions must follow from evidence: each disposition and each closing reason has explicit requirements, supporting and contradicting evidence is evaluated, analyst records carry scope and origin, and confidence is justified without numeric scores.

## Requirements

### Requirement 1 — Dispositions and catalog reasons

**User Story:** As an analyst, I want dispositions kept apart from the local closing catalog, so that a category is not mistaken for a reason ID.

#### Acceptance Criteria

1. THE SYSTEM SHALL evaluate the dispositions malicious_confirmed, authorized_activity and detection_error, and report inconclusive when none is sustained. It SHALL evaluate an explicit administrative decision separately.
2. THE SYSTEM SHALL explain how each disposition relates to the catalog and SHALL NOT treat them as equivalent.
3. THE SYSTEM SHALL read the live closing-reason catalog and SHALL NOT invent a reason or ID.
4. WHEN a catalog reason is custom THE SYSTEM SHALL evaluate it only with a valid local definition (`SOC_BRIDGE_CLOSING_REASONS`) whose requirements are known IDs.

### Requirement 2 — Scoped confirmations

**User Story:** As an analyst, I want my external records to count only for what they cover, so that a generic authorization does not close unrelated activity.

#### Acceptance Criteria

1. THE SYSTEM SHALL accept for authorization, malicious_activity_confirmed and detection_error a scope with activity, entities and window, plus source and reference.
2. WHEN an observed activity is not covered by a scoped record (activity, entity overlap, window covering the observed interval) THE SYSTEM SHALL keep the requirement unmet and name the uncovered activities.
3. WHEN a record's window does not cover the observed interval THE SYSTEM SHALL record an unresolved contradiction affecting that requirement.
4. THE SYSTEM SHALL label every confirmation as analyst-supplied and not verified by the bridge.

### Requirement 3 — Contradictions

**User Story:** As a reviewer, I want contradictions to block only what depends on them, so that facts are still reported.

#### Acceptance Criteria

1. WHEN an unresolved contradiction affects a requirement THE SYSTEM SHALL mark every conclusion that needs it as contradicted.
2. WHEN bridge evidence confirms malicious activity THE SYSTEM SHALL mark authorized_activity and detection_error as contradicted.
3. THE SYSTEM SHALL still report confirmed facts and evaluate an administrative decision separately.

### Requirement 4 — Sustained conclusions and confidence

**User Story:** As an analyst, I want a conclusion when the evidence supports it, and precise pending items when it does not.

#### Acceptance Criteria

1. WHEN every requirement of exactly one reason is met THE SYSTEM SHALL recommend it with `ready_to_close=true` for human review.
2. WHEN requirements are missing THE SYSTEM SHALL report inconclusive with each missing requirement and its next check.
3. THE SYSTEM SHALL justify confidence by link quality, provenance (bridge or external), coverage, corroboration and contradictions, with no numeric score.

### Requirement 5 — Report and note

**User Story:** As a reviewer, I want a standard report and a Portuguese note reflecting the current decision.

#### Acceptance Criteria

1. THE SYSTEM SHALL output the decision, observed behavior, decisive evidence with references, hypotheses and tests, contradictions, coverage, limitations, confidence and basis, closing reason or impediments, next action and the note.
2. THE SYSTEM SHALL build the note from the current decision and collected facts only, and SHALL NOT close, post, alter rules or contain.
