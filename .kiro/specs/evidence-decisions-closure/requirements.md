# Requirements Document

## Introduction

Decisions must follow from evidence: each disposition and each closing reason has explicit requirements, supporting and contradicting evidence is evaluated, analyst records carry precise scope and origin, a second source counts only when it demonstrably describes the same activity, and confidence is justified without numeric scores.

## Requirements

### Requirement 1 — Dispositions and catalog reasons

**User Story:** As an analyst, I want dispositions kept apart from the local closing catalog, so that a category is not mistaken for a reason ID.

#### Acceptance Criteria

1. THE SYSTEM SHALL evaluate the dispositions malicious_confirmed, authorized_activity and detection_error, and report inconclusive when none is sustained. It SHALL evaluate an explicit administrative decision separately.
2. THE SYSTEM SHALL explain how each disposition relates to the catalog and SHALL NOT treat them as equivalent.
3. THE SYSTEM SHALL read the live closing-reason catalog and SHALL NOT invent a reason or ID.
4. WHEN a catalog reason is custom THE SYSTEM SHALL evaluate it only with a valid local definition (`SOC_BRIDGE_CLOSING_REASONS`) whose requirements are known IDs.

### Requirement 2 — Precisely scoped confirmations

**User Story:** As an analyst, I want my external records to count only for the behavior they name, so that an authorization for one action on one host does not close other hosts, other commands of the same interpreter or other privileged commands.

#### Acceptance Criteria

1. THE SYSTEM SHALL accept for authorization, malicious_activity_confirmed and detection_error a scope with activity, entities and window, plus source and reference.
2. A `process_execution` scope SHALL name the processes and at least one behavior discriminator: exact command lines, script paths, artifact hashes, process instances, or an explicit breadth quoted from the external record. THE SYSTEM SHALL reject an artifact hash as the only discriminator of an interpreter (PowerShell, cmd, Python, bash and similar).
3. A `privilege_use` scope SHALL name exact commands, an explicit identity switch (su) or an explicit breadth quoted from the record, and MAY restrict the run-as accounts. A `script_execution` scope SHALL name the script block IDs.
4. THE SYSTEM SHALL evaluate each observed instance on its own: each process creation (host, image, original command line, executed script, hashes, instance, parent, time), each script block, each sudo command or su switch (host, account, run-as, command, times), and each entity of the other activities (with the times of its records).
5. WHEN an instance's entity, behavior/chain or time is not covered by a scoped record THE SYSTEM SHALL keep the requirement unmet and SHALL list that instance with the reason. Command lines SHALL be compared as original strings.
6. WHEN a broad authorization covers instances THE SYSTEM SHALL show it in the requirement evidence, the confidence basis and the note as declared by the external record.
7. THE SYSTEM SHALL evaluate every collected instance up to an analysis cap independent of the presentation caps; instances it cannot evaluate SHALL be counted per activity with reason and next action, and SHALL keep authorization and detection error unmet without blocking conclusions that do not depend on them.
8. WHEN an instance otherwise matches a record but falls outside its window THE SYSTEM SHALL record an unresolved contradiction affecting that requirement.
9. THE SYSTEM SHALL reject window times without an explicit timezone and SHALL NOT interpret local times as UTC.
10. THE SYSTEM SHALL label every confirmation as analyst-supplied and not verified by the bridge.

### Requirement 3 — Contradictions

**User Story:** As a reviewer, I want contradictions to block only what depends on them, so that facts are still reported.

#### Acceptance Criteria

1. WHEN an unresolved contradiction affects a requirement THE SYSTEM SHALL mark every conclusion that needs it as contradicted.
2. WHEN bridge evidence confirms malicious activity THE SYSTEM SHALL mark authorized_activity and detection_error as contradicted.
3. THE SYSTEM SHALL still report confirmed facts and evaluate an administrative decision separately.

### Requirement 4 — QRadar↔Trend link

**User Story:** As an analyst, I want a related Trend alert to confirm malicious activity in the offense only when the offense activity is the malicious execution or its demonstrated chain.

#### Acceptance Criteria

1. THE SYSTEM SHALL compare the offense-linked QRadar process records (INOFFENSE query) with the Trend records that sustain the malicious discriminator (executed instance with a high-risk verdict on its hash), not with alert-level observables.
2. THE SYSTEM SHALL compare hashes per algorithm and per role/artifact, keeping their source, and SHALL distinguish equal, conflicting (complete digests of the same algorithm differ), incomplete (cut or invalid), not comparable (different algorithms) and absent hashes.
3. THE SYSTEM SHALL demonstrate a same-execution link only on the same endpoint, with compatible execution times, without any conflicting hash or known identifier (PID, original command line, image path), and with either an equal complete hash plus an equal PID or identical command line, or, when no hash is comparable, an identical image path plus an equal PID.
4. WHEN complete hashes of the same algorithm or known identifiers conflict while weaker signals coincide THE SYSTEM SHALL record the conflict as a contradiction in the report and the assessment, SHALL NOT demonstrate the link with the weaker signals and SHALL NOT treat the conflict as evidence of benign activity.
5. THE SYSTEM SHALL demonstrate a parent/child relation only by instance identity: the Trend parent instance (for a newly launched object, the actor of the record) identified by the same rules, or a QRadar child whose ParentProcessGuid points to a QRadar process record on the same endpoint that is the malicious instance. Host-context records MAY serve as the parent record and SHALL be labelled as not INOFFENSE. A parent PID alone, a GUID of another endpoint or a reused PID SHALL NOT demonstrate a chain, whatever the time gap. Trend instance IDs and Sysmon GUIDs SHALL NOT be compared.
6. THE SYSTEM SHALL NOT use a file hash alone, a parent or object hash, hashes of one endpoint with the hostname of another, or the alert creation time as an execution time to demonstrate a link.
7. WHEN the link is not demonstrated THE SYSTEM SHALL keep a candidate association, SHALL NOT confirm malicious activity or corroboration, SHALL record an unresolved contradiction against benign dispositions, SHALL explain the gap and SHALL propose a pivot to demonstrate or exclude the link.
8. THE SYSTEM SHALL persist the structured basis (instances, roles, endpoints, times, hash states, verdict hashes, observables with role/source/cut flag) so the evaluation can be repeated without new calls.

### Requirement 5 — Sustained conclusions and confidence

**User Story:** As an analyst, I want a conclusion when the evidence supports it, and precise pending items when it does not.

#### Acceptance Criteria

1. WHEN every requirement of exactly one reason is met THE SYSTEM SHALL recommend it with `ready_to_close=true` for human review.
2. WHEN requirements are missing THE SYSTEM SHALL report inconclusive with each missing requirement and its next check.
3. THE SYSTEM SHALL justify confidence by link quality, provenance (bridge or external), coverage, demonstrated corroboration and contradictions, with no numeric score; high confidence SHALL require bridge-demonstrated requirements and demonstrated corroboration.

### Requirement 6 — Report and note

**User Story:** As a reviewer, I want a standard report and a Portuguese note reflecting the current decision.

#### Acceptance Criteria

1. THE SYSTEM SHALL output the decision, observed behavior, decisive evidence with references, hypotheses and tests, contradictions, coverage, limitations, confidence and basis, related alerts with their link level, closing reason or impediments, next action and the note.
2. THE SYSTEM SHALL build the note from the current decision and collected facts only, and SHALL NOT close, post, alter rules or contain.
