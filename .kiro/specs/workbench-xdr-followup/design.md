# Design

No new public tool or parameter is added. The existing `investigate_vision_alert`, `trend_read_search_resource` and `trend_search_data` tools carry the flow, and two outputs make it explicit.

## Alert report

`xdr_followup.py` builds the `xdr_followup` section of the alert report from three inputs: the structured Workbench extraction, the full Search records linked or matched by the initial collection, and the time anchor. The section contains:

- **Seeds:** the known identifiers, each with its provenance.
- **Phases:** deduplicated `trend_search_data` parameter sets. Endpoint scope uses GUID, then host, then IP, and queries use only validated values and the field names of the audited Search contract. The phases cover:
  - the endpoint command series;
  - posterior activity;
  - detections;
  - Network Activity Data;
  - per-instance activity and children;
  - for transfer or backup terms found in the alert or in collected commands, the tool's commands, its launchers and its configuration file.
- **Transfer stages:** each stage with what establishes it and what it does not establish.
- **Volume sources:** QRadar flows and Trend fields with verified counter semantics (none in the audited contracts), each with what it proves and its limits.

## Search digest

`trend_search.collect` attaches `evidence_digest` to every non-count result. The digest normalizes each returned record by role and lists, with record provenance:

- file objects and connections, each connection labelled with its attribution;
- actors that are one execution only when processHashId identifies them, separate observations otherwise, and image aggregates labelled as such; command occurrences with endpoint, role and instance;
- network counters only from the verified-semantics table, kept per record and per session; every other numeric metric unclassified with its native value. Repeated readings are flagged and nothing is summed.

## Assessment scope

`assessment.scope` and the opening line of `note_pt` delimit the assessment to the initial collection. `assessment.authorization` states that a pending authorization neither hides facts nor supports Benign True Positive.

## Kiro pack

Agents, skills and steering are updated to follow the phases, compare identifiers and deliver in the requested order. The tool lists now include the Search tools.
