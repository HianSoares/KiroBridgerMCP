"""Markdown report for alert-first investigations; every section states provenance and limits."""

from __future__ import annotations

from typing import Any

SUMMARY_KEYS = ("name", "description", "severity", "status", "investigationStatus", "investigationResult", "model",
                "score", "createdDateTime", "updatedDateTime", "firstInvestigatedDateTime")


def _clip(value: Any, size: int = 400) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= size else text[:size] + " …[preview cut]"


def render(report: dict[str, Any]) -> str:
    a = report["alert"]
    ex = report["extraction"]
    lines = [f"# Vision One alert {report['alert_id']} -> QRadar", "", f"Generated (UTC): {report['generated_at']}", "",
             "## Vision One evidence", ""]
    lines += [f"- {k}: {_clip(a[k], 500)}" for k in SUMMARY_KEYS if k in a]
    lines += [f"- IPs in alert API detail: {', '.join(report['alert_ips']) or 'none'}",
              f"- IPs searched in QRadar address indexes: {', '.join(report['searched_ips']) or 'none'}",
              "", "## Structured alert extraction (provenance per value)", "",
              f"- Field states: {ex['field_states']}",
              f"- Impact scope counts: {ex['impact_scope_counts'] or 'not returned'}"]
    for endpoint in ex["endpoints"]:
        lines.append(f"- Endpoint: name={endpoint.get('name')} guid={endpoint.get('guid')} ips={endpoint.get('ips')} "
                     f"sources={endpoint['sources'][:4]}")
    for category, items in ex["observables"].items():
        for item in items[:10]:
            lines.append(f"- {category} [{item['role']}]: {_clip(item['value'], 300)} (from {item['sources'][0]}"
                         f"{'; cut by bridge' if item.get('cut_by_bridge') else ''})")
    for indicator in ex["indicators"][:15]:
        lines.append(f"- Indicator id={indicator.get('id')} type={indicator.get('type')} field={indicator.get('field')} "
                     f"related_entities={indicator.get('related_entities')}")
    for rule in ex["matched_rules"][:10]:
        for flt in rule["matched_filters"][:5]:
            lines.append(f"- Matched rule {rule.get('name')} / filter {flt.get('name')} at {flt.get('matched_date_time')}; "
                         f"MITRE {flt.get('mitre_technique_ids')}; matched events {len(flt['matched_events'])}")
    if ex.get("extraction_note"):
        lines += [f"- {ex['extraction_note']}", f"- Received structure (keys/types only): {_clip(ex['shape'], 1200)}"]
    anchor = report["anchor"]
    lines += ["", "## Clocks and time anchor", "",
              f"- Anchor: {anchor.get('time_utc')} — {anchor.get('basis')} (provisional: {anchor.get('provisional')})",
              f"- Alert clocks: {report['clocks'].get('alert')}",
              f"- Match times: {report['clocks'].get('match')[:6]}",
              f"- Event times (Search): {report['clocks'].get('event')[:6]}",
              f"- OAT detection/ingestion: {report['clocks'].get('detection_or_ingestion')[:6]}",
              f"- Collected at: {report['clocks'].get('collected_at')}",
              f"- {report['clocks'].get('timezone_note')}"]
    if report["manual_event"]:
        lines += ["", "## Analyst-supplied View event evidence (unverified by this tool)", ""]
        lines += [f"- {k}: {_clip(v, 500)}" for k, v in report["manual_event"].items()]
    auto = report.get("auto_pivots")
    if auto:
        lines += ["", "## Automatically discovered pivots", "", f"- Discovery logic: {auto['logic']}",
                  f"- Discovery status: {auto['discovery_status']}", f"- Window: {auto.get('window')}",
                  f"- Search calls (partitions): {auto['search_calls']}; records: {auto['search_rows']}; "
                  f"by relation: {auto.get('record_counts')}",
                  "- Relations: linked = uuid listed in matchedEvents; identifier_match = alert hash/path/command on the "
                  "same endpoint (candidate); context = same endpoint/time only. A nearby detection is not a verified "
                  "Workbench View event link."]
        for pivot in auto["pivots"] + auto.get("instance_followups", []):
            lines.append(f"- {pivot['tool']} `{_clip(pivot['query'], 200)}`: {pivot['state']}; partitions "
                         f"{len(pivot['partitions'])}; records {pivot.get('records_fetched')}; purpose {pivot['purpose']}")
        for result in auto.get("oat", []):
            lines.append(f"- OAT `{result['filter']}`: {result['state']}; batches {result['batches']}; items {len(result['items'])}")
            for item in result["items"][:8]:
                lines.append(f"  - {item.get('detected_date_time')} {item.get('link')}: "
                             f"{[f['name'] for f in item['filters']]} MITRE {[f['mitre_technique_ids'] for f in item['filters']]}")
        for label, items in auto["records"].items():
            for record in items[:8]:
                lines.append(f"  - [{label}] {record.get('time_utc')} {record['tool']} uuid={record.get('uuid')} "
                             f"process={_clip(record.get('process', {}).get('filePath'), 160)} "
                             f"cmd={_clip(record.get('process', {}).get('cmd'), 300)} "
                             f"object={_clip(record.get('object', {}).get('filePath'), 160)} "
                             f"reasons={record['relation']['reasons']} cut={record.get('cut_by_bridge')}")
        if auto.get("continuation"):
            lines.append(f"- Pending Trend partitions/refinements: {_clip(auto['continuation'][:10], 1500)}")
    dumps = report.get("dump_analysis") or {}
    if dumps.get("applicable"):
        lines += ["", "## Memory-dump tool analysis (intent, execution and file kept apart)", ""]
        for dump in dumps["dumps"]:
            lines += [f"- Command: {_clip(dump['command']['value'], 500)} (preview cut: {dump['command']['preview_cut']})",
                      f"- Intent: {dump['intent']}", f"- Execution: {dump['execution']}",
                      f"- Dump file: {dump['dump_file']}", f"- Target: {dump['target']}",
                      f"- Later dump-file activity: {_clip(dump['followups'], 1200)}",
                      f"- Attributable connections: {dump['connections'][:10]}",
                      f"- Hypotheses: {dump['hypotheses']}", f"- Not proven: {dump['not_proven']}",
                      f"- Needed: {dump['request']}"]
    if report.get("enrichment"):
        lines += ["", "## Read-only enrichments", ""]
        for name, item in report["enrichment"].items():
            lines.append(f"- {name}: {item.get('state')} — {item.get('purpose', item.get('reason', ''))}; "
                         f"trigger: {item.get('trigger', '-')}; items {item.get('count', 0)}"
                         + (f"; {item['error']['category']}" if item.get("error") else ""))
            for entry in item.get("items", [])[:5]:
                lines.append(f"  - {_clip(entry, 500)}")
            if item.get("handling"):
                lines.append(f"  - {item['handling']}")
    lines += ["", "## QRadar offense leads", ""]
    for item in report["offenses"]:
        lines += [f"### Offense {item['offense_id']}", "", f"- Shared IP: {', '.join(item['shared_ips'])}",
                  f"- Time check: {item['timing']}", f"- Relation: {item['relation']}",
                  f"- QRadar interval: {item['start'] or 'unknown'} to {item['last_updated'] or 'unknown'}"]
        lines += [f"- QRadar {k}: {_clip(v, 500)}" for k, v in item["fields"].items() if k not in ("start_time", "last_updated_time")]
        lines.append("")
    if not report["offenses"]:
        lines.append("No offense lead in inspected address indexes." if report["successful_queries"]
                     else "No successful address-index query was run; inspect the warnings above.")
    corr = report.get("qradar_correlation")
    if corr:
        lines += ["", "## QRadar Ariel correlation (budgeted, epoch predicates)", ""]
        lines += [f"- IP {e['ip']}: {e['attribution']}; sources {e['sources'][:3]}" for e in corr["ips"]]
        lines += [f"- Stage {s['stage']}: {s['window_utc']} — {s['why']}; clause {s['time_clause'].get('search_window') or s['time_clause'].get('reason')}"
                  for s in corr["stages"]]
        for key, query in corr["queries"].items():
            lines.append(f"- {key}: {query['state']}; outcome {query.get('outcome')}; search ID {query.get('search_id')}; "
                         f"rows {query.get('returned_rows')}; AQL: `{_clip(query['aql'], 600)}`")
        for relation in corr["relations"][:15]:
            lines.append(f"  - relation {relation['label']}: Trend {relation['trend_uuid']} ({relation['trend_role']}) vs "
                         f"QRadar {relation['qradar']} — {relation['identifiers_equal'] or 'no identifier equal'}")
        if corr["relations"]:
            lines.append(f"- Criteria: {corr['relations'][0]['criteria']}")
        if corr["plan"]:
            lines.append(f"- QRadar plan/pending: {_clip(corr['plan'][:8], 1500)}")
        lines.append("- Hostname text or a shared IP does not link a QRadar event to the Trend process.")
    tl = report["timeline"]
    lines += ["", "## Evidence timeline (UTC, collected sample)", ""]
    lines += [f"- {e['time_utc']} | {e['source']} | {e['type']} | {_clip(e['summary'], 200)} | ref={e['reference']}"
              for e in tl["entries"]]
    if not tl["entries"]:
        lines.append("- No event timestamp returned by the enabled searches.")
    if tl["truncated"]:
        lines.append(f"- Timeline capped at {len(tl['entries'])} of {tl['total_sampled_entries']} collected entries.")
    lines.append(f"- {tl['note']}")
    asm = report["assessment"]
    lines += ["", "## Assessment (recommendation for human review)", "",
              f"- Recommended classification: {asm['classification']} (confidence {asm['confidence']})",
              f"- Justification: {asm['justification']}", f"- Facts: {asm['facts']}",
              f"- Malicious discriminators: {asm['malicious_discriminators']}",
              f"- Blocking items: {asm['blocking']}", f"- Secondary pending items: {asm['secondary']}",
              f"- Hypotheses: {asm['hypotheses']}", f"- {asm['qradar_closure_note']}", "",
              "### Nota sugerida (pt-BR, não publicada)", "", asm["note_pt"],
              "", "## Coverage and analyst checks", "", f"- Method: {report['method']}", f"- Budget: {report['budget']}"]
    lines += [f"- {item}" for item in report["warnings"]]
    lines += ["- An IP and a time overlap are investigation leads, not a verdict.",
              "- Nothing was executed, closed, isolated, posted or submitted by this tool.", ""]
    return "\n".join(lines)
