"""Alert conclusion: chronology, relations, hypotheses, coverage and a reasoned classification.

Classes follow the Workbench meanings: True Positive (malicious activity confirmed),
Benign True Positive (real detection of legitimate/authorized activity), False Positive
(the detected behavior did not happen as described) and Inconclusive. The bridge never
forces a class: Benign True Positive needs an authorization source the bridge cannot
read, and False Positive needs evidence that the behavior did not occur, never mere
absence in a bounded search. Each class has explicit requirements (decision.py); a class
is recommended only when all of its requirements are met, and a gap only blocks the
classes that need it. This is not the QRadar closing reason.
"""

from __future__ import annotations

from typing import Any

from .decision import STATUSES, evaluate, requirement
from .trend_records import full_hashes

CREDENTIAL_STORES = {"lsass.exe"}


def _base(path: Any) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def timeline(report: dict, limit: int = 40) -> dict:
    rows: list[dict] = []
    clocks = report.get("clocks", {})
    for name, entry in clocks.get("alert", {}).items():
        rows.append({"time_utc": entry["time_utc"], "source": "Workbench alert", "type": f"alert {name}",
                     "summary": "alert clock (not an event time)", "reference": report["alert_id"]})
    for entry in clocks.get("match", []):
        rows.append({"time_utc": entry["time_utc"], "source": "Workbench matchedRules", "type": entry["kind"],
                     "summary": entry["source"], "reference": entry["source"]})
    discovery = report.get("auto_pivots") or {}
    for label in ("linked", "identifier_match"):
        for record in (discovery.get("records") or {}).get(label, []):
            actor = record.get("process", {}).get("filePath")
            target = record.get("object", {}).get("filePath") or record.get("network", {}).get("dst")
            rows.append({"time_utc": record.get("time_utc"), "source": f"Vision One {record['tool']}",
                         "type": f"{label} record", "summary": f"{actor or '?'} -> {target or '?'}",
                         "reference": str(record.get("uuid") or "")})
    for result in discovery.get("oat", []):
        for item in result.get("items", [])[:20]:
            rows.append({"time_utc": item.get("detected_date_time"), "source": "Vision One OAT",
                         "type": item.get("link", "OAT"), "summary": ", ".join(f["name"] or "" for f in item["filters"])[:200],
                         "reference": str(item.get("uuid") or "")})
    for relation in (report.get("qradar_correlation") or {}).get("relations", []):
        rows.append({"time_utc": relation["qradar"].get("starttime_utc"), "source": "QRadar Ariel",
                     "type": f"relation {relation['label']}", "summary": "; ".join(relation["identifiers_equal"]) or "same host only",
                     "reference": str(relation["qradar"].get("search_id"))})
    for dump in (report.get("dump_analysis") or {}).get("dumps", []):
        for follow in dump.get("followups", []):
            for record in follow.get("records", []):
                rows.append({"time_utc": record.get("time_utc"), "source": "Vision One Search", "type": record["kind"],
                             "summary": f"{record.get('actor')} on {follow['file']}", "reference": follow["file"]})
    rows = [r for r in rows if r.get("time_utc")]
    ordered, seen = [], set()
    for row in sorted(rows, key=lambda r: (r["time_utc"], r["source"])):
        key = tuple(row.values())
        if key not in seen:
            seen.add(key)
            ordered.append(row)
    return {"entries": ordered[:limit], "total_sampled_entries": len(ordered), "truncated": len(ordered) > limit,
            "note": "Collected sample with provenance; timestamps alone do not establish causality or a shared incident"}


COVERED = ("complete_in_window", "empty")


def _reads(report: dict) -> dict:
    return {**(report.get("enrichment") or {}), **(report.get("hypothesis_checks") or {})}


def _requirements(report: dict, facts: list, signals: list, secondary: list) -> tuple[dict, list[str]]:
    discovery = report.get("auto_pivots") or {}
    counts = discovery.get("record_counts", {})
    dumps = (report.get("dump_analysis") or {}).get("dumps", [])
    reads = _reads(report)
    anchor = (report.get("clocks") or {}).get("anchor", {})
    coverage_gaps: list[str] = []
    if discovery.get("continuation"):
        coverage_gaps.append(f"{len(discovery['continuation'])} Trend search partition(s) pending or limited")
    for result in discovery.get("pivots", []) + discovery.get("instance_followups", []):
        if result.get("state") not in COVERED:
            coverage_gaps.append(f"Trend Search coverage {result.get('state')}: {result.get('purpose') or result.get('tool')}")
    for result in discovery.get("oat", []):
        if result.get("state") not in COVERED:
            coverage_gaps.append(f"OAT coverage {result.get('state')}: batches pending, failed or not started")
    for dump in dumps:
        for follow in dump.get("followups", []):
            if follow.get("state") not in COVERED:
                coverage_gaps.append(f"Dump-file followup coverage {follow.get('state')}: {follow.get('file')}")
    executed = bool(counts.get("linked")) or any(d["execution"].startswith("observed") for d in dumps)
    ran = bool(discovery.get("pivots"))
    not_run = ran and all(p.get("state") in ("not_started", "unavailable") for p in discovery.get("pivots", []))
    req: dict[str, dict] = {}
    if executed:
        req["execution_observed"] = requirement(
            "execution_observed", "detected behavior observed in records linked to the alert", "confirmed",
            facts[:3])
    elif counts.get("identifier_match"):
        req["execution_observed"] = requirement(
            "execution_observed", "detected behavior observed in records linked to the alert", "candidate",
            f"{counts['identifier_match']} identifier match(es); no search record is linked to the alert by matchedEvents uuid",
            "Confirm the View event uuid or read the matched event in the console")
    elif not_run or not ran:
        req["execution_observed"] = requirement(
            "execution_observed", "detected behavior observed in records linked to the alert", "not_executed",
            "Search pivots did not run; no Search record is linked to the alert by matchedEvents uuid",
            "Enable/resume the Search pivots (see continuation)")
    else:
        req["execution_observed"] = requirement(
            "execution_observed", "detected behavior observed in records linked to the alert", "not_returned",
            "no Search record is linked to the alert by matchedEvents uuid in the inspected window",
            "Widen the window or check sensor telemetry for the endpoint")
    verdicts, unlinked = [], []
    linked_hashes = {h for record in (discovery.get("records") or {}).get("linked", [])
                     for role in ("process", "object", "parent", "detection_file")
                     for h in full_hashes(record.get(role) or {}).values()}
    for name, item in reads.items():
        if name.startswith("sandbox:") and item.get("state") == "collected":
            prefix = name.split(":", 1)[1].lower()
            for entry in item.get("items", []):
                if isinstance(entry, dict) and str(entry.get("riskLevel", "")).lower() == "high":
                    # The verdict counts only for a hash seen in a record linked to the alert.
                    tied = any(h.startswith(prefix) for h in linked_hashes)
                    (verdicts if tied else unlinked).append(f"{name}: existing sandbox analysis riskLevel=high"
                                                            + ("" if tied else " (hash not in a linked record)"))
        if name.startswith("suspicious_objects") and item.get("state") == "collected" and any(
                isinstance(i, dict) and str(i.get("riskLevel", "")).lower() == "high" for i in item.get("items", [])):
            signals.append("alert hash present as high risk in the configured Suspicious Object List; execution role and "
                           "malicious use need corroboration")
        if item.get("state") in ("permission", "license_or_integration", "tool_absent", "unavailable", "format"):
            secondary.append(f"read {name}: {item['state']}")
    if verdicts:
        req["malicious_discriminator"] = requirement(
            "malicious_discriminator", "malicious nature of the executed artifact demonstrated", "confirmed",
            sorted(set(verdicts)), source="Vision One sandbox analysis of an alert hash (existing result, no submission)")
    elif signals or unlinked:
        req["malicious_discriminator"] = requirement(
            "malicious_discriminator", "malicious nature of the executed artifact demonstrated", "compatible",
            signals + unlinked,
            "Obtain a verdict tied to this artifact (sandbox result, confirmed IOC or malicious follow-on activity)")
    else:
        req["malicious_discriminator"] = requirement(
            "malicious_discriminator", "malicious nature of the executed artifact demonstrated", "unverified", None,
            "True Positive needs a malicious discriminator tied to this execution")
    compatible_auth = []
    tasks = reads.get("response_tasks", {})
    if tasks.get("state") == "collected":
        compatible_auth.append(f"{tasks['count']} existing response task(s) on the alert endpoint")
    for name, item in reads.items():
        if name.startswith("exceptions:") and item.get("state") == "collected":
            compatible_auth.append(f"{name}: hash on the configured Exception List (configuration, not authorization)")
    auth_text = ("authorization/diagnostic source for the dump is not accessible to the bridge" if dumps else
                 "authorization/change/vendor record matching host, account, time and purpose")
    req["authorization_source"] = requirement(
        "authorization_source", auth_text, "compatible" if compatible_auth else "unverified", compatible_auth or None,
        "Benign True Positive needs an authorization source: cite the change/owner record (signature, vendor path, "
        "SYSTEM and 'No Findings' are not authorization)")
    req["behavior_absent"] = requirement(
        "behavior_absent", "linked records show the detected behavior did not occur as described", "unverified", None,
        "False Positive needs positive evidence; absence in bounded searches is not evidence of a False Positive")
    req["search_coverage_complete"] = requirement(
        "search_coverage_complete", "every relevant Search/OAT partition completed in the window",
        "confirmed" if ran and not coverage_gaps else "not_executed" if not ran else "unverified",
        coverage_gaps or None, "Resume the pending partitions listed in continuation")
    req["anchor_reliable"] = requirement(
        "anchor_reliable", "time anchor is an event or match time", "unverified" if anchor.get("provisional") else "confirmed",
        anchor.get("basis"), "Obtain the event/match time (linked record or View event)")
    return req, coverage_gaps


CONCLUSIONS = [
    {"id": "True Positive", "label": "malicious activity confirmed",
     "requires": ["execution_observed", "malicious_discriminator"]},
    {"id": "Benign True Positive", "label": "real detection of authorized/legitimate activity",
     "requires": ["execution_observed", "authorization_source"], "contradicted_by": ["malicious_discriminator"]},
    {"id": "False Positive", "label": "the detected behavior did not occur as described",
     "requires": ["behavior_absent", "search_coverage_complete"], "contradicted_by": ["execution_observed"]},
]


def assess(report: dict) -> dict:
    discovery = report.get("auto_pivots") or {}
    counts = discovery.get("record_counts", {})
    dumps = (report.get("dump_analysis") or {}).get("dumps", [])
    qr = report.get("qradar_correlation") or {}
    facts, signals, secondary = [], [], []
    if counts.get("linked"):
        facts.append(f"{counts['linked']} Search record(s) linked to the alert by matchedEvents uuid")
    if counts.get("identifier_match"):
        facts.append(f"{counts['identifier_match']} record(s) matching alert identifiers (candidates)")
    for dump in dumps:
        facts.append(f"Dump tool: {dump['intent']}; execution {dump['execution']}; dump file: {dump['dump_file']['status']}; "
                     f"target: {dump['target'].get('status')}")
        target = _base(dump["target"].get("image"))
        if target in CREDENTIAL_STORES and dump["target"]["status"].startswith("confirmed") and \
                dump["dump_file"].get("paths"):
            signals.append("credential-store target and attributed dump-file reference; creation and authorization unverified")
        if dump.get("connections"):
            facts.append("network connection by a dump-tool or dump-file actor instance; transferred content is not established")
    insights = report.get("insights") or {}
    for entry in insights.get("related", []):
        facts.append(f"Insight {entry['id']} related to the alert ({entry['relation']})")
    if qr.get("plan"):
        secondary.append(f"{len(qr['plan'])} QRadar item(s) pending (continuation or verified-timezone run)")
    req, coverage_gaps = _requirements(report, facts, signals, secondary)
    matrix = evaluate(CONCLUSIONS, req)
    sustained = [c for c in matrix if c["sufficiency"] == "sustained"]
    classification = sustained[0]["id"] if len(sustained) == 1 else "Inconclusive"
    if classification == "Inconclusive":
        confidence = "low"
        if req["execution_observed"]["status"] == "confirmed":
            why = ("behavior observed but the collected evidence does not establish malicious or authorized use; Benign True "
                   "Positive needs an authorization source and True Positive needs a malicious discriminator tied to this execution")
        else:
            why = ("execution of the detected behavior is not confirmed in collected records; absence in bounded "
                   "searches is not evidence of a False Positive")
    else:
        strong = req["anchor_reliable"]["status"] == "confirmed" and req["search_coverage_complete"]["status"] == "confirmed"
        confidence = "high" if strong else "moderate"
        why = (f"{classification}: every requirement of this conclusion is met ({', '.join(sustained[0]['met'])}); "
               + ("time anchor and Search coverage are complete." if strong else
                  "time anchor or Search coverage is incomplete, which does not change this conclusion but limits confidence."))
    relevant = [c for c in matrix if c["sufficiency"] != "contradicted"] if classification == "Inconclusive" else sustained
    blockers = []
    for conclusion in relevant:
        for item in conclusion["blocking"]:
            text = item["requirement"]
            if item["id"] == "execution_observed" and req["execution_observed"]["status"] != "confirmed":
                text = "no Search record is linked to the alert by matchedEvents uuid"
            blockers.append(f"{conclusion['id']}: {text} [{item['status']}]")
    blockers += coverage_gaps if classification == "Inconclusive" else []
    if req["anchor_reliable"]["status"] != "confirmed":
        blockers.append(f"time anchor is provisional ({req['anchor_reliable']['evidence']})")
    malicious = req["malicious_discriminator"]["evidence"] if req["malicious_discriminator"]["status"] == "confirmed" else []
    hypotheses = [
        {"id": "malicious", "supported_by": signals + list(malicious or []),
         "status": req["malicious_discriminator"]["status"],
         "would_confirm": "verified malicious use tied to the same execution and artifact; target, risk label or a "
                          "connection alone do not prove malicious use or transfer"},
        {"id": "authorized_or_operational", "supported_by": req["authorization_source"]["evidence"] or [],
         "status": req["authorization_source"]["status"],
         "would_confirm": "authorization/change/vendor record matching host, account, time and purpose (signature, "
                          "vendor path, SYSTEM and 'No Findings' are not authorization)"},
        {"id": "detection_error", "supported_by": [], "status": req["behavior_absent"]["status"],
         "would_confirm": "linked records showing the behavior did not occur"},
        {"id": "attribution_error", "supported_by": [], "status": "unverified",
         "would_confirm": "identifiers showing the records belong to a different host/process"}]
    return {"classification": classification, "confidence": confidence, "justification": why,
            "confidence_basis": ("No numeric score. Confidence follows the requirements: sustained + reliable anchor + "
                                 "complete relevant coverage = high; sustained with incomplete anchor/coverage = moderate; "
                                 "no sustained conclusion = low."),
            "facts": facts, "malicious_discriminators": list(malicious or []), "suspicious_indicators": signals,
            "requirements": req, "decision_matrix": matrix, "evidence_status_vocabulary": STATUSES,
            "blocking": list(dict.fromkeys(blockers)),
            "secondary": list(dict.fromkeys(secondary)), "hypotheses": hypotheses,
            "classes": {"True Positive": "malicious activity confirmed",
                        "Benign True Positive": "real detection of authorized/legitimate activity (needs authorization source)",
                        "False Positive": "the detected behavior did not occur as described (needs positive evidence)",
                        "Inconclusive": "decisive data missing; see blocking items"},
            "qradar_closure_note": "Trend classification is not a QRadar closing reason; QRadar closure keeps its own criteria.",
            "note_pt": note_pt(report, classification, confidence, why, facts, blockers)}


def note_pt(report: dict, classification: str, confidence: str, why: str, facts: list[str], blockers: list[str]) -> str:
    alert = report.get("alert", {})
    labels = {"True Positive": "Verdadeiro positivo", "Benign True Positive": "Verdadeiro positivo benigno",
              "False Positive": "Falso positivo", "Inconclusive": "Inconclusivo"}
    conf = {"high": "alta", "moderate": "moderada", "low": "baixa"}.get(confidence, confidence)
    window = (report.get("auto_pivots") or {}).get("window") or {}
    budget = report.get("budget") or {}
    lines = [f"Nota sugerida para revisão humana (não publicada) — alerta {report['alert_id']}"
             f" ({alert.get('model') or alert.get('name') or 'modelo não informado'}).",
             f"Classificação recomendada: {labels[classification]} (confiança {conf}).",
             f"Fundamento: {why}.",
             f"Janela consultada (UTC): {window.get('start') or 'não definida'} até {window.get('end') or 'não definida'}"
             f"; chamadas usadas {budget.get('calls_made', '?')} de {budget.get('max_calls', '?')}."]
    if facts:
        lines.append("Fatos observados (com proveniência no relatório): " + " | ".join(facts[:6]) + ".")
    if blockers:
        lines.append(("Pendências que impedem as demais conclusões: " if classification != "Inconclusive" else
                      "Pendências por conclusão: ") + " | ".join(blockers[:8]) + ".")
    lines.append("Próximos passos: verificar o item pendente de maior impacto indicado na matriz de decisão, retomar as "
                 "consultas pendentes do plano e validar vínculos Trend↔QRadar por identificadores, não apenas por IP/horário.")
    lines.append("Esta nota não altera o status do alerta nem o motivo de fechamento de offense no QRadar.")
    return "\n".join(lines)
