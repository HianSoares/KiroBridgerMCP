"""Alert conclusion: chronology, relations, hypotheses, coverage and a reasoned classification.

Classes follow the Workbench meanings: True Positive (malicious activity confirmed),
Benign True Positive (real detection of legitimate/authorized activity), False Positive
(the detected behavior did not happen as described) and Inconclusive. The bridge never
forces a class: Benign True Positive needs an authorization source the bridge cannot
read, and False Positive needs evidence that the behavior did not occur, never mere
absence in a bounded search. The current telemetry/risk readers do not verify
malicious use or authorization, so the automated disposition remains Inconclusive;
Kiro can reassess with cited decisive evidence. This is not the QRadar closing reason.
"""

from __future__ import annotations

from typing import Any

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


def assess(report: dict) -> dict:
    discovery = report.get("auto_pivots") or {}
    counts = discovery.get("record_counts", {})
    dumps = (report.get("dump_analysis") or {}).get("dumps", [])
    enrichment = report.get("enrichment") or {}
    qr = report.get("qradar_correlation") or {}
    anchor = (report.get("clocks") or {}).get("anchor", {})
    facts, signals, blockers, secondary = [], [], [], []
    if counts.get("linked"):
        facts.append(f"{counts['linked']} Search record(s) linked to the alert by matchedEvents uuid")
    if counts.get("identifier_match"):
        facts.append(f"{counts['identifier_match']} record(s) matching alert identifiers (candidates)")
    executed = bool(counts.get("linked"))
    for dump in dumps:
        facts.append(f"Dump tool: {dump['intent']}; execution {dump['execution']}; dump file: {dump['dump_file']['status']}; "
                     f"target: {dump['target'].get('status')}")
        executed = executed or dump["execution"].startswith("observed")
        target = _base(dump["target"].get("image"))
        if target in CREDENTIAL_STORES and dump["target"]["status"].startswith("confirmed") and \
                dump["dump_file"].get("paths"):
            signals.append("credential-store target and attributed dump-file reference; creation and authorization unverified")
        if dump.get("connections"):
            facts.append("network connection by a dump-tool or dump-file actor instance; transferred content is not established")
        blockers.append("authorization/diagnostic source for the dump is not accessible to the bridge")
    for name, item in enrichment.items():
        if name.startswith("suspicious_objects") and item.get("state") == "collected" and any(
                str(i.get("riskLevel", "")).lower() == "high" for i in item.get("items", [])):
            signals.append("alert hash present as high risk in the configured Suspicious Object List; execution role and malicious use need corroboration")
        if item.get("state") in ("permission", "license_or_integration", "tool_absent", "unavailable", "format"):
            secondary.append(f"enrichment {name}: {item['state']}")
    if not counts.get("linked"):
        blockers.append("no Search record is linked to the alert by matchedEvents uuid")
    if anchor.get("provisional"):
        blockers.append(f"time anchor is provisional ({anchor.get('basis')})")
    if discovery.get("continuation"):
        blockers.append(f"{len(discovery['continuation'])} Trend search partition(s) pending or limited")
    for result in discovery.get("pivots", []) + discovery.get("instance_followups", []):
        if result.get("state") not in ("complete_in_window", "empty"):
            blockers.append(f"Trend Search coverage {result.get('state')}: {result.get('purpose') or result.get('tool')}")
    for result in discovery.get("oat", []):
        if result.get("state") not in ("complete_in_window", "empty"):
            blockers.append(f"OAT coverage {result.get('state')}: batches pending, failed or not started")
    for dump in dumps:
        for follow in dump.get("followups", []):
            if follow.get("state") not in ("complete_in_window", "empty"):
                blockers.append(f"Dump-file followup coverage {follow.get('state')}: {follow.get('file')}")
    if qr.get("plan"):
        secondary.append(f"{len(qr['plan'])} QRadar item(s) pending (continuation or verified-timezone run)")
    # Current readers expose telemetry and risk labels, not a verified finding of
    # malicious use/authorization. Do not turn either into a final disposition.
    classification, confidence = "Inconclusive", "low" if blockers else "moderate"
    if executed:
        why = ("behavior observed but the collected evidence does not establish malicious or authorized use; Benign True "
               "Positive needs an authorization source and True Positive needs a malicious discriminator tied to this execution")
    else:
        why = ("execution of the detected behavior is not confirmed in collected records; absence in bounded "
               "searches is not evidence of a False Positive")
    hypotheses = [
        {"id": "malicious", "supported_by": signals, "would_confirm": "verified malicious use tied to the same execution "
         "and artifact; target, risk label or a connection alone do not prove malicious use or transfer"},
        {"id": "authorized_or_operational", "supported_by": [], "would_confirm": "authorization/change/vendor record "
         "matching host, account, time and purpose (signature, vendor path, SYSTEM and 'No Findings' are not authorization)"},
        {"id": "detection_error", "supported_by": [], "would_confirm": "linked records showing the behavior did not occur"},
        {"id": "attribution_error", "supported_by": [], "would_confirm": "identifiers showing the records belong to a different host/process"}]
    return {"classification": classification, "confidence": confidence, "justification": why,
            "facts": facts, "malicious_discriminators": [], "suspicious_indicators": signals,
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
    lines = [f"Nota sugerida para revisão humana (não publicada) — alerta {report['alert_id']}"
             f" ({alert.get('model') or alert.get('name') or 'modelo não informado'}).",
             f"Classificação recomendada: {labels[classification]} (confiança {conf}).",
             f"Fundamento: {why}."]
    if facts:
        lines.append("Fatos observados (com proveniência no relatório): " + " | ".join(facts[:6]) + ".")
    if blockers:
        lines.append("Pendências que mantêm a avaliação preliminar: " + " | ".join(blockers[:6]) + ".")
    lines.append("Próximos passos: confirmar a fonte de autorização/diagnóstico quando houver ferramenta de uso duplo, "
                 "retomar as consultas pendentes indicadas no plano e validar vínculos Trend↔QRadar por identificadores, "
                 "não apenas por IP/horário.")
    lines.append("Esta nota não altera o status do alerta nem o motivo de fechamento de offense no QRadar.")
    return "\n".join(lines)
