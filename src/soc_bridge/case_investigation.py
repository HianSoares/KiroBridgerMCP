"""Professional, resumable offense investigation persisted as a local case.

"Investigue a offense X" runs: identify case/scope/sources -> metadata snapshot -> offense-
linked collection (resuming known Ariel jobs from their cursors) -> checkpoint -> related
Trend alerts with alert-first depth -> scenario interpretation -> competing hypotheses ->
next pivots -> per-conclusion decision with contradictions -> report revision and a
Portuguese note for human review. Nothing is closed, posted or contained.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import closure_assessment, pivot_planner, scenarios
from .ariel_collection import Budget
from .case_store import CaseStore, merge_query, merge_trend, now_iso, scrub
from .core import iso

MAX_DECISIVE = 15


def _strip(result: dict) -> dict:
    return {k: v for k, v in result.items() if k != "collected_rows"}


def _bridge_findings(result: dict, trend: dict | None) -> tuple[dict, list[dict]]:
    findings, contradictions = {}, []
    linked_rows = (result.get("queries", {}).get("events") or {}).get("returned_rows") or 0
    for item in (trend or {}).get("investigations", []):
        if item.get("state") != "collected":
            continue
        assessment = item["report"]["assessment"]
        if assessment["classification"] == "True Positive":
            findings["malicious_activity_confirmed"] = {
                "alert_id": item["alert_id"], "facts": assessment["facts"][:4],
                "association": item.get("association"),
                "meaning": "Trend alert-first evaluation sustained True Positive (execution + malicious discriminator)"}
            findings["corroborated"] = bool(linked_rows)
    return findings, contradictions


def _decisive(case: dict) -> list[dict]:
    order = ["alert_linked", "offense_associated", "identifier_demonstrated"]
    items = [{"key": k, **v} for k, v in case["evidence"].items() if v["tier"] in order]
    items.sort(key=lambda e: (order.index(e["tier"]), str(e["clocks"].get("received_utc") or e["clocks"].get("event_time_utc"))))
    return [{"tier": e["tier"], "source": e["source"], "summary": e["summary"], "clocks": e["clocks"],
             "references": e["seen_in"][:5]} for e in items[:MAX_DECISIVE]]


def _note(closure: dict, decisive: list[dict], next_step: dict | None, case: dict) -> str:
    lines = [closure["suggested_note"]]
    if decisive:
        lines.append("Evidências decisivas (referências de consulta/linha ou alerta): " + "; ".join(
            f"{e['tier']} {e['summary']} [{', '.join(str(r.get('query') or r.get('alert')) + ':' + str(r.get('search_id') or r.get('tool')) + '#' + str(r.get('row_index', '')) for r in e['references'][:2])}]"
            for e in decisive[:5]) + ".")
    if next_step:
        lines.append(f"Próxima ação pertinente: {next_step['action']} — {next_step['hypothesis']} "
                     f"({next_step['reason'] or next_step['supports_if']}).")
    lines.append(f"Caso {case['case_id']}, revisão {case['revision'] + 1}; nota gerada a partir da coleta registrada no caso.")
    return "\n".join(lines)


def build_report(case: dict, result: dict, trend: dict | None, closure: dict, pivots: list[dict],
                 capabilities: dict | None) -> dict:
    interp = scenarios.interpret(result, trend)
    decisive = _decisive(case)
    next_step = pivot_planner.next_action(pivots)
    coverage = {name: {"outcome": q.get("outcome"), "search_id": q.get("search_id"),
                       "rows": q.get("returned_rows"), "complete": q.get("result_set_complete"),
                       "resume": (q.get("resume") or {}).get("action"), "scope": q.get("scope")}
                for name, q in (result.get("queries") or {}).items()}
    return {
        "case_id": case["case_id"], "revision": case["revision"] + 1, "offense_id": result.get("offense_id"),
        "generated_at": now_iso(),
        "decision": {"recommendation": closure["recommendation"], "decision": closure["decision"],
                     "ready_to_close": closure["ready_to_close"], "recommended_reason": closure["recommended_reason"],
                     "disposition": closure["disposition"],
                     "impediments": closure["blocking_requirements"]},
        "observed_behavior": interp,
        "decisive_evidence": decisive,
        "hypotheses": scenarios.hypotheses(result, closure, trend, interp),
        "contradictions": closure["contradictions"],
        "coverage": coverage,
        "limitations": list(dict.fromkeys(result.get("gaps", [])))[:25],
        "confidence": closure["confidence_detail"],
        "closure": {"decision_matrix": closure["decision_matrix"], "disposition_matrix": closure["disposition_matrix"],
                    "catalog_state": closure["reason_catalog_state"],
                    "custom_reason_definitions": closure["custom_reason_definitions"]},
        "related_alerts": [{"alert_id": i["alert_id"], "state": i["state"],
                            "classification": (i.get("report") or {}).get("assessment", {}).get("classification")}
                           for i in (trend or {}).get("investigations", [])],
        "trend_state": (trend or {}).get("state", "not_requested"),
        "next_action": next_step, "pivots": pivots, "capabilities": capabilities or {},
        "clocks_note": ("QRadar starttime = receipt time, devicetime = device time, Trend event/detection/alert "
                        "creation and the collection time are kept separate; epoch values are converted to UTC "
                        "without assuming the console timezone."),
        "note_pt": _note(closure, decisive, next_step, case),
    }


async def investigate_offense_case(qradar: Any, vision: Any, offense_id: int, case_id: str = "",
                                   store: CaseStore | None = None, offset_hours: int = -3,
                                   timezone_verified: bool = False, include_trend: bool = True,
                                   rerun_queries: list[str] | None = None, budget: Budget | None = None,
                                   now: datetime | None = None, capabilities: dict | None = None) -> dict:
    from .offense_evidence import collect_offense_evidence
    if isinstance(offense_id, bool) or not isinstance(offense_id, int) or offense_id < 1:
        raise ValueError("offense_id must be a positive integer")
    store = store or CaseStore()
    case_id = case_id or f"offense-{offense_id}"
    case = store.load(case_id) or CaseStore.new(case_id, offenses=[offense_id], scope={
        "authorized": "read-only pivots needed to investigate this offense, within the bridge budgets",
        "sources": ["QRadar"] + (["Vision One"] if vision is not None and include_trend else [])})
    if offense_id not in case["references"]["offenses"]:
        case["references"]["offenses"].append(offense_id)
    expected = case["revision"]
    run_id = f"run-{len(case['runs']) + 1}"
    started = now_iso()
    # Windows of planned queries are derived from the first collection time so a resumed run
    # plans the same AQL instead of new jobs.
    case["collection_now"] = case.get("collection_now") or iso(now or datetime.now(timezone.utc))
    collection_now = datetime.fromisoformat(case["collection_now"].replace("Z", "+00:00"))
    offense = await qradar.call("get_offense", {"offense_id": offense_id})
    if not isinstance(offense, dict) or offense.get("id") != offense_id:
        raise ValueError("Unexpected offense metadata ID")
    case["metadata_snapshots"].append({"source": "QRadar get_offense", "reference": offense_id, "collected_at": now_iso(),
                                       "data": scrub({k: offense.get(k) for k in (
                                           "id", "description", "status", "magnitude", "severity", "credibility",
                                           "relevance", "event_count", "flow_count", "start_time", "last_updated_time",
                                           "offense_source", "rules", "log_sources", "closing_reason_id")})})
    resume = {name: {**meta, "rows": case["rows"].get(name, [])} for name, meta in case["queries"].items()}
    result = await collect_offense_evidence(qradar, offense, offset_hours, timezone_verified, now=collection_now,
                                            budget=budget or Budget(max_seconds=90),
                                            confirmations=case["confirmations"], resume=resume,
                                            rerun=set(rerun_queries or []), keep_rows=True)
    merges = [merge_query(case, name, finding, result.get("collected_rows", {}).get(name, []), run_id)
              for name, finding in result["queries"].items()]
    case["last_result"] = scrub(_strip(result))
    case["runs"].append({"run": run_id, "started_at": started, "stage": "qradar_collected", "merges": merges,
                         "budget": result.get("budget")})
    case = store.save(case, expected)  # checkpoint: QRadar progress survives a failure in later stages
    expected = case["revision"]
    trend = None
    if vision is not None and include_trend:
        from .core import investigate
        try:
            overview = await investigate(qradar, vision, offense_id, deepen_alerts=2)
            trend = overview.get("deepened_alerts") or {"state": "no_related_alert", "investigations": [],
                                                       "not_deepened": []}
            trend["related_alert_ids"] = [a["alert_id"] for a in overview.get("alerts", [])]
            for item in trend.get("investigations", []):
                if item.get("state") == "collected":
                    merge_trend(case, item["alert_id"], (item["report"].get("auto_pivots") or {}).get("records"), run_id)
                    if item["alert_id"] not in case["references"]["alerts"]:
                        case["references"]["alerts"].append(item["alert_id"])
        except Exception as exc:  # Trend is a secondary source here; the QRadar case stays valid
            trend = {"state": "unavailable", "error": type(exc).__name__, "investigations": [], "not_deepened": []}
    elif include_trend:
        trend = {"state": "not_configured", "investigations": [], "not_deepened": [],
                 "reason": "Vision One MCP not available in this session (key or Docker)"}
    findings, contradictions = _bridge_findings(result, trend)
    closure = closure_assessment.propose({**result, "collected_rows": result.get("collected_rows", {})},
                                         case["confirmations"], contradictions, findings)
    pivots = pivot_planner.plan(result, trend, case["pivots"])
    report = build_report(case, result, trend, closure, pivots, capabilities)
    case["pivots"] = pivots
    case["hypotheses"] = report["hypotheses"]
    case["contradictions"] = closure["contradictions"]
    case["pending"] = [p for p in pivots if p["status"] in ("planned", "requires_resolution", "requires_analyst", "proposed")]
    case["decisions"].append({"revision": case["revision"] + 1, "at": now_iso(), "decision": closure["decision"],
                              "disposition": closure["disposition"]["category"],
                              "recommended_reason": closure["recommended_reason"],
                              "confidence": closure["confidence_detail"]["level"]})
    case["report_revisions"].append(scrub({k: v for k, v in report.items() if k != "pivots"}))
    case["runs"][-1].update(stage="completed", finished_at=now_iso(), trend_state=(trend or {}).get("state"))
    case = store.save(case, expected)
    return report


def reassess_case(case_id: str, confirmations: list | None = None, store: CaseStore | None = None) -> dict:
    """Re-evaluate a stored case with new cited records; no upstream call, new report revision."""
    store = store or CaseStore()
    case = store.load(case_id)
    if case is None or not case.get("last_result"):
        raise ValueError("unknown case or case without a completed collection")
    offense_id = (case["references"]["offenses"] or [None])[0]
    new = closure_assessment.validate_confirmations(confirmations, offense_id)
    known = {(c["requirement"], c["reference"]) for c in case["confirmations"]}
    case["confirmations"] += [c for c in new if (c["requirement"], c["reference"]) not in known]
    result = {**case["last_result"], "collected_rows": case["rows"]}
    trend = {"investigations": [], "not_deepened": [], "state": "from_case"}
    closure = closure_assessment.propose(result, case["confirmations"], case.get("contradictions_external", []), {})
    pivots = pivot_planner.plan(result, trend, case["pivots"])
    report = build_report(case, result, trend, closure, pivots, None)
    report["reassessment"] = {"upstream_calls": 0, "new_confirmations": len(new),
                              "basis": "stored collection of the case plus analyst-supplied records"}
    expected = case["revision"]
    case["decisions"].append({"revision": expected + 1, "at": now_iso(), "decision": closure["decision"],
                              "disposition": closure["disposition"]["category"],
                              "recommended_reason": closure["recommended_reason"],
                              "confidence": closure["confidence_detail"]["level"], "reassessment": True})
    case["report_revisions"].append(scrub({k: v for k, v in report.items() if k != "pivots"}))
    case["pivots"] = pivots
    store.save(case, expected)
    return report


def case_summary(case: dict) -> dict:
    last = (case.get("report_revisions") or [{}])[-1]
    return {"case_id": case["case_id"], "revision": case["revision"], "references": case["references"],
            "updated_at": case["updated_at"], "decisions": case["decisions"][-5:],
            "pending": case["pending"][:20], "confirmations": case["confirmations"],
            "queries": {n: {k: q.get(k) for k in ("outcome", "search_id", "returned_rows", "next_start", "rows_stored")}
                        for n, q in case["queries"].items()},
            "evidence_records": len(case["evidence"]), "latest_report": last,
            "report_revisions": [{"revision": r.get("revision"), "generated_at": r.get("generated_at"),
                                  "decision": (r.get("decision") or {}).get("decision")}
                                 for r in case.get("report_revisions", [])]}


def render_case_markdown(report: dict) -> str:
    d = report["decision"]
    lines = [f"# Caso {report['case_id']} — offense {report['offense_id']} (revisão {report['revision']})", "",
             f"Gerado (UTC): {report['generated_at']}", "", "## Decisão recomendada", "",
             f"- {d['recommendation']} ({d['decision']}); pronto para fechar: {d['ready_to_close']}",
             f"- Disposição: {d['disposition']['label']} — {d['disposition']['relation_to_catalog']}",
             f"- Motivo do catálogo: {d['recommended_reason'] or 'não selecionado'}",
             f"- Impedimentos: {[i['id'] for i in d['impediments']]}",
             f"- Confiança: {report['confidence']['level']} — {report['confidence']['basis']}", "",
             "## Comportamento observado", "", f"- {report['observed_behavior']['behavior_vs_label']}",
             f"- Nomes de regra (rótulo, não comportamento): {report['observed_behavior']['rule_names']}"]
    for name, item in report["observed_behavior"]["scenarios"].items():
        lines.append(f"- **{name}**: {item.get('observed')}; não estabelecido: {item.get('not_established')}")
    lines += ["", "## Evidências decisivas", ""]
    lines += [f"- [{e['tier']}] {e['source']} {e['summary']} relógios={e['clocks']} refs={e['references'][:2]}"
              for e in report["decisive_evidence"]] or ["- Nenhum registro com vínculo demonstrado na coleta."]
    lines += ["", "## Hipóteses e testes", ""]
    lines += [f"- {h['id']}: {h['status']}; testes {h['tests'][:4]}; confirmaria: {h['would_confirm']}"
              for h in report["hypotheses"]]
    lines += ["", "## Contradições", ""]
    lines += [f"- {c['id']}: {c['summary']} ({c.get('status')})" for c in report["contradictions"]] or ["- Nenhuma registrada."]
    lines += ["", "## Cobertura, limitações e pendências", ""]
    lines += [f"- {n}: {c['outcome']} (search {c['search_id']}, linhas {c['rows']}, retomada {c['resume']})"
              for n, c in report["coverage"].items()]
    lines += [f"- Limitação: {g}" for g in report["limitations"][:10]]
    lines += [f"- Pivô {p['status']}: {p['action']} — {p['hypothesis']} ({p['reason'] or p['stop_criterion']})"
              for p in report["pivots"][:10]]
    lines += ["", "## Próxima ação", "", f"- {report['next_action']}", "", "## Nota sugerida (pt-BR, para revisão humana)",
              "", report["note_pt"], "", "Nada foi fechado, publicado, alterado ou contido pela ponte.", ""]
    return "\n".join(lines)
