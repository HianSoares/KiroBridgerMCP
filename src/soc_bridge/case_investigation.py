"""Professional, resumable offense investigation persisted as a local case.

"Investigue a offense X" runs: identify case/scope/sources -> save the case -> metadata
snapshot -> offense-linked collection (resuming known Ariel jobs of the same offense and
query from their cursors, with a checkpoint before each job creation, when the search ID
arrives and after every page) -> related Trend alerts with alert-first depth, persisted in
the case -> scenario interpretation -> competing hypotheses -> next pivots -> per-conclusion
decision with contradictions -> report revision and a Portuguese note for human review.
Nothing is closed, posted or contained.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from . import closure_assessment, pivot_planner, scenarios, trend_link
from .ariel_collection import Budget, CheckpointFailed
from .case_store import CaseStore, merge_query, merge_trend, now_iso, scrub
from .core import iso

MAX_DECISIVE = 15


def _strip(result: dict) -> dict:
    return {k: v for k, v in result.items() if k != "collected_rows"}


def compact_trend(trend: dict, run_id: str) -> dict:
    """What the case keeps from the Trend stage: enough to re-assess without new calls."""
    out = {k: trend.get(k) for k in ("state", "criterion", "related_alert_ids", "not_deepened", "reason", "error")
           if trend.get(k) is not None}
    out["investigations"] = []
    for item in trend.get("investigations", []):
        entry = {k: item.get(k) for k in ("alert_id", "state", "association", "reason", "error") if item.get(k) is not None}
        entry["collected_in_run"] = run_id
        report = item.get("report") or {}
        if item.get("state") == "collected":
            entry["report"] = {"alert": report.get("alert"), "assessment": report.get("assessment"),
                               "dump_analysis": report.get("dump_analysis"), "entities": report.get("entities"),
                               "identifiers": report.get("identifiers") or trend_link.identifiers(report)}
        out["investigations"].append(entry)
    return out


def merge_trend_state(previous: dict | None, new: dict | None) -> dict | None:
    """Keep collected alert results from earlier runs when this run did not collect them again."""
    if not previous:
        return new
    if not new:
        return {**previous, "state": f"from_case ({previous.get('state')})"}
    by_id = {i["alert_id"]: i for i in previous.get("investigations", [])}
    kept = []
    for item in new.get("investigations", []):
        old = by_id.get(item["alert_id"])
        if item.get("state") == "collected" or not old or old.get("state") != "collected":
            by_id[item["alert_id"]] = item
        else:
            by_id[item["alert_id"]] = {**old, "latest_attempt": {k: item.get(k) for k in ("state", "error", "reason",
                                                                                            "collected_in_run")}}
            kept.append(item["alert_id"])
    merged = {**new, "investigations": list(by_id.values())}
    kept += [i["alert_id"] for i in previous.get("investigations", [])
             if i.get("state") == "collected" and i["alert_id"] not in {n["alert_id"] for n in new.get("investigations", [])}]
    if kept:
        merged["earlier_results_kept"] = sorted(set(kept))
    return merged


def bridge_findings(result: dict, trend: dict | None) -> tuple[dict, list[dict]]:
    """Malicious activity is confirmed by a Trend alert only through a demonstrated link."""
    findings: dict[str, Any] = {"corroborated": False}
    contradictions = []
    for item in (trend or {}).get("investigations", []):
        if item.get("state") != "collected":
            continue
        report = item.get("report") or {}
        ids = report.get("identifiers") or trend_link.identifiers(report)
        relation = trend_link.link(result, item["alert_id"], ids, item.get("association"))
        item["link"] = relation
        assessment = report.get("assessment") or {}
        if assessment.get("classification") != "True Positive":
            continue
        if relation["level"] == "demonstrated":
            findings.setdefault("malicious_activity_confirmed", {
                "alert_id": item["alert_id"], "facts": (assessment.get("facts") or [])[:4],
                "link": relation,
                "meaning": "Trend alert-first evaluation sustained True Positive and an offense-linked QRadar record "
                           "shares its strong identifier on the same host"})
            findings["corroborated"] = True
        else:
            contradictions.append({
                "id": f"related_alert_unlinked:{item['alert_id']}",
                "summary": (f"Trend alert {item['alert_id']} was assessed True Positive but is related to the offense only "
                            "by IP/time; it does not confirm malicious activity in the offense, and a benign closure "
                            "must first demonstrate or exclude the link"),
                "affects": ["authorization", "detection_error"], "status": "unresolved",
                "evidence": {"alert_id": item["alert_id"], "association": item.get("association"), "link": relation},
                "next_action": f"Look for {trend_link.REQUIRED}"})
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
                            "classification": (i.get("report") or {}).get("assessment", {}).get("classification"),
                            "link": (i.get("link") or {}).get("level"),
                            "collected_in_run": i.get("collected_in_run")}
                           for i in (trend or {}).get("investigations", [])],
        "trend_state": (trend or {}).get("state", "not_requested"),
        "next_action": next_step, "pivots": pivots, "capabilities": capabilities or {},
        "clocks_note": ("QRadar starttime = receipt time, devicetime = device time, Trend event/detection/alert "
                        "creation and the collection time are kept separate; epoch values are converted to UTC "
                        "without assuming the console timezone."),
        "note_pt": _note(closure, decisive, next_step, case),
    }


def _bound_offense(case: dict) -> int | None:
    return case.get("offense_id") or (case.get("references", {}).get("offenses") or [None])[0]


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
    case = store.load(case_id)
    if case is not None and _bound_offense(case) != offense_id:
        raise ValueError(f"case {case_id} belongs to offense {_bound_offense(case)}; its queries, search IDs and "
                         f"evidence are not reused for offense {offense_id}. Use another case_id (default "
                         f"offense-{offense_id}).")
    case = case or CaseStore.new(case_id, offenses=[offense_id], scope={
        "authorized": "read-only pivots needed to investigate this offense, within the bridge budgets",
        "sources": ["QRadar"] + (["Vision One"] if vision is not None and include_trend else [])})
    case["offense_id"] = offense_id
    run_id = f"run-{len(case['runs']) + 1}"
    case["runs"].append({"run": run_id, "started_at": now_iso(), "stage": "started"})
    # Windows of planned queries are derived from the first collection time so a resumed run
    # plans the same AQL instead of new jobs.
    case["collection_now"] = case.get("collection_now") or iso(now or datetime.now(timezone.utc))
    state = {"case": store.save(case, case["revision"])}  # saved before any upstream call

    def save(stage: str) -> None:
        state["case"]["runs"][-1]["stage"] = stage
        state["case"] = store.save(state["case"], state["case"]["revision"])

    def checkpoint(name: str, finding: dict, stage: str) -> None:
        merge_query(state["case"], name, finding, finding.get("rows", []), run_id, offense_id)
        save(f"collecting {name}: {stage}")

    try:
        return await _run(qradar, vision, offense_id, state, save, checkpoint, offset_hours, timezone_verified,
                          include_trend, rerun_queries, budget, run_id, capabilities, collect_offense_evidence)
    except asyncio.CancelledError:
        try:  # best effort: the checkpoints already hold the search IDs, cursors and rows
            state["case"]["runs"][-1]["cancelled_at"] = now_iso()
            save("cancelled; resume with the same case_id")
        except Exception:
            pass
        raise
    except CheckpointFailed as exc:
        raise (exc.__cause__ or exc) from None


async def _run(qradar, vision, offense_id, state, save, checkpoint, offset_hours, timezone_verified,
               include_trend, rerun_queries, budget, run_id, capabilities, collect_offense_evidence) -> dict:
    case = state["case"]
    collection_now = datetime.fromisoformat(case["collection_now"].replace("Z", "+00:00"))
    offense = await qradar.call("get_offense", {"offense_id": offense_id})
    if not isinstance(offense, dict) or offense.get("id") != offense_id:
        raise ValueError("Unexpected offense metadata ID")
    case["metadata_snapshots"].append({"source": "QRadar get_offense", "reference": offense_id, "collected_at": now_iso(),
                                       "data": scrub({k: offense.get(k) for k in (
                                           "id", "description", "status", "magnitude", "severity", "credibility",
                                           "relevance", "event_count", "flow_count", "start_time", "last_updated_time",
                                           "offense_source", "rules", "log_sources", "closing_reason_id")})})
    save("metadata snapshot")
    case = state["case"]
    resume = {name: {**meta, "rows": case["rows"].get(name, [])} for name, meta in case["queries"].items()}
    result = await collect_offense_evidence(qradar, offense, offset_hours, timezone_verified, now=collection_now,
                                            budget=budget or Budget(max_seconds=90),
                                            confirmations=case["confirmations"], resume=resume,
                                            rerun=set(rerun_queries or []), keep_rows=True, progress=checkpoint)
    case = state["case"]
    merges = [merge_query(case, name, finding, result.get("collected_rows", {}).get(name, []), run_id, offense_id)
              for name, finding in result["queries"].items()]
    case["last_result"] = scrub(_strip(result))
    case["runs"][-1].update(merges=merges, budget=result.get("budget"))
    save("qradar_collected")  # QRadar progress survives a failure in later stages
    case = state["case"]
    fresh = None
    if vision is not None and include_trend:
        from .core import investigate
        try:
            overview = await investigate(qradar, vision, offense_id, deepen_alerts=2)
            raw = overview.get("deepened_alerts") or {"state": "no_related_alert", "investigations": [],
                                                     "not_deepened": []}
            raw["related_alert_ids"] = [a["alert_id"] for a in overview.get("alerts", [])]
            for item in raw.get("investigations", []):
                if item.get("state") == "collected":
                    merge_trend(case, item["alert_id"], (item["report"].get("auto_pivots") or {}).get("records"), run_id)
                    if item["alert_id"] not in case["references"]["alerts"]:
                        case["references"]["alerts"].append(item["alert_id"])
            fresh = compact_trend(raw, run_id)
        except Exception as exc:  # Trend is a secondary source here; the QRadar case stays valid
            fresh = {"state": "unavailable", "error": type(exc).__name__, "investigations": [], "not_deepened": []}
    elif include_trend:
        fresh = {"state": "not_configured", "investigations": [], "not_deepened": [],
                 "reason": "Vision One MCP not available in this session (key or Docker)"}
    trend = merge_trend_state(case.get("trend"), fresh)
    if trend is not None:
        case["trend"] = scrub(trend)
        trend = case["trend"]
    findings, contradictions = bridge_findings(result, trend)
    closure = closure_assessment.propose({**result, "collected_rows": result.get("collected_rows", {})},
                                         case["confirmations"], contradictions, findings)
    pivots = pivot_planner.plan(result, trend, case["pivots"])
    report = build_report(case, result, trend, closure, pivots, capabilities)
    _record(case, report, closure, pivots, run_id)
    case["runs"][-1].update(finished_at=now_iso(), trend_state=(trend or {}).get("state"))
    save("completed")
    return report


def _record(case: dict, report: dict, closure: dict, pivots: list[dict], run_id: str, reassessment: bool = False) -> None:
    case["pivots"] = pivots
    case["hypotheses"] = report["hypotheses"]
    case["contradictions"] = closure["contradictions"]
    case["pending"] = [p for p in pivots if p["status"] in ("planned", "requires_resolution", "requires_analyst", "proposed")]
    case["decisions"].append({"revision": case["revision"] + 1, "at": now_iso(), "decision": closure["decision"],
                              "disposition": closure["disposition"]["category"],
                              "recommended_reason": closure["recommended_reason"],
                              "confidence": closure["confidence_detail"]["level"], "run": run_id,
                              **({"reassessment": True} if reassessment else {})})
    case["report_revisions"].append(scrub({k: v for k, v in report.items() if k != "pivots"}))


def reassess_case(case_id: str, confirmations: list | None = None, store: CaseStore | None = None) -> dict:
    """Re-evaluate a stored case with new cited records; no upstream call, new report revision.

    The stored QRadar collection and the stored Trend results (including their demonstrated
    or candidate links) are both reused, so a reassessment never drops evidence of malicious
    activity because it does not query Trend again."""
    store = store or CaseStore()
    case = store.load(case_id)
    if case is None or not case.get("last_result"):
        raise ValueError("unknown case or case without a completed collection")
    offense_id = _bound_offense(case)
    new = closure_assessment.validate_confirmations(confirmations, offense_id)
    known = {(c["requirement"], c["reference"], str(c.get("scope"))) for c in case["confirmations"]}
    case["confirmations"] += [c for c in new if (c["requirement"], c["reference"], str(c.get("scope"))) not in known]
    result = {**case["last_result"], "collected_rows": case["rows"]}
    trend = case.get("trend") or {"state": "not_collected", "investigations": [], "not_deepened": []}
    findings, contradictions = bridge_findings(result, trend)
    closure = closure_assessment.propose(result, case["confirmations"], contradictions, findings)
    pivots = pivot_planner.plan(result, trend, case["pivots"])
    report = build_report(case, result, trend, closure, pivots, None)
    report["reassessment"] = {"upstream_calls": 0, "new_confirmations": len(new),
                              "basis": "stored QRadar collection and stored Trend results of the case plus "
                                       "analyst-supplied records",
                              "trend_results_reused": [i["alert_id"] for i in trend.get("investigations", [])
                                                       if i.get("state") == "collected"]}
    _record(case, report, closure, pivots, "reassessment", reassessment=True)
    store.save(case, case["revision"])
    return report


def case_summary(case: dict) -> dict:
    last = (case.get("report_revisions") or [{}])[-1]
    return {"case_id": case["case_id"], "offense_id": _bound_offense(case), "revision": case["revision"],
            "references": case["references"], "updated_at": case["updated_at"], "decisions": case["decisions"][-5:],
            "pending": case["pending"][:20], "confirmations": case["confirmations"],
            "queries": {n: {k: q.get(k) for k in ("outcome", "search_id", "returned_rows", "next_start", "rows_stored",
                                                  "checkpoint")}
                        for n, q in case["queries"].items()},
            "runs": [{k: r.get(k) for k in ("run", "stage", "started_at", "finished_at", "cancelled_at")}
                     for r in case.get("runs", [])[-5:]],
            "trend": {"state": (case.get("trend") or {}).get("state"),
                      "alerts": [{"alert_id": i.get("alert_id"), "state": i.get("state"),
                                  "classification": ((i.get("report") or {}).get("assessment") or {}).get("classification")}
                                 for i in (case.get("trend") or {}).get("investigations", [])]},
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
    lines += ["", "## Alertas Trend relacionados", ""]
    lines += [f"- {a['alert_id']}: {a['state']}, classificação {a['classification']}, vínculo {a['link'] or 'não avaliado'}"
              for a in report.get("related_alerts", [])] or ["- Nenhum alerta aprofundado."]
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
