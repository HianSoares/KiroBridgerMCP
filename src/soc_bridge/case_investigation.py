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

from . import closure_assessment, pivot_planner, scenarios, trend_link, trend_state
from .ariel_collection import Budget, CheckpointFailed
from .case_store import CaseStore, merge_query, merge_trend, now_iso, scrub
from .core import iso

MAX_DECISIVE = 15


def _strip(result: dict) -> dict:
    return {k: v for k, v in result.items() if k != "collected_rows"}


def bridge_findings(result: dict, trend: dict | None, run_id: str | None = None) -> tuple[dict, list[dict]]:
    """Malicious activity is confirmed by a Trend alert only through a demonstrated, unrefuted link.

    ``trend`` is the case's per-alert state (``trend_state``) or, for a single call, the raw
    deepening output. The validity of the alert (its True Positive facts) and the validity of its
    association with the offense (``qradar_link`` facts) are separate: a refuted link stops
    confirming malicious activity in the offense while the alert stays True Positive. Each link is
    recomputed with the current criteria; recomputing the evidence a refutation addressed never
    re-establishes the link (the rematch is reported as a conflict), and links from earlier
    criteria that are not re-demonstrated are marked for revalidation, never reused."""
    state = trend if trend is None or "alerts" in trend else trend_state.from_raw(trend)
    run_id = run_id or "this-call"
    findings: dict[str, Any] = {"corroborated": False}
    contradictions = []
    links = {}
    for alert_id, entry in (state or {}).get("alerts", {}).items():
        now = trend_state.current(entry)
        instances = [x["data"] for x in entry["facts"].values() if x["kind"] == "malicious_instance"
                     and x["status"] == "sustained"]
        computed = trend_link.link(result, alert_id, {"malicious_instances": instances}, entry.get("association"))
        outcomes = trend_state.record_link(entry, computed, run_id)
        stale = trend_state.mark_unvalidated_links(entry, set(outcomes), run_id)
        facts = entry["facts"]
        current_instances = {f: x["data"] for f, x in facts.items()
                             if x["kind"] == "malicious_instance" and x["status"] == "sustained"}
        current_links = [m for m in computed.get("matches", [])
                         if facts[trend_state.link_fact_id(m)]["status"] == "sustained"]
        kept = {trend_state.link_fact_id(m) for m in current_links}
        # A stored link (not demonstrated again now, e.g. QRadar data changed) is reused only while no
        # current evidence contradicts its own identifiers; otherwise it is withdrawn, history kept.
        stored = []
        for f, x in facts.items():
            if (x["kind"] != "qradar_link" or x["status"] != "sustained" or f in kept
                    or x.get("criteria") != trend_link.LINK_CRITERIA or x["data"].get("fact_id") not in current_instances):
                continue
            conflicts = trend_link.stored_link_conflicts(x["data"], current_instances[x["data"]["fact_id"]], computed)
            if conflicts:
                trend_state.contradict(entry, f, run_id, conflicts)
            else:
                stored.append(x["data"])
        withdrawn = [(f, x) for f, x in facts.items() if x["kind"] == "qradar_link" and x["status"] == "contradicted"]
        refuted = [(f, facts[f]) for f, outcome in outcomes.items() if outcome == "refutation_stands"]
        effective = current_links + stored
        if effective:
            relation = {**computed, "level": "demonstrated", "matches": effective[:10],
                        "basis": computed.get("basis") if current_links else
                        "link demonstrated in an earlier run under the current criteria and still sustained "
                        "(QRadar record references kept)"}
        else:
            relation = {k: v for k, v in computed.items() if k != "matches"}
            relation.update(level="candidate", missing=trend_link.REQUIRED)
            if refuted:
                relation["why_not_demonstrated"] = "; ".join(
                    f"link {f} refuted: {x['refuted_by']['basis']} ({x['refuted_by']['source']})" for f, x in refuted)
            relation.setdefault("why_not_demonstrated", computed.get("why_not_demonstrated")
                                or "no demonstrated link remains sustained")
        if stale:
            relation["needs_revalidation"] = stale
        entry["link"] = relation
        links[alert_id] = relation
        for f, x in refuted:
            observation = (x.get("observations_after_refutation") or [{}])[-1]
            changed = observation.get("probative_change")
            contradictions.append({
                "id": f"refuted_link_still_matched:{alert_id}:{f}",
                "summary": (f"the bridge comparison still matches link {f}, refuted by {x['refuted_by']['source']}: "
                            f"{x['refuted_by']['basis']}; "
                            + (f"the new observation changes {'; '.join(observation.get('changes', []))[:300]} — "
                               "review it against the refutation basis" if changed else
                               "the same evidence (or only metadata/incomplete values) was observed again")
                            + "; the refutation stands until a reasoned trend_finding_reinstated record"),
                "affects": [], "status": "unresolved",
                "evidence": {"alert_id": alert_id, "fact": f, "refuted_by": x["refuted_by"], "observation": observation}})
        for f, x in withdrawn:
            contradictions.append({
                "id": f"link_contradicted:{alert_id}:{f}",
                "summary": (f"stored link {f} of {alert_id} is contradicted by current evidence "
                            f"({'; '.join(x['contradicted_by']['conflicts'])[:300]}); it no longer supports the "
                            "association until resolved (this is not a benign finding)"),
                "affects": [], "status": "unresolved",
                "evidence": {"alert_id": alert_id, "fact": f, "contradicted_by": x["contradicted_by"]}})
        if computed.get("conflicts"):
            first = computed["conflicts"][0]
            contradictions.append({
                "id": f"link_conflict:{alert_id}",
                "summary": (f"Trend alert {alert_id} record {first['trend_record']} and QRadar record "
                            f"{first['qradar_record'].get('query')}#{first['qradar_record'].get('result_row_index')} "
                            f"share {', '.join(first['weak_signals']) or 'the same file hash'} but "
                            f"{'; '.join(first['conflicts'])}: this association is not demonstrated (not a benign finding)"),
                "affects": [], "status": "unresolved",
                "evidence": {"alert_id": alert_id, "conflicts": computed["conflicts"]}})
        if stale:
            contradictions.append({
                "id": f"link_needs_revalidation:{alert_id}",
                "summary": f"{len(stale)} stored link(s) of {alert_id} from earlier criteria were not re-demonstrated; "
                           "kept for history and not used",
                "affects": [], "status": "unresolved", "evidence": {"alert_id": alert_id, "facts": stale}})
        if now["classification"] != "True Positive":
            continue
        if relation["level"] == "demonstrated":
            findings.setdefault("malicious_activity_confirmed", {
                "alert_id": alert_id, "facts": now["sustained_facts"][:6], "link": relation,
                "basis": now["basis"],
                "meaning": "Trend alert-first evaluation sustained True Positive on an executed instance, and the "
                           "offense-linked QRadar process is that execution or its demonstrated parent/child"})
            findings["corroborated"] = True
        else:
            contradictions.append({
                "id": f"related_alert_unlinked:{alert_id}",
                "summary": (f"Trend alert {alert_id} is assessed True Positive but the offense activity is not shown to be "
                            "the malicious execution (" + str(relation.get("why_not_demonstrated"))[:300] + "); it does "
                            "not confirm malicious activity in the offense, and a benign closure must first demonstrate "
                            "or exclude the link"),
                "affects": ["authorization", "detection_error"], "status": "unresolved",
                "evidence": {"alert_id": alert_id, "association": entry.get("association"), "link": relation},
                "next_action": f"Look for {trend_link.REQUIRED}"})
    for entry in (state or {}).get("alerts", {}).values():
        for revision in entry.get("revisions", []):
            if revision.get("replaced_facts"):
                contradictions.append({"id": f"trend_finding_refuted:{entry['alert_id']}:{revision['run']}",
                                       "summary": f"Trend facts of {entry['alert_id']} refuted: {revision['basis']}",
                                       "affects": [], "status": "resolved",
                                       "evidence": {"source": revision["source"], "replaced_facts": revision["replaced_facts"]}})
    if state is not None:
        state["investigations"] = trend_state.investigations(state)
    if trend is not None and trend is not state:
        for item in trend.get("investigations", []):
            item["link"] = links.get(item.get("alert_id"))
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
                            "classification": ((i.get("report") or {}).get("assessment") or {}).get("classification"),
                            "classification_basis": ((i.get("report") or {}).get("assessment") or {}).get("basis"),
                            "link": (i.get("link") or {}).get("level"),
                            "link_relations": [m.get("relation") for m in (i.get("link") or {}).get("matches", [])],
                            "latest_attempt": i.get("latest_attempt"),
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
    raw = None
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
        except Exception as exc:  # Trend is a secondary source here; the QRadar case stays valid
            raw = {"state": "unavailable", "error": type(exc).__name__, "investigations": [], "not_deepened": []}
    elif include_trend:
        raw = {"state": "not_configured", "investigations": [], "not_deepened": [],
               "reason": "Vision One MCP not available in this session (key or Docker)"}
    # Each attempt is recorded per alert; earlier facts stay until pertinent evidence refutes them.
    trend = trend_state.apply_run(case.get("trend"), raw, run_id)
    findings, contradictions = bridge_findings(result, trend, run_id)
    case["trend"] = trend
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
    trend = trend_state.migrate(case.get("trend"))
    refutations = [c for c in new if c["requirement"] in closure_assessment.REVISION_RECORDS]
    for record in refutations:
        entry = trend["alerts"].get(record["alert_id"])
        if entry is None:
            raise ValueError(f"alert {record['alert_id']} has no stored Trend facts in case {case_id}")
        unknown = [f for f in record.get("facts", []) if f not in entry["facts"]]
        if unknown:
            raise ValueError(f"unknown fact IDs for {record['alert_id']}: {unknown}; read them with get_case")
    for record in refutations:
        apply = trend_state.refute if record["requirement"] == "trend_finding_refuted" else trend_state.reinstate
        apply(trend["alerts"][record["alert_id"]], record.get("facts"), "reassessment",
              f"analyst-supplied record (not verified by the bridge): {record['source']} {record['reference']}",
              record["summary"])
    known = {(c["requirement"], c["reference"], str(c.get("scope"))) for c in case["confirmations"]}
    case["confirmations"] += [c for c in new if (c["requirement"], c["reference"], str(c.get("scope"))) not in known]
    result = {**case["last_result"], "collected_rows": case["rows"]}
    findings, contradictions = bridge_findings(result, trend, "reassessment")
    case["trend"] = trend
    closure = closure_assessment.propose(result, case["confirmations"], contradictions, findings)
    pivots = pivot_planner.plan(result, trend, case["pivots"])
    report = build_report(case, result, trend, closure, pivots, None)
    report["reassessment"] = {"upstream_calls": 0, "new_confirmations": len(new),
                              "basis": "stored QRadar collection and stored Trend results of the case plus "
                                       "analyst-supplied records",
                              "trend_results_reused": sorted(trend.get("alerts", {})),
                              "trend_facts_refuted_now": [r["alert_id"] for r in refutations]}
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
                      "alerts": [{"alert_id": a, "current": e.get("current"),
                                  "attempts": e.get("attempts", [])[-5:], "revisions": e.get("revisions", [])[-5:],
                                  "facts": {f: {k: x.get(k) for k in ("kind", "status", "first_run", "last_observed_run",
                                                                      "source", "refuted_by")}
                                            for f, x in e.get("facts", {}).items()}}
                                 for a, e in ((case.get("trend") or {}).get("alerts") or {}).items()]},
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
