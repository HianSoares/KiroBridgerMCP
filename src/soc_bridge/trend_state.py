"""Per-alert Trend evidence kept in a case: attempts, facts, revisions and the current assessment.

A Trend call that returns is not the same as evidence that replaces an earlier finding. Each
run adds an attempt (state, classification, error); facts established by earlier runs
(the executed instance that carries a malicious verdict, the True Positive assessment, and a
demonstrated QRadar link) stay "sustained" until pertinent new evidence refutes them:

- a later alert-first evaluation sustained as False Positive or Benign True Positive (each
  needs positive evidence in that flow), or
- an analyst-supplied ``trend_finding_refuted`` record (labelled external, not verified).

Not observing a fact again (Inconclusive, timeout, failure, Trend not requested) never refutes
it. Each fact keeps three things apart: its identity (the fact ID), its probative content (the
identifiers it asserts: complete hashes, PID, launch time, image, complete command line,
QRadar instance, chain GUIDs) and its provenance (runs, jobs, rows, sources, lengths, cut
flags, incomplete values). A refutation records its basis, source, the facts it replaced and
the probative content it addressed. A refuted fact is never re-established automatically:
re-reading the same evidence, a new run or Ariel job, metadata or incomplete values, and even
changed probative content cannot show that the change is pertinent to the refutation basis.
The new observation is recorded (``observations_after_refutation``, with the probative changes)
and shown as a conflict for review; only an explicit, reasoned ``trend_finding_reinstated``
record re-establishes the fact. Refuting only a QRadar link leaves the alert's own True
Positive facts untouched, and independent links are new facts. A link whose own identifiers are
positively contradicted by current evidence becomes ``contradicted`` (history kept) until it is
re-demonstrated without conflict; missing observations never contradict. Links demonstrated
under earlier criteria that are not re-demonstrated are marked ``needs_revalidation``. The
current assessment is derived from the facts, never copied blindly from the latest report.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import trend_link
from .case_store import now_iso

REFUTING = {"False Positive", "Benign True Positive"}
MAX_ASSESSMENTS = 10
MAX_ATTEMPTS = 50
ASSESSMENT_FACT = "assessment:true_positive"


def new_state() -> dict:
    return {"state": "not_requested", "runs": [], "alerts": {}, "related_alert_ids": [], "not_deepened": []}


def _entry(state: dict, alert_id: str) -> dict:
    return state["alerts"].setdefault(alert_id, {"alert_id": alert_id, "association": None, "attempts": [],
                                                 "assessments": [], "facts": {}, "revisions": [], "report": None})


def fingerprint(data: Any) -> str:
    """Stable digest of probative content; the same evidence gives the same fingerprint in any run."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:24]


def _probative_instance(instance: dict | None) -> dict | None:
    """Identifiers of an execution that can support or contradict identity: complete hashes, PID, launch
    time, image and a complete command line. Incomplete hashes, sources, lengths and cut flags are
    metadata, not evidence."""
    if not instance:
        return None
    states = trend_link.trend_states(instance)
    return {"image": instance.get("image"), "pid": instance.get("pid"), "launch_time_utc": instance.get("launch_time_utc"),
            "command_line": None if instance.get("command_line_cut") else instance.get("command_line"),
            "hashes": {a: v["value"] for a, v in sorted(states.items()) if v.get("state") == "complete"}}


def probative(kind: str, data: Any) -> Any:
    """What a fact asserts, separated from its identity (the fact ID) and its provenance (runs, jobs,
    rows, sources). Only a change here can be a new observation of the fact."""
    data = data or {}
    if kind == "malicious_instance":
        record = data.get("trend_record") or {}
        return {"uuid": record.get("uuid"), "endpoint_host": record.get("endpoint_host"),
                "endpoint_guid": record.get("endpoint_guid"), "instance": _probative_instance(data.get("instance")),
                "parent": _probative_instance(data.get("parent")), "verdict_hashes": sorted(data.get("verdict_hashes") or [])}
    if kind == "qradar_link":
        qradar = {a: v["qradar"]["value"] for a, v in sorted(((data.get("artifact") or {}).get("by_algorithm") or {}).items())
                  if (v.get("qradar") or {}).get("state") == "complete"}
        return {"fact_id": data.get("fact_id"), "relation": data.get("relation"),
                "qradar_instance": data.get("qradar_instance_key"), "qradar_hashes": qradar,
                "qradar_execution_time": data.get("qradar_execution_time"),
                "trend": _probative_instance(data.get("trend_instance")),
                "chain": {k: v for k, v in sorted((data.get("chain") or {}).items()) if k in ("child_guid", "parent_guid")}}
    if kind == "alert_assessment":
        return {"classification": data.get("classification")}
    return data


def _flatten(value: Any, path: str = "") -> dict:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            out.update(_flatten(item, f"{path}.{key}" if path else str(key)))
        return out
    return {path: value}


def changes(before: Any, after: Any) -> list[str]:
    old, new = _flatten(before or {}), _flatten(after or {})
    return sorted(f"{k}: {old.get(k)!r} -> {new.get(k)!r}" for k in set(old) | set(new) if old.get(k) != new.get(k))[:20]


def _sustain(entry: dict, fact_id: str, kind: str, run_id: str, source: str, data: Any,
             criteria: str | None = None) -> str:
    """Record an observation; returns "new", "observed", "refutation_stands" or "revalidated".

    A refuted fact is never re-established here: neither the same evidence (another run, job or
    read) nor a changed fingerprint shows that the change is pertinent to the refutation basis.
    The observation is recorded for review, with the probative changes, and only an explicit,
    reasoned ``trend_finding_reinstated`` record re-establishes the fact."""
    fact = entry["facts"].get(fact_id)
    content = probative(kind, data)
    print_ = fingerprint(content)
    if fact is None:
        entry["facts"][fact_id] = {"kind": kind, "status": "sustained", "first_run": run_id, "last_observed_run": run_id,
                                   "source": source, "data": data, "probative": content, "fingerprint": print_,
                                   **({"criteria": criteria} if criteria else {})}
        return "new"
    if fact["status"] == "refuted":
        addressed = (fact.get("refuted_by") or {}).get("probative")
        changed = changes(addressed, content) if addressed is not None else []
        fact["rematched_after_refutation"] = (fact.get("rematched_after_refutation", []) + [run_id])[-20:]
        fact["observations_after_refutation"] = (fact.get("observations_after_refutation", []) + [{
            "run": run_id, "at": now_iso(), "source": source, "fingerprint": print_,
            "probative_change": bool(changed) or addressed is None, "changes": changed or (
                ["refuted before probative content was recorded; compare manually"] if addressed is None else []),
            "status_kept": "refuted"}])[-20:]
        return "refutation_stands"
    outcome = "observed"
    if fact["status"] in ("needs_revalidation", "contradicted"):
        # Only demonstrated, conflict-free current evidence reaches this point (record_link).
        fact["revalidated_in_run"] = run_id
        fact.setdefault("status_history", []).append({"run": run_id, "from": fact["status"], "to": "sustained",
                                                      "basis": "re-demonstrated with the current criteria and data"})
        outcome = "revalidated"
    if fact.get("fingerprint") != print_ and fact.get("probative") is not None:
        fact["history"] = (fact.get("history", []) + [{"until_run": run_id, "probative": fact["probative"],
                                                       "fingerprint": fact["fingerprint"],
                                                       "changes": changes(fact["probative"], content)}])[-10:]
    fact.update(status="sustained", last_observed_run=run_id, data=data, probative=content, fingerprint=print_,
                **({"criteria": criteria} if criteria else {}))
    return outcome


def contradict(entry: dict, fact_id: str, run_id: str, conflicts: list[str]) -> None:
    """Current evidence positively contradicts the fact: withdraw it from any conclusion, keep its data."""
    fact = entry["facts"][fact_id]
    fact.setdefault("status_history", []).append({"run": run_id, "from": fact["status"], "to": "contradicted"})
    fact.update(status="contradicted", contradicted_by={"run": run_id, "at": now_iso(), "conflicts": conflicts,
                                                        "meaning": "withdrawn until resolved; not a benign finding"})


def refute(entry: dict, fact_ids: list[str] | None, run_id: str, source: str, basis: str) -> list[str]:
    targets = [f for f, fact in sorted(entry["facts"].items())
               if fact["status"] in ("sustained", "needs_revalidation", "contradicted") and (not fact_ids or f in fact_ids)]
    for fact_id in targets:
        fact = entry["facts"][fact_id]
        addressed = fact.get("probative") if fact.get("probative") is not None else probative(fact["kind"], fact.get("data"))
        fact.update(status="refuted", refuted_by={"run": run_id, "source": source, "basis": basis, "at": now_iso(),
                                                  "probative": addressed, "fingerprint": fingerprint(addressed)})
    if targets:
        entry["revisions"].append({"at": now_iso(), "run": run_id, "source": source, "basis": basis,
                                   "replaced_facts": targets})
    return targets


def reinstate(entry: dict, fact_ids: list[str] | None, run_id: str, source: str, basis: str) -> list[str]:
    """Explicit, reasoned revision of a refutation (analyst-supplied, not verified by the bridge)."""
    targets = [f for f, fact in sorted(entry["facts"].items()) if fact["status"] == "refuted"
               and (not fact_ids or f in fact_ids)]
    for fact_id in targets:
        fact = entry["facts"][fact_id]
        fact.update(status="sustained", reinstated_by={"run": run_id, "source": source, "basis": basis, "at": now_iso(),
                                                       "previous_refutation": fact.get("refuted_by")})
    if targets:
        entry["revisions"].append({"at": now_iso(), "run": run_id, "source": source, "basis": basis,
                                   "replaced_facts": [], "reestablished_facts": targets})
    return targets


def apply_attempt(state: dict, item: dict, run_id: str) -> None:
    entry = _entry(state, item["alert_id"])
    entry["association"] = item.get("association") or entry["association"]
    report = item.get("report") if item.get("state") == "collected" else None
    assessment = (report or {}).get("assessment") or {}
    classification = assessment.get("classification")
    basis = trend_link.evidence(report) if report else None
    if basis is not None and not basis["malicious_instances"] and (report or {}).get("link_evidence"):
        basis = report["link_evidence"]  # compacted report from an earlier format
    entry["attempts"] = (entry["attempts"] + [{
        "run": run_id, "at": now_iso(), "state": item.get("state"), "classification": classification,
        "error": item.get("error"), "reason": item.get("reason"),
        "malicious_instances": len((basis or {}).get("malicious_instances", []))}])[-MAX_ATTEMPTS:]
    if report is None:
        return
    entry["assessments"] = (entry["assessments"] + [{
        "run": run_id, "classification": classification, "facts": (assessment.get("facts") or [])[:6],
        "why": assessment.get("why"), "evidence": basis}])[-MAX_ASSESSMENTS:]
    source = f"Vision One alert-first evaluation ({run_id})"
    if classification == "True Positive":
        _sustain(entry, ASSESSMENT_FACT, "alert_assessment", run_id, source,
                 {"classification": classification, "facts": (assessment.get("facts") or [])[:6]})
        for fact in basis["malicious_instances"]:
            _sustain(entry, fact["fact_id"], "malicious_instance", run_id,
                     f"Vision One Search record {fact['trend_record'].get('uuid')} with a high-risk sandbox verdict "
                     f"({run_id})", fact)
    elif classification in REFUTING:
        refute(entry, None, run_id, source, f"new assessment {classification}: "
               + (assessment.get("why") or "; ".join(assessment.get("facts") or []) or "no further basis returned"))
    previous = entry["report"] or {}
    entry["report"] = {"alert": report.get("alert") or previous.get("alert"),
                       "dump_analysis": report.get("dump_analysis") or previous.get("dump_analysis"),
                       "entities": report.get("entities") or previous.get("entities"),
                       "observables": basis["observables"] or previous.get("observables"),
                       "collected_in_run": run_id}


def link_fact_id(match: dict) -> str:
    """Stable across queries and jobs: Trend fact, relation and the QRadar process instance identity."""
    return f"link:{match['fact_id']}:{match['relation']}:{match.get('qradar_instance_key')}"


def record_link(entry: dict, relation: dict, run_id: str) -> dict[str, str]:
    """Record each demonstrated match as a qradar_link fact; returns the outcome per fact ID."""
    return {link_fact_id(match): _sustain(entry, link_fact_id(match), "qradar_link", run_id,
                                          f"bridge comparison of QRadar and Trend records ({run_id})", match,
                                          criteria=trend_link.LINK_CRITERIA)
            for match in relation.get("matches", [])}


def mark_unvalidated_links(entry: dict, rematched: set[str], run_id: str) -> list[str]:
    """Links from earlier criteria that the current criteria did not re-demonstrate: never shown as demonstrated."""
    marked = []
    for fact_id, fact in entry["facts"].items():
        if (fact["kind"] == "qradar_link" and fact["status"] == "sustained"
                and fact.get("criteria") != trend_link.LINK_CRITERIA and fact_id not in rematched):
            fact.update(status="needs_revalidation", revalidation={
                "run": run_id, "at": now_iso(), "criteria_of_fact": fact.get("criteria") or "earlier version",
                "current_criteria": trend_link.LINK_CRITERIA,
                "reason": "demonstrated under earlier link criteria and not re-demonstrated with the current criteria "
                          "and the stored data; kept for history, not used as a link"})
            marked.append(fact_id)
    return marked


def current(entry: dict) -> dict:
    sustained = {f: x for f, x in entry["facts"].items() if x["status"] == "sustained"}
    refuted = {f: x for f, x in entry["facts"].items() if x["status"] == "refuted"}
    latest = entry["attempts"][-1] if entry["attempts"] else {}
    collected = [a for a in entry["assessments"] if a.get("classification")]
    if sustained.get(ASSESSMENT_FACT) or any(x["kind"] == "malicious_instance" for x in sustained.values()):
        since = min(x["first_run"] for x in sustained.values() if x["kind"] != "qradar_link")
        basis = f"{len(sustained)} fact(s) sustained since {since}"
        if latest and latest.get("classification") != "True Positive":
            basis += (f"; latest attempt {latest.get('run')}: {latest.get('state')}"
                      + (f"/{latest['classification']}" if latest.get("classification") else "")
                      + " — not observed again, which does not refute the facts")
        return {"classification": "True Positive", "basis": basis, "since_run": since,
                "sustained_facts": sorted(sustained), "refuted_facts": sorted(refuted)}
    alert_refuted = {f: x for f, x in refuted.items() if x["kind"] != "qradar_link"}
    if alert_refuted and not (collected and collected[-1]["classification"] in REFUTING):
        # Refuted by an external record: the earlier True Positive no longer stands, and nothing newer replaced it.
        revision = entry["revisions"][-1] if entry["revisions"] else {}
        return {"classification": "Refuted", "basis": f"facts refuted: {revision.get('basis')} ({revision.get('source')})",
                "sustained_facts": sorted(sustained), "refuted_facts": sorted(refuted)}
    if collected:
        return {"classification": collected[-1]["classification"], "basis": f"latest collected assessment ({collected[-1]['run']})",
                "sustained_facts": sorted(sustained), "refuted_facts": sorted(refuted)}
    return {"classification": None, "basis": f"no assessment collected; latest attempt {latest.get('state')}",
            "sustained_facts": [], "refuted_facts": []}


def investigations(state: dict) -> list[dict]:
    """Downstream view (scenarios, report, pivots): one item per alert with the current assessment."""
    out = []
    for alert_id, entry in state.get("alerts", {}).items():
        entry["current"] = current(entry)
        latest = entry["attempts"][-1] if entry["attempts"] else {}
        has_report = entry["report"] is not None
        instances = [x["data"] for x in entry["facts"].values()
                     if x["kind"] == "malicious_instance" and x["status"] == "sustained"]
        report = {**(entry["report"] or {}),
                  "assessment": {"classification": entry["current"]["classification"],
                                 "basis": entry["current"]["basis"],
                                 "facts": ((entry["facts"].get(ASSESSMENT_FACT) or {}).get("data") or {}).get("facts", [])},
                  "link_evidence": {"malicious_instances": instances,
                                    "observables": (entry["report"] or {}).get("observables") or []}}
        out.append({"alert_id": alert_id, "state": "collected" if has_report else latest.get("state", "unknown"),
                    "association": entry["association"], "report": report if has_report else None,
                    "latest_attempt": {k: latest.get(k) for k in ("run", "state", "classification", "error")},
                    "collected_in_run": (entry["report"] or {}).get("collected_in_run"),
                    "link": entry.get("link")})
    return out


def apply_run(state: dict | None, raw: dict | None, run_id: str) -> dict:
    state = migrate(state)
    if raw is None:
        state["runs"].append({"run": run_id, "at": now_iso(), "state": "not_requested"})
    else:
        state["runs"].append({"run": run_id, "at": now_iso(), "state": raw.get("state"), "error": raw.get("error"),
                              "reason": raw.get("reason")})
        state["state"] = raw.get("state")
        if raw.get("related_alert_ids") is not None:
            state["related_alert_ids"] = raw["related_alert_ids"]
        state["not_deepened"] = raw.get("not_deepened", [])
        state["criterion"] = raw.get("criterion", state.get("criterion"))
        for item in raw.get("investigations", []):
            apply_attempt(state, item, run_id)
    state["runs"] = state["runs"][-MAX_ATTEMPTS:]
    state["investigations"] = investigations(state)
    return state


def migrate(state: dict | None) -> dict:
    """Accept states written before facts existed (a list of compacted investigations)."""
    if not state:
        return new_state()
    if "alerts" in state:
        state.setdefault("runs", [])
        return state
    migrated = new_state()
    migrated.update({k: state.get(k) for k in ("related_alert_ids", "not_deepened", "criterion") if state.get(k)})
    migrated["state"] = state.get("state", "unknown")
    for item in state.get("investigations", []):
        apply_attempt(migrated, item, item.get("collected_in_run") or "earlier-version")
    migrated["investigations"] = investigations(migrated)
    return migrated


def from_raw(raw: dict | None, run_id: str = "this-call") -> dict:
    return apply_run(None, raw, run_id) if raw else new_state()
