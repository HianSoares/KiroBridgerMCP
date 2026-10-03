"""Evidence status vocabulary and per-conclusion sufficiency.

A conclusion is sustained only when each of its own requirements is met. A gap that a
conclusion does not need never blocks it; a critical gap stays listed against the
conclusions it affects, with the next check that would resolve it. There is no numeric
score: the decision is the set of met/unmet requirements, shown explicitly.
"""

from __future__ import annotations

from typing import Any

STATUSES = {
    "confirmed": "demonstrated by collected records or by a cited analyst-supplied record",
    "compatible": "consistent with the conclusion but does not demonstrate it",
    "candidate": "possible link by identifier/time/IP; not demonstrated",
    "unverified": "not checked or not checkable with the bridge's sources",
    "not_returned": "not returned by the queries executed (not proof of absence)",
    "not_executed": "the read did not run (budget, permission, tool or license); nothing can be inferred",
}
MET = {"confirmed"}


def requirement(rid: str, text: str, status: str, evidence: Any = None, next_check: str = "",
                source: str = "bridge") -> dict:
    if status not in STATUSES:
        raise ValueError(f"unknown evidence status {status}")
    return {"id": rid, "requirement": text, "status": status, "meaning": STATUSES[status],
            "evidence": evidence, "next_check": next_check, "source": source}


def evaluate(conclusions: list[dict], requirements: dict[str, dict],
             contradictions: list[dict] | None = None) -> list[dict]:
    """Each conclusion: {id, label, requires: [requirement ids], contradicted_by: [requirement ids]}.

    An unresolved contradiction blocks every conclusion that requires one of the requirements
    it affects (or names the conclusion itself); resolved ones are only reported."""
    open_items = [c for c in contradictions or [] if c.get("status", "unresolved") == "unresolved"]
    out = []
    for conclusion in conclusions:
        needed = [requirements[r] for r in conclusion["requires"] if r in requirements]
        missing = [r for r in conclusion["requires"] if r not in requirements]
        unmet = [r for r in needed if r["status"] not in MET]
        contradictions = [requirements[r] for r in conclusion.get("contradicted_by", [])
                          if r in requirements and requirements[r]["status"] in MET]
        affected = set(conclusion["requires"]) | {str(conclusion["id"])}
        contradictions += [{"id": c["id"]} for c in open_items if affected & set(map(str, c.get("affects", [])))]
        sustained = not unmet and not missing and not contradictions
        out.append({"id": conclusion["id"], "label": conclusion["label"],
                    "sufficiency": "sustained" if sustained else
                    "contradicted" if contradictions else
                    "partially_supported" if any(r["status"] in MET | {"compatible"} for r in needed) else
                    "not_supported",
                    "met": [r["id"] for r in needed if r["status"] in MET],
                    "blocking": [{"id": r["id"], "status": r["status"], "requirement": r["requirement"],
                                  "next_check": r["next_check"]} for r in unmet] +
                                [{"id": m, "status": "unverified", "requirement": "requirement not evaluated",
                                  "next_check": ""} for m in missing],
                    "contradicted_by": [r["id"] for r in contradictions]})
    return out
