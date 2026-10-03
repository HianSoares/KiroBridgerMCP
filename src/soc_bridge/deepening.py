"""Offense -> related Workbench alerts -> the alert-first Trend flow, without recursion or duplicate reads.

An offense-first investigation finds Workbench alerts by IP. Alerts that meet an explicit
association criterion are investigated with the same Trend depth as an alert-first case
(Insights, Search/OAT pivots, hypothesis checks, enrichments), with:
- a maximum number of alerts and one shared deadline/call ceiling split fairly;
- the QRadar side skipped (the offense already is the QRadar evidence), so the alert flow
  cannot start offense lookups again (no recursion);
- a call cache shared by all deepened alerts, so identical reads run once and the alert
  detail already fetched is reused.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .ariel_collection import Budget

CRITERION = ("alert created inside the offense interval (±1 h padding) AND an offense IP equals an impactScope "
             "entity of the alert (impactScopeEntityValue match); an indicator-only match is listed, not deepened")


class CachedVision:
    """Read-through cache keyed by tool and exact arguments; only successful reads are cached."""

    def __init__(self, vision: Any, details: dict[str, dict]):
        self.vision = vision
        self.cache: dict[str, Any] = {json.dumps(["workbench_alert_detail_get", {"alertId": k}], sort_keys=True): v
                                      for k, v in details.items()}
        self.hits = 0
        self.calls = 0
        if hasattr(vision, "available"):
            self.available = vision.available

    async def call(self, tool: str, args: dict) -> Any:
        key = json.dumps([tool, args], sort_keys=True, default=str)
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.calls += 1
        value = await self.vision.call(tool, args)
        self.cache[key] = value
        return value


def eligible(alerts: list[dict]) -> tuple[list[dict], list[dict]]:
    chosen, listed = [], []
    for alert in alerts:
        ok = alert.get("temporal_check") == "within window" and "impactScopeEntityValue" in alert.get("match_fields", [])
        (chosen if ok else listed).append(alert)
    return chosen, listed


async def deepen(vision: Any, alerts: list[dict], offense_id: int, max_alerts: int = 2,
                 max_seconds: float = 90.0, max_calls: int = 80, now: datetime | None = None) -> dict:
    from .alert_investigation import investigate_vision_alert
    chosen, listed = eligible(alerts)
    out: dict[str, Any] = {"criterion": CRITERION, "max_alerts": max_alerts, "investigations": [],
                           "not_deepened": [{"alert_id": a["alert_id"], "reason": "association criterion not met"}
                                            for a in listed],
                           "recursion_guard": "alert flows started here skip QRadar lookups; the offense is the QRadar side"}
    for alert in chosen[max_alerts:]:
        out["not_deepened"].append({"alert_id": alert["alert_id"], "reason": f"cap of {max_alerts} deepened alerts"})
    chosen = chosen[:max_alerts]
    if not chosen:
        out["state"] = "no_eligible_alert"
        return out
    cached = CachedVision(vision, {a["alert_id"]: a["detail"] for a in chosen if isinstance(a.get("detail"), dict)})
    parent = Budget(max_seconds=max_seconds, max_queries=0, max_calls=max_calls, max_records=8000, max_partitions=24)
    visited: set[str] = set()
    for index, alert in enumerate(chosen):
        alert_id = alert["alert_id"]
        if alert_id in visited:
            continue
        visited.add(alert_id)
        share = len(chosen) - index
        seconds = parent.remaining_seconds() / share
        calls = (parent.max_calls - parent.calls_made) // share
        if seconds <= 1 or calls < 1:
            out["investigations"].append({"alert_id": alert_id, "state": "not_executed",
                                          "reason": "shared deepening budget exhausted"})
            continue
        budget = Budget(max_seconds=seconds, max_queries=0, max_calls=calls, max_records=4000,
                        max_partitions=max(4, parent.max_partitions // share))
        budget.reserve("hypothesis", calls=max(1, calls // 6), seconds=seconds / 8)
        budget.reserve("enrichment", calls=max(1, calls // 5), seconds=seconds / 10)
        try:
            report = await investigate_vision_alert(None, cached, alert_id, enable_vision_search=True,
                                                    qradar_correlation=False, budget=budget,
                                                    now=now or datetime.now(timezone.utc))
            out["investigations"].append({"alert_id": alert_id, "state": "collected", "report": report,
                                          "association": {"temporal_check": alert.get("temporal_check"),
                                                          "match_fields": alert.get("match_fields"),
                                                          "offense_ips": alert.get("indicators")}})
        except Exception as exc:
            out["investigations"].append({"alert_id": alert_id, "state": "failed", "error": type(exc).__name__})
        parent.calls_made += budget.calls_made
        parent.records_seen += budget.records_seen
    out["state"] = "collected"
    out["cache"] = {"upstream_calls": cached.calls, "reused_results": cached.hits}
    out["budget"] = parent.describe()
    out["offense_id"] = offense_id
    return out
