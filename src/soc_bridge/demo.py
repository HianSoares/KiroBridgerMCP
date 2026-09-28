"""Synthetic fixtures; safe to share publicly."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

OFFENSE = {
    "id": 1842,
    "description": "Repeated remote access failures followed by a successful login",
    "offense_source": "198.51.100.24",
    "start_time": 1782306000000,
    "last_updated_time": 1782307800000,
    "magnitude": 7,
}
SOURCES = [{"source_ip": "198.51.100.24", "offense_ids": [1842]}]
DESTINATIONS = [{"local_destination_ip": "192.0.2.15", "offense_ids": [1842]}]
ALERT = {
    "id": "WB-2048", "name": "Suspicious remote sign-in and endpoint activity",
    "severity": "high", "createdDateTime": "2026-06-24T12:55:00Z",
}


class DemoQRadar:
    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "get_offense" and arguments == {"offense_id": 1842}:
            return deepcopy(OFFENSE)
        if name == "list_source_addresses":
            return deepcopy(SOURCES)
        if name == "list_local_destination_addresses":
            return deepcopy(DESTINATIONS)
        raise ValueError(f"Unsupported demo tool: {name}")


class DemoVision:
    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "workbench_alerts_list":
            return {"items": [deepcopy(ALERT)] if "198.51.100.24" in arguments["filter"] else []}
        if name == "workbench_alert_detail_get" and arguments == {"alertId": "WB-2048"}:
            return deepcopy(ALERT)
        raise ValueError(f"Unsupported demo tool: {name}")
