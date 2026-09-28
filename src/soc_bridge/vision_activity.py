"""Bounded Vision One read-only searches for detection and endpoint telemetry."""

from __future__ import annotations

import re
import ipaddress
from datetime import timedelta
from typing import Any, Protocol

from .core import address, instant, iso, records


HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
HASH = re.compile(r"^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
FIELDS = ("uuid", "eventTime", "eventTimeDT", "eventName", "eventId", "eventSubId",
          "endpointHostName", "endpointIp", "endpointGUID", "logonUser", "fileHash",
          "fullPath", "filePath", "objectFilePath", "objectFileHashSha1",
          "objectFileHashSha256", "processFilePath", "processFileHashSha1",
          "processFileHashSha256", "processCmd", "parentFilePath", "parentCmd",
          "processPid", "parentPid", "objectCmd", "src", "dst", "dpt", "spt",
          "objectIp", "objectPort")

PRIVATE_RANGES = tuple(ipaddress.ip_network(cidr) for cidr in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


async def collect_vision_activity(vision: Protocol, event_time: str, host: str = "",
                                  file_hash: str = "") -> dict[str, Any]:
    """Search <= 3 exact, analyst-provided pivots; never search every tenant event."""
    when = instant(event_time)
    if not when:
        raise ValueError("Vision One activity search requires a valid event time")
    start = iso(when - timedelta(minutes=30))
    end = iso(when + timedelta(minutes=30))
    warnings: list[str] = []
    pivots: list[tuple[str, str, str]] = []
    if host:
        if HOST.fullmatch(host):
            pivots.append(("host activity", "search_endpoint_activities_list", f'endpointHostName:"{host}"'))
        else:
            warnings.append("Unsafe hostname omitted from Vision One search")
    if file_hash:
        if HASH.fullmatch(file_hash):
            h = file_hash.lower()
            pivots.append(("file detection", "search_detections_list", f'fileHash:"{h}"'))
            field = "processFileHashSha1" if len(h) == 40 else "processFileHashSha256"
            pivots.append(("process hash activity", "search_endpoint_activities_list", f'{field}:"{h}"'))
        else:
            warnings.append("Invalid SHA-1/SHA-256 omitted from Vision One search")
    findings = []
    host_ips: set[str] = set()
    for name, tool, query in pivots:
        finding: dict[str, Any] = {"pivot": name, "query": query, "state": "unavailable", "rows": []}
        findings.append(finding)
        try:
            result = await vision.call(tool, {"query": query, "startDateTime": start,
                                              "endDateTime": end, "top": "50"})
            rows = records(result)
            finding["state"] = "completed"
            finding["returned"] = len(rows)
            if len(rows) >= 50 or (isinstance(result, dict) and (result.get("nextLink") or result.get("next"))):
                warnings.append(f"Vision One {name} may have more results; only first 50 inspected")
            if name == "host activity":
                for row in rows[:50]:
                    if str(row.get("endpointHostName", "")).casefold() != host.casefold():
                        continue
                    raw_ips = row.get("endpointIp")
                    for raw in raw_ips if isinstance(raw_ips, list) else [raw_ips]:
                        ip = address(raw)
                        if ip and any(ipaddress.ip_address(ip) in net for net in PRIVATE_RANGES):
                            host_ips.add(ip)
            for row in rows[:20]:
                safe = {key: str(row[key]).replace("\n", " ")[:240]
                        for key in FIELDS if key in row and row[key] is not None}
                safe["time_utc"] = iso(instant(row.get("eventTime") or row.get("eventTimeDT")))
                finding["rows"].append(safe)
        except Exception as exc:
            warnings.append(f"Vision One {name} unavailable ({type(exc).__name__}); check Search permissions/coverage")
    if not pivots:
        warnings.append("No validated host or hash supplied; endpoint search was not run")
    if len(host_ips) > 1:
        warnings.append("Multiple private IPs found for the exact host; automatic QRadar host-IP attribution skipped")
    return {"window": {"start": start, "end": end}, "findings": findings,
            "host_ips": sorted(host_ips), "warnings": warnings,
            "method": "Exact host/hash pivots; ±30 minutes; first 50 per query, 20 displayed; raw payload omitted"}
