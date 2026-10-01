"""Code-integrity records (5038/6281) and hash comparisons, kept separate unless linked."""

from __future__ import annotations

import re

from .process_chain import host, same_host
from .windows_events import value_of

INTEGRITY_IDS = {5038: "Code integrity determined that the image hash of a file is not valid",
                 6281: "Code integrity determined that the page hashes of an image file are not valid"}
VOLUME = re.compile(r"^(?:\\device\\harddiskvolume\d+\\|[a-z]:\\|\\\\\?\\[a-z]:\\)", re.I)


def path_tail(path: str | None) -> str | None:
    """Comparable tail without drive/volume prefix; the volume mapping itself is unverified."""
    if not path:
        return None
    text = path.strip().replace("/", "\\").lower()
    return VOLUME.sub("", text) or None


def analyze(records: list[dict], processes: list[dict]) -> dict:
    findings = []
    for record in records:
        if record["event_id"] not in INTEGRITY_IDS:
            continue
        reported = value_of(record, "FileName")
        tail = path_tail(reported)
        record_host = host(value_of(record, "Computer"))
        related = []
        for process in processes:
            for role, path in (("image", process.get("image")),
                               ("argument", next((a["path_as_reported"] for a in process.get("file_arguments", [])
                                                  if path_tail(a["path_as_reported"]) == tail), None))):
                if tail and path and path_tail(path) == tail and same_host(record_host, process.get("host_norm")):
                    related.append({"process_guid": process.get("guid_norm"), "role": role,
                                    "status": "candidate",
                                    "basis": "Same path tail on the same host; volume mapping, file version and timing unverified"})
        findings.append({
            "event_id": record["event_id"], "provenance": record["provenance"],
            "file_as_reported": reported, "host": record_host,
            "windows_description": INTEGRITY_IDS[record["event_id"]],
            "interpretation": ("Windows recorded a failed hash validation for this file. This alone does not "
                               "establish disk corruption, tampering or compromise; nor does it describe any other file."),
            "relationship_to_process_chain": related or "separate finding: no demonstrated link to the observed processes",
            "file_name_possibly_truncated": record["fields"].get("FileName", {}).get("possibly_truncated", False)})
    seen: dict[str, list] = {}
    abbreviated = []
    for process in processes:
        for algo, digest in process.get("hashes", {}).items():
            if digest["comparable"]:
                seen.setdefault(f"{algo}={digest['value'].lower()}", []).append(process.get("guid_norm"))
            else:
                abbreviated.append({"process_guid": process.get("guid_norm"), "algorithm": algo,
                                    "value_as_reported": digest["value"],
                                    "note": "Not a full-length hex digest; not usable as proven equality"})
    repeated = [{"hash": key, "process_guids": guids, "records": len(guids),
                 "note": "Repetition shows the same reported digest only; it does not prove integrity, "
                         "authenticity, signer or authorization."}
                for key, guids in seen.items() if len(guids) > 1]
    return {"integrity_events": findings[:50], "integrity_events_omitted": max(0, len(findings) - 50),
            "repeated_hashes": repeated[:50], "non_comparable_hashes": abbreviated[:50],
            "vendor_path_note": "A vendor-looking path or signed-looking name is not evidence of integrity or authorization."}
