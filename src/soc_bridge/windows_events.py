"""Structured Windows/Sysmon fields from properties or recognized payloads, with provenance.

Payloads are untrusted telemetry. Values are kept as reported; absent fields stay
absent; a label repeated inside a text payload (for example inside a command
line) marks that field ambiguous so it cannot be used to link records.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .aql_fields import LOGICAL_FIELDS, normalize

# Sysmon EventID 1 message labels, Security 4688/5038 labels -> logical names.
TEXT_LABELS = {
    "UtcTime": "UtcTime", "ProcessGuid": "ProcessGuid", "ProcessId": "ProcessId", "Image": "Image",
    "CommandLine": "CommandLine", "CurrentDirectory": None, "User": "User", "LogonGuid": "LogonGuid",
    "LogonId": "LogonId", "TerminalSessionId": "TerminalSessionId", "IntegrityLevel": None,
    "Hashes": "Hashes", "ParentProcessGuid": "ParentProcessGuid", "ParentProcessId": "ParentProcessId",
    "ParentImage": "ParentImage", "ParentCommandLine": "ParentCommandLine", "ParentUser": None,
    "RuleName": None, "FileVersion": None, "Description": None, "Product": None, "Company": None,
    "OriginalFileName": None,
    "New Process Name": "Image", "Process Command Line": "CommandLine",
    "Creator Process Name": "ParentImage", "New Process ID": "ProcessId",
    "Creator Process ID": "ParentProcessId", "File Name": "FileName",
    "ScriptBlock ID": "ScriptBlockId", "Path": "ScriptPath",
}
TEXT_LABEL_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(
    re.escape(label) for label in sorted(TEXT_LABELS, key=len, reverse=True)) + r")\s*:", re.I)
XML_DATA = re.compile(r"<Data\s+Name\s*=\s*[\"']([^\"']{1,64})[\"']\s*>(.*?)</Data>", re.I | re.S)
XML_EVENT_ID = re.compile(r"<EventID[^>]*>\s*(\d{1,6})\s*</EventID>", re.I)
XML_COMPUTER = re.compile(r"<Computer>([^<]{1,255})</Computer>", re.I)
XML_RECORD = re.compile(r"<EventRecordID>\s*(\d{1,20})\s*</EventRecordID>", re.I)
XML_EXECUTION = re.compile(r"<Execution\s+ProcessID\s*=\s*[\"'](\d{1,10})[\"']", re.I)
XML_PROVIDER = re.compile(r"<Provider\s+Name\s*=\s*[\"']([^\"']{1,200})[\"']", re.I)
XML_CHANNEL = re.compile(r"<Channel>\s*([^<]{1,200}?)\s*</Channel>", re.I)
TEXT_CHANNEL = re.compile(r"(?<![A-Za-z])(?:Channel|AgentLogFile)\s*=\s*\"?([^\s\"]{1,200})", re.I)
TEXT_PROVIDER = re.compile(r"(?<![A-Za-z])(?:ProviderName|Provider|SourceName)\s*=\s*\"?([^\s\"]{1,200})", re.I)
TEXT_EVENT_ID = re.compile(r"(?<![A-Za-z])(?:EventID|Event ID|EventCode)\s*[:=]\s*\"?(\d{1,6})", re.I)
TEXT_COMPUTER = re.compile(r"(?<![A-Za-z])Computer(?:Name)?\s*[:=]\s*\"?([A-Za-z0-9][A-Za-z0-9._-]{0,254})", re.I)
TEXT_RECORD = re.compile(r"(?<![A-Za-z])(?:RecordNumber|EventRecordID)\s*[:=]\s*\"?(\d{1,20})", re.I)
SCRIPT_BLOCK = re.compile(r"Creating Scriptblock text \((\d+) of (\d+)\):\s*(.*?)(?:\s*ScriptBlock ID:\s*|\Z)", re.I | re.S)
HASH_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64, "IMPHASH": 32}
HEX = re.compile(r"^[0-9A-Fa-f]+$")
LOGICAL_BY_NORM = {alias: name for name, aliases in LOGICAL_FIELDS.items() for alias in aliases}
LOGICAL_BY_NORM.update({"filename": "FileName", "scriptpath": "ScriptPath", "path": "ScriptPath",
                        "messagenumber": "MessageNumber", "messagetotal": "MessageTotal",
                        "channel": "Channel", "provider": "Provider", "providername": "Provider",
                        "sourcename": "Provider"})


def _put(fields: dict, name: str | None, value: Any, source: str, cut: bool = False,
         ambiguous: bool = False) -> None:
    if not name or value is None:
        return
    text = str(value).strip()
    if not text:
        return
    entry = {"value": text, "source": source, "possibly_truncated": cut}
    if ambiguous:
        entry["ambiguous"] = True
    current = fields.get(name)
    if current is None:
        fields[name] = entry
    elif current["value"] != text:
        # Keep the first (property > xml > json > text) value and expose the disagreement.
        current.setdefault("conflicts", []).append({"value": text, "source": source})


def _from_text(payload: str, fields: dict, ambiguous: set[str], cut: bool) -> None:
    matches = list(TEXT_LABEL_RE.finditer(payload))
    seen: dict[str, int] = {}
    for match in matches:
        label = next(key for key in TEXT_LABELS if key.lower() == match[1].lower())
        seen[label] = seen.get(label, 0) + 1
    # A repeated label means some value carried injected label text; no text
    # field from this payload can be trusted for linking or comparison.
    repeated = any(count > 1 for count in seen.values())
    for index, match in enumerate(matches):
        label = next(key for key in TEXT_LABELS if key.lower() == match[1].lower())
        name = TEXT_LABELS[label]
        end = matches[index + 1].start() if index + 1 < len(matches) else len(payload)
        last = index + 1 == len(matches)
        value = payload[match.end():end]
        if name and (not repeated or seen[label] == 1 or name not in fields):
            if repeated:
                ambiguous.add(name)
            _put(fields, name, value, "payload:text", cut and last, repeated)


def _from_xml(payload: str, fields: dict, ambiguous: set[str], cut: bool) -> None:
    names: dict[str, int] = {}
    for match in XML_DATA.finditer(payload):
        names[match[1]] = names.get(match[1], 0) + 1
    # An unclosed final element (cut payload) does not match and stays absent.
    for match in XML_DATA.finditer(payload):
        logical = LOGICAL_BY_NORM.get(normalize(match[1]))
        if not logical:
            continue
        if names[match[1]] > 1:
            ambiguous.add(logical)
            continue
        _put(fields, logical, html.unescape(match[2]), "payload:xml")


def _from_json(payload: str, fields: dict) -> bool:
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, RecursionError):
        return False
    if not isinstance(data, dict):
        return False
    layers = [data] + [v for k, v in data.items() if isinstance(v, dict) and normalize(k) in ("eventdata", "event", "winlog")]
    for layer in layers:
        for key, value in layer.items():
            logical = LOGICAL_BY_NORM.get(normalize(key))
            if logical and isinstance(value, (str, int)):
                _put(fields, logical, value, "payload:json")
    return True


def parse_hashes(value: str) -> dict:
    """Sysmon Hashes field; only full-length hex digests are comparable."""
    result = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        algo, digest = (s.strip() for s in part.split("=", 1))
        algo = algo.upper()
        comparable = bool(HEX.fullmatch(digest)) and len(digest) == HASH_LENGTHS.get(algo, -1)
        result[algo] = {"value": digest, "comparable": comparable}
    return result


def extract(row: dict, property_map: dict | None = None, truncated: list[str] | None = None) -> dict:
    """Return {fields, event_id, payload_format, ...}; never invents an absent field."""
    fields: dict = {}
    ambiguous: set[str] = set()
    truncated = truncated or []
    for alias, info in (property_map or {}).items():
        if alias in row and row[alias] not in (None, ""):
            _put(fields, info["logical"], row[alias], f"property:{info['property']}", alias in truncated)
    payload = row.get("raw_payload")
    payload = payload if isinstance(payload, str) else ""
    cut = "raw_payload" in truncated
    payload_format = "none"
    event_id = None
    if "EventID" in fields:
        event_id = {"value": fields["EventID"]["value"], "source": fields["EventID"]["source"]}
    if payload:
        if XML_DATA.search(payload) or XML_EVENT_ID.search(payload):
            payload_format = "xml"
            _from_xml(payload, fields, ambiguous, cut)
            for regex, name in ((XML_EVENT_ID, "EventID"), (XML_COMPUTER, "Computer"), (XML_RECORD, "RecordNumber"),
                                (XML_PROVIDER, "Provider"), (XML_CHANNEL, "Channel")):
                match = regex.search(payload)
                if match:
                    _put(fields, name, html.unescape(match[1]), "payload:xml")
            match = XML_EXECUTION.search(payload)
            if match:
                _put(fields, "ExecutionProcessId", match[1], "payload:xml")
        elif payload.lstrip().startswith("{") and _from_json(payload, fields):
            payload_format = "json"
        else:
            payload_format = "text"
            for regex, name in ((TEXT_EVENT_ID, "EventID"), (TEXT_COMPUTER, "Computer"), (TEXT_RECORD, "RecordNumber"),
                                (TEXT_PROVIDER, "Provider"), (TEXT_CHANNEL, "Channel")):
                match = regex.search(payload)
                if match:
                    _put(fields, name, match[1], "payload:text")
            block = SCRIPT_BLOCK.search(payload)
            if block:
                _put(fields, "MessageNumber", block[1], "payload:text")
                _put(fields, "MessageTotal", block[2], "payload:text")
                text_cut = cut and block.end() >= len(payload)
                _put(fields, "ScriptBlockText", block[3], "payload:text", text_cut)
                rest = payload[block.end():]
                _from_text(rest, fields, ambiguous, cut)
            else:
                _from_text(payload, fields, ambiguous, cut)
    if event_id is None and "EventID" in fields:
        event_id = {"value": fields["EventID"]["value"], "source": fields["EventID"]["source"]}
    numeric = int(event_id["value"]) if event_id and str(event_id["value"]).isdigit() else None
    return {"fields": {k: v for k, v in fields.items() if k != "EventID"},
            "event_id": numeric, "event_id_source": event_id["source"] if event_id else None,
            "payload_format": payload_format, "payload_truncated_by_bridge": cut,
            "ambiguous_fields": sorted(ambiguous),
            "absence_note": ("Fields not listed were not observed in the selected properties or the "
                             "recognized payload text; this is not proof they were absent at the source.")}


def value_of(record: dict, name: str) -> str | None:
    """Usable value for analysis; ambiguous or conflicting values are withheld."""
    entry = record["fields"].get(name)
    if not entry or entry.get("ambiguous") or entry.get("conflicts"):
        return None
    return entry["value"]
