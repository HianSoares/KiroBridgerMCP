"""Process creation, parent/child links and PowerShell content as separate evidence classes.

Links require a normalized ProcessGuid/ParentProcessGuid pair on the same host.
PID, IP or time proximity alone never link records. Decoding is data
conversion only: nothing collected is executed.
"""

from __future__ import annotations

import base64
import binascii
import re

from .windows_events import parse_hashes, value_of

GUID = re.compile(r"^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
POWERSHELL = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
CREATION_IDS = {1: "Sysmon process creation", 4688: "Security process creation"}
SCRIPT_IDS = {4104: "PowerShell script-block logging", 4103: "PowerShell module logging"}
# IEX criterion: the standalone token iex or Invoke-Expression, case-insensitive,
# not part of a longer word or file name (so iexplore.exe and file.iex do not match).
IEX = re.compile(r"(?<![A-Za-z0-9_.\-])(?:iex|invoke-expression)(?![A-Za-z0-9_.\-])", re.I)
IEX_CRITERIA = ("Token 'iex' or 'Invoke-Expression' as a standalone word (case-insensitive); "
                "substrings such as iexplore.exe are excluded. Obfuscated forms (backticks, string "
                "concatenation, aliases built at runtime) are not detected.")
ENCODED = re.compile(r"(?<![A-Za-z0-9])[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|"
                     r"encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", re.I)
FILE_ARG = re.compile(r"\"((?:[A-Za-z]:\\|\\\\)[^\"]{1,400})\"|((?:[A-Za-z]:\\|\\\\)[^\s\"'|<>]{1,400})")
MAX_ITEMS = 100
MAX_DEPTH = 16
PREVIEW = 4000


def guid(value: str | None) -> str | None:
    match = GUID.fullmatch(value.strip()) if isinstance(value, str) else None
    return match[1].lower() if match else None


def host(value: str | None) -> str | None:
    if not isinstance(value, str) or not HOST.fullmatch(value.strip()):
        return None
    return value.strip().lower()


def same_host(a: str | None, b: str | None) -> bool:
    """Exact FQDN match, or short-name match when one side has no domain."""
    if not a or not b:
        return False
    if a == b:
        return True
    return ("." not in a or "." not in b) and a.split(".")[0] == b.split(".")[0]


def basename(path: str | None) -> str | None:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower() if path else None


def arguments(command_line: str | None, image: str | None) -> str | None:
    """Text after the executable token; None when the command line was not observed."""
    if command_line is None:
        return None
    text = command_line.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        rest = text[end + 1:] if end > 0 else ""
    else:
        parts = text.split(None, 1)
        rest = parts[1] if len(parts) > 1 else ""
    return rest.strip()


def file_arguments(command_line: str | None, image: str | None) -> list[dict]:
    rest = arguments(command_line, image)
    found = []
    for match in FILE_ARG.finditer(rest or ""):
        path = match[1] or match[2]
        if image and path.lower() == image.lower():
            continue
        found.append({"path_as_reported": path, "relationship": "argument_reference",
                      "note": "Named as a command-line argument. Execution of this file, or examination "
                              "of it by the process, is not established by the argument alone."})
        if len(found) >= 20:
            break
    return found


def decode_encoded(text: str) -> list[dict]:
    """Base64/UTF-16LE as data only; success never proves the command is complete."""
    commands = []
    for match in ENCODED.finditer(text or ""):
        blob = match[1]
        decoded = None
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-16le")
        except (ValueError, binascii.Error, UnicodeError):
            pass
        commands.append({"base64_observed": blob[:2048], "decoded_utf16le": decoded[:2048] if decoded else decoded,
                         "preview_truncated": len(blob) > 2048 or bool(decoded and len(decoded) > 2048),
                         "iex_tokens": len(IEX.findall(decoded or "")),
                         "completeness": "Not proven by successful decoding; compare the original record",
                         "executed_by_bridge": False})
        if len(commands) >= 10:
            break
    return commands


def _process(record: dict) -> dict:
    fields = record["fields"]
    hashes = parse_hashes(value_of(record, "Hashes") or "") if value_of(record, "Hashes") else {}
    item = {"kind": "process_creation_observed", "event_id": record["event_id"],
            "event_meaning": CREATION_IDS[record["event_id"]], "provenance": record["provenance"],
            "fields": fields, "host_norm": host(value_of(record, "Computer")),
            "guid_norm": guid(value_of(record, "ProcessGuid")),
            "parent_guid_norm": guid(value_of(record, "ParentProcessGuid")),
            "pid": value_of(record, "ProcessId"), "parent_pid": value_of(record, "ParentProcessId"),
            "image": value_of(record, "Image"), "command_line": value_of(record, "CommandLine"),
            "hashes": hashes, "ambiguous_fields": record["ambiguous_fields"]}
    item["file_arguments"] = file_arguments(item["command_line"], item["image"])
    if basename(item["image"]) in POWERSHELL:
        rest = arguments(item["command_line"], item["image"])
        item["powershell"] = {
            "command_line_observed": item["command_line"] is not None,
            "no_arguments": rest == "" if rest is not None else None,
            "iex_tokens_in_command_line": len(IEX.findall(item["command_line"] or "")),
            "encoded_commands": decode_encoded(item["command_line"] or ""),
            "note": ("Process creation shows only the launch command line. Commands typed or piped into the "
                     "session later, and content loaded at runtime, are not visible here; absence of IEX "
                     "in this command line does not exclude IEX in unobserved content.")}
    return item


def _script_block(record: dict) -> dict:
    text = value_of(record, "ScriptBlockText")
    entry = record["fields"].get("ScriptBlockText", {})
    number, total = value_of(record, "MessageNumber"), value_of(record, "MessageTotal")
    return {"kind": "powershell_session_content", "event_id": record["event_id"],
            "event_meaning": SCRIPT_IDS[record["event_id"]], "provenance": record["provenance"],
            "host_norm": host(value_of(record, "Computer")),
            "execution_pid": value_of(record, "ExecutionProcessId"),
            "script_block_id": value_of(record, "ScriptBlockId"),
            "message_part": f"{number} of {total}" if number and total else None,
            "multi_part_incomplete": bool(number and total and total != "1"),
            "text_preview": text[:PREVIEW] if text else None,
            "text_preview_truncated": bool(text and len(text) > PREVIEW),
            "text_possibly_truncated_at_source_or_bridge": entry.get("possibly_truncated", False) or record["payload_truncated_by_bridge"],
            "iex_tokens": len(IEX.findall(text or "")),
            "note": "Content logged inside a PowerShell session; not a process creation record."}


def analyze(records: list[dict]) -> dict:
    """Separate evidence classes and reconstruct GUID+host links with cycle protection."""
    creations = [_process(r) for r in records if r["event_id"] in CREATION_IDS]
    blocks = [_script_block(r) for r in records if r["event_id"] in SCRIPT_IDS]
    nodes: dict[tuple[str, str], dict] = {}
    duplicates = 0
    for item in creations:
        if item["host_norm"] and item["guid_norm"]:
            key = (item["host_norm"], item["guid_norm"])
            if key in nodes:
                duplicates += 1
            else:
                nodes[key] = item
    links, missing, guid_only = [], [], []
    by_guid: dict[str, list[dict]] = {}
    for item in nodes.values():
        by_guid.setdefault(item["guid_norm"], []).append(item)
    for item in creations:
        parent = item["parent_guid_norm"]
        if not parent:
            if item["parent_pid"]:
                guid_only.append({"child_guid": item["guid_norm"], "parent_pid": item["parent_pid"],
                                  "status": "not_linked", "reason": "ParentProcessGuid not observed; PID alone does not establish the parent"})
            continue
        matches = [n for n in by_guid.get(parent, []) if same_host(n["host_norm"], item["host_norm"])]
        if parent == item["guid_norm"]:
            guid_only.append({"child_guid": item["guid_norm"], "parent_guid": parent, "status": "rejected",
                              "reason": "Record names itself as parent; not used as a link"})
        elif matches:
            links.append({"child_guid": item["guid_norm"], "parent_guid": parent, "host": item["host_norm"],
                          "basis": "ProcessGuid/ParentProcessGuid on the same host", "status": "linked"})
        elif by_guid.get(parent):
            guid_only.append({"child_guid": item["guid_norm"], "parent_guid": parent, "status": "candidate",
                              "reason": "GUID matched a record whose host is missing or different"})
        else:
            missing.append({"child_guid": item["guid_norm"], "parent_guid": parent, "host": item["host_norm"],
                            "parent_image_as_reported": value_of_item(item, "ParentImage"),
                            "status": "parent_not_found_in_collected_window",
                            "note": "A gap in the inspected window/filters, not evidence that the parent did not exist."})
    chains, cycles = [], 0
    parents = {(l["host"], l["child_guid"]): l["parent_guid"] for l in links if l["host"] and l["child_guid"]}
    has_child = {(l["host"], l["parent_guid"]) for l in links}
    for (node_host, node_guid) in list(nodes)[:MAX_ITEMS]:
        path, seen, current, looped = [], set(), node_guid, False
        while current and len(path) < MAX_DEPTH:
            if current in seen:
                looped = True
                break
            seen.add(current)
            path.append(current)
            current = parents.get((node_host, current))
        cycles += looped
        # Chains start at leaves; inner nodes already appear inside them.
        if len(path) > 1 and (node_host, node_guid) not in has_child:
            chains.append({"host": node_host, "child_to_ancestor_guids": path, "cycle": looped})
    pid_groups: dict[tuple, set] = {}
    for item in nodes.values():
        if item["pid"]:
            pid_groups.setdefault((item["host_norm"], item["pid"]), set()).add(item["guid_norm"])
    pid_reuse = [{"host": h, "pid": pid, "distinct_guids": sorted(g),
                  "note": "Same PID, different process GUIDs: PID reuse; PID cannot link these records"}
                 for (h, pid), g in pid_groups.items() if len(g) > 1]
    for block in blocks:
        block["candidate_processes"] = [
            {"guid": p["guid_norm"], "basis": "same host and PID; PID reuse and timing make this a candidate only"}
            for p in creations if p.get("powershell") and block["host_norm"] and
            same_host(p["host_norm"], block["host_norm"]) and p["pid"] and p["pid"] == block["execution_pid"]][:5]
    powershell = [p for p in creations if p.get("powershell")]
    return {"process_creations": [_compact(p) for p in creations[:MAX_ITEMS]],
            "process_creations_omitted": max(0, len(creations) - MAX_ITEMS),
            "duplicate_creation_records": duplicates,
            "links": links[:MAX_ITEMS], "chains": chains[:MAX_ITEMS], "cycles_detected": cycles,
            "missing_parents": missing[:MAX_ITEMS], "unlinked_references": guid_only[:MAX_ITEMS],
            "pid_reuse": pid_reuse[:MAX_ITEMS],
            "powershell_processes": [_compact(p) for p in powershell[:MAX_ITEMS]],
            "script_blocks": blocks[:MAX_ITEMS], "script_blocks_omitted": max(0, len(blocks) - MAX_ITEMS),
            "iex_criteria": IEX_CRITERIA,
            "evidence_classes": {
                "process_creation_observed": "A creation record (Sysmon 1 / Security 4688) for this process.",
                "argument_reference": "A file named in a command line; execution or examination not established.",
                "powershell_session_content": "Script-block/module logging content (4104/4103) inside a session.",
                "legitimate_purpose_hypothesis": "A hypothesis that needs owner/change/inventory evidence; never a finding."}}


def value_of_item(item: dict, name: str) -> str | None:
    entry = item["fields"].get(name)
    return entry["value"] if entry and not entry.get("ambiguous") else None


def _compact(item: dict) -> dict:
    """Bound long values in the response; preview cuts are flagged separately from source cuts."""
    out = dict(item)
    out["fields"] = {}
    for name, entry in item["fields"].items():
        entry = dict(entry)
        if len(entry["value"]) > PREVIEW:
            entry.update(value=entry["value"][:PREVIEW], preview_truncated=True,
                         observed_characters=len(item["fields"][name]["value"]))
        out["fields"][name] = entry
    for key in ("image", "command_line"):
        if out.get(key) and len(out[key]) > PREVIEW:
            out[key] = out[key][:PREVIEW]
            out[f"{key}_preview_truncated"] = True
    return out


def wanted_parents(analysis: dict, already: set[str]) -> list[dict]:
    """Parents to look up next; validated GUIDs only, never repeated."""
    out = []
    for gap in analysis["missing_parents"]:
        parent = guid(gap["parent_guid"])
        if parent and parent not in already:
            out.append(gap)
    return out
