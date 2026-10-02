"""Structured Workbench alert interpretation with provenance; never scrapes free text.

Follows the documented Workbench v3 shapes (impactScope.entities with entityType,
entityId and entityValue as object or scalar; indicators with id/type/field/value
and relations; matchedRules -> matchedFilters -> matchedEvents) plus documented
top-level aliases. Every extracted value records where it came from. Field states
separate "absent", "empty", "unrecognized" and "cut by bridge"; the caller adds
"source unavailable" when the detail itself could not be read.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

MAX_VALUE = 8192
MAX_ITEMS = 200
MISSING = object()
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX = re.compile(r"^[0-9A-Fa-f]+$")
GUID = re.compile(r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")
HOST_ENTITY_TYPES = {"host", "endpoint", "device"}
USER_ENTITY_TYPES = {"account", "user", "useraccount"}
EMAIL_ENTITY_TYPES = {"emailaddress", "email", "mailbox"}

# Top-level detail aliases -> (category, role). Roles keep endpoint, process,
# object and parent apart; "unknown" means the alias does not say which one.
ALIASES = {
    "endpointhostname": ("host", "endpoint"), "endpointname": ("host", "endpoint"),
    "hostname": ("host", "endpoint"), "computername": ("host", "endpoint"),
    "endpointip": ("ip", "endpoint"), "endpointguid": ("endpoint_guid", "endpoint"),
    "agentguid": ("endpoint_guid", "endpoint"),
    "processname": ("process", "process"), "processfilepath": ("path", "process"),
    "processcmd": ("command", "process"), "processcommandline": ("command", "process"),
    "commandline": ("command", "unknown"),
    "processfilehashsha1": ("hash", "process"), "processfilehashsha256": ("hash", "process"),
    "processfilehashmd5": ("hash", "process"), "processpid": ("pid", "process"),
    "parentfilepath": ("path", "parent"), "parentcmd": ("command", "parent"),
    "parentfilehashsha1": ("hash", "parent"), "parentfilehashsha256": ("hash", "parent"),
    "parentpid": ("pid", "parent"),
    "objectfilepath": ("path", "object"), "objectcmd": ("command", "object"),
    "objectfilehashsha1": ("hash", "object"), "objectfilehashsha256": ("hash", "object"),
    "objectpid": ("pid", "object"),
    "fullpath": ("path", "object"), "filepath": ("path", "object"), "filename": ("file", "object"),
    "filehash": ("hash", "object"), "sha1": ("hash", "unknown"), "sha256": ("hash", "unknown"),
    "logonuser": ("user", "process"), "username": ("user", "unknown"), "accountname": ("user", "unknown"),
    "useraccount": ("user", "unknown"),
}
# Indicator "field" prefixes -> role.
FIELD_ROLES = (("process", "process"), ("parent", "parent"), ("object", "object"),
               ("endpoint", "endpoint"), ("logon", "process"), ("src", "network"), ("dst", "network"))


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def bounded(value: Any) -> tuple[Any, bool]:
    """Keep values whole up to MAX_VALUE characters; report any cut explicitly."""
    if isinstance(value, str) and len(value) > MAX_VALUE:
        return value[:MAX_VALUE], True
    return value, False


def shape(node: Any, depth: int = 0) -> Any:
    """Keys and types only (no values) to diagnose extractor failures safely."""
    if depth >= 4:
        return type(node).__name__
    if isinstance(node, dict):
        keys = list(node)[:40]
        out = {str(k)[:64]: shape(node[k], depth + 1) for k in keys}
        if len(node) > 40:
            out["..."] = f"{len(node) - 40} more keys"
        return out
    if isinstance(node, list):
        return [f"list[{len(node)}]", shape(node[0], depth + 1)] if node else ["list[0]"]
    return type(node).__name__


def field_state(value: Any) -> str:
    if value is MISSING:
        return "absent"
    if value in (None, "", [], {}):
        return "empty"
    return "present"


def ip_values(value: Any) -> tuple[list[str], int]:
    """IPv4/IPv6 from a scalar or a list; returns (valid, rejected count)."""
    items = value if isinstance(value, list) else [value]
    valid, rejected = [], 0
    for item in items[:MAX_ITEMS]:
        try:
            valid.append(str(ipaddress.ip_address(str(item).strip())))
        except ValueError:
            rejected += 1
    return valid, rejected


def hash_kind(value: str) -> str | None:
    value = value.strip()
    return HASH_LENGTHS.get(len(value)) if HEX.fullmatch(value) else None


class Collector:
    def __init__(self) -> None:
        self.observables: dict[str, list[dict]] = {}
        self.cut: list[str] = []
        self.rejected: list[dict] = []

    def add(self, category: str, value: Any, source: str, role: str = "unknown", **extra: Any) -> None:
        if value in (None, ""):
            return
        if isinstance(value, (dict, list)):
            self.rejected.append({"source": source, "reason": f"{category}: structured value not interpreted"})
            return
        value, cut = bounded(str(value).strip())
        if cut:
            self.cut.append(source)
        items = self.observables.setdefault(category, [])
        for item in items:
            if item["value"] == value and item["role"] == role:
                item["sources"].append(source)
                return
        if len(items) < MAX_ITEMS:
            items.append({"value": value, "role": role, "sources": [source], "cut_by_bridge": cut, **extra})


def _host_value(c: Collector, value: Any, path: str) -> dict:
    """entityValue as object (name/guid/ips) or scalar; returns the parsed endpoint."""
    endpoint: dict[str, Any] = {"source": path}
    if isinstance(value, dict):
        name, guid, ips = value.get("name", MISSING), value.get("guid", MISSING), value.get("ips", MISSING)
        endpoint["fields"] = {"name": field_state(name), "guid": field_state(guid), "ips": field_state(ips)}
        if isinstance(name, str) and name.strip():
            endpoint["name"] = name.strip()
            c.add("host", name, f"{path}.name", "endpoint")
        if isinstance(guid, str) and guid.strip():
            endpoint["guid"] = guid.strip()
            c.add("endpoint_guid", guid, f"{path}.guid", "endpoint")
        if ips not in (MISSING, None):
            valid, rejected = ip_values(ips)
            endpoint["ips"] = valid
            endpoint["ips_rejected"] = rejected
            for ip in valid:
                c.add("ip", ip, f"{path}.ips", "endpoint")
    elif isinstance(value, str) and value.strip():
        endpoint["name"] = value.strip()
        c.add("host", value, path, "endpoint")
    return endpoint


def _entities(detail: dict, c: Collector) -> tuple[list[dict], dict, dict]:
    scope = detail.get("impactScope", MISSING)
    state = {"impactScope": field_state(scope)}
    counts: dict[str, int] = {}
    if isinstance(scope, dict):
        entities = scope.get("entities", MISSING)
        counts = {k: v for k, v in scope.items() if k.endswith("Count") and isinstance(v, int)}
        base = "impactScope.entities"
    elif isinstance(scope, list):
        entities, base = scope, "impactScope"
        state["impactScope"] = "present (list shape; parsed as entities)"
    else:
        entities, base = MISSING, "impactScope.entities"
        if scope is not MISSING and scope is not None:
            state["impactScope"] = "unrecognized"
    state["impactScope.entities"] = field_state(entities) if isinstance(entities, list) or entities is MISSING else "unrecognized"
    parsed: list[dict] = []
    for index, entity in enumerate(entities if isinstance(entities, list) else []):
        path = f"{base}[{index}]"
        if index >= MAX_ITEMS:
            state["impactScope.entities"] += f"; {len(entities) - MAX_ITEMS} entities beyond the bridge cap"
            break
        if not isinstance(entity, dict):
            parsed.append({"source": path, "state": "unrecognized", "shape": shape(entity)})
            continue
        etype = str(entity.get("entityType") or entity.get("type") or "")
        value = entity.get("entityValue", entity.get("value", MISSING))
        eid = entity.get("entityId", MISSING)
        item = {"source": path, "entity_type": etype or None, "entity_id": eid if eid is not MISSING else None,
                "value_kind": ("object" if isinstance(value, dict) else "list" if isinstance(value, list)
                               else "absent" if value is MISSING else "empty" if value in (None, "") else "scalar"),
                "related_indicator_ids": entity.get("relatedIndicatorIds") or [],
                "related_entities": entity.get("relatedEntities") or [],
                "provenance": entity.get("provenance") or []}
        kind = _norm_key(etype)
        if kind in HOST_ENTITY_TYPES or (isinstance(value, dict) and {"name", "guid", "ips"} & set(value)):
            item["endpoint"] = _host_value(c, value, f"{path}.entityValue")
            if isinstance(eid, list):
                for ip in ip_values(eid)[0]:
                    c.add("ip", ip, f"{path}.entityId", "endpoint")
        elif kind in USER_ENTITY_TYPES:
            name = value.get("name") if isinstance(value, dict) else value
            c.add("user", name, f"{path}.entityValue", "account")
        elif kind in EMAIL_ENTITY_TYPES:
            c.add("email", value if not isinstance(value, dict) else value.get("name"), f"{path}.entityValue", "mailbox")
        elif kind in {"ip", "ipaddress"}:
            for ip in ip_values(value)[0]:
                c.add("ip", ip, f"{path}.entityValue", "unknown")
        elif value is not MISSING and not isinstance(value, (dict, list)):
            c.add("other", value, f"{path}.entityValue", etype or "unknown")
        else:
            item["state"] = "unrecognized entity shape"
            item["shape"] = shape(value)
        parsed.append(item)
    return parsed, state, counts


def indicator_category(itype: str, field: str, value: str) -> str:
    t = _norm_key(itype)
    f = _norm_key(field)
    if "sha256" in t or "sha256" in f or "sha1" in t or "sha1" in f or "md5" in t or "md5" in f or "hash" in t:
        return "hash"
    if t in {"ip", "ipaddress", "ipv4", "ipv6"} or f.endswith("ip") or f.endswith("ips"):
        return "ip"
    if "command" in t or f.endswith("cmd") or "commandline" in f:
        return "command"
    if "fullpath" in t or "path" in t or f.endswith("filepath"):
        return "path"
    if "domain" in t or "fqdn" in t:
        return "domain"
    if "url" in t or f in {"request", "url"}:
        return "url"
    if "email" in t or "mail" in t:
        return "email"
    if "user" in t or "account" in t or f in {"logonuser", "username"}:
        return "user"
    if "host" in t or f.endswith("hostname"):
        return "host"
    if "filename" in t or t == "file" or f.endswith("filename"):
        return "file"
    if "pid" in t or f.endswith("pid"):
        return "pid"
    return "other"


def role_from_field(field: str) -> str:
    low = field.lower()
    return next((role for prefix, role in FIELD_ROLES if low.startswith(prefix)), "unknown")


def _indicators(detail: dict, c: Collector) -> tuple[list[dict], str]:
    raw = detail.get("indicators", MISSING)
    state = field_state(raw) if isinstance(raw, list) or raw is MISSING else "unrecognized"
    parsed = []
    for index, ind in enumerate(raw if isinstance(raw, list) else []):
        path = f"indicators[{index}]"
        if index >= MAX_ITEMS:
            state += f"; {len(raw) - MAX_ITEMS} indicators beyond the bridge cap"
            break
        if not isinstance(ind, dict):
            parsed.append({"source": path, "state": "unrecognized", "shape": shape(ind)})
            continue
        itype = str(ind.get("type") or "")
        field = str(ind.get("field") or "")
        value = ind.get("value", ind.get("indicatorValue", MISSING))
        item = {"source": path, "id": ind.get("id"), "type": itype or None, "field": field or None,
                "related_entities": ind.get("relatedEntities") or [], "filter_ids": ind.get("filterIds") or [],
                "provenance": ind.get("provenance") or [], "value_kind": "object" if isinstance(value, dict) else
                ("absent" if value is MISSING else "empty" if value in (None, "") else "scalar")}
        if "indicatorValue" in ind and "value" not in ind:
            item["note"] = "legacy indicatorValue key"
        role = role_from_field(field)
        if isinstance(value, dict):
            # Object-valued indicators (for example a host) are interpreted by known keys only.
            if {"name", "guid", "ips"} & set(value):
                item["endpoint"] = _host_value(c, value, f"{path}.value")
            else:
                item["state"] = "unrecognized object value"
                item["shape"] = shape(value)
        elif value not in (MISSING, None, ""):
            text = str(value)
            category = indicator_category(itype, field, text)
            if category == "other" and not itype and ip_values(text)[0]:
                category = "ip"
            item["category"] = category
            item["role"] = role
            if category == "ip":
                for ip in ip_values(text)[0]:
                    c.add("ip", ip, f"{path}.value", role, indicator_id=ind.get("id"))
            elif category == "hash":
                c.add("hash", text, f"{path}.value", role, indicator_id=ind.get("id"), algorithm=hash_kind(text))
            else:
                c.add(category, text, f"{path}.value", role, indicator_id=ind.get("id"))
        parsed.append(item)
    return parsed, state


def _matched_rules(detail: dict) -> tuple[list[dict], str, list[str]]:
    raw = detail.get("matchedRules", MISSING)
    state = field_state(raw) if isinstance(raw, list) or raw is MISSING else "unrecognized"
    rules, uuids = [], []
    for r_index, rule in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(rule, dict):
            continue
        filters = []
        for f_index, flt in enumerate(rule.get("matchedFilters") or []):
            if not isinstance(flt, dict):
                continue
            events = []
            for event in (flt.get("matchedEvents") or [])[:MAX_ITEMS]:
                if isinstance(event, dict):
                    events.append({"uuid": event.get("uuid"), "matched_date_time": event.get("matchedDateTime"),
                                   "type": event.get("type")})
                    if isinstance(event.get("uuid"), str):
                        uuids.append(event["uuid"])
            filters.append({"id": flt.get("id"), "name": flt.get("name"),
                            "matched_date_time": flt.get("matchedDateTime"),
                            "mitre_technique_ids": flt.get("mitreTechniqueIds") or [],
                            "matched_events": events, "source": f"matchedRules[{r_index}].matchedFilters[{f_index}]"})
        rules.append({"id": rule.get("id"), "name": rule.get("name"), "matched_filters": filters})
    return rules, state, list(dict.fromkeys(uuids))


def _aliases(detail: dict, c: Collector) -> list[str]:
    used = []
    for key, value in detail.items():
        alias = ALIASES.get(_norm_key(key))
        if not alias or value in (None, "", []):
            continue
        category, role = alias
        used.append(key)
        if category == "ip":
            for ip in ip_values(value)[0]:
                c.add("ip", ip, key, role)
        elif category == "hash" and isinstance(value, str):
            c.add("hash", value, key, role, algorithm=hash_kind(value))
        elif isinstance(value, list):
            for item in value[:MAX_ITEMS]:
                c.add(category, item, key, role)
        else:
            c.add(category, value, key, role)
    return used


def endpoints(entities: list[dict], indicators: list[dict], observables: dict) -> list[dict]:
    """Every endpoint seen, merged only on an equal GUID or equal name; never the first one silently."""
    merged: list[dict] = []
    for item in [e.get("endpoint") for e in entities] + [i.get("endpoint") for i in indicators]:
        if not item:
            continue
        match = next((m for m in merged if (item.get("guid") and m.get("guid") == item.get("guid")) or
                      (item.get("name") and m.get("name") and m["name"].lower() == item["name"].lower())), None)
        if match:
            match["sources"].append(item["source"])
            match["ips"] = sorted(set(match.get("ips", [])) | set(item.get("ips", [])))
            match["guid"] = match.get("guid") or item.get("guid")
            match["name"] = match.get("name") or item.get("name")
        else:
            merged.append({"name": item.get("name"), "guid": item.get("guid"), "ips": item.get("ips", []),
                           "sources": [item["source"]]})
    if not merged:
        names = [o for o in observables.get("host", []) if o["role"] == "endpoint"]
        guids = [o for o in observables.get("endpoint_guid", [])]
        if len(names) <= 1 and len(guids) <= 1 and (names or guids):
            merged.append({"name": names[0]["value"] if names else None, "guid": guids[0]["value"] if guids else None,
                           "ips": [o["value"] for o in observables.get("ip", []) if o["role"] == "endpoint"],
                           "sources": [s for o in names + guids for s in o["sources"]],
                           "note": "built from top-level aliases"})
        else:
            for o in names:
                merged.append({"name": o["value"], "guid": None, "ips": [], "sources": o["sources"],
                               "note": "alias host without a guid/ip binding"})
    return merged


def parse_alert(detail: dict) -> dict:
    """Structured, bounded view of one Workbench alert detail."""
    c = Collector()
    entities, scope_state, counts = _entities(detail, c)
    indicators, indicator_state = _indicators(detail, c)
    rules, rule_state, uuids = _matched_rules(detail)
    alias_keys = _aliases(detail, c)
    found = endpoints(entities, indicators, c.observables)
    states = {**scope_state, "indicators": indicator_state, "matchedRules": rule_state}
    for name in ("createdDateTime", "updatedDateTime", "firstInvestigatedDateTime", "model", "severity", "score"):
        states[name] = field_state(detail.get(name, MISSING))
    if c.cut:
        states["cut_by_bridge"] = sorted(set(c.cut))[:50]
    nothing = not any(c.observables.values())
    return {
        "entities": entities, "impact_scope_counts": counts, "indicators": indicators,
        "matched_rules": rules, "matched_event_uuids": uuids, "endpoints": found,
        "observables": c.observables, "alias_keys_used": alias_keys, "field_states": states,
        "rejected_values": c.rejected[:50],
        "shape": shape({k: v for k, v in detail.items() if k in {"impactScope", "indicators", "matchedRules"}}),
        "extraction_note": ("No entity extracted. Check field_states and shape before concluding the API exposes none: "
                            "absent, empty and unrecognized formats are different situations.") if nothing else None,
    }
