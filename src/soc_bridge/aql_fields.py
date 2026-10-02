"""Live AQL field metadata as untrusted data: discover, never presume, custom properties."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Custom property names are quoted in AQL. Anything outside this alphabet is
# ignored rather than escaped: metadata must not be able to inject syntax.
SAFE_PROPERTY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,127}$")
NAME_KEYS = ("name", "field", "column", "columnName", "column_name", "propertyName",
             "property_name", "display_name", "displayName")
CONTAINER_KEYS = ("fields", "columns", "properties", "event_fields", "flow_fields",
                  "data", "items", "results")
MAX_FIELDS = 5000

# Logical Windows/Sysmon fields and the normalized property names that may
# carry them. These are search keys matched against the live catalog only.
LOGICAL_FIELDS: dict[str, tuple[str, ...]] = {
    "EventID": ("eventid", "eventcode", "windowseventid"),
    "Computer": ("computer", "computername"),
    "UtcTime": ("utctime",),
    "ProcessGuid": ("processguid",),
    "ParentProcessGuid": ("parentprocessguid",),
    "ProcessId": ("processid", "newprocessid"),
    "ParentProcessId": ("parentprocessid", "creatorprocessid"),
    "Image": ("image", "processimage", "newprocessname", "processpath"),
    "ParentImage": ("parentimage", "parentprocessname", "creatorprocessname", "parentprocesspath"),
    "CommandLine": ("commandline", "processcommandline"),
    "ParentCommandLine": ("parentcommandline", "parentprocesscommandline"),
    "User": ("user",),
    "LogonId": ("logonid",),
    "LogonGuid": ("logonguid",),
    "TerminalSessionId": ("terminalsessionid",),
    "Hashes": ("hashes", "processhashes"),
    "RecordNumber": ("recordnumber", "eventrecordid"),
    "ScriptBlockText": ("scriptblocktext",),
    "ScriptBlockId": ("scriptblockid",),
}


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def field_names(data: Any, depth: int = 0) -> list[str]:
    """Extract candidate field names from common metadata shapes; ignore everything else."""
    if depth > 4:
        return []
    names: list[str] = []
    if isinstance(data, list):
        for item in data[:MAX_FIELDS]:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = next((item[key] for key in NAME_KEYS if isinstance(item.get(key), str)), None)
                if name:
                    names.append(name)
    elif isinstance(data, dict):
        for key in CONTAINER_KEYS:
            if key in data:
                names.extend(field_names(data[key], depth + 1))
    return names[:MAX_FIELDS]


@dataclass
class FieldCatalog:
    resource: str
    state: str = "unavailable"
    names: dict[str, str] = field(default_factory=dict)
    ignored_unsafe_names: int = 0

    @classmethod
    def from_metadata(cls, resource: str, payload: Any) -> "FieldCatalog":
        data = payload.get("metadata", payload) if isinstance(payload, dict) else payload
        catalog = cls(resource, "unparsed")
        for name in field_names(data):
            stripped = name.strip()
            if not SAFE_PROPERTY.fullmatch(stripped):
                catalog.ignored_unsafe_names += 1
                continue
            catalog.names.setdefault(normalize(stripped), stripped)
        if catalog.names:
            catalog.state = "available"
        return catalog

    def find(self, aliases: tuple[str, ...]) -> str | None:
        return next((self.names[a] for a in aliases if a in self.names), None)

    def lists(self, name: str) -> bool:
        return normalize(name) in self.names

    def describe(self) -> dict:
        return {"resource": self.resource, "state": self.state, "fields_listed": len(self.names),
                "ignored_unsafe_names": self.ignored_unsafe_names}


async def load_catalog(qradar: Any, resource: str) -> FieldCatalog:
    try:
        return FieldCatalog.from_metadata(resource, await qradar.read_aql_resource(resource))
    except Exception:
        return FieldCatalog(resource)


def quote_property(name: str) -> str:
    if not isinstance(name, str) or not SAFE_PROPERTY.fullmatch(name):
        raise ValueError("Unsafe AQL property name")
    return f'"{name}"'


@dataclass
class SelectPlan:
    """Required columns are always requested; optional ones only when listed live."""
    required: list[tuple[str, str | None]]
    optional: dict[str, tuple[str, str]] = field(default_factory=dict)
    missing_optional: list[str] = field(default_factory=list)
    required_unlisted: list[str] = field(default_factory=list)
    catalog_state: str = "unavailable"
    optional_rejected_by_validation: bool = False

    def select(self, with_optional: bool = True) -> str:
        columns = [expression for expression, _ in self.required]
        # Once QRadar rejected the optional set, later queries in this collection skip it.
        if with_optional and not self.optional_rejected_by_validation:
            columns += [f"{quote_property(prop)} AS {alias}" for alias, (_, prop) in self.optional.items()]
        return "SELECT " + ", ".join(columns)

    def property_map(self) -> dict[str, dict[str, str]]:
        if self.optional_rejected_by_validation:
            return {}
        return {alias: {"logical": logical, "property": prop} for alias, (logical, prop) in self.optional.items()}

    def describe(self) -> dict:
        return {"catalog_state": self.catalog_state,
                "required_columns": [expression for expression, _ in self.required],
                "required_not_listed_in_metadata": self.required_unlisted,
                "optional_selected": {} if self.optional_rejected_by_validation else
                    {logical: prop for logical, prop in self.optional.values()},
                "optional_missing": self.missing_optional,
                "optional_rejected_by_validation": (sorted(logical for logical, _ in self.optional.values())
                                                    if self.optional_rejected_by_validation else []),
                "note": ("Missing optional fields keep the query possible; QRadar validation is authoritative "
                         "for required fields. Unlisted is not proof of absence from stored records.")}


def plan_select(required: list[tuple[str, str | None]], catalog: FieldCatalog,
                logical: tuple[str, ...] = ()) -> SelectPlan:
    plan = SelectPlan(required=list(required), catalog_state=catalog.state)
    if catalog.state == "available":
        plan.required_unlisted = [name for _, name in required if name and not catalog.lists(name)]
    for name in logical:
        prop = catalog.find(LOGICAL_FIELDS[name]) if catalog.state == "available" else None
        if prop:
            plan.optional[f"prop_{name.lower()}"] = (name, prop)
        else:
            plan.missing_optional.append(name)
    return plan


EVENT_COLUMNS: list[tuple[str, str | None]] = [
    ("starttime", "starttime"), ("devicetime", "devicetime"), ("sourceip", "sourceip"),
    ("sourceport", "sourceport"), ("destinationip", "destinationip"),
    ("destinationport", "destinationport"), ("username", "username"), ("qid", "qid"),
    ("QIDNAME(qid) AS event_name", None), ("LOGSOURCENAME(logsourceid) AS log_source", "logsourceid"),
    ("UTF8(payload) AS raw_payload", "payload")]
FLOW_COLUMNS: list[tuple[str, str | None]] = [
    (name, name) for name in ("firstpackettime", "lastpackettime", "sourceip", "sourceport",
                              "destinationip", "destinationport", "protocolid", "sourcebytes",
                              "destinationbytes", "sourcepackets", "destinationpackets")]
