"""Build src/soc_bridge/upstream_registry.json from the audited upstream catalogs and the reviewed policy.

Inputs (docs/coverage/): handler facts (*-mcp-tools.json) and the announced tools/list snapshots
(*-tools-list.json) of the same commits. Policy: src/soc_bridge/upstream_policy.py.

Usage: python scripts/build_upstream_registry.py [--check]
--check exits 1 when the committed registry differs from what the inputs produce.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from soc_bridge import upstream_policy as policy  # noqa: E402

TARGET = ROOT / "src" / "soc_bridge" / "upstream_registry.json"


def load(name: str) -> dict:
    return json.loads((ROOT / "docs" / "coverage" / name).read_text(encoding="utf-8"))


def summary(text: str) -> str:
    first = re.split(r"(?<=[.!?])\s|\n", (text or "").strip(), maxsplit=1)[0]
    return first[:200]


def qradar_pagination(facts: dict, schema: dict) -> dict:
    props = set(schema.get("properties", {}))
    if facts.get("range_pagination") and {"offset", "limit"} <= props:
        return {"style": "range", "offset_param": "offset", "limit_param": "limit",
                "note": "the handler sends a Range header items=offset-(offset+limit-1); no total is returned, so a "
                        "page equal to the limit may have more items"}
    if facts.get("range_pagination") and {"start", "limit"} <= props:
        return {"style": "range", "offset_param": "start", "limit_param": "limit",
                "note": "the handler sends a Range header for the same search ID; results expire upstream"}
    if facts.get("range_pagination"):
        return {"style": "range_internal", "note": "the handler builds a Range header from its own defaults"}
    return {"style": "single_response"}


def trend_pagination(facts: dict, schema: dict) -> dict:
    declared, missing = set(facts.get("declared", [])), set(facts.get("not_forwarded", []))
    page = {"page_size_param": "top"} if "top" in declared and "top" not in missing else {}
    for token, field in (("skipToken", "nextLink"), ("nextBatchToken", "nextBatchToken")):
        if token in declared:
            if token in missing:
                return {"style": "not_forwarded", "param": token, "response_field": field, **page,
                        "note": f"{token} is declared but the handler does not send it: only the first page is readable"}
            return {"style": "token", "param": token, "response_field": field, **page,
                    "note": f"continue with {token} taken from the response {field}"}
    if page:
        return {"style": "single_page", **page, "note": "no continuation input in the handler; a returned nextLink "
                                                         "cannot be followed through this tool"}
    return {"style": "single_response"}


def build() -> dict:
    qfacts, tfacts = load("qradar-mcp-tools.json"), load("vision-one-mcp-tools.json")
    qlist, tlist = load("qradar-tools-list.json"), load("vision-one-tools-list.json")
    if qfacts["source"]["commit"] != qlist["source"]["commit"] or tfacts["source"]["commit"] != tlist["source"]["commit"]:
        raise SystemExit("handler facts and tools/list snapshots come from different commits")
    announced_q = {t["name"]: t for t in qlist["tools"]}
    announced_t = {t["name"]: t for t in tlist["tools"]}
    entries = []
    for facts in qfacts["tools"]:
        listed = announced_q.get(facts["name"])
        if listed is None:
            raise SystemExit(f"QRadar tool {facts['name']} has handler facts but is not announced")
        decision = policy.classify_qradar(facts)
        # Validate with the handler's own schema (ranges, enums, descriptions); FastMCP announces a
        # reduced one, kept as announced_schema to detect contract changes in a running server.
        own = facts.get("handler_schema")
        if not own or set(own.get("properties", {})) != set(listed["inputSchema"].get("properties", {})):
            raise SystemExit(f"QRadar {facts['name']}: handler schema missing or different from the announced one")
        entries.append({
            "platform": "qradar", "name": facts["name"], "category": facts["group"],
            "summary": summary(listed.get("description", "")), "description": listed.get("description", ""),
            "input_schema": {**own, "additionalProperties": False},
            "announced_schema": listed["inputSchema"],
            "http": {"methods": [facts["verb"]], "paths": [facts["endpoint"]]},
            "upstream_registration": {"approval_required": facts["approval_required"],
                                      "meta": listed.get("meta", {})},
            **decision,
            "pagination": qradar_pagination(facts, listed["inputSchema"]),
            "output": facts["output"],
            "dependencies": policy.QRADAR_DEPENDENCIES.get(facts["group"], "QRadar user capability for this endpoint"),
            "handler": facts["source_file"]})
    for facts in tfacts["tools"]:
        listed = announced_t.get(facts["name"])
        if listed is None:
            raise SystemExit(f"Vision One tool {facts['name']} has handler facts but is not announced")
        decision = policy.classify_trend(facts)
        entries.append({
            "platform": "vision_one", "name": facts["name"], "category": facts["toolset"],
            "summary": summary(listed.get("description", "")), "description": listed.get("description", ""),
            "input_schema": listed["inputSchema"],
            "http": {"methods": facts["http_methods"], "paths": facts["paths"]},
            "upstream_registration": {"registered_as": facts["registered_as"],
                                      "annotations": listed.get("annotations", {})},
            **decision,
            "server_flags": {"toolset": facts["toolset"], "readonly": facts["registered_as"] == "read"},
            "pagination": trend_pagination(facts, listed["inputSchema"]),
            "output": ("json_text; ETag/Operation-Location/Location headers as an extra text block; non-text bodies "
                       "as base64 embedded resources" if facts["response_handler"] == "handleResponse" else "json_text"),
            "dependencies": policy.TREND_DEPENDENCIES.get(facts["toolset"], "Vision One API key permissions"),
            "handler": facts["source_file"]})
    unannounced = (set(announced_q) - {f["name"] for f in qfacts["tools"]}) | \
                  (set(announced_t) - {f["name"] for f in tfacts["tools"]})
    if unannounced:
        raise SystemExit(f"announced tools without handler facts: {sorted(unannounced)}")
    return {"policy_version": policy.POLICY_VERSION,
            "sources": {"qradar": qfacts["source"], "vision_one": tfacts["source"]},
            "tools": sorted(entries, key=lambda e: (e["platform"], e["name"]))}


def render(data: dict) -> str:
    return json.dumps(data, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> int:
    text = render(build())
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != text:
            print("src/soc_bridge/upstream_registry.json is out of date; run scripts/build_upstream_registry.py",
                  file=sys.stderr)
            return 1
        print("upstream registry up to date")
        return 0
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
