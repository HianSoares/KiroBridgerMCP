"""Build docs/coverage-matrix.md from the audited upstream registry and soc_bridge.coverage.

Usage: python scripts/build_coverage_matrix.py [--check]
--check exits 1 when the committed matrix differs from what the registry produces, or when the
registry, the curated workflows and the contract-test list disagree.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from soc_bridge import coverage  # noqa: E402
from soc_bridge.transports import ALERT_VISION_TOOLS, QRADAR_READ_TOOLS  # noqa: E402
from soc_bridge.upstream_policy import callable_for_change, callable_for_query  # noqa: E402

PLATFORM_NAMES = {"qradar": "IBM QRadar MCP", "vision_one": "Trend Vision One MCP"}
CURATED = {"qradar": (QRADAR_READ_TOOLS, coverage.QRADAR), "vision_one": (ALERT_VISION_TOOLS, coverage.TREND)}


def cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def registry() -> dict:
    return json.loads((ROOT / "src/soc_bridge/upstream_registry.json").read_text(encoding="utf-8"))


def problems(reg: dict) -> list[str]:
    found = []
    index = {(t["platform"], t["name"]): t for t in reg["tools"]}
    for platform, (allowed, described) in CURATED.items():
        if set(allowed) != set(described):
            found.append(f"{platform}: curated allowlist and coverage descriptions differ")
        for name in allowed:
            t = index.get((platform, name))
            if t is None or not callable_for_query(t):
                found.append(f"{platform}/{name}: curated workflow tool is not a query tool in the registry")
    for key in coverage.CONTRACT_TESTED:
        if key not in index:
            found.append(f"{key[0]}/{key[1]}: contract-tested tool is not in the registry")
    for t in reg["tools"]:
        if not (callable_for_query(t) or callable_for_change(t) or (t["support"] == "unsupported"
                                                                  and t["unsupported_reason"])):
            found.append(f"{t['platform']}/{t['name']}: no route and no unsupported reason")
    return found


def access(t: dict) -> str:
    if callable_for_query(t):
        return "query: upstream_query"
    if callable_for_change(t):
        return "change: soc-bridge-change"
    if t["review"] != "verified":
        return "pending review"
    return "unsupported"


def enabled(t: dict) -> str:
    if callable_for_query(t):
        return "yes"
    if callable_for_change(t):
        return "no (opt-in + human approval)"
    return "no"


def pagination(t: dict) -> str:
    p = t["pagination"]
    return {"range": f"Range from {p.get('offset_param')}/{p.get('limit_param')}",
            "range_internal": "Range set internally (one page)",
            "token": f"{p.get('param')} continuation",
            "not_forwarded": f"{p.get('param')} declared, not forwarded (first page only)",
            "single_page": f"{p.get('page_size_param')} only, no continuation",
            "single_response": "single response"}[p["style"]]


def summary(reg: dict, platform: str) -> list[str]:
    tools = [t for t in reg["tools"] if t["platform"] == platform]
    rows: dict[str, Counter] = {}
    for t in tools:
        rows.setdefault(t["category"], Counter())[access(t).split(":")[0]] += 1
    out = ["| Category | Tools | Query | Change | Unsupported | Pending review |", "|---|---|---|---|---|---|"]
    total = Counter()
    for category in sorted(rows):
        c = rows[category]
        total.update(c)
        out.append(f"| {category} | {sum(c.values())} | {c['query']} | {c['change']} | {c['unsupported']} | "
                   f"{c['pending review']} |")
    out.append(f"| **total** | **{sum(total.values())}** | **{total['query']}** | **{total['change']}** | "
               f"**{total['unsupported']}** | **{total['pending review']}** |")
    return out


def table(reg: dict, platform: str) -> list[str]:
    allowed, described = CURATED[platform]
    out = ["| Tool | Category | Effect | Bridge access | Policy-enabled | Curated workflow | Contract-tested | "
           "Pagination | Dependencies and limits |", "|---|---|---|---|---|---|---|---|---|"]
    for t in sorted((t for t in reg["tools"] if t["platform"] == platform), key=lambda t: (t["category"], t["name"])):
        name = t["name"]
        curated = described[name][1] if name in allowed else ""
        tested = coverage.CONTRACT_TESTED.get((platform, name), "")
        limits = t["dependencies"]
        if t["support"] == "unsupported":
            limits = f"{limits}. Unsupported: {t['unsupported_reason']}"
        elif name in allowed:
            limits = f"{limits}. Workflow: {described[name][3]}"
        out.append("| " + " | ".join(cell(c) for c in (
            name, t["category"], t["effect"], access(t), enabled(t), curated, tested, pagination(t), limits)) + " |")
    return out


def build() -> str:
    reg = registry()
    lines = [
        "# Upstream MCP coverage matrix",
        "",
        "Generated by `scripts/build_coverage_matrix.py` from `src/soc_bridge/upstream_registry.json` "
        "(audited handlers and complete `tools/list` of the versions below). Do not edit by hand.",
        "",
    ]
    for platform, label in PLATFORM_NAMES.items():
        src = reg["sources"][platform]
        tags = f" ({', '.join(src['tags'])})" if src["tags"] else ""
        lines.append(f"- {label}: {src['repository']} at `{src['commit'][:12]}`{tags}, committed {src['commit_date']}.")
    lines += [
        f"- Policy version `{reg['policy_version']}`. The effect comes from the handler (HTTP method, client calls, "
        "registration), never from the tool name or `readOnlyHint` alone.",
        "",
        "Coverage levels, kept separate:",
        "",
        "- **Catalogued** and **announced**: every row. Each tool is in the audited handler catalog and in the "
        "complete `tools/list` of that version (Vision One write tools are announced only without `-readonly`). "
        "A given installation may not announce a tool (feature toggles, toolsets, version); `upstream_inventory` "
        "reports that at run time.",
        "- **Bridge access**: `query` tools run through `upstream_query` on soc-bridge-readonly; `change` tools only "
        "through the separate soc-bridge-change server; `unsupported` tools have a stated reason.",
        "- **Policy-enabled**: query tools are enabled. Change tools are disabled by default and need "
        "`SOC_BRIDGE_ENABLE_CHANGES=1`, the tool in the policy file and a human approval typed in a terminal per call.",
        "- **Curated workflow**: tools the investigation workflows call automatically when their trigger applies.",
        "- **Contract-tested**: end-to-end test through the bridge against the synthetic upstream in the product's "
        "response format. Every other tool is covered by registry, routing, gate and schema-validation tests only.",
        "- **Real-executed**: none recorded for the upstream_* tools in this version. Validation against real "
        "QRadar and Vision One tenants is pending and requires customer credentials.",
        "",
    ]
    for platform, label in PLATFORM_NAMES.items():
        lines += [f"## {label}", "", "### Totals by category", "", *summary(reg, platform), "",
                  "### Tools", "", *table(reg, platform), ""]
    return "\n".join(lines)


def main() -> int:
    reg = registry()
    found = problems(reg)
    if found:
        print("\n".join(found), file=sys.stderr)
        return 1
    target = ROOT / "docs" / "coverage-matrix.md"
    text = build()
    if "--check" in sys.argv:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current != text:
            print("docs/coverage-matrix.md is out of date; run scripts/build_coverage_matrix.py", file=sys.stderr)
            return 1
        print("coverage matrix up to date")
        return 0
    target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
