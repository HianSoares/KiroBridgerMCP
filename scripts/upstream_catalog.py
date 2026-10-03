"""Extract the tool catalogs of the official upstream MCP servers from local clones.

Usage: python scripts/upstream_catalog.py <qradar-mcp clone> <vision-one-mcp-server clone> <out dir>
Writes qradar-mcp-tools.json and vision-one-mcp-tools.json with the clone commit. Arguments are
read from the handlers (what is forwarded), not only from schemas or README text. Re-run after
an upstream update, then regenerate docs/coverage-matrix.md with build_coverage_matrix.py.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


def commit(repo: Path) -> dict:
    out = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%H %cs"], capture_output=True,
                         text=True, check=True).stdout.split()
    remote = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                            text=True, check=True).stdout.strip()
    return {"repository": remote, "commit": out[0], "commit_date": out[1]}


def qradar(root: Path) -> list[dict]:
    endpoints = dict(re.findall(r'^(\w+)\s*=\s*"([^"]+)"', (root / "tools/endpoints.py").read_text(encoding="utf-8"), re.M))
    rows = []
    for path in sorted((root / "tools").glob("*/*.py")):
        if path.name == "__init__.py":
            continue
        text = path.read_text(encoding="utf-8")
        name = re.search(r'def name\(self\)[^:]*:\s*return "([^"]+)"', text)
        verb = re.search(r'def http_verb\(self\)[^:]*:\s*return "([^"]+)"', text)
        endpoint = re.search(r'def endpoint\(self\)[^:]*:\s*return endpoints\.(\w+)', text)
        args = [a for _, a in re.findall(r'\.(string|integer|boolean|array|object|number)\("([^"]+)"\)', text)]
        impl = text.split("_execute_impl", 1)[-1]
        rows.append({"name": name.group(1) if name else path.stem, "group": path.parent.name,
                     "verb": verb.group(1) if verb else None,
                     "endpoint": endpoints.get(endpoint.group(1)) if endpoint else None, "args": args,
                     "args_not_used_in_handler": [a for a in args if not re.search(r'["\']%s["\']' % re.escape(a), impl)],
                     "range_pagination": "build_headers(" in impl or "parse_range_from_limit_offset" in impl})
    return rows


def trend(root: Path) -> list[dict]:
    base = root / "internal" / "v1mcp"
    toolsets = re.findall(r'\{"(\w+)", tools\.(\w+), (?:tools\.(\w+)|nil)\}', (base / "toolsets.go").read_text(encoding="utf-8"))
    sources = {p.name: p.read_text(encoding="utf-8") for p in (base / "tools").glob("*.go") if not p.name.endswith("_test.go")}
    alltext = "\n".join(sources.values())
    funcs = {}
    for text in sources.values():
        for match in re.finditer(r"^func (tool\w+)\(client \*v1client\.V1ApiClient\) mcpserver\.ServerTool \{(.*?)^\}", text, re.S | re.M):
            body = match.group(2)
            tool_part, _, handler = body.partition("Handler:")
            declared = re.findall(r'mcp\.With(?:String|Number|Boolean|Array|Object)\("(\w+)"', tool_part)
            forwarded = set(re.findall(r'(?:Name|Arg):\s*"(\w+)"', handler)) | set(re.findall(r'pathValue\("(\w+)"', handler))
            # Go rejects unused variables, so a value read from the arguments is used by the handler.
            forwarded |= set(re.findall(r'\w+(?:\[[^\]]*\])?\(\s*"(\w+)"', handler))
            forwarded |= set(re.findall(r'(?:args|request\.GetArguments\(\))\["(\w+)"\]', handler))
            name = re.search(r'mcp\.NewTool\(\s*"([^"]+)"', body)
            funcs[match.group(1)] = {"name": name.group(1) if name else None, "declared": declared,
                                     "not_forwarded": [d for d in declared if d not in forwarded],
                                     "readonly_hint": "ReadOnlyHint: toPtr(true)" in tool_part}
    rows = []
    for toolset, read_var, write_var in toolsets:
        for kind, var in (("read", read_var), ("write", write_var)):
            match = re.search(r"var %s = \[\]func\([^)]*\) mcpserver\.ServerTool\{(.*?)\n\}" % re.escape(var or "_none_"), alltext, re.S)
            for func in re.findall(r"(\w+),", match.group(1)) if match else []:
                rows.append({"toolset": toolset, "registered_as": kind, **funcs[func]})
    return rows


def main() -> int:
    qroot, troot, out = (Path(a) for a in sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=True)
    for name, root, extract in (("qradar-mcp-tools.json", qroot, qradar), ("vision-one-mcp-tools.json", troot, trend)):
        data = {"source": commit(root), "tools": sorted(extract(root), key=lambda r: r["name"])}
        (out / name).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"{name}: {len(data['tools'])} tools at {data['source']['commit'][:7]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
