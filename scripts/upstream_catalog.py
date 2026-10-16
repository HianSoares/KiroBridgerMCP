"""Audit the official upstream MCP servers: handler facts plus the tools/list they announce.

Usage:
  python scripts/upstream_catalog.py <qradar-mcp clone> <vision-one-mcp-server clone> \\
      <qradar tools/list json> <vision-one tools/list json> <out dir>

The clones are only read as text (Python with ``ast``, Go with regular expressions); nothing from
them is imported or executed. The tools/list files are the paginated listings of the servers built
from the same commits (see docs/upstream-access.md, "Refreshing the audit"); they carry the input
schemas the servers actually announce. Writes, in <out dir>:

- qradar-mcp-tools.json / vision-one-mcp-tools.json: handler facts per tool;
- qradar-tools-list.json / vision-one-tools-list.json: the announced tools (schemas, annotations).

Then run scripts/build_upstream_registry.py and scripts/build_coverage_matrix.py.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import subprocess
import sys


def commit(repo: Path) -> dict:
    out = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%H %cs"], capture_output=True,
                         text=True, encoding="utf-8", check=True).stdout.split()
    remote = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                            text=True, encoding="utf-8", check=True).stdout.strip()
    tags = subprocess.run(["git", "-C", str(repo), "tag", "--points-at", "HEAD"], capture_output=True,
                          text=True, encoding="utf-8", check=True).stdout.split()
    return {"repository": remote, "commit": out[0], "commit_date": out[1], "tags": tags}


# ---------------------------------------------------------------- QRadar (Python, ast)

def _returned(cls: ast.ClassDef, prop: str, endpoints: dict) -> object:
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name == prop:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    value = sub.value
                    if isinstance(value, ast.Constant):
                        return value.value
                    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) \
                            and value.value.id == "endpoints":
                        return endpoints.get(value.attr, value.attr)
                    return ast.unparse(value)[:120]
    return None


BUILDER_KEYS = {"description": "description", "minimum": "minimum", "maximum": "maximum", "min_length": "minLength",
                "max_length": "maxLength", "pattern": "pattern", "enum": "enum", "default": "default"}
BUILDER_TYPES = {"string", "integer", "number", "boolean", "array", "object"}


def _literal(node: ast.AST, constants: dict) -> object:
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return {"unresolved_expression": ast.unparse(node)[:200]}


def handler_schema(cls: ast.ClassDef, constants: dict) -> dict | None:
    """Rebuild the tool's own input_schema (IBM SchemaBuilder chain or a dict literal) without running it.

    The schema FastMCP announces drops descriptions, ranges and enums; this one is what the handler
    was written against, so the bridge validates arguments with it."""
    for node in cls.body:
        if not (isinstance(node, ast.FunctionDef) and node.name == "input_schema"):
            continue
        ret = next((n.value for n in ast.walk(node) if isinstance(n, ast.Return) and n.value is not None), None)
        if isinstance(ret, ast.Dict):
            value = _literal(ret, constants)
            return value if isinstance(value, dict) else None
        chain = []
        current = ret.func.value if isinstance(ret, ast.Call) and isinstance(ret.func, ast.Attribute) \
            and ret.func.attr == "build" else None
        while isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
            chain.append((current.func.attr, current.args))
            current = current.func.value
        if not (isinstance(current, ast.Call) and isinstance(current.func, ast.Name) and current.func.id == "schema"):
            return None
        properties, required, prop = {}, [], None
        for method, args in reversed(chain):
            if method in BUILDER_TYPES:
                name = _literal(args[0], constants)
                prop = properties.setdefault(name, {"type": method})
            elif method == "required" and prop is not None:
                required.append(next(k for k, v in properties.items() if v is prop))
            elif method == "items" and prop is not None:
                prop["items"] = {"type": _literal(args[0], constants)}
            elif method in BUILDER_KEYS and prop is not None:
                prop[BUILDER_KEYS[method]] = _literal(args[0], constants)
        out = {"type": "object", "properties": properties}
        if required:
            out["required"] = required
        return out
    return None


def qradar(root: Path) -> list[dict]:
    endpoints = dict(re.findall(r'^(\w+)\s*=\s*"([^"]+)"', (root / "tools/endpoints.py").read_text(encoding="utf-8"),
                                re.M))
    rows = []
    for path in sorted((root / "tools").glob("*/*.py")):
        if path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    constants[node.targets[0].id] = ast.literal_eval(node.value)
                except (ValueError, SyntaxError, TypeError):
                    pass
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            name = _returned(cls, "name", endpoints)
            if not isinstance(name, str):
                continue
            args = [a for _, a in re.findall(r'\.(string|integer|boolean|array|object|number)\("([^"]+)"\)', source)]
            impl = source.split("_execute_impl", 1)[-1]
            # An argument is used when its quoted name appears outside the schema declaration (in the
            # handler or in a module constant such as a list of updatable fields).
            usage = re.sub(r'\.(string|integer|boolean|array|object|number)\("[^"]+"\)', "", source)
            range_pagination = bool(re.search(r"Range|build_headers\(|parse_range_from_limit_offset", impl))
            if "json.dumps(" in source and "format_output" in source:
                output = "json_text (format_output=true returns a formatted table)"
            elif "json.dumps(" in source:
                output = "json_text"
            else:
                output = "formatted_text"
            rows.append({
                "name": name, "group": path.parent.name, "source_file": f"tools/{path.parent.name}/{path.name}",
                "verb": _returned(cls, "http_verb", endpoints), "endpoint": _returned(cls, "endpoint", endpoints),
                "approval_required": _returned(cls, "approval_required", endpoints) is not False,
                "client_calls": sorted(set(re.findall(r"self\.client\.(\w+)\(", source))),
                "args": args,
                "args_not_used_in_handler": [a for a in args if not re.search(r'["\']%s["\']' % re.escape(a), usage)],
                "range_pagination": range_pagination, "output": output,
                "handler_schema": handler_schema(cls, constants)})
    return rows


# ---------------------------------------------------------------- Vision One (Go, regular expressions)

HELPERS = {"searchAndFilter": "GET", "searchAndFilterWithOptions": "GET", "genericGet": "GET",
           "genericJSONPost": "POST", "genericJSONPatch": "PATCH", "genericDelete": "DELETE"}


def _client_methods(root: Path) -> dict:
    text = "\n".join(p.read_text(encoding="utf-8") for p in (root / "internal/v1client").glob("*.go")
                     if not p.name.endswith("_test.go"))
    out = {}
    for m in re.finditer(r"^func \(c \*V1ApiClient\) (\w+)\((.*?)\) \(\*http\.Response, error\) \{(.*?)^\}", text,
                         re.S | re.M):
        body = m.group(3)
        do = re.search(r"c\.do\(http\.Method(\w+),\s*(?:pathf\()?(?:fmt\.Sprintf\()?\"([^\"]+)\"", body)
        if do:
            out[m.group(1)] = {"method": do.group(1).upper(), "path": do.group(2)}
            continue
        helper = re.search(r"c\.(searchAndFilter\w*|genericGet|genericJSONPost|genericJSONPatch|genericDelete|newRequest)\(",
                           body)
        method = HELPERS.get(helper.group(1)) if helper else None
        if helper and helper.group(1) == "newRequest":
            nm = re.search(r"http\.Method(\w+)", body)
            method = nm.group(1).upper() if nm else None
        path = re.search(r"\"(v\d\.\d/[^\"]+)\"", body)
        out[m.group(1)] = {"method": method, "path": path.group(1) if path else None}
    return out


def trend(root: Path) -> list[dict]:
    base = root / "internal" / "v1mcp"
    toolsets = re.findall(r'\{"(\w+)", tools\.(\w+), (?:tools\.(\w+)|nil)\}', (base / "toolsets.go").read_text(encoding="utf-8"))
    sources = {p.name: p.read_text(encoding="utf-8") for p in (base / "tools").glob("*.go") if not p.name.endswith("_test.go")}
    alltext = "\n".join(sources.values())
    methods = _client_methods(root)
    funcs = {}
    for fname, text in sources.items():
        for match in re.finditer(r"^func (tool\w+)\(client \*v1client\.V1ApiClient\) mcpserver\.ServerTool \{(.*?)^\}",
                                 text, re.S | re.M):
            body = match.group(2)
            tool_part, _, handler = body.partition("Handler:")
            declared = re.findall(r'mcp\.With(?:String|Number|Boolean|Array|Object)\("(\w+)"', tool_part)
            forwarded = set(re.findall(r'(?:Name|Arg):\s*"(\w+)"', handler)) | set(re.findall(r'pathValue\("(\w+)"', handler))
            # Go rejects unused variables, so a value read from the arguments is used by the handler.
            forwarded |= set(re.findall(r'\w+(?:\[[^\]]*\])?\(\s*"(\w+)"', handler))
            forwarded |= set(re.findall(r'(?:args|request\.GetArguments\(\))\["(\w+)"\]', handler))
            if "bodyArray" in handler:
                forwarded.add("items")  # sent as the JSON array body (bodyArrayArgument)
            calls = re.findall(r"client\.(\w+)\(", handler)
            name = re.search(r'mcp\.NewTool\(\s*"([^"]+)"', body)
            funcs[match.group(1)] = {
                "name": name.group(1) if name else None, "source_file": f"internal/v1mcp/tools/{fname}",
                "declared": declared, "not_forwarded": [d for d in declared if d not in forwarded],
                "readonly_hint": "ReadOnlyHint: toPtr(true)" in tool_part,
                "client_calls": calls,
                "http_methods": sorted({methods.get(c, {}).get("method") or "unknown" for c in calls}),
                "paths": sorted({methods.get(c, {}).get("path") or "unknown" for c in calls}),
                "file_upload": "FileFields" in handler,
                "response_handler": ("handleResponse" if "handleResponse(" in handler else
                                     "handleStatusResponse" if "handleStatusResponse(" in handler else "custom")}
    rows = []
    for toolset, read_var, write_var in toolsets:
        for kind, var in (("read", read_var), ("write", write_var)):
            match = re.search(r"var %s = \[\]func\([^)]*\) mcpserver\.ServerTool\{(.*?)\n\}" % re.escape(var or "_none_"),
                              alltext, re.S)
            for func in re.findall(r"(\w+),", match.group(1)) if match else []:
                rows.append({"toolset": toolset, "registered_as": kind, **funcs[func]})
    return rows


def listing(path: Path, server: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("complete"):
        raise SystemExit(f"{path}: tools/list discovery incomplete; refusing to write a partial catalog")
    return {"server": server, "listed_from": data.get("server"), "pages": data.get("pages"),
            "readonly_flag": data.get("readonly"), "tools": sorted(data["tools"], key=lambda t: t["name"])}


def main() -> int:
    qroot, troot, qlist, tlist, out = (Path(a) for a in sys.argv[1:6])
    out.mkdir(parents=True, exist_ok=True)
    qsource, tsource = commit(qroot), commit(troot)
    outputs = {
        "qradar-mcp-tools.json": {"source": qsource, "tools": sorted(qradar(qroot), key=lambda r: r["name"])},
        "vision-one-mcp-tools.json": {"source": tsource, "tools": sorted(trend(troot), key=lambda r: r["name"])},
        "qradar-tools-list.json": {"source": qsource, **listing(qlist, "IBM QRadar MCP stdio_server.py")},
        "vision-one-tools-list.json": {"source": tsource, **listing(tlist, "ghcr.io/trendmicro/vision-one-mcp-server "
                                                                          "-readonly=false -toolsets=all")},
    }
    for name, data in outputs.items():
        (out / name).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"{name}: {len(data['tools'])} tools at {data['source']['commit'][:7]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
