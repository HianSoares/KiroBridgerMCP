"""Bounded preservation of upstream JSON: keep values, identifiers and relations, mark every cut.

Optional reads used to reduce responses to their field names, which discarded the
evidence. preserve() keeps the structure and values instead, within explicit limits of
depth, list items, keys, string length and total characters, and reports what was cut
so a reader never mistakes a truncated response for a complete one.
"""

from __future__ import annotations

from typing import Any

LIMITS = {"max_depth": 6, "max_items": 50, "max_keys": 80, "max_string": 4000, "max_total_chars": 60000}


def preserve(value: Any, **limits: int) -> tuple[Any, dict]:
    """Return (bounded copy, cut report). The copy is plain JSON-compatible data."""
    conf = {**LIMITS, **limits}
    report = {"truncated_strings": 0, "omitted_list_items": 0, "omitted_keys": 0, "depth_cut": 0,
              "total_chars_cut": False, "paths": [], "limits": conf}
    used = [0]

    def note(path: str, what: str) -> None:
        if len(report["paths"]) < 20:
            report["paths"].append(f"{path or '$'}: {what}")

    def walk(node: Any, depth: int, path: str) -> Any:
        if used[0] >= conf["max_total_chars"]:
            if not report["total_chars_cut"]:
                note(path, "total character limit reached; remaining content omitted")
            report["total_chars_cut"] = True
            return None
        if isinstance(node, dict):
            if depth >= conf["max_depth"]:
                report["depth_cut"] += 1
                note(path, f"object with {len(node)} keys below the depth limit")
                return {"_omitted_object_keys": len(node)}
            out = {}
            for index, (key, item) in enumerate(node.items()):
                if index >= conf["max_keys"]:
                    report["omitted_keys"] += len(node) - index
                    note(path, f"{len(node) - index} keys omitted")
                    break
                used[0] += len(str(key))
                out[str(key)] = walk(item, depth + 1, f"{path}.{key}")
            return out
        if isinstance(node, list):
            if depth >= conf["max_depth"]:
                report["depth_cut"] += 1
                note(path, f"list with {len(node)} items below the depth limit")
                return [{"_omitted_list_items": len(node)}]
            out = [walk(item, depth + 1, f"{path}[{i}]") for i, item in enumerate(node[:conf["max_items"]])]
            if len(node) > conf["max_items"]:
                report["omitted_list_items"] += len(node) - conf["max_items"]
                note(path, f"{len(node) - conf['max_items']} of {len(node)} items omitted")
            return out
        if isinstance(node, str):
            if len(node) > conf["max_string"]:
                report["truncated_strings"] += 1
                note(path, f"string cut from {len(node)} to {conf['max_string']} characters")
                used[0] += conf["max_string"]
                return node[:conf["max_string"]]
            used[0] += len(node)
            return node
        if node is None or isinstance(node, (bool, int, float)):
            used[0] += 8
            return node
        used[0] += 16
        return str(node)[:conf["max_string"]]

    copy = walk(value, 0, "")
    report["complete"] = not (report["truncated_strings"] or report["omitted_list_items"] or report["omitted_keys"]
                              or report["depth_cut"] or report["total_chars_cut"])
    return copy, report


def find_paths(node: Any, wanted: str, path: str = "", limit: int = 10) -> list[str]:
    """JSON paths whose string value equals wanted exactly (no substring or case folding)."""
    found: list[str] = []

    def walk(item: Any, where: str) -> None:
        if len(found) >= limit:
            return
        if isinstance(item, dict):
            for key, value in item.items():
                walk(value, f"{where}.{key}")
        elif isinstance(item, list):
            for index, value in enumerate(item[:500]):
                walk(value, f"{where}[{index}]")
        elif isinstance(item, str) and item == wanted:
            found.append(where or "$")

    walk(node, path)
    return found
