"""Change control for upstream tools that alter state or send data out (soc-bridge-change only).

soc-bridge-readonly never reaches this module. A change runs only when all of these hold:

1. The operator enabled changes for the change server process (SOC_BRIDGE_ENABLE_CHANGES=1).
2. A human-maintained policy file (SOC_BRIDGE_CHANGE_POLICY) lists the exact platform/tool.
3. The request was proposed with validated arguments and a justification (stored locally).
4. A human approved that exact request from an interactive terminal (``soc-bridge change approve``),
   typing its confirmation code; the approval is signed with a local key and expires.
5. The approval matches the stored request digest and has not been used.

Nothing the model fills in (for example ``confirm=true`` or a justification) counts as approval.
Investigations never call this module. Results of credential generation are returned once and not
stored. A timeout during execution leaves the outcome uncertain; the request is never retried.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .case_store import CaseStore
from .upstream_access import Refused, entry, validate_arguments
from .upstream_policy import callable_for_change

REQUEST_TTL = timedelta(minutes=30)
APPROVAL_TTL = timedelta(minutes=15)
SECRET_EFFECTS = {"credential_generation"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def change_dir() -> Path:
    configured = os.environ.get("SOC_BRIDGE_CHANGE_DIR", "").strip()
    if configured:
        return Path(configured)
    project = Path(__file__).resolve().parents[2]
    base = project if (project / "pyproject.toml").is_file() else Path.cwd()
    return base / "reports" / "changes"


def key_path() -> Path:
    configured = os.environ.get("SOC_BRIDGE_APPROVAL_KEY", "").strip()
    return Path(configured) if configured else Path.home() / ".soc-bridge" / "change-approval.key"


def _key(create: bool) -> bytes | None:
    path = key_path()
    if path.is_file():
        return path.read_bytes()
    if not create:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_bytes(32)
    path.write_bytes(data)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return data


def digest(request: dict) -> str:
    body = {k: request[k] for k in ("id", "platform", "tool", "arguments", "justification", "created_at")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _signature(key: bytes, request: dict, approval: dict) -> str:
    message = "|".join([request["id"], request["digest"], approval["approved_by"], approval["approved_at"],
                        approval["expires_at"]])
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _store() -> CaseStore:
    return CaseStore(change_dir())


def _write(request: dict) -> None:
    store = _store()
    path = store.path(request["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".change-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(request, stream, ensure_ascii=False, indent=1)
            stream.write("\n")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(request_id: str) -> dict:
    if not isinstance(request_id, str) or len(request_id) != 32 or not all(c in "0123456789abcdef" for c in request_id):
        raise Refused("invalid_arguments", "request_id must be the 32-character ID returned by change_request")
    path = _store().path(request_id)
    if not path.is_file():
        raise Refused("not_found", "no change request with this ID")
    return json.loads(path.read_text(encoding="utf-8"))


def policy() -> dict[str, Any]:
    enabled = os.environ.get("SOC_BRIDGE_ENABLE_CHANGES", "").strip() == "1"
    path = os.environ.get("SOC_BRIDGE_CHANGE_POLICY", "").strip()
    allowed: set[str] = set()
    problem = None
    if path:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            values = data.get("allowed_tools") if isinstance(data, dict) else None
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                problem = "policy file must be {\"allowed_tools\": [\"platform/tool\", ...]}"
            else:
                allowed = set(values)
        except (OSError, ValueError):
            problem = "policy file unreadable or not JSON"
    return {"changes_enabled": enabled, "policy_file_configured": bool(path), "allowed_tools": sorted(allowed),
            "policy_problem": problem}


def propose(platform: str, tool: str, arguments: Any, justification: str) -> dict[str, Any]:
    t = entry(platform, tool) if isinstance(tool, str) else None
    if t is None:
        raise Refused("unknown_tool", f"{platform}/{tool} is not in the audited registry")
    if t["access"] != "change":
        raise Refused("policy_blocked", f"{tool} is a query tool; use upstream_query on soc-bridge-readonly")
    if not callable_for_change(t):
        raise Refused("unsupported", f"{tool}: {t.get('unsupported_reason') or t['review']}")
    if not isinstance(justification, str) or not 10 <= len(justification.strip()) <= 1000:
        raise Refused("invalid_arguments", "justification must explain the change in 10..1000 characters")
    args = validate_arguments(t, arguments)
    created = _now()
    request = {"id": uuid.uuid4().hex, "platform": platform, "tool": tool, "effect": t["effect"],
               "effect_meaning": t["effect_meaning"], "arguments": args, "justification": justification.strip(),
               "created_at": _iso(created), "expires_at": _iso(created + REQUEST_TTL), "status": "pending_approval",
               "history": [{"at": _iso(created), "event": "proposed"}]}
    request["digest"] = digest(request)
    _write(request)
    return {**summary(request), "next_step": (
        "A human must review and approve this exact request from an interactive terminal: "
        f"soc-bridge change approve {request['id']} . Execution also needs SOC_BRIDGE_ENABLE_CHANGES=1 and "
        f"{platform}/{tool} in the SOC_BRIDGE_CHANGE_POLICY file. Nothing in this conversation approves it.")}


def summary(request: dict) -> dict[str, Any]:
    keep = ("id", "platform", "tool", "effect", "effect_meaning", "arguments", "justification", "created_at",
            "expires_at", "status", "history", "result")
    return {k: request[k] for k in keep if k in request}


def approve_interactively(request_id: str, stdin=None, stdout=None) -> dict[str, Any]:
    """Human approval from a terminal; refuses when stdin/stdout are not interactive."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    if not (stdin.isatty() and stdout.isatty()):
        raise Refused("approval_requires_terminal", "approval must be typed by a person in an interactive terminal")
    request = load(request_id)
    if request["status"] != "pending_approval":
        raise Refused("invalid_state", f"request is {request['status']}")
    if _now() > _parse(request["expires_at"]):
        raise Refused("expired", "request expired; propose it again")
    if digest(request) != request["digest"]:
        raise Refused("tampered", "stored request does not match its digest")
    code = request["digest"][:8]
    print(json.dumps(summary(request), indent=2, ensure_ascii=False), file=stdout)
    print(f"\nThis will run {request['platform']}/{request['tool']} ({request['effect_meaning']}).", file=stdout)
    print(f"Type the confirmation code {code} to approve, anything else to cancel: ", end="", file=stdout, flush=True)
    typed = stdin.readline().strip()
    if typed != code:
        raise Refused("not_approved", "confirmation code not typed; nothing approved")
    approved = _now()
    approval = {"approved_by": getpass.getuser(), "approved_at": _iso(approved),
                "expires_at": _iso(approved + APPROVAL_TTL)}
    approval["signature"] = _signature(_key(create=True), request, approval)
    with _store().lock(request_id):
        current = load(request_id)
        if current["status"] != "pending_approval" or current["digest"] != request["digest"]:
            raise Refused("invalid_state", "request changed while it was being approved")
        current.update(status="approved", approval=approval)
        current["history"].append({"at": approval["approved_at"], "event": "approved", "by": approval["approved_by"]})
        _write(current)
    return summary(current)


def reject(request_id: str, reason: str = "rejected by operator") -> dict[str, Any]:
    with _store().lock(request_id):
        request = load(request_id)
        if request["status"] in ("executed", "executing", "outcome_uncertain"):
            raise Refused("invalid_state", f"request is {request['status']}")
        request["status"] = "rejected"
        request["history"].append({"at": _iso(_now()), "event": "rejected", "reason": reason[:200]})
        _write(request)
    return summary(request)


def check_executable(request: dict) -> dict:
    """Every precondition, in order; raises Refused with the first one that fails."""
    current = policy()
    if not current["changes_enabled"]:
        raise Refused("changes_disabled", "changes are disabled for this server (SOC_BRIDGE_ENABLE_CHANGES is not 1)")
    if current["policy_problem"]:
        raise Refused("policy_invalid", current["policy_problem"])
    name = f"{request['platform']}/{request['tool']}"
    if name not in current["allowed_tools"]:
        raise Refused("not_enabled_by_policy", f"{name} is not listed in the SOC_BRIDGE_CHANGE_POLICY file")
    t = entry(request["platform"], request["tool"])
    if t is None or not callable_for_change(t):
        raise Refused("policy_blocked", f"{name} is not a supported change tool in this registry")
    if request["status"] != "approved" or "approval" not in request:
        raise Refused("not_approved", f"request is {request['status']}; a human must approve it in a terminal")
    if digest(request) != request["digest"]:
        raise Refused("tampered", "stored request does not match its digest")
    key = _key(create=False)
    approval = request["approval"]
    if key is None or not hmac.compare_digest(approval.get("signature", ""), _signature(key, request, approval)):
        raise Refused("approval_invalid", "approval signature does not verify with the local approval key")
    if _now() > _parse(approval["expires_at"]):
        raise Refused("approval_expired", "approval expired; propose and approve again")
    validate_arguments(t, request["arguments"])
    return t


async def execute(request_id: str, timeout_seconds: float = 120, settings: dict | None = None) -> dict[str, Any]:
    from .upstream_live import call_registered
    with _store().lock(request_id):
        request = load(request_id)
        t = check_executable(request)
        request["status"] = "executing"  # single use: a second execute finds this state
        request["history"].append({"at": _iso(_now()), "event": "executing"})
        _write(request)
    out, _ = await call_registered(t, request["arguments"], readonly=bool((t.get("server_flags") or {}).get("readonly")),
                                   timeout_seconds=timeout_seconds, max_chars=50_000, settings=settings)
    attempted = out.get("upstream_call_attempted", out.get("outcome") != "refused")
    if out.get("outcome") in ("ok", "empty", "partial", "empty_response"):
        status = "executed"
    elif out.get("error", {}).get("category") == "timeout" and attempted:
        status = "outcome_uncertain"
    else:
        status = "failed"
    with _store().lock(request_id):
        request = load(request_id)
        stored = {"outcome": out.get("outcome"), "error": out.get("error"), "at": _iso(_now())}
        if t["effect"] not in SECRET_EFFECTS:
            stored["response_headers"] = out.get("response_headers")
        request.update(status=status, result=stored)
        request["history"].append({"at": stored["at"], "event": status})
        _write(request)
    note = {"executed": "executed once; the request cannot be reused",
            "outcome_uncertain": "no answer in time: the change may or may not have been applied; verify in the "
                                 "product before proposing it again",
            "failed": "not applied according to the upstream response; propose a new request if still needed"}[status]
    return {**out, "request_id": request_id, "request_status": status, "note": note,
            **({"secret_handling": "the generated value is shown only in this response and was not stored"}
               if t["effect"] in SECRET_EFFECTS else {})}
