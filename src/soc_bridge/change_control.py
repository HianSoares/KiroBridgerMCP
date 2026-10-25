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
stored. Once the request has been sent, any failure without a valid upstream answer (timeout,
cancellation, broken connection, invalid response, server error) leaves the outcome uncertain: the
change may have been applied, so it is never retried and must be reconciled in the product.

File uploads (the Vision One tools whose handler opens a local path): at proposal the file is
copied into a private staging folder and its SHA-256 and size enter the request digest, so the
approval covers the destination, the arguments and the exact bytes. At execution the staged copy is
verified again, bind-mounted read-only as a single file into the container, verified once more
after the call, and removed.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
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
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
# HTTP statuses that mean the upstream refused the request as sent; anything else after sending is uncertain.
DEFINITE_REJECTIONS = {400, 401, 403, 404, 409, 422, 429}
FINAL = {"executed", "rejected_by_upstream", "outcome_uncertain", "not_sent", "rejected", "expired"}


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


def staging_dir(request_id: str) -> Path:
    return change_dir() / "staged" / request_id


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
    if request.get("upload"):
        body["upload"] = {k: request["upload"][k] for k in ("field", "source_path", "name", "bytes", "sha256",
                                                             "container_path")}
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


# ------------------------------------------------------------------ file staging for uploads

def _safe_name(source: str) -> str:
    base = re.split(r"[\\/]", source.strip())[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:100]
    return name or "upload.bin"


def _hash_file(path: Path) -> tuple[str, int]:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("file_changed", "the staged file is no longer a regular file")
    sha, size = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size


LINK_REPARSE_TAGS = {0xA000000C, 0xA0000003}  # Windows symbolic link, junction (mount point)


def _through_link(path: Path) -> bool:
    """True when the path or any parent is a symbolic link or a Windows junction (8.3 names are fine)."""
    for part in (path, *path.parents):
        st = os.lstat(part)
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) in LINK_REPARSE_TAGS:
            return True
    return False


def _stage(request_id: str, field: str, source: Any) -> dict[str, Any]:
    """Copy one approved file into the private staging folder; refuse links, devices and directories."""
    if not isinstance(source, str) or "\x00" in source or not os.path.isabs(source):
        raise Refused("invalid_arguments", f"{field} must be an absolute path to a local file (in WSL use /mnt/c/...)")
    path = Path(source)
    try:
        st = os.lstat(path)
    except OSError:
        raise Refused("invalid_arguments", f"{field}: file not found or not readable") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Refused("invalid_arguments", f"{field} must be a regular file, not a link, directory or device")
    if _through_link(Path(os.path.abspath(source))):
        raise Refused("invalid_arguments", f"{field}: the path goes through a link or junction; give the real path")
    if st.st_size > MAX_UPLOAD_BYTES:
        raise Refused("invalid_arguments", f"{field}: file larger than {MAX_UPLOAD_BYTES} bytes")
    folder = staging_dir(request_id)
    folder.mkdir(parents=True, exist_ok=False)
    if os.name != "nt":
        os.chmod(folder, 0o700)
    name = _safe_name(source)
    target = folder / name
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    sha, size = hashlib.sha256(), 0
    try:
        fd = os.open(source, flags)
        with os.fdopen(fd, "rb") as src:
            opened = os.fstat(src.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_ino, opened.st_dev) != (st.st_ino, st.st_dev):
                raise Refused("invalid_arguments", f"{field}: the file changed while it was being staged")
            out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(out_fd, "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise Refused("invalid_arguments", f"{field}: file larger than {MAX_UPLOAD_BYTES} bytes")
                    sha.update(chunk)
                    dst.write(chunk)
        if os.name != "nt":
            os.chmod(target, 0o400)
    except Refused:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    except OSError:
        shutil.rmtree(folder, ignore_errors=True)
        raise Refused("invalid_arguments", f"{field}: file could not be read") from None
    return {"field": field, "source_path": source, "name": name, "bytes": size, "sha256": sha.hexdigest(),
            "staged_path": str(target), "container_path": f"/approved/{name}",
            "note": "the approval covers these exact bytes; the source file is not read again"}


def _verify_staged(request: dict) -> None:
    upload = request["upload"]
    path = Path(upload["staged_path"])
    if path.parent != staging_dir(request["id"]) or path.is_symlink() or not path.is_file():
        raise Refused("file_changed", "the staged file is missing or was replaced")
    sha, size = _hash_file(path)
    if (sha, size) != (upload["sha256"], upload["bytes"]):
        raise Refused("file_changed", "the staged file no longer matches the approved SHA-256")


def discard_staged(request_id: str) -> None:
    shutil.rmtree(staging_dir(request_id), ignore_errors=True)


def sweep_expired() -> list[str]:
    """Mark expired pending/approved requests and remove staged files nobody can use any more."""
    removed = []
    root = change_dir() / "staged"
    for folder in sorted(root.iterdir()) if root.is_dir() else []:
        request_id = folder.name
        try:
            with _store().lock(request_id):
                request = load(request_id)
                limit = request["approval"]["expires_at"] if request["status"] == "approved" else request["expires_at"]
                if request["status"] in ("pending_approval", "approved") and _now() > _parse(limit):
                    request["status"] = "expired"
                    request["history"].append({"at": _iso(_now()), "event": "expired"})
                    _write(request)
                if request["status"] not in ("pending_approval", "approved", "executing"):
                    discard_staged(request_id)
                    removed.append(request_id)
        except Refused:  # no request behind this folder (invalid name or deleted request)
            shutil.rmtree(folder, ignore_errors=True)
            removed.append(request_id)
    return removed


# ------------------------------------------------------------------ requests

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
    sweep_expired()
    created = _now()
    request = {"id": uuid.uuid4().hex, "platform": platform, "tool": tool, "effect": t["effect"],
               "effect_meaning": t["effect_meaning"], "arguments": args, "justification": justification.strip(),
               "created_at": _iso(created), "expires_at": _iso(created + REQUEST_TTL), "status": "pending_approval",
               "history": [{"at": _iso(created), "event": "proposed"}]}
    upload = t.get("upload")
    if upload and upload["field"] in args:
        request["upload"] = _stage(request["id"], upload["field"], args[upload["field"]])
    request["digest"] = digest(request)
    try:
        _write(request)
    except BaseException:
        discard_staged(request["id"])
        raise
    return {**summary(request), "next_step": (
        "A human must review and approve this exact request from an interactive terminal: "
        f"soc-bridge change approve {request['id']} . Execution also needs SOC_BRIDGE_ENABLE_CHANGES=1 and "
        f"{platform}/{tool} in the SOC_BRIDGE_CHANGE_POLICY file. Nothing in this conversation approves it.")}


def summary(request: dict) -> dict[str, Any]:
    keep = ("id", "platform", "tool", "effect", "effect_meaning", "arguments", "justification", "created_at",
            "expires_at", "status", "history", "result")
    out = {k: request[k] for k in keep if k in request}
    if request.get("upload"):
        out["upload"] = {k: request["upload"][k] for k in ("field", "source_path", "name", "bytes", "sha256",
                                                            "container_path")}
    return out


def approve_interactively(request_id: str, stdin=None, stdout=None) -> dict[str, Any]:
    """Human approval from a terminal; refuses when stdin/stdout are not interactive."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    if not (stdin.isatty() and stdout.isatty()):
        raise Refused("approval_requires_terminal", "approval must be typed by a person in an interactive terminal")
    request = load(request_id)
    if request["status"] != "pending_approval":
        raise Refused("invalid_state", f"request is {request['status']}")
    if _now() > _parse(request["expires_at"]):
        discard_staged(request_id)
        raise Refused("expired", "request expired; propose it again")
    if digest(request) != request["digest"]:
        raise Refused("tampered", "stored request does not match its digest")
    if request.get("upload"):
        _verify_staged(request)
    code = request["digest"][:8]
    print(json.dumps(summary(request), indent=2, ensure_ascii=False), file=stdout)
    print(f"\nThis will run {request['platform']}/{request['tool']} ({request['effect_meaning']}).", file=stdout)
    if request.get("upload"):
        up = request["upload"]
        print(f"It uploads {up['source_path']} ({up['bytes']} bytes, SHA-256 {up['sha256']}) to "
              f"{request['platform']}.", file=stdout)
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
        if request["status"] in FINAL | {"executing"}:
            raise Refused("invalid_state", f"request is {request['status']}")
        request["status"] = "rejected"
        request["history"].append({"at": _iso(_now()), "event": "rejected", "reason": reason[:200]})
        _write(request)
    discard_staged(request_id)
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
    if request.get("upload"):
        _verify_staged(request)
    return t


NOTES = {
    "executed": "executed once; the request cannot be reused",
    "rejected_by_upstream": "the upstream answered with an explicit rejection (see error.http_status); by that answer "
                            "the change was not applied. Propose a new request if it is still needed",
    "outcome_uncertain": "the request was sent but no valid answer was received (timeout, cancellation, broken "
                         "connection, invalid response or server error): the change may or may not have been "
                         "applied. Reconcile in the product before proposing it again; this request is not retried",
    "not_sent": "the request was not sent to the upstream (connection, discovery or contract check failed); nothing "
                "was applied. Propose a new request if it is still needed",
}


def _final_status(out: dict, progress: dict) -> str:
    if out.get("outcome") in ("ok", "empty", "partial", "empty_response"):
        return "executed"
    if not (progress.get("sent") or out.get("upstream_call_attempted")):
        return "not_sent"
    error = out.get("error") or {}
    # Only an upstream answer (stage "response") with an explicit rejection status means "not applied".
    if progress.get("stage") == "response" and error.get("http_status") in DEFINITE_REJECTIONS:
        return "rejected_by_upstream"
    return "outcome_uncertain"


def _record(request_id: str, status: str, stored: dict) -> None:
    with _store().lock(request_id):
        request = load(request_id)
        request.update(status=status, result=stored)
        request["history"].append({"at": stored["at"], "event": status})
        _write(request)


async def execute(request_id: str, timeout_seconds: float = 120, settings: dict | None = None) -> dict[str, Any]:
    from .upstream_live import call_registered
    with _store().lock(request_id):
        request = load(request_id)
        try:
            t = check_executable(request)
        except Refused as refused:
            if refused.category == "file_changed":
                request["status"] = "not_sent"
                request["history"].append({"at": _iso(_now()), "event": "not_sent", "reason": "file_changed"})
                _write(request)
                discard_staged(request_id)
            raise
        request["status"] = "executing"  # single use: a second execute finds this state
        request["history"].append({"at": _iso(_now()), "event": "executing"})
        _write(request)
    arguments, mounts = dict(request["arguments"]), None
    if request.get("upload"):
        up = request["upload"]
        arguments[up["field"]] = up["container_path"]
        mounts = [(up["staged_path"], up["container_path"])]
    progress: dict[str, Any] = {}
    try:
        out, _ = await call_registered(t, arguments,
                                       readonly=bool((t.get("server_flags") or {}).get("readonly")),
                                       timeout_seconds=timeout_seconds, max_chars=50_000, settings=settings,
                                       mounts=mounts, progress=progress)
    except BaseException:
        # Cancellation or an unexpected failure: after sending, the outcome is unknown.
        status = "outcome_uncertain" if progress.get("sent") else "not_sent"
        _record(request_id, status, {"outcome": "interrupted", "stage": progress.get("stage"),
                                     "upstream_call_attempted": bool(progress.get("sent")), "at": _iso(_now())})
        discard_staged(request_id)
        raise
    status = _final_status(out, progress)
    integrity = None
    if request.get("upload"):
        try:
            _verify_staged(request)
            integrity = "staged file verified before and after the call"
        except Refused:
            integrity = "the staged file changed during execution: the uploaded bytes may differ from the approved ones"
            if status == "executed":
                status = "outcome_uncertain"
        discard_staged(request_id)
    stored = {"outcome": out.get("outcome"), "stage": out.get("stage"), "error": out.get("error"),
              "upstream_call_attempted": bool(progress.get("sent")), "at": _iso(_now())}
    if t["effect"] not in SECRET_EFFECTS:
        stored["response_headers"] = out.get("response_headers")
    if integrity:
        stored["upload_integrity"] = integrity
    _record(request_id, status, stored)
    return {**out, "request_id": request_id, "request_status": status, "note": NOTES[status],
            **({"upload_integrity": integrity} if integrity else {}),
            **({"secret_handling": "the generated value is shown only in this response and was not stored"}
               if t["effect"] in SECRET_EFFECTS else {})}
