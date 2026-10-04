"""Local, versioned case store: atomic writes, revisions, retention and consolidation.

A case keeps what is needed to resume and re-assess an investigation: references, scope,
metadata snapshots with collection times, planned/executed queries with search IDs,
states and cursors, collected rows, consolidated evidence with every query that returned
it, pivots, hypotheses, contradictions, pending items, analyst confirmations (labelled as
external) and report revisions. It never stores tokens, MCP sessions or network clients.
The default directory is ``reports/cases`` (ignored by Git); see docs/case-store.md.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Iterator

if os.name == "nt":
    import msvcrt
else:
    import fcntl

SCHEMA_VERSION = 1
CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MAX_ROWS_PER_QUERY = 5000
MAX_REVISIONS = 50
SECRET_ENV = ("QRADAR_MCP_TOKEN", "TREND_VISION_ONE_API_KEY")
SECRET_KEYS = re.compile(r"^(sec|token|api_?key|authorization|cookie|password|secret|headers?)$", re.I)
DEFAULT_RETENTION_DAYS = 30
LOCK_TIMEOUT_SECONDS = 15.0
MAX_PROPERTY_CHARS = 500

# Query scope -> relation tier of the records it returned (see docs/case-store.md).
TIER_BY_SCOPE = {
    "offense_linked": "offense_associated",
    "parent_process_lookup": "identifier_demonstrated",
    "host_ip_time_context": "context",
}
TIERS = {
    "offense_associated": "returned by an INOFFENSE query of the offense",
    "alert_linked": "record uuid listed in the Workbench alert matchedEvents",
    "identifier_demonstrated": "shares a strong identifier (GUID, process instance, full hash, exact path)",
    "candidate": "related by IP, account or time proximity only",
    "context": "same host/time window without a demonstrated link",
}


class CaseConflict(RuntimeError):
    """The case changed on disk since it was loaded; reload and merge instead of overwriting."""


class SecretInCase(ValueError):
    """A configured credential value appeared in data to be persisted; nothing was written."""


class CaseLocked(TimeoutError):
    """Another process held the case lock for longer than the lock timeout; nothing was written."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def default_root() -> Path:
    configured = os.environ.get("SOC_BRIDGE_CASE_DIR", "").strip()
    if configured:
        return Path(configured)
    project = Path(__file__).resolve().parents[2]
    base = project if (project / "pyproject.toml").is_file() else Path.cwd()
    return base / "reports" / "cases"


def _secrets() -> list[str]:
    return [v for v in (os.environ.get(name, "") for name in SECRET_ENV) if len(v) >= 8]


def scrub(value: Any, secrets: list[str] | None = None, path: str = "$") -> Any:
    """Drop credential-like keys; refuse to persist any configured secret value."""
    secrets = _secrets() if secrets is None else secrets
    if isinstance(value, dict):
        return {k: scrub(v, secrets, f"{path}.{k}") for k, v in value.items() if not SECRET_KEYS.match(str(k))}
    if isinstance(value, list):
        return [scrub(v, secrets, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, str) and any(secret in value for secret in secrets):
        raise SecretInCase(f"a configured credential value appeared at {path}; the case was not written")
    return value


def _row_hash(row: dict) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def evidence_identity(database: str, row: dict, query: str, search_id: Any, index: int) -> tuple[str, str]:
    """Conservative identity of one returned record.

    Records are merged across queries only when they carry the same origin (log source),
    stored time, device time, QID and identical payload. Without a payload, log source or
    stored time there is not enough identity: the record stays tied to the query, job and
    row that returned it and is never merged with another one."""
    payload = row.get("raw_payload")
    if (isinstance(payload, str) and payload and row.get("log_source") not in (None, "")
            and row.get("starttime") is not None):
        parts = [database, row.get("log_source"), row.get("starttime"), row.get("devicetime"), row.get("qid"),
                 hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()]
        return ("rec:" + hashlib.sha256(json.dumps(parts, default=str).encode("utf-8")).hexdigest()[:32],
                "log source, stored/device time, QID and payload")
    parts = [database, query, search_id, index, _row_hash(row)]
    return ("row:" + hashlib.sha256(json.dumps(parts, default=str).encode("utf-8")).hexdigest()[:32],
            "insufficient identity (no payload, log source or stored time): kept separate per query/job/row")


def evidence_key(database: str, row: dict, query: str = "", search_id: Any = None, index: int = 0) -> str:
    return evidence_identity(database, row, query, search_id, index)[0]


def properties(row: dict) -> dict:
    """Non-payload properties used to detect records that share a payload key but differ."""
    out = {}
    for key, value in row.items():
        if key == "raw_payload" or value is None:
            continue
        out[str(key)] = value[:MAX_PROPERTY_CHARS] if isinstance(value, str) else value
    return out


def _conflicting(stored: dict, new: dict) -> list[str]:
    return sorted(k for k in set(stored) & set(new) if stored[k] != new[k])


def epoch_utc(value: Any) -> str | None:
    """Epoch milliseconds to UTC; independent of any assumed console timezone."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(number / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CaseStore:
    def __init__(self, root: Path | None = None, retention_days: int | None = None):
        self.root = Path(root) if root is not None else default_root()
        env_days = os.environ.get("SOC_BRIDGE_CASE_RETENTION_DAYS", "").strip()
        self.retention_days = retention_days if retention_days is not None else (
            int(env_days) if env_days.isdigit() else DEFAULT_RETENTION_DAYS)

    def path(self, case_id: str) -> Path:
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise ValueError("case_id must be 1..100 letters, digits, '.', '_' or '-' starting with a letter/digit")
        return self.root / f"{case_id}.json"

    @staticmethod
    def new(case_id: str, offenses: list[int] | None = None, alerts: list[str] | None = None,
            scope: dict | None = None) -> dict:
        created = now_iso()
        return {"schema_version": SCHEMA_VERSION, "case_id": case_id, "created_at": created, "updated_at": created,
                "revision": 0, "references": {"offenses": list(offenses or []), "alerts": list(alerts or [])},
                "scope": scope or {}, "collection_now": None, "metadata_snapshots": [], "queries": {}, "rows": {},
                "evidence": {}, "pivots": [], "hypotheses": [], "contradictions": [], "pending": [],
                "confirmations": [], "decisions": [], "report_revisions": [], "runs": [],
                "storage_note": "Local case file; contains collected telemetry. Keep out of Git and public locations."}

    @contextmanager
    def lock(self, case_id: str, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
        """Exclusive inter-process lock for one case (msvcrt on Windows, flock on Linux/WSL).

        Reading the revision, comparing it and replacing the file happen under this lock, so
        two writers of the same revision cannot both succeed."""
        self.path(case_id)  # validates the identifier before touching the filesystem
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / f".{case_id}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    if os.name == "nt":
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise CaseLocked(f"case {case_id} is locked by another process; nothing was written") from None
                    time.sleep(0.02)
            try:
                yield
            finally:
                if os.name == "nt":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _read(self, case_id: str) -> dict | None:
        path = self.path(case_id)
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("case_id") != case_id:
            raise ValueError("case file does not match its name")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(f"unsupported case schema_version {version}; expected {SCHEMA_VERSION}")
        return data

    def load(self, case_id: str) -> dict | None:
        with self.lock(case_id):
            return self._read(case_id)

    def _before_write(self) -> None:
        """Hook between the revision check and the replace (used by concurrency tests)."""

    def save(self, case: dict, expected_revision: int) -> dict:
        """Atomic replace with optimistic concurrency under an inter-process lock: the on-disk
        revision is read, compared and replaced while holding the lock."""
        path = self.path(case["case_id"])
        case = scrub(case)
        with self.lock(case["case_id"]):
            current = self._read(case["case_id"])
            on_disk = current["revision"] if current else 0
            if on_disk != expected_revision:
                raise CaseConflict(f"case {case['case_id']} is at revision {on_disk}, expected {expected_revision}")
            self._before_write()
            case["revision"] = expected_revision + 1
            case["updated_at"] = now_iso()
            case["report_revisions"] = case.get("report_revisions", [])[-MAX_REVISIONS:]
            fd, temporary = tempfile.mkstemp(prefix=".case-", suffix=".json", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump(case, stream, ensure_ascii=False, indent=1, default=str)
                    stream.write("\n")
                if os.name != "nt":
                    os.chmod(temporary, 0o600)
                for attempt in range(50):
                    try:
                        os.replace(temporary, path)
                        break
                    except PermissionError:
                        # Windows refuses to replace a file that an unlocked reader (list) has open.
                        if attempt == 49:
                            raise
                        time.sleep(0.02)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return case

    def list(self) -> list[dict]:
        out = []
        for path in sorted(self.root.glob("*.json")) if self.root.is_dir() else []:
            try:
                case = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out.append({"case_id": path.stem, "state": "unreadable"})
                continue
            last = (case.get("decisions") or [{}])[-1]
            out.append({"case_id": case.get("case_id"), "references": case.get("references"),
                        "updated_at": case.get("updated_at"), "revision": case.get("revision"),
                        "decision": last.get("decision"), "disposition": last.get("disposition"),
                        "pending": len(case.get("pending", []))})
        return out

    def delete(self, case_id: str) -> bool:
        path = self.path(case_id)
        if not path.is_file():
            return False
        with self.lock(case_id):
            if path.is_file():
                path.unlink()
                return True
        return False

    def purge(self, now: datetime | None = None) -> list[str]:
        """Delete cases not updated within the retention period."""
        limit = (now or datetime.now(timezone.utc)) - timedelta(days=self.retention_days)
        removed = []
        for item in self.list():
            updated = item.get("updated_at")
            try:
                when = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
            except ValueError:
                continue
            if when < limit and self.delete(item["case_id"]):
                removed.append(item["case_id"])
        return removed


def merge_query(case: dict, name: str, finding: dict, rows: list[dict], run_id: str,
                offense_id: int | None = None) -> dict:
    """Store query state and rows; consolidate records conservatively keeping every reference.

    The query state records the offense, database, scope and AQL it belongs to, so a later
    run resumes it only for the same offense and the same query."""
    meta = {k: v for k, v in finding.items() if k not in ("rows", "samples")}
    previous = case["queries"].get(name)
    history = list((previous or {}).get("history", []))
    if previous and previous.get("search_id") != meta.get("search_id") and (
            previous.get("search_id") or previous.get("outcome") == "creation_uncertain"):
        history.append({"search_id": previous.get("search_id"), "outcome": previous.get("outcome"),
                        "aql": previous.get("aql"), "offense_id": previous.get("offense_id"),
                        "next_start": previous.get("next_start"), "rows_stored": previous.get("rows_stored"),
                        "replaced_at": now_iso()})
    meta["history"] = history
    if offense_id is not None:
        meta["offense_id"] = offense_id
    stored = rows[:MAX_ROWS_PER_QUERY]
    meta["rows_stored"] = len(stored)
    meta["rows_not_stored"] = max(0, len(rows) - MAX_ROWS_PER_QUERY)
    meta["last_run"] = run_id
    case["queries"][name] = meta
    case["rows"][name] = stored
    tier = TIER_BY_SCOPE.get(str(finding.get("scope")), "candidate")
    database = str(finding.get("database"))
    search_id = finding.get("search_id")
    added = kept_apart = 0
    for index, row in enumerate(stored):
        if not isinstance(row, dict):
            continue
        key, basis = evidence_identity(database, row, name, search_id, index)
        ref = {"query": name, "search_id": search_id, "row_index": index, "run": run_id}
        props = properties(row)
        item = case["evidence"].get(key)
        if item is not None and not _seen(item, ref):
            differing = _conflicting(item.get("properties", {}), props)
            if differing:
                # Same payload key but different properties (for example ProcessGuid): not the same record.
                key = f"{key}:{_row_hash(row)[:16]}"
                basis = "payload key shared but properties differ (" + ", ".join(differing[:5]) + "): kept separate"
                kept_apart += 1
                item = case["evidence"].get(key)
        if item is None:
            case["evidence"][key] = {"source": "QRadar Ariel", "database": finding.get("database"), "tier": tier,
                                     "identity": basis,
                                     "clocks": {"received_utc": epoch_utc(row.get("starttime")),
                                                "device_time_utc": epoch_utc(row.get("devicetime")),
                                                "collected_in_run": run_id},
                                     "summary": {k: row.get(k) for k in ("event_name", "log_source", "sourceip",
                                                                       "destinationip", "username", "qid")
                                                 if row.get(k) is not None},
                                     "properties": props, "seen_in": [ref]}
            added += 1
        else:
            if not _seen(item, ref):
                item["seen_in"].append(ref)
            # A stronger relation from another query upgrades the tier; never downgrades it.
            order = list(TIERS)
            if order.index(tier) < order.index(item["tier"]):
                item["tier"] = tier
    return {"query": name, "rows": len(stored), "new_records": added, "kept_apart_by_properties": kept_apart}


def _seen(item: dict, ref: dict) -> bool:
    return any(r.get("query") == ref["query"] and r.get("search_id") == ref["search_id"]
               and r.get("row_index") == ref["row_index"] for r in item["seen_in"])


def merge_trend(case: dict, alert_id: str, records: dict, run_id: str) -> int:
    """Trend Search records from an alert flow, keyed by uuid, with their relation tier."""
    tier_by_label = {"linked": "alert_linked", "identifier_match": "identifier_demonstrated", "context": "context"}
    added = 0
    for label, items in (records or {}).items():
        for record in items:
            key = "trend:" + str(record.get("uuid") or hashlib.sha256(
                json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()[:24])
            ref = {"alert": alert_id, "tool": record.get("tool"), "run": run_id}
            if key in case["evidence"]:
                if ref not in case["evidence"][key]["seen_in"]:
                    case["evidence"][key]["seen_in"].append(ref)
                continue
            case["evidence"][key] = {"source": "Vision One Search", "tier": tier_by_label.get(label, "context"),
                                     "clocks": {"event_time_utc": record.get("time_utc"), "collected_in_run": run_id},
                                     "summary": {"tool": record.get("tool"), "endpoint_host": record.get("endpoint_host"),
                                                 "relation": record.get("relation")},
                                     "seen_in": [ref]}
            added += 1
    return added
