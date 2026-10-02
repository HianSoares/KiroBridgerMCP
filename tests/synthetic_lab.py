"""Synthetic QRadar responses and Windows payloads for offense evidence tests (no real data)."""

from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 10, 9, 18, 0, tzinfo=timezone.utc)
START = NOW - timedelta(hours=2)
MS = int(START.timestamp() * 1000)
HOST = "ws-demo-01.example.test"
IP = "192.0.2.10"
G_PARENT = "{11111111-1111-4111-8111-111111111111}"
G_PS = "{22222222-2222-4222-8222-222222222222}"
G_OTHER = "{33333333-3333-4333-8333-333333333333}"
G_CHILD = "{44444444-4444-4444-8444-444444444444}"
SHA = "AB" * 32  # artificial SHA256


def offense(oid=12345, **extra):
    return {"id": oid, "description": "Synthetic process rule", "status": "OPEN", "offense_source": IP,
            "start_time": MS, "last_updated_time": MS + 120000, "event_count": 2, "flow_count": 0,
            "rules": [{"id": 12, "type": "CRE_RULE"}], **extra}


def sysmon(guid, pid, image, command_line, parent_guid=None, parent_pid=None, host=HOST,
           hashes=None, tail=""):
    parts = [f"EventID=1 Computer={host} Process Create: RuleName: - UtcTime: 2026-10-09 16:00:01.000",
             f"ProcessGuid: {guid}", f"ProcessId: {pid}", f"Image: {image}", f"CommandLine: {command_line}",
             "CurrentDirectory: C:\\Users\\demo.user\\", "User: EXAMPLE\\demo.user", "LogonId: 0x3E7",
             "TerminalSessionId: 1"]
    if hashes:
        parts.append(f"Hashes: {hashes}")
    if parent_guid:
        parts.append(f"ParentProcessGuid: {parent_guid}")
    if parent_pid:
        parts.append(f"ParentProcessId: {parent_pid}")
    parts.append("ParentImage: C:\\Windows\\explorer.exe")
    return " ".join(parts) + tail


def script_block_xml(text, pid="4321", host=HOST, number="1", total="1"):
    return ("<Event><System><EventID>4104</EventID><Execution ProcessID=\"" + pid + "\" ThreadID=\"9\"/>"
            f"<Computer>{host}</Computer></System><EventData><Data Name=\"MessageNumber\">{number}</Data>"
            f"<Data Name=\"MessageTotal\">{total}</Data><Data Name=\"ScriptBlockText\">{text}</Data>"
            "<Data Name=\"ScriptBlockId\">{55555555-5555-4555-8555-555555555555}</Data>"
            "<Data Name=\"Path\"></Data></EventData></Event>")


def integrity_text(path, host=HOST):
    return (f"EventCode=5038 ComputerName={host} Code integrity determined that the image hash of a file "
            f"is not valid. File Name: {path}")


def row(payload, offset_ms=0, name="Synthetic event"):
    return {"starttime": MS + offset_ms, "devicetime": MS + offset_ms, "sourceip": IP,
            "event_name": name, "log_source": "Synthetic WinCollect", "raw_payload": payload}


class Lab:
    """Routes AQL by content to synthetic rows; records every call for assertions."""

    def __init__(self, routes=None, catalog=None, pending_polls=0, reject=None, offenses=None):
        self.routes = routes or {}
        self.catalog = catalog
        self.pending_polls = pending_polls
        self.reject = reject or (lambda query: False)
        self.offenses = offenses or {12345: offense()}
        self.calls, self.jobs, self.queries = [], {}, []

    async def read_aql_resource(self, resource):
        self.calls.append(("resource", resource))
        if self.catalog is None:
            raise RuntimeError("resource unavailable")
        return {"metadata": self.catalog.get(resource, {"fields": []})}

    def route(self, query):
        for marker, (database, rows, total) in self.routes.items():
            if marker in query:
                return database, rows, total
        return ("flows" if "FROM flows" in query else "events"), [], None

    async def call(self, name, args):
        self.calls.append((name, args))
        if name == "get_offense":
            return self.offenses[args["offense_id"]]
        if name == "get_rule":
            return {"id": args["rule_id"], "name": "Synthetic rule", "enabled": True}
        if name == "validate_aql":
            return {"valid": not self.reject(args["query_expression"])}
        if name == "create_ariel_search":
            query = args["query_expression"]
            self.queries.append(query)
            database, rows, total = self.route(query)
            sid = f"synthetic-job-{len(self.jobs)}"
            self.jobs[sid] = {"database": database, "rows": rows,
                              "total": len(rows) if total is None else total, "pending": self.pending_polls}
            return {"search_id": sid, "status": "WAIT"}
        if name == "get_ariel_search_status":
            job = self.jobs[args["search_id"]]
            if job["pending"] > 0:
                job["pending"] -= 1
                return {"status": "EXECUTE", "record_count": None}
            return {"status": "COMPLETED", "record_count": job["total"]}
        if name == "get_ariel_search_results":
            job = self.jobs[args["search_id"]]
            return {job["database"]: job["rows"][args["start"]:args["start"] + args["limit"]]}
        raise AssertionError(name)

    def created(self):
        return sum(1 for name, _ in self.calls if name == "create_ariel_search")
