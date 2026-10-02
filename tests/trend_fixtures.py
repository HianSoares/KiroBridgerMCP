"""Synthetic Vision One alert, Search/OAT records and a fake read-only MCP (no real incident data)."""

from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(hours=1)
HOST = "ws-synth-01.example.test"
GUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
IP4 = "192.0.2.50"
IP6 = "2001:db8::50"
DUMP = "C:\\ProgramData\\Synth\\app_4321.dmp"
PD = "C:\\Tools\\procdump64.exe"
APP = "C:\\Program Files\\ExampleVendor\\VendorApp.exe"
CMD = f"procdump64.exe -accepteula -ma 4321 {DUMP}"
SHA = "cd" * 32
ALERT_ID = "WB-SYNTH-0001"


def z(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


ALERT = {
    "id": ALERT_ID, "model": "Synthetic Memory Dump Activity", "severity": "high", "score": 61,
    "investigationResult": "No Findings",
    "createdDateTime": z(T0 + timedelta(minutes=10)), "updatedDateTime": z(T0 + timedelta(minutes=10)),
    "description": "Narrative mentions 203.0.113.99 and evil.example.test; never parsed",
    "impactScope": {"desktopCount": 1, "accountCount": 1, "entities": [
        {"entityType": "host", "entityId": GUID, "entityValue": {"name": HOST, "guid": GUID, "ips": [IP4, IP6]},
         "relatedIndicatorIds": [1, 2, 3], "relatedEntities": [], "provenance": ["Alert"]},
        {"entityType": "account", "entityId": "EXAMPLE\\svc.synth", "entityValue": "EXAMPLE\\svc.synth",
         "relatedIndicatorIds": [], "relatedEntities": [GUID], "provenance": ["Alert"]}]},
    "indicators": [
        {"id": 1, "type": "command_line", "field": "objectCmd", "value": CMD, "relatedEntities": [GUID],
         "filterIds": ["f1"], "provenance": ["Alert"]},
        {"id": 2, "type": "file_sha256", "field": "objectFileHashSha256", "value": SHA, "relatedEntities": [GUID]},
        {"id": 3, "type": "fullpath", "field": "objectFilePath", "value": PD, "relatedEntities": [GUID]}],
    "matchedRules": [{"id": "r1", "name": "Synthetic dump rule", "matchedFilters": [
        {"id": "f1", "name": "Dump tool with full-memory flag", "matchedDateTime": z(T0 + timedelta(seconds=5)),
         "mitreTechniqueIds": ["T1003.001"],
         "matchedEvents": [{"uuid": "ev-launch-1", "matchedDateTime": z(T0 + timedelta(seconds=1)),
                            "type": "TELEMETRY_PROCESS"}]}]}],
}


def rec(uuid, seconds, **fields):
    return {"uuid": uuid, "eventTime": z(T0 + timedelta(seconds=seconds)), "endpointGuid": GUID,
            "endpointHostName": HOST, "endpointIp": [IP4], **fields}


APP_LAUNCH = rec("ev-app-1", -60, processFilePath=APP, processPid=4321, processHashId="inst-app",
                 processLaunchTime=z(T0 - timedelta(hours=1)), objectFilePath="C:\\Windows\\System32\\cmd.exe",
                 objectCmd="cmd.exe /c run-diagnostics.cmd", objectPid=5000, objectProcessHashId="inst-cmd",
                 eventId=1, eventSubId=2)
PD_LAUNCH = rec("ev-launch-1", 1, processFilePath="C:\\Windows\\System32\\cmd.exe", processPid=5000,
                processHashId="inst-cmd", parentFilePath=APP, parentPid=4321, objectFilePath=PD, objectCmd=CMD,
                objectPid=6000, objectProcessHashId="inst-pd", objectFileHashSha256=SHA, eventId=1, eventSubId=2,
                objectLaunchTime=z(T0 + timedelta(seconds=1)),
                objectSigner=["Example Signer"], objectSignerValid=[True])
PD_ACCESS = rec("ev-access-1", 2, processFilePath=PD, processCmd=CMD, processPid=6000, processHashId="inst-pd",
                processLaunchTime=z(T0 + timedelta(seconds=1)), objectFilePath=APP, objectPid=4321,
                objectProcessHashId="inst-app", eventId=2, eventSubId=5)
PD_WRITE = rec("ev-write-1", 5, processFilePath=PD, processCmd=CMD, processPid=6000, processHashId="inst-pd",
               objectFilePath=DUMP, eventId=3, eventSubId=101)
ZIP_READ = rec("ev-zip-1", 1200, processFilePath="C:\\Program Files\\7-Zip\\7z.exe",
               processCmd=f"7z.exe a C:\\ProgramData\\Synth\\out.7z {DUMP}", processPid=7000, processHashId="inst-7z",
               objectFilePath=DUMP, eventId=3, eventSubId=102)
OAT_ITEM = {"uuid": "oat-1", "detectedDateTime": z(T0 + timedelta(seconds=3)), "ingestedDateTime": z(T0 + timedelta(seconds=40)),
            "source": "endpointActivityData", "filters": [{"id": "o1", "name": "Process memory dump", "riskLevel": "medium",
                                                           "mitreTacticIds": ["TA0006"], "mitreTechniqueIds": ["T1003.001"]}],
            "endpoint": {"endpointName": HOST, "agentGuid": GUID, "ips": [IP4]}, "detail": {"processFilePath": PD}}


class FakeVision:
    """Routes read-only calls; records every call; optional failures per tool."""

    def __init__(self, alert=None, search=None, oat=None, failures=None, available=None, responses=None):
        self.alert = dict(ALERT if alert is None else alert)
        self.search = search
        self.oat = oat
        self.failures = failures or {}
        self.responses = responses or {}
        self.calls = []
        if available is not None:
            self.available = available

    async def call(self, tool, args):
        self.calls.append((tool, dict(args)))
        if tool in self.failures:
            raise self.failures[tool]
        if tool == "workbench_alert_detail_get":
            return dict(self.alert)
        if tool in ("search_endpoint_activities_list", "search_detections_list"):
            return {"items": self.search(tool, args) if self.search else []}
        if tool == "workbench_observed_attack_techniques_list":
            return self.oat(args) if self.oat else {"items": []}
        if tool in self.responses:
            value = self.responses[tool]
            return value(args) if callable(value) else value
        return {"items": []}


def procdump_search(tool, args):
    query = args["query"]
    if tool == "search_detections_list":
        return []
    if 'processHashId:"inst-pd"' in query:
        return [PD_ACCESS, PD_WRITE]
    if 'objectFilePath:"app_4321.dmp"' in query:
        return [PD_WRITE, ZIP_READ]
    if query == f'endpointGuid:"{GUID}"':
        return [APP_LAUNCH, PD_LAUNCH, PD_ACCESS, PD_WRITE]
    if "objectFileHashSha256" in query:
        return [PD_LAUNCH]
    return []


def sysmon_payload(image, command, pid, seconds, host=HOST):
    utc = (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return (f"EventID=1 Computer={host} Process Create: UtcTime: {utc} ProcessGuid: "
            f"{{11111111-2222-4333-8444-555555555555}} ProcessId: {pid} Image: {image} CommandLine: {command} "
            f"User: EXAMPLE\\svc.synth")
