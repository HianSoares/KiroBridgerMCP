"""Synthetic evidence cases; no real identifiers or incident payloads."""

import json
import unittest
from datetime import datetime, timezone

from soc_bridge.extra_cases import investigate_epm_uac, investigate_web_reputation, _aql


T = "2026-09-25T14:32:24Z"
MS = int(datetime(2026, 9, 25, 14, 32, 24, tzinfo=timezone.utc).timestamp() * 1000)


class Fake:
    def __init__(self, rows=None, detections=None, agent_rows=None, activity=None, inventory=None):
        self.rows = rows or []
        self.agent_rows = agent_rows
        self.detections = detections or []
        self.activity = activity or []
        self.inventory = inventory or []
        self.calls = []
        self.active_rows = self.rows

    async def call(self, name, args):
        self.calls.append((name, args))
        if name == "validate_aql":
            return {"valid": True}
        if name == "create_ariel_search":
            self.active_rows = (self.agent_rows if self.agent_rows is not None and "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in args["query_expression"] else self.rows)
            return {"search_id": "synthetic-123"}
        if name == "get_ariel_search_status":
            return {"status": "COMPLETED", "record_count": len(self.active_rows)}
        if name == "get_ariel_search_results":
            return {"events": self.active_rows}
        if name == "search_detections_list":
            return {"items": self.detections}
        if name == "search_endpoint_activities_list":
            return {"items": self.activity}
        if name == "endpoint_security_endpoints_list":
            return {"items": self.inventory}
        raise AssertionError(name)


class ExtraCases(unittest.IsolatedAsyncioTestCase):
    async def test_epm_missing_host_never_pivots_generic_updater(self):
        payload = {"eventType": "UacAudit", "lastEventId": "fakeUac88888",
                   "lastEventDate": T, "lastEventFileName": "updater.exe", "hash": "",
                   "policyAction": "Collect UAC actions", "fileLocation": "C:\\Temp\\demo\\"}
        q = Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(payload), "starttime": MS}])
        v = Fake()
        report = await investigate_epm_uac(q, v, "fakeUac88888", T, -3)
        self.assertIn("Busca por hostname não executada", report)
        self.assertNotIn("prova", report.split("## Trend Vision One")[0])
        self.assertEqual(v.calls, [])

    async def test_epm_requires_exact_event_id_and_log_source(self):
        q = Fake(rows=[{"log_source": "other", "raw_payload": json.dumps({"lastEventId": "fakeUac88888", "eventType": "UacAudit"})}])
        report = await investigate_epm_uac(q, Fake(), "fakeUac88888", T, -3)
        self.assertIn("Nenhum evento", report)
        with self.assertRaises(ValueError):
            await investigate_epm_uac(q, Fake(), "x' OR TRUE", T, -3)

    async def test_epm_agent_candidate_enables_bounded_trend_pivot(self):
        agent = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        base = {"eventType": "UacAudit", "lastEventId": "fakeUac88888", "lastEventDate": T,
                "lastEventFileName": "updater.exe", "lastEventAgentId": agent}
        linked = {"lastEventAgentId": agent, "lastEventComputerName": "LAB-01", "lastEventDate": T,
                  "lastEventId": "differentEvent", "eventType": "Application"}
        q = Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(base)}],
                 agent_rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(linked)}])
        v = Fake(detections=[{"endpointHostName": "LAB-01", "fileName": "updater.exe", "eventTime": T,
                              "fileHash": "0" * 40}])
        report = await investigate_epm_uac(q, v, "fakeUac88888", T, -3)
        self.assertIn("outro registro EPM_API, mesmo lastEventAgentId (candidato)", report)
        self.assertIn("Detecções candidatas no host + nome + ±10 min: 1", report)
        self.assertIn("não prova", report)

    async def test_epm_ambiguous_agent_host_never_pivots(self):
        agent = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        base = {"eventType": "UacAudit", "lastEventId": "fakeUac88888", "lastEventDate": T,
                "lastEventFileName": "updater.exe", "lastEventAgentId": agent}
        linked = [{"log_source": "EPM_API", "raw_payload": json.dumps({
            "lastEventAgentId": agent, "lastEventComputerName": h, "lastEventDate": T})} for h in ("LAB-01", "LAB-02")]
        v = Fake()
        report = await investigate_epm_uac(Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(base)}], agent_rows=linked),
                                           v, "fakeUac88888", T, -3)
        self.assertIn("2 host(s) distinto(s)", report)
        self.assertIn("Busca por hostname não executada", report)
        self.assertEqual(v.calls, [])

    async def test_epm_unique_temp_path_pivots_without_hostname(self):
        path = "C:\\Users\\synthetic\\AppData\\Local\\Temp\\mk13579135.tmp\\"
        payload = {"eventType": "UacAudit", "lastEventId": "fakeUac88888", "lastEventDate": T,
                   "lastEventFileName": "updater.exe", "fileLocation": path}
        q = Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(payload)}])
        v = Fake(detections=[{"filePathName": path + "updater.exe", "eventTime": T,
                              "endpointHostName": "LAB-01", "fileHash": "a" * 40, "uuid": "synthetic-1"},
                             {"filePathName": "C:\\Users\\other\\AppData\\Local\\Temp\\mk13579135.tmp\\updater.exe",
                              "eventTime": T, "endpointHostName": "LAB-02"}])
        report = await investigate_epm_uac(q, v, "fakeUac88888", T, -3)
        self.assertIn("4/4 consultas concluídas; 1 eventos com caminho", report)
        self.assertIn("Linhas nas páginas inspecionadas (soma das consultas, com possíveis duplicatas): 4; caminho completo exato: 2", report)
        self.assertIn("somente segmento de pasta com caminho diferente: 2", report)
        self.assertIn("host=LAB-01", report)
        self.assertNotIn("host=LAB-02", report)
        self.assertIn("Busca por hostname não executada", report)

    async def test_epm_searches_first_and_last_aggregation_windows(self):
        path = "C:\\Users\\synthetic\\AppData\\Local\\Temp\\mk13579135.tmp\\"
        payload = {"eventType": "UacAudit", "lastEventId": "fakeUac88888", "lastEventDate": T,
                   "firstEventDate": "2026-09-24T13:57:53Z", "lastEventFileName": "updater.exe", "fileLocation": path}
        q = Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(payload)}])
        v = Fake()
        report = await investigate_epm_uac(q, v, "fakeUac88888", T, -3)
        self.assertIn("8/8 consultas concluídas", report)
        self.assertIn("2026-09-24T13:57:53+00:00", report)
        self.assertIn("Linhas nas páginas inspecionadas (soma das consultas, com possíveis duplicatas): 0", report)

    async def test_epm_exact_path_outside_time_is_not_promoted(self):
        path = "C:\\Users\\synthetic\\AppData\\Local\\Temp\\mk13579135.tmp\\"
        payload = {"eventType": "UacAudit", "lastEventId": "fakeUac88888", "lastEventDate": T,
                   "lastEventFileName": "updater.exe", "fileLocation": path}
        q = Fake(rows=[{"log_source": "EPM_API", "raw_payload": json.dumps(payload)}])
        v = Fake(detections=[{"filePathName": path + "updater.exe", "eventTime": "2026-09-25T13:00:00Z",
                              "endpointHostName": "LAB-01"}])
        report = await investigate_epm_uac(q, v, "fakeUac88888", T, -3)
        self.assertIn("caminho completo exato: 2; caminho exato sem horário válido/fora da janela: 2", report)
        self.assertIn("0 eventos com caminho **completo e exato** + horário conferidos", report)
        self.assertNotIn("host=LAB-01", report)

    async def test_web_traffic_accept_does_not_claim_url_allowed(self):
        q = Fake(rows=[{"log_source": "FGT-EDGE", "starttime": MS,
                        "raw_payload": 'type=traffic action=accept srcip=10.0.0.5 hostname="bad.example" dstip=203.0.113.1 policyid=42'}])
        v = Fake(detections=[{"eventTime": T, "endpointIp": ["10.0.0.5"], "request": "https://bad.example/a", "uuid": "synthetic"}])
        report = await investigate_web_reputation(q, v, "https://bad.example/a", T, "10.0.0.5", -3)
        self.assertIn("não comprova que a URL", report)
        self.assertIn("Registros Trend com request, IP e horário coincidentes: 1", report)
        self.assertIn("Nenhuma mensagem foi enviada", report)

    async def test_webfilter_passthrough_requires_exact_source_and_domain(self):
        rows = [
            {"log_source": "FortiGate", "starttime": MS,
             "raw_payload": 'type=utm subtype=webfilter action=passthrough srcip=10.0.0.5 hostname=bad.example policyid=21'},
            {"log_source": "FortiGate", "starttime": MS,
             "raw_payload": 'type=utm subtype=webfilter action=passthrough srcip=10.0.0.8 hostname=bad.example'},
            {"log_source": "FortiGate", "starttime": MS,
             "raw_payload": 'type=utm subtype=webfilter action=passthrough srcip=10.0.0.5 hostname=other.example'},
        ]
        report = await investigate_web_reputation(Fake(rows), Fake(), "bad.example", T, "10.0.0.5", -3)
        self.assertIn("Logs FortiGate com srcip + hostname/url + horário exatos: 1", report)
        self.assertIn("webfilter do FortiGate com ação de permissão", report)
        self.assertIn("Rascunho para equipe de rede", report)

    async def test_webfilter_blocked_does_not_draft_block_request(self):
        rows = [{"log_source": "FortiGate", "starttime": MS,
                 "raw_payload": "type=utm subtype=webfilter action=blocked "
                                "srcip=10.0.0.5 hostname=bad.example policyid=148"}] * 4
        rows += [{"log_source": "FortiGate", "starttime": MS,
                  "raw_payload": "type=traffic action=accept srcip=10.0.0.8 hostname=other.example"}] * 4
        report = await investigate_web_reputation(Fake(rows), Fake(), "bad.example", T, "10.0.0.5", -3)
        self.assertIn("Logs FortiGate com srcip + hostname/url + horário exatos: 4", report)
        self.assertIn("teto de 100 não atingido nesta consulta", report)
        self.assertIn("Nenhum log webfilter de permissão confirmado", report)
        self.assertNotIn("Rascunho para equipe de rede", report)

    async def test_web_input_validation_and_bounded_search(self):
        with self.assertRaises(ValueError):
            await investigate_web_reputation(Fake(), Fake(), "bad.example' OR 1=1", T, "10.0.0.5", -3)
        with self.assertRaises(ValueError):
            await investigate_web_reputation(Fake(), Fake(), "bad.example", "2026-09-25T14:32:24", "10.0.0.5", -3)
        aql = _aql("bad.example", datetime.fromisoformat(T.replace("Z", "+00:00")), 5, -3)
        self.assertIn("UTF8(payload)", aql)
        self.assertIn("11:27:24", aql)

    async def test_web_finds_ip_on_exact_event_without_analyst_ip(self):
        guid = "11111111-2222-3333-4444-555555555555"
        uid = "01234567-89ab-cdef-0123-456789abcdef"
        hit = {"uuid": uid, "endpointGUID": guid, "endpointHostName": "DEMO-PC",
               "endpointIp": ["10.0.0.5"], "request": "https://bad.example/path", "eventTime": T}
        q, v = Fake(), Fake(detections=[hit])
        report = await investigate_web_reputation(q, v, "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC", endpoint_guid=guid, event_id=uid)
        self.assertIn("IP informado pelo registro Trend com UUID", report)
        self.assertIn("IP 10.0.0.5", report)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in q.calls))
        self.assertFalse(any(name == "endpoint_security_endpoints_list" for name, _ in v.calls))

    async def test_web_host_activity_ip_is_clearly_candidate(self):
        guid = "11111111-2222-3333-4444-555555555555"
        host_activity = {"endpointGUID": guid, "endpointHostName": "DEMO-PC",
                         "endpointIp": ["10.0.0.5", "169.254.10.4"], "eventTime": T}
        q, v = Fake(), Fake(activity=[host_activity])
        report = await investigate_web_reputation(q, v, "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC", endpoint_guid=guid,
                                                  event_id="01234567-89ab-cdef-0123-456789abcdef")
        self.assertIn("IP 10.0.0.5", report)
        self.assertIn("candidato; vínculo com evento não verificado", report)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in q.calls))

    async def test_web_ambiguous_host_ips_only_show_current_inventory_as_hint(self):
        guid = "11111111-2222-3333-4444-555555555555"
        rows = [{"endpointGUID": guid, "endpointHostName": "DEMO-PC", "endpointIp": [ip],
                 "eventTime": T} for ip in ("10.0.0.5", "192.168.56.1")]
        inv = [{"agentGuid": guid, "endpointName": "DEMO-PC", "ipAddresses": ["10.0.0.5"]}]
        q, v = Fake(), Fake(activity=rows, inventory=inv)
        report = await investigate_web_reputation(q, v, "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC", endpoint_guid=guid,
                                                  event_id="01234567-89ab-cdef-0123-456789abcdef")
        self.assertIn("IPs privados candidatos no host/GUID: 2", report)
        self.assertIn("Estes IPs são atuais; não provam", report)
        self.assertIn("Correlação QRadar por IP do endpoint não executada", report)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in q.calls))

    async def test_web_inventory_alone_never_establishes_historical_ip(self):
        guid = "11111111-2222-3333-4444-555555555555"
        inv = [{"agentGuid": guid, "endpointName": "DEMO-PC", "ipAddresses": ["10.0.0.5"]}]
        q = Fake()
        report = await investigate_web_reputation(q, Fake(inventory=inv), "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC", endpoint_guid=guid,
                                                  event_id="01234567-89ab-cdef-0123-456789abcdef")
        self.assertIn("Inventário atual: 1 registro(s)", report)
        self.assertIn("Correlação QRadar por IP do endpoint não executada", report)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in q.calls))

    async def test_web_capped_host_page_uses_complete_focused_window(self):
        guid = "11111111-2222-3333-4444-555555555555"
        uid = "01234567-89ab-cdef-0123-456789abcdef"
        class BusyVision(Fake):
            async def call(self, name, args):
                if name == "search_endpoint_activities_list" and "endpointGuid:" in args["query"]:
                    self.calls.append((name, args))
                    item = {"endpointGUID": guid, "endpointHostName": "DEMO-PC",
                            "endpointIp": ["10.0.0.5"], "eventTime": T}
                    return {"items": [item] * (50 if args["top"] == "50" else 2)}
                return await super().call(name, args)

        q, v = Fake(), BusyVision()
        report = await investigate_web_reputation(q, v, "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC", endpoint_guid=guid, event_id=uid)
        self.assertIn("atividade no host/GUID: 50/50", report)
        self.assertIn("atividade focada ±60s: 2/100", report)
        self.assertIn("IP privado único em atividade Trend do mesmo host/GUID e janela focada", report)
        self.assertTrue(any(name == "create_ariel_search" for name, _ in q.calls))

    async def test_web_domain_lead_without_endpoint_ip_is_not_attributed(self):
        q = Fake(rows=[{"log_source": "FortiGate", "starttime": MS,
                        "raw_payload": "type=utm subtype=webfilter action=passthrough "
                                       "srcip=10.0.0.8 hostname=bad.example"}])
        report = await investigate_web_reputation(q, Fake(), "bad.example", T, "", -3,
                                                  endpoint_host="DEMO-PC",
                                                  event_id="01234567-89ab-cdef-0123-456789abcdef")
        self.assertIn("QRadar/FortiGate por domínio: 1 logs", report)
        self.assertIn("srcip=10.0.0.8", report)
        self.assertIn("não atribui estes logs ao endpoint", report)
        self.assertIn("Correlação QRadar por IP do endpoint não executada", report)


if __name__ == "__main__":
    unittest.main()
