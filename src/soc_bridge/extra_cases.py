"""Bounded EPM UAC and web-reputation investigations over read-only MCP tools."""

from __future__ import annotations

import json
import ipaddress
import re
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from .ariel import SEARCH_ID
from .core import address, instant, iso, records
from .vision_activity import HOST, PRIVATE_RANGES


EVENT_ID = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
AGENT_GUID = re.compile(r"^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$")
TEMP_MARKER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{7,99}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
FORTI_FIELD = re.compile(r'(?:^|\s)(action|hostname|url|srcip|dstip|policyid|type|subtype|trandisp)=(?:"((?:[^"\\]|\\.)*)"|(\S+))', re.I)
EVENT_UUID = re.compile(r"^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$")


def _time(value: str):
    when = instant(value)
    if not when or (isinstance(value, str) and not re.search(r"(?:Z|[+-]\d\d:\d\d)$", value)):
        raise ValueError("Use an ISO-8601 timestamp with explicit UTC offset (for example ...Z)")
    return when


def _aql(term: str, when: Any, minutes: int, offset: int) -> str:
    if not -12 <= offset <= 14 or not 1 <= minutes <= 30:
        raise ValueError("Invalid QRadar offset or search window")
    local = when + timedelta(hours=offset)
    start, end = local - timedelta(minutes=minutes), local + timedelta(minutes=minutes)
    # TEXT SEARCH cannot be combined with an AND predicate in QRadar AQL.
    return ("SELECT starttime, sourceip, destinationip, LOGSOURCENAME(logsourceid) AS log_source, "
            "UTF8(payload) AS raw_payload FROM events WHERE TEXT SEARCH '" + term + "' "
            f"LIMIT 100 START '{start:%Y-%m-%d %H:%M:%S}' STOP '{end:%Y-%m-%d %H:%M:%S}'")


async def _qr_search(qradar: Any, query: str) -> tuple[list[dict[str, Any]], list[str]]:
    valid = await qradar.call("validate_aql", {"query_expression": query})
    if not isinstance(valid, dict) or valid.get("valid") is not True:
        raise ValueError("QRadar did not validate AQL")
    created = await qradar.call("create_ariel_search", {"query_expression": query})
    sid = created.get("search_id") if isinstance(created, dict) else None
    if not isinstance(sid, str) or not SEARCH_ID.fullmatch(sid):
        raise ValueError("QRadar returned an invalid Ariel search ID")
    for _ in range(4):
        status = await qradar.call("get_ariel_search_status", {"search_id": sid, "wait_seconds": 3})
        state = str(status.get("status", "unknown")).upper()
        if state in {"ERROR", "CANCELED"}:
            raise RuntimeError(f"QRadar Ariel search ended with {state}")
        if state == "COMPLETED":
            response = await qradar.call("get_ariel_search_results", {"search_id": sid, "start": 0, "limit": 100})
            events = response.get("events") if isinstance(response, dict) else None
            if not isinstance(events, list):
                raise ValueError("QRadar returned malformed Ariel rows")
            warning = ["100-row cap reached; results may be incomplete"] if len(events) >= 100 or (isinstance(status.get("record_count"), int) and status["record_count"] >= 100) else []
            return [row for row in events[:100] if isinstance(row, dict)], warning
    raise TimeoutError("Ariel query still running after bounded polling; no complete result")


def _epm_payload(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str) or len(value) > 131072:
        return None
    index = value.find("{")
    if index < 0:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(value[index:])
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


def _text(value: Any, limit: int = 220) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")[:limit]


async def _epm_host_by_agent(qradar: Any, agent: str, when: Any, offset: int) -> tuple[str, str, list[str]]:
    """Use other EPM_API records with the *same last-event* agent ID as host candidates."""
    if not AGENT_GUID.fullmatch(agent):
        return "", "Agent GUID ausente ou inválido; busca adicional não executada.", []
    try:
        rows, warnings = await _qr_search(qradar, _aql(agent, when, 30, offset))
    except Exception as exc:
        return "", f"Busca de host pelo agente indisponível ({type(exc).__name__}); cobertura parcial.", []
    candidates = set()
    supporting = 0
    for row in rows:
        if str(row.get("log_source", "")).casefold() != "epm_api":
            continue
        obj = _epm_payload(row.get("raw_payload"))
        if not obj or str(obj.get("lastEventAgentId", "")).casefold() != agent.casefold():
            continue
        timestamp = instant(obj.get("lastEventDate"))
        host = str(obj.get("lastEventComputerName") or "")
        if timestamp and abs((timestamp - when).total_seconds()) <= 1800 and HOST.fullmatch(host):
            candidates.add(host.casefold())
            supporting += 1
    label = f"Busca suplementar EPM_API pelo lastEventAgentId: {len(rows)} linhas na primeira página, {supporting} registros com hostname e mesmo agente; {len(candidates)} host(s) distinto(s)."
    if warnings:
        return "", label + " Página limitada; host não atribuído automaticamente.", warnings
    if len(candidates) == 1:
        return next(iter(candidates)), label + " Vínculo de agente é candidato, não prova de que o UAC tenha esse arquivo/host.", warnings
    return "", label + " Nenhum host único atribuído.", warnings


async def _epm_path_candidates(vision: Any, event: dict[str, Any], when: Any) -> tuple[list[str], list[str]]:
    """Find exact EPM file-path candidates without inventing a host from a generic name."""
    location = str(event.get("fileLocation") or "").replace("/", "\\").rstrip("\\")
    name = str(event.get("lastEventFileName") or "")
    if ("\\appdata\\local\\temp\\" not in location.casefold() or
        not re.fullmatch(r"[A-Za-z0-9._-]{3,120}", name) or not location):
        return ["Busca por caminho não executada: o EPM não informou uma pasta temporária específica e um nome de arquivo seguro."], []
    marker = location.split("\\")[-1]
    if not TEMP_MARKER.fullmatch(marker):
        return ["Busca por caminho não executada: pasta terminal pouco específica ou inválida."], []
    target = f"{location}\\{name}".casefold()
    anchors = [when]
    first = instant(event.get("firstEventDate"))
    if first and abs((first - when).total_seconds()) > 1200:
        anchors.append(first)
    pivots = (("search_detections_list", "filePathName", ("filePathName", "fullPath", "filePath", "objectFilePath")),
              ("search_detections_list", "objectFilePath", ("filePathName", "fullPath", "filePath", "objectFilePath")),
              ("search_endpoint_activities_list", "objectFilePath", ("objectFilePath",)),
              ("search_endpoint_activities_list", "processFilePath", ("processFilePath",)))
    lines = []
    warnings = []
    candidates = {}
    completed = 0
    attempted = 0
    returned_total = 0
    exact_path_total = 0
    exact_path_outside_time = 0
    path_fragment_only = 0
    no_reported_path = 0
    per_query = []
    for anchor in anchors:
        for tool, field, result_fields in pivots:
            attempted += 1
            try:
                response = await vision.call(tool, {
                    "query": f'{field}:"{marker}"',
                    "startDateTime": iso(anchor - timedelta(minutes=10)),
                    "endDateTime": iso(anchor + timedelta(minutes=10)), "top": "50"})
                rows = records(response)
                completed += 1
                returned_total += len(rows)
                query_exact = 0
                query_outside = 0
                if len(rows) >= 50 or (isinstance(response, dict) and (response.get("nextLink") or response.get("next"))):
                    warnings.append(f"Trend {tool}/{field} at {iso(anchor)} reached first-page cap or has more pages")
                for row in rows[:50]:
                    stamp = instant(row.get("eventTime") or row.get("eventTimeDT"))
                    paths = {key: row[key].replace("/", "\\").casefold()
                             for key in result_fields if isinstance(row.get(key), str) and row[key]}
                    matches = [key for key, path in paths.items() if path == target]
                    if not matches:
                        if not paths:
                            no_reported_path += 1
                        elif any(marker.casefold() in path for path in paths.values()):
                            path_fragment_only += 1
                        continue
                    exact_path_total += 1
                    if not stamp or abs((stamp - anchor).total_seconds()) > 600:
                        exact_path_outside_time += 1
                        query_outside += 1
                        continue
                    query_exact += 1
                    unique = str(row.get("uuid") or "") or f"{tool}:{iso(stamp)}:{row.get('endpointHostName')}:{matches[0]}"
                    candidates[unique] = {
                        "time": iso(stamp), "source": tool, "field": matches[0],
                        "host": _text(row.get("endpointHostName"), 100),
                        "hash": _text(row.get("fileHash") or row.get("objectFileHashSha1") or row.get("processFileHashSha1"), 100),
                        "uuid": _text(row.get("uuid"), 100)}
                per_query.append(f"- {iso(anchor)} | {tool}/{field} | primeira página: {len(rows)}/50 | caminho exato e tempo: {query_exact} | caminho exato fora da janela/sem horário: {query_outside}.")
            except Exception as exc:
                warnings.append(f"Trend {tool}/{field} at {iso(anchor)} unavailable ({type(exc).__name__}); coverage partial")
                per_query.append(f"- {iso(anchor)} | {tool}/{field} | indisponível ({type(exc).__name__}).")
    lines.append(f"Busca Trend pelo segmento específico `{marker}`: {completed}/{attempted} consultas concluídas; {len(candidates)} eventos com caminho **completo e exato** + horário conferidos.")
    lines.append("Janelas ±10 min: " + ", ".join(iso(t) for t in anchors) + ". Detecção de arquivo e atividade de processo são fontes distintas.")
    lines.append(f"Linhas nas páginas inspecionadas (soma das consultas, com possíveis duplicatas): {returned_total}; caminho completo exato: {exact_path_total}; caminho exato sem horário válido/fora da janela: {exact_path_outside_time}; somente segmento de pasta com caminho diferente: {path_fragment_only}; sem campo de caminho esperado: {no_reported_path}.")
    lines.extend(per_query)
    for row in list(candidates.values())[:8]:
        lines.append(f"- Candidato {row['time']} ({row['source']}, {row['field']}): host={row['host'] or 'ausente'}; hash={row['hash'] or 'ausente'}; uuid={row['uuid'] or 'ausente'}.")
    lines.append("Mesmo caminho e tempo são uma pista; sem hash EPM ou ID comum não há vínculo comprovado entre as plataformas, execução elevada ou veredito.")
    return lines, warnings


async def investigate_epm_uac(qradar: Any, vision: Any, event_id: str,
                              occurred_at: str, offset: int, endpoint_host: str = "") -> str:
    if not EVENT_ID.fullmatch(event_id):
        raise ValueError("Supply exact CyberArk lastEventId (8–100 letters/digits/_/-)")
    when = _time(occurred_at)
    if endpoint_host and not HOST.fullmatch(endpoint_host):
        raise ValueError("Invalid hostname")
    rows, warnings = await _qr_search(qradar, _aql(event_id, when, 5, offset))
    epm = []
    for row in rows:
        if str(row.get("log_source", "")).casefold() != "epm_api":
            continue
        obj = _epm_payload(row.get("raw_payload"))
        if obj and obj.get("eventType") == "UacAudit" and obj.get("lastEventId") == event_id:
            epm.append(obj)
    lines = [f"# EPM UAC {event_id}", "", f"Busca QRadar: ±5 min de {iso(when)} UTC; offset local {offset:+d}h (confirmar); primeira página {len(rows)}/100.", ""]
    if not epm:
        lines += ["Nenhum evento UacAudit com lastEventId exato e origem EPM_API foi confirmado na amostra.",
                  "Confirme horário de ingestão no QRadar, permissões da origem e cobertura da primeira página."]
        return "\n".join(lines + [f"Aviso: {w}" for w in warnings])
    event = epm[0]
    explicit_host = str(event.get("lastEventComputerName") or "")
    discovered = ""
    agent_note = ""
    if not explicit_host:
        discovered, agent_note, agent_warnings = await _epm_host_by_agent(
            qradar, str(event.get("lastEventAgentId") or ""), when, offset)
        warnings.extend(agent_warnings)
    host = explicit_host or discovered or endpoint_host
    host_origin = ("EPM, neste evento" if explicit_host else
                   "outro registro EPM_API, mesmo lastEventAgentId (candidato)" if discovered else
                   "analista (não verificado pela ferramenta)")
    if (explicit_host or discovered) and endpoint_host and host.casefold() != endpoint_host.casefold():
        host = ""
        warnings.append("Host fornecido diverge do host EPM candidato; busca Trend não executada")
    name = str(event.get("lastEventFileName") or "")
    location = str(event.get("fileLocation") or "")
    lines += ["## Evidência EPM", "",
              f"- Arquivo: {_text(name)}; local: {_text(location)}; host: {_text(host) or 'não informado'} ({host_origin if host else 'indisponível'}).",
              f"- Horário do último evento: {_text(event.get('lastEventDate'))}; primeiro evento agregado: {_text(event.get('firstEventDate'))}; chegada à EPM: {_text(event.get('arrivalTime'))}.",
              f"- Política: {_text(event.get('policyName'))}; ação: {_text(event.get('policyAction'))}; hash SHA1: {_text(event.get('hash')) or 'ausente'}; assinante: {_text(event.get('publisher')) or 'ausente'}.",
              f"- Skipped: {event.get('skipped')}; skippedCount: {event.get('skippedCount')}; totalEvents: {event.get('totalEvents')}. Campos de agregação não demonstram quantas elevações foram concedidas.", ""]
    if agent_note:
        lines += ["## Busca de host pelo agente EPM", "", agent_note, ""]
    if not host:
        path_lines, path_warnings = await _epm_path_candidates(vision, event, when)
        warnings.extend(path_warnings)
        lines += ["## Trend Vision One: caminho temporário", "", *path_lines, ""]
    if not host or not HOST.fullmatch(host) or not name or not re.fullmatch(r"[A-Za-z0-9._-]{3,120}", name):
        lines += ["## Trend Vision One: busca por hostname", "", "Busca por hostname não executada: falta host exato ou nome de arquivo seguro. `updater.exe` isolado não identifica um binário."]
    else:
        t = instant(event.get("lastEventDate")) or when
        query = f'endpointHostName:"{host}" and fileName:"{name}"'
        try:
            response = await vision.call("search_detections_list", {"query": query,
                "startDateTime": iso(t - timedelta(minutes=10)), "endDateTime": iso(t + timedelta(minutes=10)), "top": "50"})
            hits = records(response)
            matches = []
            for hit in hits[:50]:
                ht = instant(hit.get("eventTime") or hit.get("eventTimeDT"))
                if (str(hit.get("endpointHostName", "")).casefold() == host.casefold() and
                    str(hit.get("fileName") or hit.get("lastEventFileName") or hit.get("fullPath", "")).replace("/", "\\").split("\\")[-1].casefold() == name.casefold() and
                    ht and abs((ht - t).total_seconds()) <= 600):
                    matches.append(hit)
            lines += ["## Trend Vision One", "", f"Detecções candidatas no host + nome + ±10 min: {len(matches)} (primeira página: {len(hits)}/50)."]
            for hit in matches[:5]:
                lines.append(f"- {_text(hit.get('eventTime') or hit.get('eventTimeDT'))}: {_text(hit.get('fullPath') or hit.get('filePath'))}; hash {_text(hit.get('fileHash')) or 'ausente'}; evento {_text(hit.get('uuid'))}.")
            if len(hits) >= 50:
                warnings.append("Trend reached first-page 50-row cap")
            lines.append("Coincidência de nome/host/tempo ainda não prova que seja o mesmo arquivo. Comparar hash, caminho completo e GUID do agente antes de atribuir.")
        except Exception as exc:
            warnings.append(f"Vision One Search indisponível ({type(exc).__name__}); cobertura parcial")
    lines += ["", "## Próximo passo", "", "Obter no EPM o hostname, SHA1 e contexto da elevação (ação efetiva, assinante e processo pai); comparar com a telemetria exata da Trend. Não concluir execução elevada apenas de 'Collect UAC actions'."]
    return "\n".join(lines + [f"Aviso: {w}" for w in warnings])


def _domain(value: str) -> str:
    raw = value.strip().lower()
    host = urlsplit(raw if "://" in raw else "https://" + raw).hostname
    if not host or not DOMAIN.fullmatch(host) or raw.count("@") or len(raw) > 2048:
        raise ValueError("Supply an exact domain or URL from one specific Trend event")
    return host


def _forti(raw: Any) -> dict[str, str]:
    if not isinstance(raw, str):
        return {}
    return {m.group(1).lower(): (m.group(2) if m.group(2) is not None else m.group(3)).replace('\\"', '"')[:512]
            for m in FORTI_FIELD.finditer(raw[:8192])}


def _host_from_url(value: str) -> str:
    try:
        return (urlsplit(value if "://" in value else "https://" + value).hostname or "").lower()
    except ValueError:
        return ""


def _row_ips(row: dict[str, Any]) -> set[str]:
    value = row.get("endpointIp")
    values = value if isinstance(value, list) else [value]
    return {ip for item in values if (ip := address(item))}


async def _web_inventory_hint(vision: Any, host: str, guid: str) -> str:
    """Current inventory is context, never a historical IP attribution."""
    if not guid:
        return "Inventário atual não consultado: GUID ausente."
    try:
        response = await vision.call("endpoint_security_endpoints_list", {
            "filter": f"agentGuid eq '{guid}'"})
        rows = records(response)
        matching = [row for row in rows if
            str(row.get("agentGuid") or "").casefold() == guid.casefold() and
            str(row.get("endpointName") or "").casefold() == host.casefold()]
        if len(rows) >= 50 or (isinstance(response, dict) and
            (response.get("nextLink") or response.get("next") or response.get("skipToken"))):
            return "Inventário atual: página incompleta; nenhum IP histórico atribuído."
        ips = set()
        for row in matching:
            values = row.get("ipAddresses")
            if isinstance(values, list):
                for item in values:
                    candidate = item.get("ipAddress") if isinstance(item, dict) else item
                    if ip := address(candidate):
                        ips.add(ip)
        return (f"Inventário atual: {len(matching)} registro(s) com GUID e host exatos; "
                f"IPs: {', '.join(sorted(ips)) or 'não informados'}. "
                "Estes IPs são atuais; não provam qual interface estava ativa no horário do evento.")
    except Exception as exc:
        return f"Inventário de endpoints indisponível ({type(exc).__name__}); IP histórico não atribuído."


async def _discover_web_endpoint_ip(vision: Any, domain: str, when: Any,
                                    event_id: str, host: str, guid: str) -> tuple[str, str, list[str]]:
    """Prefer the exact event; use host activity only as a clearly labelled lead."""
    warnings: list[str] = []
    exact_ips: set[str] = set()
    activity_ips: set[str] = set()
    activities_complete = True
    broad_capped = False
    focused_complete = False
    focused_ips: set[str] = set()
    details = []
    start, end = iso(when - timedelta(minutes=5)), iso(when + timedelta(minutes=5))
    for tool in ("search_detections_list", "search_endpoint_activities_list"):
        try:
            response = await vision.call(tool, {"query": f'request:"{domain}"',
                "startDateTime": start, "endDateTime": end, "top": "50"})
            rows = records(response)
            capped = len(rows) >= 50 or (isinstance(response, dict) and
                (response.get("nextLink") or response.get("next")))
            details.append(f"{tool}: {len(rows)}/50 linhas inspecionadas")
            if capped:
                warnings.append(f"Trend {tool}: primeira página limitada; IP não atribuído por esta busca")
            if capped:
                continue
            for row in rows[:50]:
                stamp = instant(row.get("eventTime") or row.get("eventTimeDT"))
                if not stamp or abs((stamp - when).total_seconds()) > 300:
                    continue
                if _host_from_url(str(row.get("request") or "")) != domain:
                    continue
                if str(row.get("uuid") or "").casefold() != event_id.casefold():
                    continue
                if str(row.get("endpointHostName") or "").casefold() != host.casefold():
                    continue
                if guid and str(row.get("endpointGUID") or row.get("endpointGuid") or "").casefold() != guid.casefold():
                    continue
                exact_ips.update(_row_ips(row))
        except Exception as exc:
            warnings.append(f"Trend {tool} indisponível ({type(exc).__name__}); cobertura parcial")
    if len(exact_ips) == 1:
        return next(iter(exact_ips)), "IP informado pelo registro Trend com UUID, host, GUID, domínio e horário exatos", details + warnings
    if len(exact_ips) > 1:
        details.append(await _web_inventory_hint(vision, host, guid))
        return "", "Evento exato retornou múltiplos IPs; nenhuma interface atribuída automaticamente", details + warnings

    # Endpoint activity is a separate telemetry source. A unique private IP
    # near the event is useful for a QRadar lead, but does not prove that the
    # Web Reputation event or a particular process used that interface.
    query = f'endpointGuid:"{guid}"' if guid else f'endpointHostName:"{host}"'
    try:
        response = await vision.call("search_endpoint_activities_list", {
            "query": query, "startDateTime": start, "endDateTime": end, "top": "50"})
        rows = records(response)
        details.append(f"atividade no host/GUID: {len(rows)}/50 linhas inspecionadas")
        broad_capped = len(rows) >= 50 or (isinstance(response, dict) and
            (response.get("nextLink") or response.get("next")))
        if broad_capped:
            activities_complete = False
            warnings.append("Atividade do host/GUID limitada à primeira página na janela ±5 min")
        for row in rows[:50]:
            stamp = instant(row.get("eventTime") or row.get("eventTimeDT"))
            if not stamp or abs((stamp - when).total_seconds()) > 300:
                continue
            if str(row.get("endpointHostName") or "").casefold() != host.casefold():
                continue
            if guid and str(row.get("endpointGUID") or row.get("endpointGuid") or "").casefold() != guid.casefold():
                continue
            activity_ips.update(ip for ip in _row_ips(row) if
                any(ipaddress.ip_address(ip) in network for network in PRIVATE_RANGES))
    except Exception as exc:
        activities_complete = False
        warnings.append(f"Atividade Trend por host/GUID indisponível ({type(exc).__name__})")
    if broad_capped:
        # A smaller server-side time range prevents an arbitrary first page of
        # busy host activity from deciding the endpoint's historical address.
        for seconds, top in ((60, 100), (10, 500)):
            try:
                response = await vision.call("search_endpoint_activities_list", {
                    "query": query,
                    "startDateTime": iso(when - timedelta(seconds=seconds)),
                    "endDateTime": iso(when + timedelta(seconds=seconds)),
                    "top": str(top)})
                rows = records(response)
                capped = len(rows) >= top or (isinstance(response, dict) and
                    (response.get("nextLink") or response.get("next")))
                details.append(f"atividade focada ±{seconds}s: {len(rows)}/{top} linhas; " +
                               ("página limitada" if capped else "página não limitada"))
                for row in rows[:top]:
                    stamp = instant(row.get("eventTime") or row.get("eventTimeDT"))
                    if not stamp or abs((stamp - when).total_seconds()) > seconds:
                        continue
                    if str(row.get("endpointHostName") or "").casefold() != host.casefold():
                        continue
                    if guid and str(row.get("endpointGUID") or row.get("endpointGuid") or "").casefold() != guid.casefold():
                        continue
                    found = {ip for ip in _row_ips(row) if
                             any(ipaddress.ip_address(ip) in network for network in PRIVATE_RANGES)}
                    focused_ips.update(found)
                    activity_ips.update(found)
                if not capped:
                    focused_complete = True
                    break
            except Exception as exc:
                warnings.append(f"Atividade focada ±{seconds}s indisponível ({type(exc).__name__}); cobertura parcial")
        activities_complete = focused_complete and bool(focused_ips)
    if activities_complete and len(activity_ips) == 1:
        label = ("IP privado único em atividade Trend do mesmo host/GUID e janela focada "
                 "(candidato; vínculo com evento não verificado)" if broad_capped else
                 "IP privado único em atividade Trend do mesmo host/GUID e horário "
                 "(candidato; vínculo com evento não verificado)")
        return next(iter(activity_ips)), label, details + warnings
    details.append(f"IPs privados candidatos no host/GUID: {len(activity_ips)}; nenhum IP atribuído")
    details.append(await _web_inventory_hint(vision, host, guid))
    return "", "Não foi possível obter IP único para o evento ou host na janela consultada", details + warnings


async def _web_domain_only_qradar(qradar: Any, domain: str, when: Any, offset: int) -> list[str]:
    """Look for domain-level FortiGate leads without claiming endpoint attribution."""
    try:
        rows, warnings = await _qr_search(qradar, _aql(domain, when, 5, offset))
    except Exception as exc:
        return [f"Busca QRadar por domínio indisponível ({type(exc).__name__}); nenhuma conclusão sobre tráfego."]
    matches = []
    for row in rows:
        source = str(row.get("log_source") or "").casefold()
        if "fortigate" not in source and not re.search(r"(?:^|\W)fgt(?:\W|$)", source):
            continue
        fields = _forti(row.get("raw_payload"))
        stamp = instant(row.get("starttime"))
        if (_host_from_url(fields.get("hostname") or fields.get("url", "")) == domain and
            stamp and abs((stamp - when).total_seconds()) <= 300):
            matches.append((iso(stamp), fields.get("srcip") or "ausente",
                            fields.get("action") or "ausente", fields.get("subtype") or "ausente"))
    lines = [f"QRadar/FortiGate por domínio: {len(matches)} logs com domínio e horário exatos "
             f"na primeira página ({len(rows)}/100); offset local {offset:+d}h a confirmar."]
    for stamp, ip, action, subtype in matches[:8]:
        lines.append(f"- {stamp}: srcip={ip}; action={action}; subtype={subtype}.")
    lines.append("Busca por domínio não atribui estes logs ao endpoint nem confirma acesso à URL específica; "
                 "um traffic accept não comprova liberação pelo webfilter.")
    lines.extend(f"Aviso: {warning}" for warning in warnings)
    return lines


async def investigate_web_reputation(qradar: Any, vision: Any, url_or_domain: str,
                                     event_time: str, endpoint_ip: str, offset: int,
                                     endpoint_host: str = "", endpoint_guid: str = "",
                                     event_id: str = "") -> str:
    domain, when = _domain(url_or_domain), _time(event_time)
    if endpoint_ip and not address(endpoint_ip):
        raise ValueError("Supply a valid endpoint IP")
    if endpoint_host and not HOST.fullmatch(endpoint_host):
        raise ValueError("Supply a valid endpoint hostname")
    if endpoint_guid and not EVENT_UUID.fullmatch(endpoint_guid):
        raise ValueError("Supply a valid endpoint GUID")
    if event_id and not EVENT_UUID.fullmatch(event_id):
        raise ValueError("Supply a valid Trend event UUID")
    if not endpoint_ip and (not event_id or not endpoint_host):
        raise ValueError("Supply endpoint IP, or exact Trend event UUID and hostname for automatic discovery")
    warnings: list[str] = []
    ip = address(endpoint_ip)
    attribution = "IP fornecido pelo analista (não verificado pela ferramenta)"
    discovery: list[str] = []
    if not ip:
        ip, attribution, discovery = await _discover_web_endpoint_ip(
            vision, domain, when, event_id, endpoint_host, endpoint_guid)
        if not ip:
            domain_leads = await _web_domain_only_qradar(qradar, domain, when, offset)
            return "\n".join([f"# Trend Web Reputation × QRadar FortiGate: {domain}", "",
                f"Referência informada pelo analista: evento {event_id}; host {endpoint_host}; "
                f"GUID {endpoint_guid or 'ausente'}; horário {iso(when)} UTC. "
                "A identificação do evento e um IP único não foram confirmados juntos nesta execução.",
                attribution, *discovery, "", *domain_leads,
                "Correlação QRadar por IP do endpoint não executada: IP histórico não atribuído com segurança. "
                "Um log de domínio, caso exista, é uma pista independente, não prova de tráfego deste host."])
    # Both searches are bounded. Domain TEXT SEARCH cannot be combined with source IP in AQL.
    rows, qr_warn = await _qr_search(qradar, _aql(domain, when, 5, offset))
    warnings += qr_warn
    confirmed = []
    for row in rows:
        logsource = str(row.get("log_source") or "").casefold()
        if "fortigate" not in logsource and not re.search(r"(?:^|\W)fgt(?:\W|$)", logsource):
            continue
        fields = _forti(row.get("raw_payload"))
        if (fields.get("srcip") != ip or
            _host_from_url(fields.get("hostname") or fields.get("url", "")) != domain or
            not (instant(row.get("starttime")) and abs((instant(row["starttime"]) - when).total_seconds()) <= 300)):
            continue
        confirmed.append({"time": iso(instant(row["starttime"])), "action": fields.get("action", ""),
                          "subtype": fields.get("subtype", ""), "destination": fields.get("dstip", ""),
                          "policy": fields.get("policyid", ""), "log_source": _text(row.get("log_source"), 80)})
    trend = []
    seen = set()
    for tool in ("search_detections_list", "search_endpoint_activities_list"):
        try:
            response = await vision.call(tool, {"query": f'request:"{domain}"',
                "startDateTime": iso(when - timedelta(minutes=5)), "endDateTime": iso(when + timedelta(minutes=5)), "top": "50"})
            hits = records(response)
            for hit in hits[:50]:
                ht = instant(hit.get("eventTime") or hit.get("eventTimeDT"))
                event_ip = hit.get("endpointIp")
                ips = event_ip if isinstance(event_ip, list) else [event_ip]
                key = str(hit.get("uuid") or "") or f"{tool}:{ht}:{hit.get('request')}"
                if (key not in seen and ht and abs((ht - when).total_seconds()) <= 300 and
                    _host_from_url(str(hit.get("request") or "")) == domain and
                    ip in [address(v) for v in ips]):
                    seen.add(key)
                    trend.append({"time": iso(ht), "severity": _text(hit.get("filterRiskLevel")),
                                  "blocking": _text(hit.get("blocking")), "action": _text(hit.get("act")),
                                  "uuid": _text(hit.get("uuid")), "source": tool})
            if len(hits) >= 50:
                warnings.append(f"Trend {tool} first page reached 50 rows; coverage incomplete")
        except Exception as exc:
            warnings.append(f"Vision One {tool} unavailable ({type(exc).__name__}); corroboration incomplete")
    passthrough = [r for r in confirmed if r["subtype"].casefold() in {"webfilter", "web-filter"} and r["action"].casefold() in {"passthrough", "allow", "allowed"}]
    traffic_accept = [r for r in confirmed if r["action"].casefold() in {"accept", "accepted"}]
    blocked = [r for r in confirmed if r["action"].casefold() in {"blocked", "deny", "denied"}]
    lines = [f"# Trend Web Reputation × QRadar FortiGate: {domain}", "",
             f"Referência do analista: {iso(when)} UTC; IP {ip} ({attribution}). QRadar ±5 min, offset {offset:+d}h (confirmar).", "",
             *(discovery + [""] if discovery else []),
             f"Registros Trend com request, IP e horário coincidentes: {len(trend)} (detecção/atividade; buscas limitadas à primeira página).",
             f"Logs FortiGate com srcip + hostname/url + horário exatos: {len(confirmed)} "
             f"(de {len(rows)} resultados QRadar na primeira página; "
             f"{'teto atingido' if qr_warn else 'teto de 100 não atingido nesta consulta'}).", ""]
    for row in confirmed[:12]:
        lines.append(f"- {row['time']}: action={row['action'] or 'ausente'}; subtype={row['subtype'] or 'ausente'}; dstip={row['destination'] or 'ausente'}; policyid={row['policy'] or 'ausente'}; origem={row['log_source']}.")
    lines += ["", "## Leitura da evidência", ""]
    if passthrough:
        lines.append("Há log de webfilter do FortiGate com ação de permissão para este domínio e IP de origem. Confirmar identidade do endpoint/NAT e se a Trend bloqueou a requisição antes de afirmar acesso efetivo.")
    elif traffic_accept:
        lines.append("Há conexão de tráfego aceita, mas isso não comprova que a URL maliciosa foi acessada. Revisar webfilter, proxy, SNI, DNS e NAT.")
    elif blocked:
        lines.append("Logs correspondentes mostram bloqueio; verificar cobertura e se há também sessões permitidas no restante da janela.")
    else:
        lines.append("Nenhum log FortiGate com domínio, IP e tempo confirmados na amostra; isso não demonstra bloqueio nem ausência de conexão.")
    if trend:
        for item in trend[:5]:
            lines.append(f"- Trend {item['source']}, {item['time']}, ref={item['uuid'] or 'ausente'}, "
                         f"severidade={item['severity'] or 'ausente'}, blocking={item['blocking'] or 'ausente'}, "
                         f"act={item['action'] or 'ausente'}.")
    if passthrough:
        lines += ["", "## Rascunho para equipe de rede — revisão humana obrigatória", "",
                  f"Solicito validar a política de saída para o domínio {domain}. Origem candidata: {ip}; referência UTC: {iso(when)}.",
                  f"Evidência atual: {len(passthrough)} logs webfilter com permissão; {len(traffic_accept)} logs de conexão aceita; {len(blocked)} logs de bloqueio; {len(trend)} registros Trend coincidentes.",
                  "Confirmar domínio exato, endpoint/NAT, política e impacto antes de propor bloqueio; não bloquear um IP de infraestrutura de filtragem apenas por esta correlação."]
    else:
        lines += ["", "## Encaminhamento", "",
                  "Nenhum log webfilter de permissão confirmado nesta amostra; não gerar pedido de bloqueio. "
                  "Verificar identidade do host, cobertura dos logs e eventual tráfego permitido em outras fontes antes de escalar."]
    lines.append("Nenhuma mensagem foi enviada nem regra foi modificada.")
    return "\n".join(lines + [f"Aviso: {w}" for w in warnings])
