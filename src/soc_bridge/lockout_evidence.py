"""Account lockouts and authentication candidates, preserving account roles and provenance."""
from __future__ import annotations

import html
import json
import re
from collections import Counter
from typing import Any

from .core import instant
from .windows_events import extract, value_of

IDS = {4740, 4625, 4771, 4776}
KEYS = ('TargetUserName', 'TargetDomainName', 'CallerComputerName', 'IpAddress', 'WorkstationName',
        'Workstation', 'Status', 'SubStatus', 'FailureCode', 'LogonType', 'Computer')
# Underscores are allowed in AQL equality; payload ILIKE remains broad and must be checked after parsing.
SAFE_ACCOUNT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@$\-]{0,127}$')
XML_DATA = re.compile(r'<Data\s+Name=[\"\']([^\"\']+)[\"\']\s*>(.*?)</Data>', re.I | re.S)
KEY_VALUE = re.compile(r'\b(' + '|'.join(KEYS) + r')\s*[=:]\s*\"?([^\s\"<>;]+)', re.I)


def fields(payload: str) -> dict:
    candidates: dict[str, set[str]] = {}
    names = {k.lower(): k for k in KEYS}
    def put(key, val):
        if isinstance(val, (str, int)) and key.lower() in names and str(val).strip():
            candidates.setdefault(names[key.lower()], set()).add(html.unescape(str(val)).strip())
    if '<Data' in payload:
        for key, val in XML_DATA.findall(payload):
            put(key, val)
    elif payload.lstrip().startswith('{'):
        try:
            data = json.loads(payload)
        except ValueError:
            data = None
        def walk(item, depth=0):
            if depth > 5:
                return
            if isinstance(item, dict):
                if isinstance(item.get('Name'), str) and '#text' in item:
                    put(item['Name'], item['#text'])
                for key, val in item.items():
                    put(key, val)
                    if isinstance(val, (dict, list)):
                        walk(val, depth + 1)
            elif isinstance(item, list):
                for val in item[:200]:
                    walk(val, depth + 1)
        walk(data)
    else:
        for key, val in KEY_VALUE.findall(payload):
            put(key, val)
        # Repeated Account Name labels have distinct Windows roles. Read only the target section.
        target = re.search(r'(?:Account That Was Locked Out|Account For Which Logon Failed|Account Information):\s*(.*?)(?:Additional Information:|Failure Information:|Service Information:|\Z)', payload, re.I | re.S)
        if target:
            section = target[1]
            for label, key in (('Account Name', 'TargetUserName'), ('Account Domain', 'TargetDomainName')):
                match = re.search(r'\b' + label + r':\s*([^\s;]+)', section, re.I)
                if match:
                    put(key, match[1])
        for label, key in (('Caller Computer Name', 'CallerComputerName'), ('Source Network Address', 'IpAddress'),
                           ('Workstation Name', 'WorkstationName'), ('Failure Code', 'FailureCode'),
                           ('Logon Type', 'LogonType')):
            for match in re.finditer(r'\b' + label + r':\s*([^\s;]+)', payload, re.I):
                put(key, match[1])
    # Conflicting fields are withheld. A generic normalized username never supplies the target role.
    return {key: next(iter(vals)) for key, vals in candidates.items() if len(vals) == 1 and next(iter(vals)) != '-'}


def analyze(finding: dict | None, query: str) -> dict:
    finding = finding or {}
    records, counts = [], Counter()
    unparsed = 0
    for index, row in enumerate(finding.get('rows', [])):
        parsed = extract(row)
        eid = parsed['event_id']
        if eid not in IDS:
            if re.search(r'locked out|lockout', str(row.get('event_name', '')), re.I):
                unparsed += 1
            continue
        data = fields(str(row.get('raw_payload') or ''))
        record = dict(event_id=eid, target_user=data.get('TargetUserName'), target_domain=data.get('TargetDomainName'),
                      caller_computer=data.get('CallerComputerName'), source_ip=data.get('IpAddress'),
                      workstation=data.get('WorkstationName') or data.get('Workstation'),
                      status=data.get('Status') or data.get('FailureCode'), substatus=data.get('SubStatus'),
                      logon_type=data.get('LogonType'), recording_computer=value_of(parsed, 'Computer'),
                      provenance=dict(query=query, search_id=finding.get('search_id'), row_index=index,
                                      log_source=row.get('log_source'), starttime=row.get('starttime'),
                                      devicetime=row.get('devicetime')),
                      payload_cut=bool(str(index) in finding.get('truncated_rows', {})))
        code = record['status']
        record['authentication_outcome'] = ('failure' if eid in (4625, 4771) else
            ('success' if int(code, 16) == 0 else 'failure') if eid == 4776 and isinstance(code, str)
            and re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', code) else 'not_verified')
        records.append(record)
        counts[eid] += 1
    groups = Counter((r['target_user'], r['target_domain'], r['caller_computer'], r['provenance']['log_source'])
                     for r in records if r['event_id'] == 4740)
    return dict(detected=bool(counts.get(4740)), event_id_counts=dict(counts), records=records[:100],
                records_omitted=max(0, len(records) - 100), records_for_analysis=records,
                groups=[dict(target_user=user, target_domain=domain, caller_computer=caller, log_source=source, rows=n)
                        for (user, domain, caller, source), n in groups.most_common(100)],
                groups_omitted=max(0, len(groups) - 100), unparsed_lockout_named_rows=unparsed,
                result_set_complete=finding.get('result_set_complete', False),
                interpretation='4740 records a lockout, not successful user authentication. CallerComputerName is '
                               'a reported caller, distinct from the recording DC; not proof of the responsible process.')


def correlate(linked: dict, context: dict) -> list[dict]:
    candidates = []
    failures = [r for r in context.get('records_for_analysis', []) if r['authentication_outcome'] == 'failure' and not r['payload_cut']]
    for lock in [r for r in linked.get('records_for_analysis', []) if r['event_id'] == 4740][:100]:
        if lock['payload_cut']:
            continue
        user, domain = lock['target_user'], lock['target_domain']
        if not user:
            continue
        for failure in failures:
            if not failure['target_user'] or failure['target_user'].casefold() != user.casefold():
                continue
            fd = failure['target_domain']
            if domain and fd and domain.casefold() != fd.casefold():
                continue
            a = instant(lock['provenance']['starttime'])
            b = instant(failure['provenance']['starttime'])
            if a is None or b is None or abs((a - b).total_seconds()) > 900:
                continue
            candidates.append(dict(lockout=lock['provenance'], authentication=failure['provenance'],
                event_id=failure['event_id'], target_user=user, target_domain=domain,
                domain_match='equal' if domain and fd else 'not_verified', caller_computer=lock['caller_computer'],
                failure_source_ip=failure['source_ip'], failure_workstation=failure['workstation'],
                status=failure['status'], substatus=failure['substatus'], relation='candidate',
                seconds_before_lockout=round((a - b).total_seconds(), 3), clock='starttime (QRadar receipt)',
                criterion='Same reported target account and nearby receipt time; conflicting known domains excluded. '
                          'Caller-to-IP resolution, responsible process and causal link are not verified.'))
            if len(candidates) == 100:
                return candidates
    return candidates


def pivot(plan: Any, tail: str, start_ms: int, end_ms: int, linked: dict) -> dict | str:
    accounts = sorted({r['target_user'] for r in linked.get('records_for_analysis', [])
                       if r['event_id'] == 4740 and r['target_user'] and SAFE_ACCOUNT.fullmatch(r['target_user'])})
    if not accounts:
        return 'No safely parsed target account; do not use Subject or normalized username as a substitute'
    chosen = accounts[:3]
    account_filter = '(' + ' OR '.join(f"(username = '{u}' OR UTF8(payload) ILIKE '%{u}%')" for u in chosen) + ')'
    ids = '(' + ' OR '.join(f"UTF8(payload) ILIKE '%{eid}%'" for eid in sorted(IDS)) + ')'
    where = f'{account_filter} AND {ids} AND starttime >= {start_ms} AND starttime <= {end_ms}'
    query = f'{plan.select()} FROM events WHERE {where} ORDER BY starttime ASC LIMIT 1000 {tail}'
    fallback = f'{plan.select(False)} FROM events WHERE {where} ORDER BY starttime ASC LIMIT 1000 {tail}'
    return dict(query=query, fallback=fallback if plan.optional else None, database='events',
                scope='lockout_account_time_context', selected_accounts=chosen,
                accounts_omitted=max(0, len(accounts) - 3),
                criteria='Broad account/EventID payload retrieval; parse exact EventID and target role afterward. '
                         'Context is not INOFFENSE and does not prove causality or complete source logging.')
