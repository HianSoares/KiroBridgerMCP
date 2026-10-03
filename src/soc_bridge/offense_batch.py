"""Read-only offense discovery and bounded investigations; descriptions are not incident IDs."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .aql_errors import ResponseFormatError, classify_failure
from .ariel_collection import Budget, BudgetExhausted
from .offense_evidence import verify_offense

FIELDS = ('id,description,status,offense_source,start_time,last_updated_time,'
          'event_count,flow_count,magnitude,severity,rules')


def integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'{name} must be an integer between {low} and {high}')
    return value


def selection(description: str, status: str, match: str, start_time_from: int | None,
              start_time_to: int | None) -> tuple[str, dict]:
    if not isinstance(description, str) or not description.strip() or len(description) > 1000:
        raise ValueError('description must contain 1..1000 characters')
    if any(ord(c) < 32 for c in description):
        raise ValueError('description must not contain control characters')
    if status not in ('OPEN', 'CLOSED', 'HIDDEN', 'ALL') or match not in ('exact', 'contains'):
        raise ValueError('status must be OPEN/CLOSED/HIDDEN/ALL; match must be exact/contains')
    for name, bound in (('start_time_from', start_time_from), ('start_time_to', start_time_to)):
        if bound is not None:
            integer(bound, name, 0, 9999999999999)
    if start_time_from is not None and start_time_to is not None and start_time_from > start_time_to:
        raise ValueError('start_time_from must not exceed start_time_to')
    parts = []
    if status != 'ALL':
        parts.append(f'status = "{status}"')
    if start_time_from is not None:
        parts.append(f'start_time >= {start_time_from}')
    if start_time_to is not None:
        parts.append(f'start_time <= {start_time_to}')
    return ' and '.join(parts), dict(description=description, status=status, match=match,
                                    start_time_from=start_time_from, start_time_to=start_time_to)


async def find_offenses(qradar: Any, description: str, status: str = 'OPEN', match: str = 'exact',
                        offset: int = 0, limit: int = 50, start_time_from: int | None = None,
                        start_time_to: int | None = None, budget: Budget | None = None) -> dict:
    """Scan bounded REST pages and match description locally; description is not API-filterable."""
    integer(offset, 'offset', 0, 1000000)
    integer(limit, 'limit', 1, 100)
    expression, scope = selection(description, status, match, start_time_from, start_time_to)
    budget = budget or Budget(max_seconds=20)
    result = dict(scope=scope, offset=offset, limit=limit, offenses=[], outcome='unavailable',
                  page_complete=False, discovery_exhausted=False, total_count=None,
                  upstream_total_count=None, description_matching='local literal comparison',
                  offset_semantics='Cursor in the status/time-filtered upstream population, including nonmatches',
                  next_offset=offset, upstream_rows_scanned=0, upstream_pages_read=0,
                  mcp_tool_call_attempted=False, mcp_tool_calls_attempted=0,
                  decoded_response_returned=False, diagnostic_stage='before_tool_call',
                  continuation_plan=[], warnings=[], collected_at=datetime.now(timezone.utc).isoformat(),
                  consistency_note='Live +id pagination is not an immutable snapshot. Changed descriptions/status '
                                   'can move the selected population between calls; retain seen IDs.',
                  time_filter_note='Bounds select offense start_time in epoch milliseconds, not event time or interval overlap.')
    parameters = {**scope, 'offset': offset, 'limit': limit}
    cursor = offset
    previous_id = None
    try:
        while True:
            reason = budget.blocked('call') or budget.blocked('record')
            if reason:
                result['warnings'].append(reason + '; scan incomplete, not a negative finding')
                result['outcome'] = 'partial'
                break
            # Fetch raw pages independently of the requested number of matches.
            page_size = min(100, budget.max_records - budget.records_seen)
            async def request():
                budget.calls_made += 1
                result['mcp_tool_call_attempted'] = True
                result['mcp_tool_calls_attempted'] += 1
                result['diagnostic_stage'] = 'upstream_tool_call'
                return await qradar.call('list_offenses', dict(filter=expression, sort='+id',
                    fields=FIELDS, offset=cursor, limit=page_size, format_output=False))
            data = await budget.run(request, 'offense discovery')
            result['decoded_response_returned'] = True
            result['diagnostic_stage'] = 'response_validation'
            if not isinstance(data, dict) or not isinstance(data.get('offenses'), list):
                raise ResponseFormatError('Expected raw offense list JSON')
            rows = data['offenses']
            if len(rows) > page_size:
                raise ResponseFormatError('Offense page exceeds requested limit')
            ids = []
            for row in rows:
                if not isinstance(row, dict):
                    raise ResponseFormatError('Invalid offense entry')
                oid = row.get('id')
                if isinstance(oid, bool) or not isinstance(oid, int) or oid < 1 or oid in ids:
                    raise ResponseFormatError('Invalid or repeated offense ID')
                if not isinstance(row.get('description'), str):
                    raise ResponseFormatError('Offense description unavailable')
                if status != 'ALL' and row.get('status') != status:
                    raise ResponseFormatError('Upstream returned an offense outside status scope')
                moment = row.get('start_time')
                if ((start_time_from is not None or start_time_to is not None) and
                        (not isinstance(moment, int) or isinstance(moment, bool) or
                         (start_time_from is not None and moment < start_time_from) or
                         (start_time_to is not None and moment > start_time_to))):
                    raise ResponseFormatError('Offense outside start_time bounds')
                ids.append(oid)
            if ids != sorted(ids) or (ids and previous_id is not None and ids[0] <= previous_id):
                raise ResponseFormatError('Repeated/non-advancing offense ID order; live population may have changed')
            total = data.get('total_count')
            if total is not None and (isinstance(total, bool) or not isinstance(total, int) or total < 0):
                raise ResponseFormatError('Invalid upstream total_count')
            if rows and total is not None and total < cursor + len(rows):
                raise ResponseFormatError('Inconsistent upstream total_count')
            if not rows and total is not None and cursor < total:
                raise ResponseFormatError('Empty page before reported total_count')
            result['upstream_total_count'] = total
            result['upstream_pages_read'] += 1
            end_of_population = len(rows) < page_size if total is None else cursor + len(rows) >= total
            consumed = 0
            for row in rows:
                consumed += 1
                budget.records_seen += 1
                result['upstream_rows_scanned'] += 1
                previous_id = row['id']
                matches = row['description'] == description if match == 'exact' else description in row['description']
                if matches:
                    result['offenses'].append(row)
                if len(result['offenses']) >= limit:
                    break
            cursor += consumed
            result['next_offset'] = cursor
            if consumed == len(rows) and end_of_population:
                result.update(discovery_exhausted=True, page_complete=True,
                              outcome='page_collected' if result['offenses'] else 'empty')
                if offset == 0:
                    result['total_count'] = len(result['offenses'])
                break
            if len(result['offenses']) >= limit:
                result.update(page_complete=True, outcome='page_collected')
                break
    except Exception as exc:
        error = classify_failure(exc)
        if isinstance(exc, ValueError) and not isinstance(exc, ResponseFormatError):
            error = {'category': 'upstream_client', 'outcome': 'unavailable', 'retryable': False,
                     'message': 'ValueError inside the offense listing client',
                     'next_action': 'Inspect the upstream MCP response/logs; this does not establish a local argument rejection'}
        if isinstance(exc, ResponseFormatError) and result['diagnostic_stage'] == 'upstream_tool_call':
            result['diagnostic_stage'] = 'upstream_response_decoding'
        error.update(stage=result['diagnostic_stage'], mcp_tool_call_attempted=result['mcp_tool_call_attempted'])
        result['error'] = error
        result['outcome'] = 'partial' if result['offenses'] else 'unavailable'
    result['returned_count'] = len(result['offenses'])
    result['budget'] = budget.describe()
    if not result['discovery_exhausted']:
        plan = dict(tool='qradar_find_offenses', parameters={**parameters, 'offset': cursor},
                    cursor_semantics=result['offset_semantics'])
        if result.get('error'):
            plan['requires_resolution'] = not result['error']['retryable']
            plan['reason'] = result['error']['category']
        result['continuation_plan'] = [plan]
    if result['page_complete']:
        result['diagnostic_stage'] = 'page_collected'
    return result


def consolidate(reports: list[dict]) -> dict:
    groups: dict[tuple, dict] = {}
    decisions = []
    for report in reports:
        oid = report['offense_id']
        closure = report.get('closure_assessment', {})
        decisions.append(dict(offense_id=oid, description=report.get('metadata', {}).get('description'),
                              recommendation=closure.get('recommendation'), confidence=closure.get('confidence'),
                              reported_lockout_groups=report.get('lockout', {}).get('groups', []),
                              recommended_reason=closure.get('recommended_reason'), ready_to_close=closure.get('ready_to_close', False),
                              blocking_requirements=closure.get('blocking_requirements', []),
                              suggested_note=closure.get('suggested_note'), note_status='draft_for_analyst_review'))
        for group in report.get('lockout', {}).get('groups', []):
            # Account domains and caller names are explicit; missing identity never joins two offenses.
            if not all(group.get(k) for k in ('target_user', 'target_domain', 'caller_computer')):
                continue
            key = tuple(group[k].casefold() for k in ('target_domain', 'target_user', 'caller_computer'))
            entry = groups.setdefault(key, dict(target_user=group['target_user'], target_domain=group['target_domain'],
                                                caller_computer=group['caller_computer'], offenses=[]))
            if oid not in entry['offenses']:
                entry['offenses'].append(oid)
    return dict(per_offense_decisions=decisions, recurring_lockout_identities=list(groups.values()),
                relation='Same reported account/domain/caller is a recurrence candidate, not proof of a common cause or duplicate incident.',
                count_note='Do not sum event counts across offenses: records and snapshots may overlap.',
                executed_actions=[])


async def investigate_offenses(qradar: Any, description: str = '', offense_ids: list[int] | None = None,
                               status: str = 'OPEN', match: str = 'exact', offset: int = 0,
                               max_offenses: int = 3, start_time_from: int | None = None,
                               start_time_to: int | None = None, qradar_utc_offset_hours: int = -3,
                               timezone_verified: bool = False, budget: Budget | None = None) -> dict:
    """Discover then investigate one bounded batch; keep each case and its Ariel jobs separate."""
    integer(max_offenses, 'max_offenses', 1, 5)
    integer(qradar_utc_offset_hours, 'qradar_utc_offset_hours', -12, 14)
    if not isinstance(timezone_verified, bool):
        raise ValueError('timezone_verified must be boolean')
    if offense_ids is not None:
        if description or offset or start_time_from is not None or start_time_to is not None:
            raise ValueError('Choose either a description search or explicit offense_ids')
        if not isinstance(offense_ids, list) or not 1 <= len(offense_ids) <= 100:
            raise ValueError('offense_ids must contain 1..100 positive integer IDs')
        for oid in offense_ids:
            integer(oid, 'offense_id', 1, 2147483647)
        ids = list(dict.fromkeys(offense_ids))
    else:
        selection(description, status, match, start_time_from, start_time_to)
        integer(offset, 'offset', 0, 1000000)
        ids = []
    budget = budget or Budget(max_seconds=90)
    result: dict = dict(reports=[], failures=[], pending_offense_ids=[], continuation_plan=[],
                        discovery=None, scope='explicit IDs' if offense_ids is not None else 'description search',
                        warnings=[], executed_actions=[], collection_complete=False, all_matching_offenses_investigated=False)
    discovery_next = []
    if offense_ids is None:
        discovery = await find_offenses(qradar, description, status, match, offset, max_offenses,
                                        start_time_from, start_time_to,
                                        budget=Budget(max_seconds=max(.001, min(20, budget.remaining_seconds())))) if budget.remaining_seconds() > 0 else None
        if discovery:
            budget.calls_made += discovery.get('mcp_tool_calls_attempted', 0)
        result['discovery'] = discovery
        if discovery is None or (not discovery['page_complete'] and discovery['outcome'] != 'partial'):
            result.update(outcome='discovery_unavailable', consolidation=consolidate([]), budget=budget.describe())
            result['continuation_plan'] = discovery['continuation_plan'] if discovery else [dict(
                tool='qradar_investigate_offenses', parameters=dict(description=description, status=status,
                match=match, offset=offset, max_offenses=max_offenses, start_time_from=start_time_from,
                start_time_to=start_time_to, qradar_utc_offset_hours=qradar_utc_offset_hours,
                timezone_verified=timezone_verified))]
            return result
        ids = [row['id'] for row in discovery['offenses']]
        if not discovery['discovery_exhausted']:
            for plan in discovery['continuation_plan']:
                discovery_next.append(dict(tool='qradar_investigate_offenses', parameters=dict(description=description,
                    status=status, match=match, offset=plan['parameters']['offset'], max_offenses=max_offenses,
                    start_time_from=start_time_from, start_time_to=start_time_to,
                    qradar_utc_offset_hours=qradar_utc_offset_hours, timezone_verified=timezone_verified),
                    requires_resolution=plan.get('requires_resolution', False),
                    cursor_semantics=plan.get('cursor_semantics')))
    selected = ids[:max_offenses]
    result['pending_offense_ids'] = ids[max_offenses:]
    for index, oid in enumerate(selected):
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            result['pending_offense_ids'].extend(selected[index:])
            break
        # A slow case gets a share of remaining time, preserving a chance for later cases.
        child = Budget(max_seconds=min(60, remaining / (len(selected) - index)))
        try:
            report = await verify_offense(qradar, oid, qradar_utc_offset_hours, timezone_verified, budget=child)
            result['reports'].append(report)
            if description and report.get('metadata', {}).get('description') != description and match == 'exact':
                result['warnings'].append(f'Offense {oid} description changed since discovery; retain the ID and review its individual report.')
            for plan in report.get('continuation_plan', []):
                result['continuation_plan'].append(dict(offense_id=oid, **plan))
        except Exception as exc:
            result['failures'].append(dict(offense_id=oid, error=classify_failure(exc),
                next_action='Inspect the collection stage and existing Ariel jobs before retrying this offense.'))
    if result['pending_offense_ids']:
        result['continuation_plan'].append(dict(tool='qradar_investigate_offenses', parameters=dict(
            offense_ids=result['pending_offense_ids'], max_offenses=max_offenses,
            qradar_utc_offset_hours=qradar_utc_offset_hours, timezone_verified=timezone_verified)))
    result['continuation_plan'].extend(discovery_next)
    # Only the current batch is summarized; never claim all matching offenses were investigated.
    result.update(outcome='batch_collected' if not result['failures'] else 'partial',
                  batch_size=len(selected), investigated_count=len(result['reports']),
                  all_matching_offenses_investigated=False,
                  consolidation=consolidate(result['reports']), budget=budget.describe())
    if offense_ids is not None:
        result['all_supplied_ids_collected'] = not result['pending_offense_ids'] and not result['failures']
    elif result['discovery']['discovery_exhausted'] and offset == 0 and not result['failures'] and not result['pending_offense_ids']:
        result['all_matching_offenses_investigated'] = True
    result['collection_complete'] = (not result['continuation_plan'] and not result['failures'] and
        all({'events', 'flows'} <= r.get('queries', {}).keys() and
            all(q.get('result_set_complete') for q in r['queries'].values()) for r in result['reports']))
    result['warnings'].append('Collected means the verification returned a report, not that every query completed or a closing verdict is justified.')
    return result
