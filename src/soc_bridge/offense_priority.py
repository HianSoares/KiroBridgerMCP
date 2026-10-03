"""Metadata triage of the offense queue: no Ariel jobs, Trend calls or verdicts."""
from __future__ import annotations

from typing import Any

from .ariel_collection import Budget
from .offense_batch import FIELDS, _discover, integer, status_selection

CRITERIA = (
    ('magnitude', 'desc', 10),
    ('severity', 'desc', 10),
    ('credibility', 'desc', 10),
    ('relevance', 'desc', 10),
    ('last_updated_time', 'desc', 9999999999999),
    ('id', 'asc', 2147483647),
)


def priority_inputs(row: dict) -> dict:
    """Missing/invalid metadata stays unknown; it is never manufactured as zero."""
    result = {}
    for field, _, maximum in CRITERIA:
        value = row.get(field)
        low = 1 if field == 'id' else 0
        result[field] = (value if isinstance(value, int) and not isinstance(value, bool)
                         and low <= value <= maximum else None)
    return result


def priority_key(row: dict) -> tuple:
    """Lexicographic order, known values before unknown at each criterion."""
    values = priority_inputs(row)
    return tuple((values[field] is None, -values[field] if direction == 'desc'
                  and values[field] is not None else values[field] or 0)
                 for field, direction, _ in CRITERIA)


def rank_offenses(rows: list[dict]) -> list[dict]:
    """Rank only the supplied population. Positions are not a risk score."""
    ranked = []
    for position, row in enumerate(sorted(rows, key=priority_key), 1):
        values = priority_inputs(row)
        missing = [field for field, value in values.items() if value is None]
        rationale = '; '.join(f'{field}={value if value is not None else "não disponível"}'
                              for field, value in values.items())
        ranked.append({**row, 'priority': {
            'position_in_returned_set': position,
            'inputs': values,
            'missing_or_invalid_fields': missing,
            'rationale': 'Ordem de triagem pelos metadados do QRadar: ' + rationale,
        }})
    return ranked


async def list_offenses(qradar: Any, status: str = 'OPEN', offset: int = 0, limit: int = 100,
                        start_time_from: int | None = None, start_time_to: int | None = None,
                        budget: Budget | None = None) -> dict:
    """List by status without a description; sort returned metadata for investigation."""
    integer(offset, 'offset', 0, 1000000)
    integer(limit, 'limit', 1, 500)
    expression, scope = status_selection(status, start_time_from, start_time_to)
    result = await _discover(qradar, expression, scope, offset, limit, budget,
                             tool='qradar_list_offenses', fields=FIELDS + ',credibility,relevance')
    result['offenses'] = rank_offenses(result['offenses'])
    result['offset_semantics'] = 'Cursor in the status/start_time-filtered upstream population in +id order'
    for plan in result['continuation_plan']:
        plan['cursor_semantics'] = result['offset_semantics']
    complete = offset == 0 and result['discovery_exhausted']
    result['ranking'] = {
        'basis': 'QRadar offense metadata only; lexicographic comparison, no calculated risk score',
        'criteria': [{'field': field, 'direction': direction, 'unknown': 'after known values'}
                     for field, direction, _ in CRITERIA],
        'scope': 'entire_scanned_selection' if complete else 'returned_set_only',
        'complete_selection_ranked': complete,
        'merge_instruction': 'For an all-offenses request, follow continuation_plan, retain seen IDs, '
                            'then re-sort all collected rows with the same criteria. Page positions are '
                            'not global ranks. Disclose live population changes and collection failures.',
        'limitations': 'Priority suggests investigation order, not maliciousness, confidence, business '
                      'criticality, authorization or a reason to close. Those require investigation.',
    }
    result['all_open_offenses_listed'] = complete and status == 'OPEN'
    result['executed_actions'] = []
    result['investigations_started'] = 0
    if any(row['priority']['missing_or_invalid_fields'] for row in result['offenses']):
        result['warnings'].append('Some ranking metadata is missing/invalid; values remain unknown. '
                                  'Review priority inputs before treating this as a complete triage assessment.')
    return result
