# Discover and investigate matching offenses

The bridge exposes **17 read-only tools**. The original 15 schemas are preserved.
`qradar_find_offenses` and `qradar_investigate_offenses` use QRadar only; no Trend
credentials are required. The upstream must expose `list_offenses` for discovery.
Existing ID-based investigations continue working when that optional tool is absent.

## Discovery and scope

`qradar_find_offenses(description, status="OPEN", match="exact", offset=0, limit=50)`
scans bounded REST pages through the offense API, with `format_output=false` and
`+id` ordering. **QRadar can return description while rejecting it as a filterable
field (HTTP 422).** The bridge sends only status and optional start_time predicates
to the upstream, then compares each returned description locally. It does not
search Ariel and does not send description equality/LIKE to the offense API.

Exact literal description is the default. `contains` is a literal Python substring
comparison, including percent, underscore and backslash characters; they are not
API wildcards. Status may be OPEN, CLOSED, HIDDEN or ALL. Without a status request,
search OPEN and state that scope. Optional `start_time_from` / `start_time_to` are
inclusive **offense start_time epochs in milliseconds**, not event timestamps or
overlap filters. These API filters do not depend on the console timezone.

`limit` is the number of matching offenses to return (1..100), not the raw REST page
size. Raw pages contain up to 100 entries; a call scans within its wall-time,
call and record budget until the match quota or population end. A page with no
matching descriptions does not end the scan. If the budget ends first, `outcome`
is partial even if zero matches were returned. Follow the concrete continuation.

**offset / next_offset are raw population positions**, including nonmatching rows,
within the status/time-filtered upstream list. Never calculate offset by adding
the number of matching offenses. If the match quota is reached in the middle of a
raw page, the cursor points just after the last examined row, so remaining entries
are fetched on continuation rather than skipped. Repeated/non-advancing IDs are
response errors. `upstream_rows_scanned` and `upstream_pages_read` expose coverage.

`upstream_total_count` counts the status/time-filtered population, not the matching
description. `total_count` is populated with a matching total only when this
invocation starts at raw offset zero and reaches the population end; otherwise it
stays unknown. Later suffixes cannot establish the whole matching population.

Each response distinguishes successful exhaustion with no matches from permission,
tool, timeout and format failures. Errors preserve earlier matches and the raw
cursor. A continuation with `requires_resolution=true` must wait for the reported
failure to be resolved, not be repeatedly called. `discovery_exhausted` describes
the scanned selection, not complete logging or a static historical snapshot.
Offenses can change status/description between calls; retain seen IDs and report
changed-population limitations instead of promising an immutable census.

## Investigation batches

Call `qradar_investigate_offenses(description="Synthetic account lockout rule")`
to discover and verify up to 3 cases. `max_offenses` may be 1..5. Alternatively,
pass `offense_ids=[12345,12346]` (up to 100 unique supplied IDs per request); do not
combine explicit IDs with description search parameters. Extra IDs are preserved
in `pending_offense_ids` and a concrete continuation call.

A batch has a 90-second collection budget. Each case receives a share of the
remaining time (maximum 60 seconds) so a slow case cannot consume every later
case's allocation. Each case reuses the existing offense verifier, with its own
metadata, INOFFENSE jobs, coverage, rule metadata, closing recommendation and
Portuguese note draft. Failure in one case does not abort subsequent cases.
Connection/initialization overhead is outside the collection budget.

For an authorized request for all matching offenses, continue:

1. Existing Ariel search IDs/cursors for pending jobs/pages. Do not recreate a
   query or repeat the entire offense to read another page.
2. Explicit pending IDs which were not started.
3. The next discovery batch using its returned description/status/offset.

`all_matching_offenses_investigated` only applies to a single invocation which
started at offset zero and reached the end of discovery with reports for each ID.
It does not assert all Ariel queries completed or any verdict was established.
`collection_complete`, per-query outcomes and continuation plans express those
limits. Later-page calls cannot independently claim the whole population.

## Account lockout evidence

A parsed 4740 triggers a bounded account-context pivot before flow collection.
Target account/domain, CallerComputerName and the computer recording the event
are kept separate. XML, JSON and recognizable Windows target sections are read;
Subject account and generic normalized username never replace TargetUserName.
Repeated conflicting values are withheld. QID names alone do not establish EventID.

The pivot searches up to 3 safely parsed accounts over the offense interval with
15-minute margins, capped at collection time, using epoch predicates plus bounded
LAST/START/STOP. Historical windows require the existing verified console timezone;
raw windows over 24 hours need partitioning. Query LIMIT is 1000; existing Ariel
continuation and coverage rules apply. Missing accounts/windows do not become
negative authentication findings.

4625 and 4771 describe failures. 4776 may describe success or failure: only a
recognized nonzero status enters failure correlations. Candidate links require an
exact target account, no conflicting known domain and receipt times within 15
minutes. A missing domain stays unverified. These links do not prove the failure
caused the lockout, identify a service/task/process or resolve caller name to IP.
`starttime` receipt and `devicetime` remain distinct clocks. Status codes are kept
as observed; their interpretation and configuration evidence remain analyst work.

Censuses traverse the retrieved rows. Record previews/groups and candidate links
are explicitly bounded (100 each); omissions and correlation caps are reported.
File-source truncation and absent forwarding are not diagnosed from missing fields.

## Consolidation and decisions

The batch provides one decision and suggested note per offense, plus recurrence
candidates by reported account/domain/caller. Missing identity never groups cases.
Equal descriptions or identities do not demonstrate equal causes or duplicate
incidents. Counts are not summed across offenses because events may overlap.

For each case provide: ID, account/caller observations, query/search IDs, coverage,
causal hypotheses and contradictions, confidence, recommended disposition and
why, unresolved evidence, real closing reason if supported, and the note draft.
Validate service/task/application credentials, ownership, active CRE tests and
post-remediation behavior before attributing a cause or recommending closure.
A successful audit of 4740 means the lockout was recorded, not successful login.
No offense is closed, note posted, rule changed or response action executed.

## Discovery diagnostics

The IBM FastMCP adapter can return an upstream error as ordinary text while losing
`isError`. The bridge recognizes fixed error prefixes and sanitizes the result;
it accepts the documented JSON/string envelopes and older REST-array responses.
Non-JSON/table responses are `response_format`, not local argument rejection.
A ValueError inside the listing client is `upstream_client`, not proof that public
arguments were rejected. Real local argument checks run before tool invocation.

Read `mcp_tool_call_attempted`, `mcp_tool_calls_attempted`, `diagnostic_stage`,
`decoded_response_returned`, `error.stage` and the discovery budget. These count
attempted MCP tool invocations, not confirmed QRadar REST requests. Shared batch
counters include the discovery call. Zero elapsed/counter values from older
versions did not establish that the upstream was never contacted. Permission,
upstream filter validation, malformed responses and successful empty JSON pages
have distinct outcomes. Unknown upstream errors require local server logs; no
response body, URL, token or description from an error is copied into diagnostics.
Do not infer that spaces, colons or `containing` are rejected without a reported
local validation error. Do not repeatedly rerun the same deterministic failure.

## Upstream initialization failures

An HTTP 500 during MCP initialization is separate from offense filter rejection.
The initialization/authentication middleware is shared by tools. A traceback
through identify_user/get_current_user ending in httpx.ConnectError shows a
connection failure during authentication, not proof of an invalid token or a
special offense initialization endpoint. Inspect container-to-QRadar connectivity
and local server logs when that trace occurs. A responding static guide does not
test the QRadar API; dynamic event fields exercise Ariel metadata, not the offense
list. The bridge does not change credentials, network settings or upstream code.
