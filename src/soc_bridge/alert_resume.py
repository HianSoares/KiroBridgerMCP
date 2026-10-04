"""Short-lived, credential-scoped alert read state, never credentials or disk writes.

This is best-effort resumption in one running bridge, not a durable case store.
Known Ariel jobs live separately from memoized successful reads. Polling and job
creation are never memoized. Same-alert runs serialize; other alerts stay isolated.
"""

import asyncio
import hashlib
import json
import time
import weakref
from collections import OrderedDict
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timezone


class AlertReadState:
    MAX_MEMO_BYTES = 8 * 1024 * 1024
    UNCACHED = frozenset({"validate_aql", "create_ariel_search", "get_ariel_search_status", "get_ariel_search_results"})

    def __init__(self):
        self.lock = asyncio.Lock()
        self.users = 0  # includes waiters, which must not be evicted before acquiring the lock
        self.now = datetime.now(timezone.utc)
        self.touched = time.monotonic()
        self.queries = {}
        self.memo = OrderedDict()
        self.memo_bytes = 0
        self.reused = 0

    @staticmethod
    def read_key(source, tool, arguments):
        return json.dumps([source, tool, arguments], sort_keys=True, separators=(",", ":"))

    def get(self, source, tool, arguments):
        if tool in self.UNCACHED:
            return False, None
        key = self.read_key(source, tool, arguments)
        if key not in self.memo:
            return False, None
        self.memo.move_to_end(key)
        self.reused += 1
        return True, deepcopy(self.memo[key][0])

    def put(self, source, tool, arguments, result):
        if tool in self.UNCACHED:
            return
        try:
            size = len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return
        if size > self.MAX_MEMO_BYTES:
            return
        key = self.read_key(source, tool, arguments)
        previous = self.memo.pop(key, None)
        if previous:
            self.memo_bytes -= previous[1]
        while self.memo and self.memo_bytes + size > self.MAX_MEMO_BYTES:
            _, (_, dropped) = self.memo.popitem(last=False)
            self.memo_bytes -= dropped
        self.memo[key] = (deepcopy(result), size)
        self.memo_bytes += size


class AlertReadCache:
    MAX_ALERTS = 4
    TTL_SECONDS = 900

    def __init__(self):
        # SDK transports and locks belong to one event loop; never reuse them in another.
        self.loops = weakref.WeakKeyDictionary()

    @asynccontextmanager
    async def session(self, identity):
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()
        entries = self.loops.setdefault(asyncio.get_running_loop(), OrderedDict())
        now = time.monotonic()
        for old_key, old in list(entries.items()):
            if old.users == 0 and now - old.touched >= self.TTL_SECONDS:
                del entries[old_key]
        state = entries.get(key)
        if state is None:
            if len(entries) >= self.MAX_ALERTS:
                expired = next((k for k, v in entries.items() if v.users == 0), None)
                if expired is None:
                    # Fail before any connection/query instead of launching duplicate untracked jobs.
                    raise RuntimeError("Alert read cache busy; finish an active alert before starting another")
                del entries[expired]
            state = entries[key] = AlertReadState()
        entries.move_to_end(key)
        state.users += 1
        try:
            async with state.lock:
                yield state
        finally:
            state.users -= 1
            state.touched = time.monotonic()


ALERT_READ_CACHE = AlertReadCache()
