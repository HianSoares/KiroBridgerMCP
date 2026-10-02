"""Shared validation constants for Vision One query values.

The former fixed host/hash collector (which cut values to 240 characters) was replaced
by the budgeted Search collector in vision_search.py and the generic alert discovery.
"""

from __future__ import annotations

import ipaddress
import re

HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
HASH = re.compile(r"^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
PRIVATE_RANGES = tuple(ipaddress.ip_network(cidr) for cidr in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
