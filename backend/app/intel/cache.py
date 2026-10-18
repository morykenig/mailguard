"""Small in-process TTL cache for intel lookups.

Caching matters here: the free VirusTotal tier allows 4 requests/minute, and the same
phishing URL often arrives in many mailboxes. Only verdicts (numbers) are cached, keyed
by indicator - never message content. A multi-instance deployment would swap this for
Redis/Memorystore behind the same interface.
"""

from __future__ import annotations

import time
from collections import OrderedDict


class TTLCache[T]:
    def __init__(self, maxsize: int = 4096, ttl_s: float = 6 * 3600) -> None:
        self._data: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self.maxsize, self.ttl_s = maxsize, ttl_s

    def get(self, key: str) -> T | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if expires < time.monotonic():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: T, ttl_s: float | None = None) -> None:
        self._data[key] = (time.monotonic() + (ttl_s or self.ttl_s), value)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)
