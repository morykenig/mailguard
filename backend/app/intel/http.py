"""Hardened outbound HTTP for threat-intel providers.

Provider responses are treated as untrusted input: bodies are size-capped while
streaming, redirects are not followed automatically, and callers only read the few
typed fields they need.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

MAX_RESPONSE_BYTES = 512 * 1024
USER_AGENT = "MailGuard/1.0 (+email-risk-scoring)"


class IntelError(Exception):
    """A provider failed in a way that should be reported as 'unavailable', not crash analysis."""


class RateLimited(IntelError):
    pass


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(5.0, connect=3.0),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


async def fetch_json(
    client: httpx.AsyncClient, method: str, url: str, *, max_bytes: int = MAX_RESPONSE_BYTES, **kwargs: Any
) -> tuple[int, Any, httpx.Headers]:
    """Return (status, parsed JSON or None, headers). Raises IntelError on transport problems."""
    try:
        async with client.stream(method, url, **kwargs) as resp:
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise IntelError("response too large")
            status, headers = resp.status_code, resp.headers
    except httpx.HTTPError as exc:
        raise IntelError(type(exc).__name__) from None
    if status == 429:
        raise RateLimited("rate limited")
    if not buf:
        return status, None, headers
    try:
        return status, json.loads(buf), headers
    except (ValueError, UnicodeDecodeError):
        return status, None, headers


def as_int(value: Any, default: int = 0, lo: int = 0, hi: int = 10_000) -> int:
    """Coerce an untrusted value into a bounded int."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return default
    return max(lo, min(hi, int(value)))
