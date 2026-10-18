"""Request authentication, replay protection and rate limiting.

The add-on signs every request with HMAC-SHA256 over ``timestamp.nonce.client.body``
using a secret stored in Apps Script *Script Properties* (not in source). The backend:

  1. rejects stale or future timestamps (bounded clock skew),
  2. recomputes the MAC and compares in constant time,
  3. rejects a (nonce) seen before inside the validity window (replay),
  4. rate-limits per pseudonymous client id (a hash of the user's address, never the address).

Authentication happens *before* the JSON body is parsed, so unauthenticated callers
cannot make the service do any expensive work.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from itertools import islice

from fastapi import HTTPException, status

TS_HEADER = "X-MG-Timestamp"
NONCE_HEADER = "X-MG-Nonce"
CLIENT_HEADER = "X-MG-Client"
SIG_HEADER = "X-MG-Signature"
RESPONSE_SIG_HEADER = "X-MG-Response-Signature"

MAX_CLOCK_SKEW_S = 30

_TS_RE = re.compile(r"[0-9]{1,12}")
_NONCE_RE = re.compile(r"^[A-Za-z0-9-]{16,64}$")
_CLIENT_RE = re.compile(r"^[0-9a-f]{16,64}$")
_SIG_RE = re.compile(r"^[0-9a-f]{64}$")


def sign(secret: str, timestamp: str, nonce: str, client: str, body: bytes) -> str:
    msg = f"{timestamp}.{nonce}.{client}.".encode() + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class NonceCache:
    """Remembers each nonce until its signature can no longer be valid. In-memory, per instance."""

    def __init__(self, maxsize: int = 100_000) -> None:
        self._expiry: OrderedDict[str, float] = OrderedDict()  # nonce -> time it stops mattering
        self.maxsize = maxsize

    def check_and_add(self, nonce: str, expires_at: float, now: float) -> bool:
        # Entries are inserted in arrival order, but expiry depends on the request's own
        # timestamp, so purge by scanning the oldest few rather than assuming order.
        expired = [k for k, exp in islice(self._expiry.items(), 64) if exp < now]  # O(1) per request
        for key in expired:
            del self._expiry[key]
        if nonce in self._expiry:
            return False
        if len(self._expiry) >= self.maxsize:
            return False  # fail closed rather than forget nonces that may still be replayed
        self._expiry[nonce] = expires_at
        return True


class RateLimiter:
    """Token bucket per client. Good enough for one instance; use Redis/Cloud Armor at scale."""

    def __init__(self, per_minute: int, maxsize: int = 10_000) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self.maxsize = maxsize

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        tokens, last = self._buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0
        self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
        self._buckets.move_to_end(key)
        while len(self._buckets) > self.maxsize:
            self._buckets.popitem(last=False)
        return allowed


def _reject(code: int = status.HTTP_401_UNAUTHORIZED) -> HTTPException:
    # Deliberately vague: don't tell an attacker which check failed.
    return HTTPException(status_code=code, detail="unauthorized" if code == 401 else "rejected")


@dataclass(frozen=True)
class Verified:
    client: str
    nonce: str
    secret: str = field(repr=False)  # the key that verified: the response is signed with the same one


def verify_request(
    *,
    secrets: tuple[str, ...],
    headers: dict[str, str],
    body: bytes,
    nonces: NonceCache,
    max_age_s: int,
    now: float | None = None,
) -> Verified:
    """Validate the signature headers against the current key (and, during a rotation, the
    previous one). Every key is always tried, so timing does not reveal which one matched."""
    now = time.time() if now is None else now
    ts = headers.get(TS_HEADER.lower(), "")
    nonce = headers.get(NONCE_HEADER.lower(), "")
    client = headers.get(CLIENT_HEADER.lower(), "")
    sig = headers.get(SIG_HEADER.lower(), "").lower()

    # ASCII digits only: str.isdigit() accepts '²', which int() then rejects (a 500 for anyone).
    if not (_TS_RE.fullmatch(ts) and _NONCE_RE.match(nonce) and _CLIENT_RE.match(client) and _SIG_RE.match(sig)):
        raise _reject()
    issued = int(ts)
    # Past: up to max_age_s old. Future: only small clock skew, so a request stamped far
    # ahead cannot outlive its nonce in the replay cache.
    if now - issued > max_age_s or issued - now > MAX_CLOCK_SKEW_S:
        raise _reject()
    matched = None
    for secret in secrets:
        if hmac.compare_digest(sign(secret, ts, nonce, client, body), sig) and matched is None:
            matched = secret
    if matched is None:
        raise _reject()
    if not nonces.check_and_add(nonce, expires_at=issued + max_age_s + MAX_CLOCK_SKEW_S, now=now):
        raise _reject()
    return Verified(client=client, nonce=nonce, secret=matched)


def sign_response(secret: str, nonce: str, body: bytes) -> str:
    """Response signature, bound to the request's nonce.

    The add-on verifies it before showing a verdict, so whoever sits between the add-on and
    the backend (a hijacked custom domain, a misconfigured BACKEND_URL, a TLS-inspecting
    proxy) cannot inject a fake "safe" verdict - and cannot replay an old genuine one,
    because the nonce is fresh per request. The "resp." prefix separates it from request
    signatures, so one can never be passed off as the other.
    """
    return hmac.new(secret.encode(), b"resp." + nonce.encode() + b"." + body, hashlib.sha256).hexdigest()
