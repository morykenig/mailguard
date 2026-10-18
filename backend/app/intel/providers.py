"""Threat-intelligence providers: VirusTotal, Google Safe Browsing and RDAP domain age.

Privacy rules applied to every provider:
  * Only indicators leave the backend (URLs, domains, file hashes) - never the email body,
    subject, sender or recipient address.
  * Nothing is *submitted* for scanning. VirusTotal submissions are public, and a URL in
    an email may carry a personal token (password-reset links, invoices). We only look
    up whether the indicator is already known.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import httpx

from .cache import TTLCache
from .http import IntelError, as_int, fetch_json


@dataclass(frozen=True)
class EngineVerdict:
    found: bool
    malicious: int = 0
    suspicious: int = 0
    total: int = 0


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, client: httpx.AsyncClient, cache: TTLCache[EngineVerdict]) -> None:
        self._key, self._client, self._cache = api_key, client, cache

    async def _lookup(self, kind: str, ident: str) -> EngineVerdict:
        key = f"vt:{kind}:{ident}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        status, data, _ = await fetch_json(
            self._client, "GET", f"{self.BASE}/{kind}/{ident}", headers={"x-apikey": self._key}
        )
        if status == 404:
            verdict = EngineVerdict(found=False)
        elif status == 200 and isinstance(data, dict):
            attrs = (data.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
            stats = stats if isinstance(stats, dict) else {}
            verdict = EngineVerdict(
                found=True,
                malicious=as_int(stats.get("malicious"), hi=200),
                suspicious=as_int(stats.get("suspicious"), hi=200),
                total=sum(as_int(v, hi=200) for v in stats.values()),
            )
        else:
            raise IntelError(f"virustotal status {status}")
        self._cache.set(key, verdict)
        return verdict

    async def url(self, url: str) -> EngineVerdict:
        ident = base64.urlsafe_b64encode(canonical_url(url).encode()).decode().rstrip("=")
        return await self._lookup("urls", ident)

    async def file(self, sha256: str) -> EngineVerdict:
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise IntelError("invalid hash")
        return await self._lookup("files", sha256)


def canonical_url(url: str) -> str:
    """Light canonicalisation so lookups hit VirusTotal's stored form of the URL:
    lowercase scheme and host, '/' for an empty path, no fragment."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


class SafeBrowsing:
    """Google Safe Browsing Lookup API v4 (non-commercial; Web Risk is the commercial twin)."""

    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")

    def __init__(self, api_key: str, client: httpx.AsyncClient, cache: TTLCache[str]) -> None:
        self._key, self._client, self._cache = api_key, client, cache

    async def check(self, urls: list[str]) -> dict[str, str]:
        """Return {url: threat_type} for URLs on a Safe Browsing list."""
        result: dict[str, str] = {}
        todo = []
        for u in urls:
            cached = self._cache.get(f"sb:{u}")
            if cached is None:
                todo.append(u)
            elif cached:
                result[u] = cached
        if not todo:
            return result
        body = {
            "client": {"clientId": "mailguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": list(self.THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in todo[:500]],
            },
        }
        # Key in a header rather than the query string, so it never lands in URL logs.
        status, data, _ = await fetch_json(
            self._client, "POST", self.URL, json=body, headers={"X-Goog-Api-Key": self._key}
        )
        if status != 200 or not isinstance(data, dict):
            raise IntelError(f"safebrowsing status {status}")
        matches = data.get("matches") if isinstance(data.get("matches"), list) else []
        allowed = set(self.THREAT_TYPES)
        for m in matches:
            if not isinstance(m, dict):
                continue
            url = ((m.get("threat") or {}).get("url")) if isinstance(m.get("threat"), dict) else None
            ttype = m.get("threatType")
            if url in todo and ttype in allowed:  # only accept answers about what we asked
                result[url] = ttype
        for u in todo:
            self._cache.set(f"sb:{u}", result.get(u, ""), ttl_s=1800)
        return result


class Rdap:
    """Domain registration date via RDAP (the structured successor of WHOIS). No API key."""

    BOOTSTRAP = "https://rdap.org/domain/"
    MAX_REDIRECTS = 2

    def __init__(self, client: httpx.AsyncClient, cache: TTLCache[int]) -> None:
        self._client, self._cache = client, cache

    async def age_days(self, registrable: str) -> int | None:
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", registrable):
            return None  # only well-formed ASCII domains go into the URL
        cached = self._cache.get(f"rdap:{registrable}")
        if cached is not None:
            return cached if cached >= 0 else None
        url = self.BOOTSTRAP + registrable
        for _ in range(self.MAX_REDIRECTS + 1):
            status, data, headers = await fetch_json(
                self._client, "GET", url, headers={"Accept": "application/rdap+json"}
            )
            if status in (301, 302, 303, 307, 308):
                nxt = headers.get("location", "")
                if not _safe_redirect(nxt):
                    raise IntelError("unsafe redirect")
                url = nxt
                continue
            break
        else:
            raise IntelError("too many redirects")
        age = -1
        if status == 200 and isinstance(data, dict):
            for event in data.get("events") or []:
                if isinstance(event, dict) and event.get("eventAction") == "registration":
                    age = _days_since(event.get("eventDate"))
                    break
        elif status != 404:
            raise IntelError(f"rdap status {status}")
        self._cache.set(f"rdap:{registrable}", age, ttl_s=24 * 3600)
        return age if age >= 0 else None


def _safe_redirect(url: str) -> bool:
    """RDAP bootstrap redirects to the registry's server. Only follow https to a public name."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return False
    if parts.scheme != "https" or "." not in host or host == "localhost" or host.endswith(".internal"):
        return False
    try:
        ipaddress.ip_address(host)
        return False  # registries publish names, never raw IPs
    except ValueError:
        return True


def _days_since(value: object) -> int:
    if not isinstance(value, str) or len(value) > 40:
        return -1
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return -1
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - dt).days)
