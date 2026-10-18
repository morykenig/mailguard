"""Threat-intel integration, with providers mocked at the HTTP layer."""

import base64
import json

import httpx
from helpers import ctx_for, headers, run, sha

from app.analyzers.reputation import IntelClients
from app.analyzers.reputation import analyze as reputation
from app.intel.cache import TTLCache
from app.intel.providers import Rdap, SafeBrowsing, VirusTotal

EVIL = "http://evil-login.example/verify"


def intel(handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return IntelClients(
        vt=VirusTotal("k", client, TTLCache()) if kw.get("vt", True) else None,
        safe_browsing=SafeBrowsing("k", client, TTLCache()) if kw.get("sb", True) else None,
        rdap=Rdap(client, TTLCache()) if kw.get("rdap", True) else None,
        deadline_s=kw.get("deadline", 3.0),
    )


def ctx():
    return ctx_for(
        raw_headers=headers("Bob <bob@fresh-domain.example>"),
        html_body=f'<a href="{EVIL}">click</a>',
        attachments=[{"filename": "a.exe", "size": 1, "sha256": sha(b"a")}],
    )


def handler_factory(sb_match=True, vt_malicious=5, rdap_date="2026-10-10T00:00:00Z", vt_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "safebrowsing" in url:
            assert request.headers["x-goog-api-key"] == "k"  # key in header, not URL
            assert "key=" not in url
            sent = json.loads(request.content)["threatInfo"]["threatEntries"]
            body = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": sent[0]}]} if sb_match else {}
            return httpx.Response(200, json=body)
        if "virustotal" in url:
            if vt_status != 200:
                return httpx.Response(vt_status)
            stats = {"malicious": vt_malicious, "suspicious": 0, "harmless": 60, "undetected": 10}
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})
        if "rdap.org" in url:
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": rdap_date}]})
        return httpx.Response(404)

    return handler


def test_all_providers_contribute():
    findings, coverage = run(reputation(ctx(), intel(handler_factory())))
    found = {f.id for f in findings}
    assert {"INTEL_SAFE_BROWSING", "INTEL_VT_FILE_MALICIOUS", "INTEL_VT_URL_MALICIOUS"} <= found
    assert "INTEL_NEW_SENDER_DOMAIN" in found or "INTEL_NEW_LINK_DOMAIN" in found
    assert all(not v.startswith(("unavailable", "timed out")) for v in coverage.values())


def test_vt_lookup_uses_url_id_and_never_submits():
    seen = []

    def handler(request):
        seen.append((request.method, str(request.url)))
        return httpx.Response(404)

    run(reputation(ctx(), intel(handler, sb=False, rdap=False)))
    url_id = base64.urlsafe_b64encode(EVIL.encode()).decode().rstrip("=")  # already canonical
    assert ("GET", f"https://www.virustotal.com/api/v3/urls/{url_id}") in seen
    assert all(method == "GET" for method, _ in seen)  # lookups only, no uploads


def test_rate_limit_is_reported_not_hidden():
    _, coverage = run(reputation(ctx(), intel(handler_factory(vt_status=429), sb=False, rdap=False)))
    assert coverage["VirusTotal"] == "rate-limited"


def test_malformed_provider_response_is_tolerated():
    def handler(request):
        return httpx.Response(200, content=b"not json at all")

    findings, coverage = run(reputation(ctx(), intel(handler)))
    assert findings == [] or all(f.points >= 0 for f in findings)
    assert coverage["Google Safe Browsing"] == "unavailable"


def test_safe_browsing_ignores_answers_about_urls_we_did_not_ask():
    def handler(request):
        if "safebrowsing" in str(request.url):
            return httpx.Response(200, json={"matches": [{"threatType": "MALWARE", "threat": {"url": "http://x/"}}]})
        return httpx.Response(404)

    findings, _ = run(reputation(ctx(), intel(handler, vt=False, rdap=False)))
    assert findings == []


def test_slow_provider_times_out_gracefully():
    import asyncio

    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    clients = IntelClients(vt=None, safe_browsing=SafeBrowsing("k", client, TTLCache()), rdap=None, deadline_s=0.2)
    _, coverage = run(reputation(ctx(), clients))
    assert coverage["Google Safe Browsing"] == "timed out"


def test_rdap_refuses_unsafe_redirect():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    _, coverage = run(reputation(ctx(), intel(handler, vt=False, sb=False)))
    assert coverage["Domain age (RDAP)"].startswith("checked 0")


def test_vt_url_canonicalisation():
    from app.intel.providers import canonical_url

    assert canonical_url("HTTPS://Example.COM") == "https://example.com/"
    assert canonical_url("https://example.com/a?b=1#frag") == "https://example.com/a?b=1"


def test_nonce_survives_until_signature_expires():
    from app.security import NonceCache

    cache = NonceCache()
    assert cache.check_and_add("n1", expires_at=1300, now=1000)
    assert not cache.check_and_add("n1", expires_at=1300, now=1290)  # still inside the window
    assert cache.check_and_add("n2", expires_at=1700, now=1400)  # n1 purged after expiry


def test_tokens_in_urls_are_never_sent_to_intel_providers():
    from app.analyzers.reputation import lookup_safe_url

    assert lookup_safe_url("https://bank.example/reset?token=abc123&lang=en") == "https://bank.example/reset"
    assert lookup_safe_url("https://x.example/p?email=me@acme.com") == "https://x.example/p"
    key = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    assert key not in lookup_safe_url(f"https://x.example/p?q={key}")
    assert lookup_safe_url("https://news.example/a?utm_source=x") == "https://news.example/a?utm_source=x"


def test_intel_requests_carry_no_secrets():
    seen = []

    def handler(request):
        seen.append(str(request.url) + request.content.decode(errors="ignore"))
        return httpx.Response(404)

    c = ctx_for(html_body='<a href="https://evil.example/reset?token=SUPERSECRET123">x</a>')
    run(reputation(c, intel(handler, rdap=False)))
    assert seen and not any("SUPERSECRET123" in s for s in seen)
    vt_ids = [s.rsplit("/", 1)[-1] for s in seen if "virustotal" in s]
    assert not any("SUPERSECRET123" in base64.urlsafe_b64decode(i + "==").decode() for i in vt_ids)
