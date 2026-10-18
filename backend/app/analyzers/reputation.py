"""Threat-intelligence enrichment: known-bad URLs/files and newly registered domains.

Runs after the local analysers so it can spend a scarce lookup budget on the most
suspicious indicators first. Every provider is optional and time-boxed: if one is
slow, rate-limited or down, the verdict is still produced and the UI says what was
not checked - a missing check must never silently look like a clean result.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import dataclass
from urllib.parse import urldefrag

from ..context import EmailContext, Link
from ..domains import FREE_MAIL_DOMAINS, brand_for_domain
from ..intel.http import IntelError, RateLimited
from ..intel.providers import Rdap, SafeBrowsing, VirusTotal
from ..redact import lookup_safe_url
from ..textutil import clean, defang_domain, defang_url
from .attachments import EXECUTABLE_EXT, HTML_EXT, MACRO_EXT
from .base import Category, Finding
from .links import ESP_TRACKING, SHORTENERS

C = Category.REPUTATION
log = logging.getLogger("mailguard.intel")

MAX_SB_URLS = 25
MAX_RDAP_DOMAINS = 4


@dataclass
class IntelClients:
    vt: VirusTotal | None
    safe_browsing: SafeBrowsing | None
    rdap: Rdap | None
    vt_max_lookups: int = 4
    deadline_s: float = 8.0


ProviderResult = tuple[list[Finding], str]


def _candidate_urls(ctx: EmailContext) -> list[str]:
    """Unique web URLs, most suspicious first."""
    links = [lk for lk in ctx.links if lk.host is not None and lk.scheme in ("http", "https")]

    def priority(lk: Link) -> tuple[int, int]:
        trusted = lk.host is not None and brand_for_domain(lk.host.registrable) is not None
        return (-len(lk.flags), 1 if trusted else 0)

    seen: dict[str, None] = {}
    for lk in sorted(links, key=priority):
        seen.setdefault(lookup_safe_url(urldefrag(lk.href)[0]), None)
    return list(seen)


def _rdap_domains(ctx: EmailContext) -> list[tuple[str, str]]:
    """(domain, role) pairs worth an age check - skips brands, webmail and shorteners."""
    skip = FREE_MAIL_DOMAINS | SHORTENERS | ESP_TRACKING
    out: dict[str, str] = {}
    if ctx.from_addr and ctx.from_addr.host and not ctx.from_addr.host.is_ip:
        d = ctx.from_addr.host.registrable
        if d not in skip and not brand_for_domain(d):
            out[d] = "sender"
    for lk in sorted(ctx.links, key=lambda x: -len(x.flags)):
        if len(out) >= MAX_RDAP_DOMAINS:
            break
        if lk.host and not lk.host.is_ip:
            d = lk.host.registrable
            if d not in skip and d not in out and not brand_for_domain(d):
                out[d] = "link"
    return list(out.items())


async def _safe_browsing(sb: SafeBrowsing, urls: list[str]) -> ProviderResult:
    urls = urls[:MAX_SB_URLS]
    if not urls:
        return [], "no links to check"
    matches = await sb.check(urls)
    findings = []
    if matches:
        kinds = sorted(set(matches.values()))
        findings.append(
            Finding(
                "INTEL_SAFE_BROWSING",
                C,
                "Google Safe Browsing lists a link as dangerous",
                f"Google has flagged {defang_url(next(iter(matches)), 70)}"
                + (f" and {len(matches) - 1} more link(s)" if len(matches) > 1 else "")
                + f" as {', '.join(k.replace('_', ' ').lower() for k in kinds)}.",
                60,
                tuple(defang_url(u, 70) for u in list(matches)[:3]),
                floor=85,
            )
        )
    return findings, f"checked {len(urls)} link(s)"


async def _virustotal(vt: VirusTotal, ctx: EmailContext, urls: list[str], budget: int) -> ProviderResult:
    findings: list[Finding] = []
    risky = EXECUTABLE_EXT | HTML_EXT | MACRO_EXT
    atts = sorted(ctx.attachments, key=lambda a: a.filename.rsplit(".", 1)[-1].lower() not in risky)
    jobs: list[tuple[str, str, Awaitable]] = []
    for att in atts:
        if len(jobs) < budget:
            jobs.append(("file", clean(att.filename, 60), vt.file(att.sha256)))
    for url in urls:
        if len(jobs) < budget:
            jobs.append(("url", defang_url(url, 70), vt.url(url)))
    if not jobs:
        return [], "nothing to check"

    results = await asyncio.gather(*(j[2] for j in jobs), return_exceptions=True)
    checked, limited = 0, False
    for (kind, label, _), res in zip(jobs, results, strict=True):
        if isinstance(res, RateLimited):
            limited = True
            continue
        if isinstance(res, BaseException):
            continue
        checked += 1
        if not res.found:
            continue
        noun = "attachment" if kind == "file" else "link"
        if res.malicious >= 3:
            findings.append(
                Finding(
                    f"INTEL_VT_{kind.upper()}_MALICIOUS",
                    C,
                    f"Known-malicious {noun} (VirusTotal)",
                    f"{res.malicious} of {res.total} security vendors on VirusTotal flag {label} as malicious.",
                    60 if kind == "file" else 50,
                    (label,),
                    floor=90 if kind == "file" else 80,
                )
            )
        elif res.malicious >= 1 or res.suspicious >= 2:
            findings.append(
                Finding(
                    f"INTEL_VT_{kind.upper()}_SUSPICIOUS",
                    C,
                    f"Some vendors flag this {noun} (VirusTotal)",
                    f"{res.malicious} malicious and {res.suspicious} suspicious detections out of {res.total} vendors.",
                    15,
                    (label,),
                )
            )
    if checked == 0 and limited:
        raise RateLimited("all lookups rate limited")
    status = f"checked {checked} of {len(jobs)} indicator(s)"
    return findings, status + (" (rate-limited, rest skipped)" if limited else "")


async def _rdap(rdap: Rdap, ctx: EmailContext) -> ProviderResult:
    domains = _rdap_domains(ctx)
    if not domains:
        return [], "only well-known domains"
    ages = await asyncio.gather(*(rdap.age_days(d) for d, _ in domains), return_exceptions=True)
    findings: list[Finding] = []
    known = 0
    for (domain, role), age in zip(domains, ages, strict=True):
        if not isinstance(age, int):
            continue
        known += 1
        if age >= 90:
            continue
        when = "today" if age == 0 else f"{age} day{'s' if age != 1 else ''} ago"
        if role == "sender":
            pts = 40 if age < 7 else 30 if age < 30 else 10
            fid, title = "INTEL_NEW_SENDER_DOMAIN", "Sender domain was registered very recently"
        else:
            pts = 30 if age < 7 else 20 if age < 30 else 8
            fid, title = "INTEL_NEW_LINK_DOMAIN", "Link points to a brand-new domain"
        findings.append(
            Finding(
                fid,
                C,
                title,
                f"{defang_domain(domain)} was registered {when}. Phishing domains are typically used "
                "within days of registration, before blocklists catch up.",
                pts,
                (defang_domain(domain),),
            )
        )
    return findings, f"checked {known} of {len(domains)} domain(s)"


async def analyze(ctx: EmailContext, intel: IntelClients) -> tuple[list[Finding], dict[str, str]]:
    urls = _candidate_urls(ctx)
    coverage: dict[str, str] = {}
    tasks: dict[str, asyncio.Task[ProviderResult]] = {}

    if intel.safe_browsing:
        tasks["Google Safe Browsing"] = asyncio.create_task(_safe_browsing(intel.safe_browsing, urls))
    else:
        coverage["Google Safe Browsing"] = "not configured"
    if intel.vt:
        tasks["VirusTotal"] = asyncio.create_task(_virustotal(intel.vt, ctx, urls, intel.vt_max_lookups))
    else:
        coverage["VirusTotal"] = "not configured"
    if intel.rdap:
        tasks["Domain age (RDAP)"] = asyncio.create_task(_rdap(intel.rdap, ctx))
    else:
        coverage["Domain age (RDAP)"] = "disabled"

    findings: list[Finding] = []
    if tasks:
        _done, pending = await asyncio.wait(tasks.values(), timeout=intel.deadline_s)
        for t in pending:
            t.cancel()
        for name, task in tasks.items():
            if task in pending:
                coverage[name] = "timed out"
            elif isinstance(task.exception(), RateLimited):
                coverage[name] = "rate-limited"
            elif isinstance(task.exception(), IntelError):
                log.warning("intel provider failed", extra={"provider": name, "error": str(task.exception())})
                coverage[name] = "unavailable"
            elif task.exception() is not None:
                log.error("intel provider crashed", extra={"provider": name, "error": type(task.exception()).__name__})
                coverage[name] = "unavailable"
            else:
                f, status = task.result()
                findings.extend(f)
                coverage[name] = status
    return findings, coverage
