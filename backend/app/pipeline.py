"""Orchestrates parsing, analysers, threat intel and scoring for one email."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from . import i18n
from .analyzers import (
    attachments,
    authentication,
    cloud,
    content,
    hidden,
    history,
    links,
    reputation,
    sender,
    subject,
    visual,
)
from .analyzers.base import Analyzer, Category, Finding
from .analyzers.reputation import IntelClients
from .context import EmailContext, Link, build_context
from .language import detect as detect_language
from .schemas import AnalyzeRequest, AnalyzeResponse, LinkOut, SenderOut, Verdict
from .scoring import (
    MALICIOUS_AT,
    compute_score,
    confidence_for,
    merge_duplicates,
    recommendations,
    summarize,
    to_out,
    verdict_for,
)
from .textutil import clean, defang_url

ENGINE_VERSION = "1.4.4"
log = logging.getLogger("mailguard.pipeline")

# Order matters only for display; analysers are independent.
LOCAL_ANALYZERS: dict[str, Analyzer] = {
    "Sender authentication": authentication.analyze,
    "Sender identity": sender.analyze,
    "Subject line": subject.analyze,
    "Links": links.analyze,
    "Attachments": attachments.analyze,
    "Message content": content.analyze,
    "Sender history": history.analyze,
    "Cloud & identity attacks": cloud.analyze,
    "Hidden content & AI manipulation": hidden.analyze,
    "Images & emojis": visual.analyze,
}
FLAG_LABELS = {**links.FLAG_LABELS, **cloud.FLAG_LABELS}
MAX_LINKS_SHOWN = 12
LANGUAGE_LABEL = {
    "en": "English",
    "he": "Hebrew",
    "ar": "Arabic",
    "ru": "Russian",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
}


def _run_local(
    req: AnalyzeRequest, protected_domains: tuple[str, ...]
) -> tuple[EmailContext, list[Finding], dict[str, str], int, str]:
    """CPU-bound part: parsing and local analysers. Runs in a worker thread."""
    ctx = build_context(req, protected_domains)
    findings: list[Finding] = []
    coverage: dict[str, str] = {}
    errors = 0
    for name, analyzer in LOCAL_ANALYZERS.items():
        try:
            findings.extend(analyzer(ctx))
            coverage[name] = "checked"
        except Exception:  # one broken analyser must not hide the others' evidence
            errors += 1
            coverage[name] = "error"
            log.exception("analyser failed", extra={"analyser": name})
    if req.sender_history is None:
        coverage["Sender history"] = "not provided"
    lang = detect_language(f"{ctx.subject}\n{ctx.text[:20_000]}")
    coverage["Language"] = LANGUAGE_LABEL.get(lang, "not detected")
    if ctx.truncated:
        coverage["Message parsing"] = "partial (very large or malformed HTML)"
    return ctx, findings, coverage, errors, lang


class AnalysisBusy(Exception):
    """All analysis slots are taken: the caller should answer 503 + Retry-After."""


class _Slots:
    """Admission control for CPU-bound analysis.

    At most ``n`` analyses run at once, on a dedicated pool of ``n`` threads, and the rest get
    a fast 503 instead of degrading everyone. A slot is released by the job's *done callback*:
    that fires when the job finishes - however long after the request timed out (Python
    threads can't be killed) - and also when a job that never started is cancelled, so slots
    can never leak.
    """

    def __init__(self, n: int) -> None:
        self.n = n
        self._sem = threading.BoundedSemaphore(n)
        self.executor = ThreadPoolExecutor(max_workers=n, thread_name_prefix="mg-analyze")

    def try_acquire(self) -> bool:
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        self._sem.release()

    def submit(self, fn, *args):  # type: ignore[no-untyped-def]
        """Run ``fn`` in the pool; the caller must already hold a slot."""
        try:
            fut = self.executor.submit(fn, *args)
        except BaseException:
            self.release()
            raise
        fut.add_done_callback(lambda _f: self.release())
        return fut


_SLOTS = _Slots(4)


def configure(max_parallel: int) -> None:
    global _SLOTS
    if max_parallel != _SLOTS.n:
        _SLOTS = _Slots(max(1, max_parallel))


async def analyze_email(
    req: AnalyzeRequest,
    intel: IntelClients | None = None,
    protected_domains: tuple[str, ...] = (),
    wait_for_slot_s: float = 2.0,
) -> AnalyzeResponse:
    started = time.perf_counter()
    slots = _SLOTS
    deadline = time.monotonic() + wait_for_slot_s
    while not slots.try_acquire():
        if time.monotonic() >= deadline:
            raise AnalysisBusy
        await asyncio.sleep(0.05)
    # Off the event loop, so one pathological email cannot stall other requests or the
    # timeout that guards them.
    ctx, findings, coverage, errors, lang = await asyncio.wrap_future(slots.submit(_run_local, req, protected_domains))

    if intel is not None:
        intel_findings, intel_coverage = await reputation.analyze(ctx, intel)
        findings.extend(intel_findings)
        coverage.update(intel_coverage)

    findings = merge_duplicates(findings)
    score = compute_score(findings)
    verdict = verdict_for(score)
    authenticated = ctx.sender_authenticated()
    ui = i18n.ui_language(req.locale)
    # Recommendations are chosen from the English findings, then translated as whole sentences.
    recs = [i18n.recommendation(r, ui) for r in recommendations(verdict, findings, authenticated, ctx.sender_spoofed())]
    findings = [_localize(f, ui) for f in findings]
    # Conclusive evidence (a floor that alone makes the verdict malicious) leads; then by weight.
    risks = sorted(
        (f for f in findings if f.points > 0),
        key=lambda f: (-(f.floor or 0) if (f.floor or 0) >= MALICIOUS_AT else 0, -f.points),
    )
    mitigations = [f for f in findings if f.points < 0]
    exposures = [f for f in findings if f.category == Category.EXPOSURE]
    risk_out = [to_out(f) for f in risks]
    techniques = list({ref.id: ref for fo in risk_out for ref in fo.attack}.values())  # exposures are not attacks

    sender = None
    if ctx.from_addr and ctx.from_addr.email:
        sender = SenderOut(
            email=clean(ctx.from_addr.email, 320),
            display_name=clean(ctx.from_addr.name, 120),
            domain=clean(ctx.from_addr.host.unicode_host if ctx.from_addr.host else "", 253),
            authenticated=authenticated,
            spoofed=ctx.sender_spoofed(),
        )
    headline = ""
    if risks and verdict is not Verdict.SAFE:
        top = risks[0]
        # English details already name the specifics; the Hebrew explanation is generic, so add the evidence.
        headline = top.detail if ui == "en" else f"{top.title}" + (f": {top.evidence[0]}" if top.evidence else "")

    return AnalyzeResponse(
        engine_version=ENGINE_VERSION,
        score=score,
        verdict=verdict,
        headline=clean(headline, 300),
        confidence=confidence_for(findings, coverage, errors, partial=ctx.truncated),
        summary=summarize(verdict, risks, ui),
        findings=risk_out,
        mitigations=[to_out(f) for f in mitigations],
        recommendations=recs,
        links=_link_views(ctx.links, ui),
        coverage=dict(i18n.coverage_entry(k, v, ui) for k, v in coverage.items()),
        sender=sender,
        subject=clean(ctx.subject, 200),
        language=lang,
        exposures=[to_out(f) for f in exposures],
        attack_techniques=techniques,
        analysis_ms=round((time.perf_counter() - started) * 1000, 1),
    )


def _localize(f: Finding, ui: str) -> Finding:
    text = i18n.finding_text(f.id, dict(f.params), ui)
    return replace(f, title=text[0], detail=text[1]) if text else f


def _link_views(all_links: list[Link], ui: str = "en") -> list[LinkOut]:
    """A de-fanged 'where does this really go' table, flagged links first."""
    seen: set[str] = set()
    views: list[LinkOut] = []
    for lk in sorted(all_links, key=lambda x: -len(x.flags)):
        if lk.href in seen or len(views) >= MAX_LINKS_SHOWN:
            continue
        seen.add(lk.href)
        domain = lk.host.unicode_host if lk.host else (lk.scheme or "?")
        if lk.host and lk.host.is_idn:
            domain = f"{lk.host.unicode_host} ({lk.host.host})"
        views.append(
            LinkOut(
                text=clean(lk.text, 60),
                destination=defang_url(lk.href, 80),
                domain=clean(domain, 80),
                flags=[i18n.link_flag(FLAG_LABELS.get(f, f), ui) for f in dict.fromkeys(lk.flags)],
            )
        )
    return views
