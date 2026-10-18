"""Turn findings into a 0-100 score, a verdict and an explanation.

Design: additive points with per-category caps, plus hard floors.

* Additive points keep the result explainable: every point on screen traces to a finding.
* Category caps stop one noisy dimension from dominating - twenty urgent words cannot
  push an email to "malicious" by themselves; it takes evidence across dimensions.
* Floors let conclusive evidence (three VirusTotal engines, a disguised .exe) decide the
  verdict even if nothing else looks wrong.
* Reassuring findings subtract, but their total is capped, so a well-authenticated
  attacker domain cannot launder strong red flags.
"""

from __future__ import annotations

from collections import defaultdict

from . import i18n
from .analyzers.base import Category, Finding
from .mitre import techniques_for
from .schemas import AttackRef, Confidence, FindingOut, Verdict

CATEGORY_CAPS = {
    Category.AUTHENTICATION: 35,
    Category.SENDER: 45,
    Category.LINKS: 45,
    Category.ATTACHMENTS: 60,
    Category.CONTENT: 25,
    Category.SOCIAL: 20,
    Category.HISTORY: 50,  # first contact alone is +10; past malicious verdicts can add more
    Category.REPUTATION: 100,
    Category.SUBJECT: 30,
    Category.VISUAL: 35,
    Category.CLOUD: 50,
    Category.EVASION: 45,
    Category.EXPOSURE: 0,  # informational only
}
MAX_MITIGATION = 20
SUSPICIOUS_AT = 30
MALICIOUS_AT = 65


def merge_duplicates(findings: list[Finding]) -> list[Finding]:
    """The same rule can fire for several links/attachments; count it once, keep evidence."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        prev = by_id.get(f.id)
        if prev is None:
            by_id[f.id] = f
            continue
        evidence = tuple(dict.fromkeys(prev.evidence + f.evidence))[:3]
        strongest = f if f.points > prev.points else prev
        floor = max(x for x in (prev.floor, f.floor, -1) if x is not None)
        by_id[f.id] = Finding(
            strongest.id,
            strongest.category,
            strongest.title,
            strongest.detail,
            strongest.points,
            evidence,
            floor if floor >= 0 else None,
            strongest.params,
        )
    return list(by_id.values())


def compute_score(findings: list[Finding]) -> int:
    per_cat: dict[str, int] = defaultdict(int)
    mitigation = 0
    for f in findings:
        if f.points >= 0:
            per_cat[f.category] += f.points
        else:
            mitigation += -f.points
    risk = sum(min(CATEGORY_CAPS.get(cat, 30), pts) for cat, pts in per_cat.items())
    score = risk - min(mitigation, MAX_MITIGATION)
    floors = [f.floor for f in findings if f.floor is not None]
    if floors:
        score = max(score, max(floors))
    return max(0, min(100, score))


def verdict_for(score: int) -> Verdict:
    if score >= MALICIOUS_AT:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def confidence_for(
    findings: list[Finding], coverage: dict[str, str], analyzer_errors: int, partial: bool = False
) -> Confidence:
    """How much of the picture we actually saw - shown so 'safe' is never overstated."""
    if analyzer_errors:
        return Confidence.LOW
    degraded = sum(1 for v in coverage.values() if v in {"unavailable", "timed out", "rate-limited"})
    no_auth = any(f.id == "AUTH_MISSING" for f in findings)
    if degraded >= 2 or (degraded and no_auth):
        return Confidence.LOW
    if degraded or no_auth or partial:
        return Confidence.MEDIUM
    return Confidence.HIGH


def summarize(verdict: Verdict, risks: list[Finding], ui: str = "en") -> str:
    """Lead sentence plus up to three reasons. ``risks`` titles must already be in the UI language."""
    if not risks:
        return i18n.summary(verdict.value, [], ui) or "No warning signs were found in this message."
    # One reason per category first, so the summary shows breadth of evidence
    # rather than three variations of the same attachment problem.
    picked: list[Finding] = []
    for f in risks:
        if f.category not in {p.category for p in picked}:
            picked.append(f)
    picked = (picked + [f for f in risks if f not in picked])[:3]
    lead = {
        Verdict.MALICIOUS: "This looks like a phishing or malware email.",
        Verdict.SUSPICIOUS: "Treat this email with caution.",
        Verdict.SAFE: "Probably fine, with minor notes.",
    }[verdict]
    localized = i18n.summary(verdict.value, [f.title for f in picked], ui)
    if localized:
        return localized
    return f"{lead} Main reasons: {'; '.join(f.title.rstrip('.') for f in picked)}."


def recommendations(
    verdict: Verdict,
    findings: list[Finding],
    sender_authenticated: bool = False,
    sender_spoofed: bool = False,
) -> list[str]:
    """Concrete next steps, tied to what was found and to the action buttons in the add-on."""
    cats = {f.category for f in findings if f.points > 0}
    ids = {f.id for f in findings}
    recs: list[str] = []
    exposed = sorted({f.title.removesuffix(" in this email") for f in findings if f.category == Category.EXPOSURE})
    if exposed:
        recs.append(
            f"🔑 Revoke and rotate the exposed {', '.join(exposed)} now - assume anyone with access to this "
            "email can use it - and ask the sender to share secrets through a secrets manager."
        )
    if verdict is Verdict.SAFE:
        return [*recs, "No other action needed. If anything in the message surprises you, verify it with the sender."]
    if "CLOUD_DEVICE_CODE" in ids:
        recs.append(
            "Never enter a sign-in code that arrived by email. If you already did, sign out of all sessions and "
            "tell your security team - the attacker may hold a valid token."
        )
    if "CLOUD_OAUTH_CONSENT" in ids:
        recs.append(
            "Don't approve the app. If you already did, remove it from your account's third-party app access "
            "page and report it."
        )
    if "HIDDEN_PROMPT_INJECTION" in ids:
        recs.append("Don't rely on an AI summary of this email - it contains hidden instructions written for AI tools.")
    link_intel = {"INTEL_SAFE_BROWSING", "INTEL_VT_URL_MALICIOUS", "INTEL_VT_URL_SUSPICIOUS", "INTEL_NEW_LINK_DOMAIN"}
    if Category.LINKS in cats or ids & link_intel:
        recs.append("Don't click the links. If you need the site, type its address yourself or use a bookmark.")
    if Category.ATTACHMENTS in cats or "INTEL_VT_FILE_MALICIOUS" in ids:
        recs.append('Don\'t download or open the attachments, and never click "Enable content".')
    if ids & {
        "CONTENT_PAYMENT",
        "CONTENT_SECRECY",
        "SENDER_FREEMAIL_ROLE",
        "SENDER_REPLYTO_MISMATCH",
        "CONTENT_BEC_PATTERN",
    }:
        recs.append(
            "Verify any payment or bank-detail change by phone, using a number you already know - "
            "not one from this email."
        )
    if ids & {"CONTENT_CREDENTIALS", "LINK_EMBEDDED_FORM", "ATT_HTML"}:
        recs.append("Never enter your password or codes from a link in an email.")
    if verdict is Verdict.MALICIOUS:
        recs.append("Report it to SecOps, then move it to Trash (buttons below).")
        if sender_authenticated:
            recs.append("Block the sender: the address is authenticated, so blocking only stops this sender.")
        elif sender_spoofed:
            recs.append(
                "Don't block this address - it is forged, so blocking it would filter mail from the real "
                "owner, not the attacker. Reporting is the right action."
            )
        else:
            recs.append(
                "Think twice before blocking: the sender address could not be verified, so it may belong to "
                "someone else. Reporting is always safe."
            )
        recs.append("If you already clicked or entered details, change your password and tell your IT/security team.")
    else:
        recs.append("If you are unsure, contact the sender through a channel you already trust, or report it.")
    return recs


def attack_refs(finding_id: str) -> list[AttackRef]:
    return [AttackRef(id=t.id, name=t.name, framework=t.framework, url=t.url) for t in techniques_for(finding_id)]


def to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id,
        category=f.category,
        title=f.title,
        detail=f.detail,
        points=f.points,
        evidence=list(f.evidence),
        attack=attack_refs(f.id),
    )
