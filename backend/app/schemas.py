"""Request/response contract between the add-on and the backend.

Every field is bounded. The request is untrusted input (it is built from an email an
attacker wrote), so limits here are the first line of defence against resource abuse.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

MAX_INSPECTED_ATTACHMENT_BYTES = 2 * 1024 * 1024  # decoded size
_B64_LIMIT = (MAX_INSPECTED_ATTACHMENT_BYTES * 4) // 3 + 8

Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Attachment(_Strict):
    filename: str = Field(default="", max_length=512)
    content_type: str = Field(default="application/octet-stream", max_length=255)
    size: int = Field(ge=0, le=50 * 1024 * 1024)
    sha256: Sha256Hex
    # Only sent for small, inspectable file types (Office, PDF, archives). Never stored.
    content_b64: str | None = Field(default=None, max_length=_B64_LIMIT)


class SenderHistory(_Strict):
    """Computed by the add-on from the user's own mailbox; the backend never sees the mailbox."""

    prior_messages_from_sender: int = Field(ge=0, le=10_000)
    user_has_emailed_sender: bool
    # Verdict memory, kept by the add-on in the user's own (private) script storage, keyed by a
    # salted hash of the address. Counts exclude the message being analysed.
    prior_malicious_verdicts: int = Field(default=0, ge=0, le=1000)
    prior_suspicious_verdicts: int = Field(default=0, ge=0, le=1000)
    reported_sender: bool = False  # the user reported this sender to SecOps before
    blocked_sender: bool = False  # the user blocked this sender before
    prior_spam_messages: int = Field(default=0, ge=0, le=1000)  # earlier mail Gmail put in Spam
    domain_prior_malicious: int = Field(default=0, ge=0, le=1000)  # other senders from the same domain


class AnalyzeRequest(_Strict):
    client_version: str = Field(default="unknown", max_length=32)
    raw_headers: str = Field(max_length=128 * 1024)
    text_body: str = Field(default="", max_length=200_000)
    html_body: str = Field(default="", max_length=600_000)
    attachments: list[Attachment] = Field(default_factory=list, max_length=25)
    sender_history: SenderHistory | None = None
    # Only the *domain* of the recipient, used to detect look-alikes of the user's own org.
    recipient_domain: str = Field(default="", max_length=253)
    # UI language for titles and recommendations ("en", "he"); detection is always multilingual.
    locale: str = Field(default="en", pattern=r"^[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})?$")


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackRef(BaseModel):
    """A MITRE ATT&CK (or ATLAS, for attacks on AI) technique."""

    id: str
    name: str
    framework: str
    url: str


class FindingOut(BaseModel):
    id: str
    category: str
    title: str
    detail: str
    points: int
    evidence: list[str] = []
    attack: list[AttackRef] = []


class LinkOut(BaseModel):
    text: str
    destination: str  # defanged, never clickable
    domain: str
    flags: list[str]


class SenderOut(BaseModel):
    """Who the message claims to be from, and whether that claim is authenticated.

    The add-on uses ``authenticated`` to decide how to offer "Block sender": blocking a
    forged address would filter mail from the real owner, not the attacker."""

    email: str
    display_name: str
    domain: str
    authenticated: bool  # SPF/DKIM/DMARC tie this message to the From domain
    spoofed: bool  # authentication positively failed: the From address is likely forged


class AnalyzeResponse(BaseModel):
    engine_version: str
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    confidence: Confidence
    headline: str  # the single most important, specific threat ("" when nothing was found)
    summary: str
    findings: list[FindingOut]
    mitigations: list[FindingOut]
    recommendations: list[str]
    links: list[LinkOut]
    coverage: dict[str, str]  # analyser/provider name -> human-readable status
    sender: SenderOut | None
    subject: str  # cleaned, for display
    language: str  # detected language code of the email ("he", "en", ... or "")
    exposures: list[FindingOut]  # secrets found in the email; informational, never scored
    attack_techniques: list[AttackRef]  # union over findings, most severe first
    analysis_ms: float  # server-side processing time, parsing to verdict


class ReportRequest(_Strict):
    """A user-initiated "Report to SecOps". Carries indicators, not the message itself."""

    message_id_header: str = Field(default="", max_length=256)  # RFC 5322 Message-ID, for mailbox search
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    engine_version: str = Field(default="", max_length=32)
    sender_email: str = Field(default="", max_length=320)
    indicators: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=15)
    attack_techniques: list[Annotated[str, Field(pattern=r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")]] = Field(
        default_factory=list, max_length=20
    )
    user_note: str = Field(default="", max_length=500)


class ReportResponse(BaseModel):
    report_id: str
    status: str
