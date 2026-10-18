"""Shared types for analysers.

An analyser is a pure function ``(EmailContext) -> list[Finding]``. Keeping analysers
independent and side-effect free makes each one trivially unit-testable and lets the
pipeline isolate a failure in one of them from the others.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..context import EmailContext


class Category:
    AUTHENTICATION = "Sender authentication"
    SENDER = "Sender identity"
    LINKS = "Links"
    ATTACHMENTS = "Attachments"
    CONTENT = "Message content"
    SOCIAL = "Social engineering pattern"
    HISTORY = "Your history with the sender"
    REPUTATION = "Threat intelligence"
    SUBJECT = "Subject line"
    VISUAL = "Images & emojis"
    CLOUD = "Cloud & identity attacks"
    EVASION = "Hidden content & AI manipulation"
    EXPOSURE = "Sensitive data exposure"  # informational: never changes the maliciousness score


@dataclass(frozen=True)
class Finding:
    """One explainable piece of evidence.

    ``points`` is the contribution to the 0-100 risk score (negative = reassuring).
    ``floor`` forces a minimum final score, for evidence that is conclusive on its own
    (e.g. multiple threat-intel engines agree a URL is malicious).
    """

    id: str
    category: str
    title: str
    detail: str
    points: int
    evidence: tuple[str, ...] = field(default_factory=tuple)
    floor: int | None = None
    # Values interpolated into translated titles, e.g. {"brand": "PayPal"} (see app/i18n.py).
    params: tuple[tuple[str, str], ...] = ()


Analyzer = Callable[[EmailContext], list[Finding]]
