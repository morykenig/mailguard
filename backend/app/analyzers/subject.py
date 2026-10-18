"""The subject line: the first thing a victim reads, and a favourite place for tricks.

* Fake replies - "RE: Invoice 8812" makes a first contact look like an ongoing conversation.
  A genuine reply carries threading headers (In-Reply-To / References / Thread-Index); a
  subject that claims to be a reply without any of them was written to look like one.
* Alarm framing - "[ACTION REQUIRED]", "FINAL NOTICE!!!", ALL CAPS.
* Obfuscation - letters from other alphabets inside words ("PаyPal") or invisible
  characters, used to slip past keyword filters.

Social-engineering *phrases* in the subject are matched by the content analyser (which reads
subject and body together, in seven languages); emojis by the visual analyser.
"""

from __future__ import annotations

import re

from ..context import EmailContext
from ..language import obfuscated_words
from ..textutil import clean, has_hidden_unicode
from .base import Category, Finding

C = Category.SUBJECT

# Reply prefixes across mail clients and languages (English/German/Nordic/Polish/Italian/
# Spanish/Portuguese/Russian/Hebrew/Arabic/Chinese/Japanese).
_REPLY_PREFIX = re.compile(
    r"^\s*(?:re|aw|sv|vs|antw|odp|rif|res|ответ|השב|תשובה|رد|回复|返信)\s*(?:\[\d{1,3}\]|\(\d{1,3}\))?\s*[:：]",
    re.IGNORECASE,
)
_THREAD_HEADERS = ("In-Reply-To", "References", "Thread-Index", "Thread-Topic")
_ALARM_TAG = re.compile(
    r"(?i)[\[(](?:urgent|action required|important|final notice|warning|alert|security alert|immediate action|"
    r"דחוף|חשוב|פעולה נדרשת|התראה|срочно|важно|عاجل|urgente|dringend|wichtig)[\])]"
    r"|^(?:urgent|action required|final notice|security alert|security warning|important)\s*[:!-]"
    r"|^(?:אזהרת אבטחה|התראת אבטחה|דחוף|הודעה אחרונה)\s*[:!-]"
    r"|!{2,}"
)


def _caps_ratio(text: str) -> tuple[int, float]:
    """Share of capitals among Latin letters - only meaningful when the subject is mostly Latin.

    A Hebrew subject that names a brand in capitals ("... DYSON ... DREAM CARD") is not shouting.
    """
    letters = [c for c in text if c.isalpha()]
    latin = [c for c in letters if c.isascii()]
    if not latin or len(latin) < 0.6 * len(letters):
        return 0, 0.0
    return len(latin), sum(c.isupper() for c in latin) / len(latin)


def analyze(ctx: EmailContext) -> list[Finding]:
    subject = ctx.subject or ""
    if not subject.strip():
        return []
    shown = clean(subject, 120)
    out: list[Finding] = []

    if _REPLY_PREFIX.match(subject) and not any(ctx.headers.get(h) for h in _THREAD_HEADERS):
        knows_sender = bool(ctx.history and ctx.history.user_has_emailed_sender)
        if not knows_sender:
            out.append(
                Finding(
                    "SUBJECT_FAKE_REPLY",
                    C,
                    "Pretends to be a reply to you",
                    f"The subject '{shown}' looks like a reply, but the message carries none of the headers a "
                    "real reply has (In-Reply-To, References). Fake replies make a first contact look like an "
                    "ongoing conversation you already trust.",
                    15,
                    (shown,),
                )
            )

    letters, caps = _caps_ratio(subject)
    tag = _ALARM_TAG.search(subject)
    if tag or (letters >= 12 and caps >= 0.7):
        out.append(
            Finding(
                "SUBJECT_ALARM",
                C,
                "Alarmist subject line",
                f"The subject '{shown}' is written to alarm"
                + (f" ('{clean(tag.group(0), 30)}')" if tag else " (mostly capital letters)")
                + ". Pressure in the subject is meant to get you to act before reading carefully.",
                8,
                (shown,),
            )
        )

    words = obfuscated_words(subject)
    if words:
        out.append(
            Finding(
                "SUBJECT_OBFUSCATED",
                C,
                "Disguised letters in the subject",
                f"'{clean(words[0], 30)}' in the subject mixes letters from different alphabets (or uses "
                "full-width letters) so that it looks normal to you but not to spam filters.",
                20,
                tuple(clean(w, 30) for w in words[:3]),
            )
        )

    if has_hidden_unicode(subject):
        out.append(
            Finding(
                "SUBJECT_HIDDEN_CHARS",
                C,
                "Invisible characters in the subject",
                "The subject contains zero-width or direction-changing characters, which split words to dodge "
                "filters or reorder what you see.",
                15,
                (shown,),
            )
        )
    return out
