"""Helpers for turning attacker-controlled strings into safe, display-ready text."""

from __future__ import annotations

import re
import unicodedata

from .redact import mask_secrets, redact_url

# Bidirectional overrides/isolates and zero-width characters. They let an attacker make
# "invoice<U+202E>fdp.exe" render as "invoiceexe.pdf", or hide text inside a URL.
BIDI_AND_INVISIBLE = frozenset(
    chr(cp)
    for cp in (
        *range(0x200B, 0x2010),  # zero-width space/joiners, LRM, RLM
        *range(0x202A, 0x202F),  # LRE, RLE, PDF, LRO, RLO
        *range(0x2066, 0x206A),  # LRI, RLI, FSI, PDI
        0x2060,  # word joiner
        0xFEFF,  # zero-width no-break space / BOM
    )
)
_WS = re.compile(r"\s+")


def has_hidden_unicode(text: str) -> bool:
    return any(ch in BIDI_AND_INVISIBLE for ch in text)


def clean(text: str | None, max_len: int = 300) -> str:
    """Strip control/bidi characters, collapse whitespace and truncate.

    Output of this function is still *untrusted* (the add-on HTML-escapes it before
    rendering); this only guarantees it is short, single-line and visually honest.
    """
    if not text:
        return ""
    out = []
    for ch in text:
        if ch in BIDI_AND_INVISIBLE:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co"):
            out.append(" ")
            continue
        out.append(ch)
    s = _WS.sub(" ", "".join(out)).strip()
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def defang_url(url: str, max_len: int = 90) -> str:
    """Render a URL so it is readable but not clickable or auto-linkified."""
    s = clean(url, max_len=4000)
    if "[.]" in s or s.lower().startswith("hxxp"):
        return clean(mask_secrets(s), max_len)  # already de-fanged (e.g. indicators echoed back by the add-on)
    s = clean(redact_url(s), max_len)  # credentials never reach the screen, a report or a log
    s = re.sub(r"(?i)^http", "hxxp", s)
    return s.replace(".", "[.]").replace("://", "[://]")


def defang_domain(domain: str) -> str:
    return clean(domain, 120).replace(".", "[.]")
