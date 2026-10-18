"""Language identification and script-mixing detection - offline, no dependencies.

Phishing is not an English-only problem: Israeli users receive Hebrew lures ("your package
is waiting, pay the customs fee"), and campaigns run in every language. MailGuard matches
social-engineering patterns in seven languages; this module tells the UI which language an
email is in, and spots a classic filter-evasion trick: letters from different alphabets mixed
*inside one word* ("PаyPal" with a Cyrillic "а", "Ｐａｙｐａｌ" in full-width letters). Ordinary
Russian, Greek or Hebrew text is never flagged - only words that mix alphabets.
"""

from __future__ import annotations

import re
import unicodedata

LANG_NAMES = {
    "en": "English",
    "he": "Hebrew",
    "ar": "Arabic",
    "ru": "Russian",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
}
SUPPORTED = tuple(LANG_NAMES)

_SCRIPT_RANGES = (
    ("he", 0x0590, 0x05FF),
    ("ar", 0x0600, 0x06FF),
    ("ru", 0x0400, 0x04FF),  # Cyrillic
)
# A handful of very frequent function words per Latin-script language.
_STOPWORDS = {
    "en": {"the", "and", "you", "your", "to", "of", "is", "for", "please", "this", "with", "account"},
    "es": {"el", "la", "los", "las", "de", "que", "y", "su", "por", "para", "usted", "cuenta", "es"},
    "fr": {"le", "la", "les", "de", "des", "et", "vous", "votre", "pour", "est", "une", "compte"},
    "de": {"der", "die", "das", "und", "sie", "ihr", "ihre", "ist", "nicht", "mit", "bitte", "konto"},
}
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def detect(text: str) -> str:
    """Best-guess language code of ``text`` ('' if there is too little text)."""
    sample = text[:20_000]
    counts = {code: 0 for code, _, _ in _SCRIPT_RANGES}
    latin = 0
    for ch in sample:
        cp = ord(ch)
        if ch.isascii():
            latin += ch.isalpha()
            continue
        for code, lo, hi in _SCRIPT_RANGES:
            if lo <= cp <= hi:
                counts[code] += 1
                break
    best = max(counts, key=counts.__getitem__)
    if counts[best] >= 8 and counts[best] >= latin * 0.3:
        return best
    if latin < 20:
        return ""
    words = [w.lower() for w in _WORD.findall(sample[:5000])]
    scores = {code: sum(1 for w in words if w in stop) for code, stop in _STOPWORDS.items()}
    lang = max(scores, key=scores.__getitem__)
    return lang if scores[lang] >= 2 else "en"


def _script(ch: str) -> str:
    cp = ord(ch)
    if ch.isascii():
        return "latin" if ch.isalpha() else ""
    if 0xFF21 <= cp <= 0xFF3A or 0xFF41 <= cp <= 0xFF5A:
        return "fullwidth"
    if 0x0400 <= cp <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "greek"
    if unicodedata.category(ch).startswith("L") and 0x00C0 <= cp <= 0x024F:
        return "latin"  # accented Latin (é, ü, ñ) is ordinary Latin
    return "other"


def obfuscated_words(text: str, limit: int = 5) -> list[str]:
    """Words that mix Latin with look-alike alphabets, or use full-width letters."""
    out: list[str] = []
    for m in _WORD.finditer(text[:50_000]):
        word = m.group(0)
        scripts = {_script(c) for c in word} - {""}
        mixed = "latin" in scripts and scripts & {"cyrillic", "greek"}
        if mixed or "fullwidth" in scripts:
            out.append(word)
            if len(out) >= limit:
                break
    return out
