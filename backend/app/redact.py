"""Privacy guard: secrets and sensitive URL parts.

One place decides what may be *shown* (to the user, in a SecOps report) and what may be
*disclosed* (to a threat-intel provider). Links in email routinely carry credentials -
password-reset tokens, signed-URL signatures, meeting passwords, API keys - and none of
that should reach a log, a report or a third party.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

# ----------------------------------------------------------------------------- invisible characters

# Every Unicode "format" character (zero-width spaces/joiners, bidi controls, soft hyphen, ...).
# Removing them before matching stops "ign<U+200B>ore previous instructions" style evasions.
_FORMAT_CHARS = {cp: None for cp in range(0x10000) if unicodedata.category(chr(cp)) == "Cf"}


def strip_format(text: str) -> str:
    return text.translate(_FORMAT_CHARS)


# ----------------------------------------------------------------------------- secrets

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\b((?:AKIA|ASIA)[A-Z2-7]{16})\b")),
    ("AWS secret key", re.compile(r"(?i)aws_?secret_?access_?key\W{0,5}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")),
    ("GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b")),
    ("GitHub token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})")),
    ("GitLab token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})")),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])")),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})")),
    ("Slack webhook", re.compile(r"(hooks\.slack\.com/services/[A-Za-z0-9/]{20,})")),
    ("Stripe secret key", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})")),
    ("Private key", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)")),
    ("Azure storage key", re.compile(r"(AccountKey=[A-Za-z0-9+/=]{80,})")),
)


def mask(secret: str) -> str:
    """Enough to recognise the secret, never enough to use it."""
    if secret.startswith("-----BEGIN"):
        return secret
    return f"{secret[:4]}…{secret[-4:]} ({len(secret)} chars)" if len(secret) > 12 else "…"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """(kind, value) pairs. Public documentation examples (…EXAMPLE…) are ignored."""
    found: list[tuple[str, str]] = []
    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1)
            if "EXAMPLE" in value.upper():
                continue
            found.append((kind, value))
            if len(found) >= 20:
                return found
    return found


def contains_secret(text: str) -> bool:
    return bool(find_secrets(text))


def mask_secrets(text: str) -> str:
    for _, value in find_secrets(text):
        text = text.replace(value, mask(value).split(" (")[0])
    return text


# ----------------------------------------------------------------------------- URLs

# Query parameters that are safe to keep when a URL is shared with a third party.
# Everything else (token, sig, pwd, jwt, code, email, X-Goog-Signature, ...) is dropped.
_HARMLESS_PARAMS = re.compile(r"(?i)^(utm_[a-z]+|lang|hl|locale|page|ref|source|campaign)$")
# Parameter names whose *values* must never be displayed or logged.
SENSITIVE_PARAM = re.compile(
    r"(?i)(token|secret|passw|pwd|pass$|session|auth|^key$|api_?key|sig|signature|credential|^code$|otp|"
    r"reset|ticket|^state$|nonce|jwt|email|^user(name)?$|sso|saml)"
)
# A path segment that looks like a credential: long, and mixing letters with digits.
_TOKENISH_SEGMENT = re.compile(r"^(?=[A-Za-z0-9_\-.~%]{20,}$)(?=.*[A-Za-z])(?=.*[0-9]).*$")


def _split(url: str):  # type: ignore[no-untyped-def]
    try:
        return urlsplit(url)
    except ValueError:
        return None


def _netloc_without_userinfo(netloc: str) -> str:
    return netloc.rsplit("@", 1)[-1]


def redact_url(url: str) -> str:
    """For display and reports: same URL, credentials replaced by '…'.

    The host and path stay visible (that is what the user and the analyst need); userinfo,
    sensitive parameter values and credential-shaped path segments do not.
    """
    p = _split(url)
    if p is None or not p.scheme:
        return mask_secrets(url)
    netloc = p.netloc
    if "@" in netloc:
        user = netloc.rsplit("@", 1)[0]
        # Keep the visible "user" part (it is often the trick itself: paypal.com@evil), drop a password.
        netloc = user.split(":", 1)[0] + ":…@" + _netloc_without_userinfo(netloc) if ":" in user else netloc
    segments = [("…" if _TOKENISH_SEGMENT.match(s) else s) for s in p.path.split("/")]
    try:
        params = parse_qsl(p.query, keep_blank_values=True)
    except ValueError:
        params = []
    query = "&".join(
        quote(k, safe="") + "=" + ("…" if SENSITIVE_PARAM.search(k) else quote(v, safe="/:@")) for k, v in params
    )
    return mask_secrets(urlunsplit((p.scheme, netloc, "/".join(segments), query, "")))


def lookup_safe_url(url: str) -> str:
    """The form of a URL that may be disclosed to a threat-intel provider.

    A lookup reveals the URL to the provider, so: userinfo is always removed; the query is
    kept only if *every* parameter is on a short allow-list of harmless names; and if any
    path segment looks like a credential the path is dropped too. A few exact-URL matches
    are lost - the price of never leaking a user's reset link, signed URL or API key.
    """
    p = _split(url)
    if p is None or not p.scheme or not p.hostname:
        return url
    host = p.netloc.rsplit("@", 1)[-1]
    try:
        params = parse_qsl(p.query, keep_blank_values=True)
    except ValueError:
        params = [("x", "x")]
    query = p.query if params and all(_HARMLESS_PARAMS.match(k) for k, _ in params) else ""
    path = p.path or "/"
    if any(_TOKENISH_SEGMENT.match(unquote(s)) for s in path.split("/")) or contains_secret(unquote(url)):
        path, query = "/", ""
    return urlunsplit((p.scheme.lower(), host.lower(), path, query, ""))
