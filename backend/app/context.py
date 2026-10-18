"""Parse an AnalyzeRequest into a normalised EmailContext that analysers can consume.

Parsing is defensive: malformed headers, broken HTML or odd encodings must degrade to
"less information", never to an exception that skips analysis.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from .domains import FREE_MAIL_DOMAINS, HostInfo, host_info
from .schemas import AnalyzeRequest, Attachment, SenderHistory

TRUSTED_AUTHSERV_IDS = frozenset({"mx.google.com"})
MAX_LINKS = 200
_TEXT_URL = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""")


# --------------------------------------------------------------------------- headers


def decode_mime_words(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (UnicodeError, LookupError, ValueError, binascii.Error):
        return value


@dataclass
class Address:
    name: str
    email: str
    domain: str
    host: HostInfo | None


def parse_address(value: str | None) -> Address | None:
    if not value:
        return None
    name, email = parseaddr(decode_mime_words(value))
    email = email.strip().lower()
    if "@" not in email:
        return Address(name.strip(), email, "", None)
    domain = email.rsplit("@", 1)[1].strip(">").strip()
    return Address(name.strip(), email, domain, host_info(domain))


@dataclass
class AuthResults:
    """Parsed Authentication-Results from a trusted receiver (RFC 8601)."""

    authserv_id: str
    spf: str = "none"
    dkim: list[tuple[str, str]] = field(default_factory=list)  # (result, d= domain)
    dmarc: str = "none"
    dmarc_policy: str = ""
    header_from: str = ""

    @property
    def dkim_pass_domains(self) -> set[str]:
        return {d for r, d in self.dkim if r == "pass" and d}


def _strip_comments(value: str) -> str:
    """Remove (possibly nested) RFC 5322 comments in one linear pass."""
    out, depth = [], 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


MAX_AUTH_HEADER_CHARS = 8192


def parse_auth_results(value: str) -> AuthResults | None:
    """Parse a single Authentication-Results header value."""
    value = _strip_comments(value[:MAX_AUTH_HEADER_CHARS].replace("\r", " ").replace("\n", " "))
    parts = [p.strip() for p in value.split(";")]
    if not parts or not parts[0]:
        return None
    authserv_id = parts[0].split()[0].lower()
    res = AuthResults(authserv_id=authserv_id)
    for part in parts[1:]:
        m = re.match(r"(?i)\s*([a-z0-9-]+)\s*=\s*([a-z]+)(.*)", part)
        if not m:
            continue
        method, result, props = m.group(1).lower(), m.group(2).lower(), m.group(3)
        kv = dict((k.lower(), v.lower()) for k, v in re.findall(r"([\w.-]+)=([^\s;]+)", props))
        if method == "spf":
            res.spf = result
        elif method == "dkim":
            d = kv.get("header.d") or kv.get("header.i", "").lstrip("@").split("@")[-1]
            res.dkim.append((result, d))
        elif method == "dmarc":
            res.dmarc = result
            res.header_from = kv.get("header.from", "")
    return res


def _claims_better(lower: AuthResults, top: AuthResults) -> bool:
    return (lower.dmarc == "pass" and top.dmarc != "pass") or (lower.spf == "pass" and top.spf != "pass")


def _dmarc_policy_from_raw(value: str) -> str:
    m = re.search(r"(?i)dmarc=\w+\s*\(p=([a-z]+)", value)
    return m.group(1).lower() if m else ""


# --------------------------------------------------------------------------- HTML


@dataclass
class Link:
    href: str
    text: str
    source: str  # html | text | form
    scheme: str = ""
    host: HostInfo | None = None
    has_userinfo: bool = False
    flags: list[str] = field(default_factory=list)


class _HTMLScanner(HTMLParser):
    """Collects anchors, forms and visible text. Never fetches anything."""

    _SKIP: frozenset[str] = frozenset({"script", "style", "head", "title", "noscript"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self.text_parts: list[str] = []
        self.has_meta_refresh = False
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag == "a" and "href" in a:
            self._anchor_href, self._anchor_text = a["href"], []
        elif tag == "area" and "href" in a:
            self.links.append((a["href"], a.get("alt", "")))
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag in {"input"} and a.get("type", "").lower() == "password":
            self.forms.append(a.get("form", "") or "password-field")
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.has_meta_refresh = True
        elif tag == "img" and self._anchor_href is not None and a.get("alt"):
            self._anchor_text.append(a["alt"])

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._anchor_href is not None:
            self.links.append((self._anchor_href, " ".join(self._anchor_text)))
            self._anchor_href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        self.text_parts.append(data)


_WEB_SCHEME = re.compile(r"(?i)^(https?|ftp):[\\/]*")


def normalize_href(href: str) -> str:
    """Rewrite an href into the URL a browser would actually open (WHATWG URL standard).

    Without this, tricks a browser happily accepts slip past analysis: tabs/newlines inside
    the URL, backslashes instead of slashes (https:\\evil.com), missing slashes
    (https:evil.com), protocol-relative links (//evil.com) and percent-encoded hosts.
    """
    href = re.sub(r"[\t\n\r]", "", href).strip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f \"'")
    if href.startswith(("//", "\\\\")):
        href = "https:" + href
    m = _WEB_SCHEME.match(href)
    if m:
        rest = href[m.end() :]
        cut = min((i for i in (rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
        href = m.group(1).lower() + "://" + rest[:cut].replace("\\", "/") + rest[cut:]
    return href


def _make_link(href: str, text: str, source: str) -> Link | None:
    href = normalize_href(href)
    if not href or href.startswith("#"):
        return None
    lowered = href.lower()
    if lowered.startswith(("mailto:", "tel:", "cid:", "sms:")):
        return None
    if lowered.startswith("www."):
        href = "http://" + href
    try:
        parts = urlsplit(href)
    except ValueError:
        return Link(href=href, text=text, source=source, flags=["unparseable"])
    link = Link(href=href, text=" ".join(text.split()), source=source, scheme=parts.scheme.lower())
    if parts.scheme.lower() in ("http", "https", "ftp"):
        try:
            hostname = unquote(parts.hostname or "")  # browsers percent-decode hosts
        except ValueError:
            hostname = ""
        link.host = host_info(hostname) if hostname else None
        link.has_userinfo = "@" in parts.netloc
    return link


# --------------------------------------------------------------------------- context


@dataclass
class EmailContext:
    headers: Message
    subject: str
    from_addr: Address | None
    reply_to: list[Address]
    return_path: Address | None
    auth: AuthResults | None
    forged_auth_headers: int
    text: str  # visible text (plain body, or text extracted from HTML)
    html: str  # raw HTML body, for analysers that need markup (hidden content); never logged
    links: list[Link]
    forms: list[str]
    has_meta_refresh: bool
    attachments: list[Attachment]
    history: SenderHistory | None
    recipient_domain: str
    org_domains: tuple[str, ...] = ()  # the user's own organisation; protected from look-alikes
    truncated: bool = False

    def auth_dmarc_passed(self) -> bool:
        return self.auth is not None and self.auth.dmarc == "pass"

    def sender_spoofed(self) -> bool:
        """Authentication positively failed for the From domain - the address is likely forged."""
        a = self.auth
        return a is not None and (a.dmarc == "fail" or (a.spf in ("fail", "softfail") and not a.dkim_pass_domains))

    def sender_authenticated(self) -> bool:
        """True when the From domain is cryptographically or policy-wise tied to this message:
        DMARC pass, or (without a DMARC verdict) an aligned DKIM signature or SPF pass for the
        same domain as the From address. Decides whether the visible sender can be trusted as
        an identity - e.g. whether blocking that address is safe."""
        a = self.auth
        if a is None or self.from_addr is None or self.from_addr.host is None:
            return False
        if a.dmarc in ("pass", "fail"):
            return a.dmarc == "pass"
        dom = self.from_addr.host.registrable
        dkim_aligned = any(d == dom or d.endswith("." + dom) for d in a.dkim_pass_domains)
        rp = self.return_path.host.registrable if self.return_path and self.return_path.host else ""
        return dkim_aligned or (a.spf == "pass" and rp == dom)

    def attachment_bytes(self, att: Attachment) -> bytes | None:
        if not att.content_b64:
            return None
        try:
            return base64.b64decode(att.content_b64, validate=False)
        except (binascii.Error, ValueError):
            return None


def build_context(req: AnalyzeRequest, protected_domains: tuple[str, ...] = ()) -> EmailContext:
    headers = HeaderParser().parsestr(req.raw_headers, headersonly=True)

    # Headers are prepended in transit, so the first Authentication-Results header that
    # carries our receiver's authserv-id is the one Gmail added for *this* delivery. Lower
    # ones were already in the message when it arrived: legitimately (e.g. forwarded mail)
    # or forged by the sender. We never trust them, and report a forgery only when a lower
    # header claims a *better* result than Gmail actually recorded - the point of forging.
    auth: AuthResults | None = None
    forged = 0
    for value in headers.get_all("Authentication-Results", []) or []:
        value = str(value)
        if not value.lstrip().lower().startswith(tuple(TRUSTED_AUTHSERV_IDS)):
            continue  # cheap pre-filter: don't parse headers from other receivers
        parsed = parse_auth_results(value)
        if parsed is None or parsed.authserv_id not in TRUSTED_AUTHSERV_IDS:
            continue
        if auth is None:
            auth = parsed
            auth.dmarc_policy = _dmarc_policy_from_raw(value[:MAX_AUTH_HEADER_CHARS])
        elif _claims_better(parsed, auth):
            forged += 1

    reply_to = []
    for name, email in getaddresses([decode_mime_words(v) for v in headers.get_all("Reply-To", []) or []]):
        addr = parse_address(f"{name} <{email}>")
        if addr and addr.email:
            reply_to.append(addr)

    scanner = _HTMLScanner()
    truncated_html = False
    if req.html_body:
        try:
            scanner.feed(req.html_body)
            scanner.close()
        except Exception:  # noqa: BLE001 - html.parser can raise on pathological input
            truncated_html = True  # keep whatever was parsed before the failure
    # What the user actually reads: the HTML when there is one. The plain-text alternative is written
    # by the sender too and is never shown by Gmail, so a benign text part must not hide a lure in HTML.
    html_text = " ".join(" ".join(scanner.text_parts).split())
    text = html_text if req.html_body and html_text else req.text_body

    links: list[Link] = []
    seen: set[tuple[str, str]] = set()

    def add(href: str, label: str, source: str) -> None:
        if len(links) >= MAX_LINKS or (href, label) in seen:
            return
        seen.add((href, label))
        link = _make_link(href, label, source)
        if link:
            links.append(link)

    for href, label in scanner.links:
        add(href, label, "html")
    # URLs in the plain-text part only matter when there is no HTML part: otherwise the
    # attacker-written text alternative (which the user never sees) would add misleading
    # "clean" links and waste the threat-intel budget.
    if not req.html_body:
        for m in _TEXT_URL.finditer(req.text_body[:200_000]):
            add(m.group(0).rstrip(".,;:!?"), "", "text")

    recipient = req.recipient_domain.strip().lower()
    return EmailContext(
        headers=headers,
        subject=decode_mime_words(str(headers.get("Subject", "") or "")),
        from_addr=parse_address(str(headers.get("From", "") or "")),
        reply_to=reply_to,
        return_path=parse_address(str(headers.get("Return-Path", "") or "")),
        auth=auth,
        forged_auth_headers=forged,
        text=text[:100_000],
        html=req.html_body,
        links=links,
        forms=scanner.forms,
        has_meta_refresh=scanner.has_meta_refresh,
        attachments=list(req.attachments),
        history=req.sender_history,
        recipient_domain=recipient,
        org_domains=tuple(
            dict.fromkeys(
                ([recipient] if recipient and recipient not in FREE_MAIL_DOMAINS else []) + list(protected_domains)
            )
        ),
        truncated=truncated_html or len(links) >= MAX_LINKS,
    )
