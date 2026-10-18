"""Where the links in the message really lead.

Links are inspected statically. The backend never visits them: following an
attacker-supplied URL from our server would be an SSRF vector, would tip off the
attacker that the email was opened, and could "burn" one-time links meant for the user.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, unquote, urlsplit

from ..context import EmailContext, Link
from ..domains import BRANDS, GENERIC_LABELS, HostInfo, brand_for_domain, find_lookalike, host_info, same_owner
from ..textutil import clean, defang_domain, defang_url, has_hidden_unicode
from .base import Category, Finding

C = Category.LINKS

SHORTENERS = frozenset(
    """
    bit.ly bl.ink buff.ly cutt.ly goo.gl is.gd lnkd.in ow.ly rb.gy rebrand.ly s.id shorte.st
    shorturl.at t.ly tiny.cc tinyurl.com v.gd
    """.split()
)
# Free hosting, form builders and tunnels: legitimate services that are heavily abused
# because their domains have good reputation and TLS certificates for free.
FREE_HOSTING = tuple(
    """
    firebaseapp.com web.app pages.dev workers.dev netlify.app vercel.app github.io glitch.me
    ngrok.io ngrok-free.app trycloudflare.com r2.dev herokuapp.com onrender.com replit.app repl.co
    000webhostapp.com weebly.com wixsite.com webflow.io blogspot.com ipfs.io dweb.link
    sites.google.com forms.gle docs.google.com/forms forms.office.com typeform.com jotform.com
    notion.site canva.site framer.website godaddysites.com square.site
    """.split()
)
# Click-tracking hosts of mailing platforms: link text shows the brand, href goes via the ESP.
ESP_TRACKING = frozenset(
    """
    awstrack.me cmail19.com cmail20.com createsend1.com ct.sendgrid.net exacttarget.com hs-sites.com
    hubspotlinks.com intercom-clicks.com klclick.com list-manage.com mailchimp.com mailgun.org
    mandrillapp.com mjt.lu mlsend.com rs6.net sendgrid.net sendibt3.com sparkpostmail.com
    """.split()
)
SUSPICIOUS_TLDS = frozenset(
    """
    bond buzz cam cf cfd click country ga gq icu live lol ml mov quest rest sbs support tk top work
    xyz zip
    """.split()
)
RISKY_DOWNLOAD = re.compile(
    r"(?i)\.(exe|scr|msi|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|iso|img|vhdx?|apk|jar|"
    r"zip|rar|7z|docm|xlsm|one)$"
)
LOGIN_WORDS = re.compile(r"(?i)(log-?in|sign-?in|verify|account|password|secure|update|wallet|auth)")
_LOOKS_LIKE_URL = re.compile(r"(?i)^(https?://)?(www\.)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$")

# finding id -> (title, detail template, points)
_RULES: dict[str, tuple[str, str, int]] = {
    "LINK_TEXT_MISMATCH": (
        "Link text disguises the real destination",
        "Showing one address while opening another is the single most common phishing technique.",
        30,
    ),
    "LINK_LOOKALIKE": (
        "Link to a look-alike domain",
        "Look-alike domains are registered specifically to trick you into trusting them.",
        30,
    ),
    "LINK_BRAND_IN_SUBDOMAIN": (
        "Brand name hidden in an unrelated address",
        "The address starts with a familiar brand (e.g. paypal.com.something.xyz) but actually "
        "belongs to a different site.",
        25,
    ),
    "LINK_SCRIPT_SCHEME": (
        "Link runs code instead of opening a page",
        "A link uses a javascript: or data: address, which can run code or render a fake page.",
        25,
    ),
    "LINK_USERINFO": (
        "Address hides the real site after an '@'",
        "Everything before '@' in a web address is ignored by the browser; it is used to make "
        "the link look like it goes somewhere it does not.",
        20,
    ),
    "LINK_IP_ADDRESS": (
        "Link to a bare IP address",
        "Legitimate organisations link to named websites, not raw IP addresses.",
        20,
    ),
    "LINK_DOWNLOAD": ("Link downloads a risky file", "A link points directly to an executable, script or archive.", 15),
    "LINK_IDN": (
        "Link uses international characters",
        "A link's domain is written with non-Latin characters that can imitate familiar letters.",
        15,
    ),
    "LINK_HIDDEN_CHARS": (
        "Hidden characters in a link",
        "A link contains invisible or direction-changing Unicode characters.",
        15,
    ),
    "LINK_FREE_HOSTING": (
        "Link to free hosting or a form builder",
        "Free hosting and form services are legitimate but are heavily abused to host phishing "
        "pages, because their domains have a good reputation.",
        10,
    ),
    "LINK_SHORTENER": (
        "Shortened link hides the destination",
        "A URL shortener conceals where the link really goes.",
        10,
    ),
    "LINK_REDIRECT": (
        "Link bounces through a redirect",
        "The link carries another web address inside it and forwards you there.",
        8,
    ),
    "LINK_HTTP_LOGIN": (
        "Unencrypted link to a login-style page",
        "A plain http:// link points to what looks like a login or verification page.",
        8,
    ),
    "LINK_SUSPICIOUS_TLD": (
        "Link to a domain ending often used for abuse",
        "Some domain endings are cheap and disproportionately used for malicious sites.",
        6,
    ),
}


# Short labels for the per-link table in the add-on.
FLAG_LABELS = {
    "LINK_TEXT_MISMATCH": "text ≠ destination",
    "LINK_LOOKALIKE": "look-alike domain",
    "LINK_BRAND_IN_SUBDOMAIN": "brand in subdomain",
    "LINK_SCRIPT_SCHEME": "runs code",
    "LINK_USERINFO": "'@' trick",
    "LINK_IP_ADDRESS": "raw IP address",
    "LINK_DOWNLOAD": "file download",
    "LINK_IDN": "international characters",
    "LINK_HIDDEN_CHARS": "hidden characters",
    "LINK_FREE_HOSTING": "free hosting",
    "LINK_SHORTENER": "shortener",
    "LINK_REDIRECT": "redirect",
    "LINK_HTTP_LOGIN": "unencrypted login",
    "LINK_SUSPICIOUS_TLD": "risky domain ending",
}


# TLDs that are also common file extensions: "README.md" or "invoice.zip" as link text is a
# file name, not a claim about where the link goes.
_FILE_LIKE_TLDS = frozenset({"md", "py", "zip", "mov", "sh", "pl", "rs", "cs", "ps", "rb", "pdf", "doc", "txt"})


def _text_domain(text: str) -> str | None:
    """The domain a link's visible text *claims* to go to, if the text looks like an address."""
    t = text.strip().rstrip("/.")
    if not t or " " in t or not _LOOKS_LIKE_URL.match(t):
        return None
    explicit = bool(re.match(r"(?i)^(https?://|www\.)", t))
    if not re.match(r"(?i)^https?://", t):
        t = "http://" + t
    try:
        hostname = urlsplit(t).hostname
    except ValueError:
        return None
    info = host_info(hostname) if hostname else None
    if info is None or info.is_ip:
        return None
    if not explicit and info.registrable.rsplit(".", 1)[-1] in _FILE_LIKE_TLDS:
        return None
    return info.registrable


def _is_free_hosting(host: str, path: str) -> bool:
    for h in FREE_HOSTING:
        if "/" in h:
            if (host + path).startswith(h):
                return True
        elif host == h or host.endswith("." + h):
            return True
    return False


_BRAND_LABELS = (
    frozenset(d.split(".")[0] for b in BRANDS for d in b.protected if len(d.split(".")[0]) >= 5) - GENERIC_LABELS
)


def _brand_in_subdomain(host: HostInfo) -> bool:
    """paypal.com.secure-login.xyz or login.paypal.evil.xyz - but not the brand's own hosts."""
    if brand_for_domain(host.registrable) or not host.host.endswith("." + host.registrable):
        return False
    sub = host.host[: -len(host.registrable) - 1]
    info = host_info(sub)
    if info and brand_for_domain(info.registrable):
        return True  # a complete brand domain used as a prefix
    return any(label in _BRAND_LABELS for label in sub.split("."))


def _flags_for(link: Link, extra_protected: tuple[str, ...]) -> list[str]:
    """Return rule ids triggered by a single link."""
    if link.scheme in ("javascript", "data", "vbscript"):
        return ["LINK_SCRIPT_SCHEME"]
    hits: list[str] = []
    if has_hidden_unicode(link.href) or has_hidden_unicode(link.text):
        hits.append("LINK_HIDDEN_CHARS")
    host = link.host
    if host is None:
        return hits
    try:
        parts = urlsplit(link.href)
        path, query = unquote(parts.path), parts.query
    except ValueError:
        path, query = "", ""

    shown = _text_domain(link.text)
    if shown and not same_owner(shown, host.registrable) and host.registrable not in ESP_TRACKING:
        hits.append("LINK_TEXT_MISMATCH")
    if host.is_ip:
        hits.append("LINK_IP_ADDRESS")
    if link.has_userinfo:
        hits.append("LINK_USERINFO")
    if host.is_idn:
        hits.append("LINK_IDN")
    if find_lookalike(host, extra_protected):
        hits.append("LINK_LOOKALIKE")
    elif _brand_in_subdomain(host):
        hits.append("LINK_BRAND_IN_SUBDOMAIN")
    if host.registrable in SHORTENERS:
        hits.append("LINK_SHORTENER")
    if _is_free_hosting(host.host, path):
        hits.append("LINK_FREE_HOSTING")
    if RISKY_DOWNLOAD.search(path):
        hits.append("LINK_DOWNLOAD")
    if link.scheme == "http" and LOGIN_WORDS.search(path):
        hits.append("LINK_HTTP_LOGIN")
    if not host.is_ip and host.registrable.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        hits.append("LINK_SUSPICIOUS_TLD")
    for _, value in parse_qsl(query):
        if re.match(r"(?i)^https?://", value):
            try:
                target = host_info(urlsplit(value).hostname or "")
            except ValueError:
                continue
            if target and not same_owner(target.registrable, host.registrable):
                hits.append("LINK_REDIRECT")
                break
    return hits


def _specific(rule: str, link: Link, extra: tuple[str, ...]) -> str:
    """One sentence naming the exact link, so the user sees *this* threat, not a category."""
    dest = defang_url(link.href, 70)
    host = defang_domain(link.host.unicode_host) if link.host else dest
    if rule == "LINK_TEXT_MISMATCH":
        return f"The link shows '{clean(link.text, 50)}' but actually opens {dest}."
    if rule == "LINK_LOOKALIKE" and link.host:
        match = find_lookalike(link.host, extra)
        if match:
            return f"{host} {match.describe()}."
    if rule == "LINK_BRAND_IN_SUBDOMAIN":
        return (
            f"{host} only looks like a brand address; it belongs to {defang_domain(link.host.registrable)}."
            if link.host
            else ""
        )
    if rule == "LINK_IP_ADDRESS" and link.host and link.host.ip_obfuscated:
        return f"Link: {dest} - that number is the IP address {link.host.host}, written in disguise."
    if rule in (
        "LINK_DOWNLOAD",
        "LINK_SHORTENER",
        "LINK_FREE_HOSTING",
        "LINK_IP_ADDRESS",
        "LINK_USERINFO",
        "LINK_REDIRECT",
        "LINK_HTTP_LOGIN",
        "LINK_SUSPICIOUS_TLD",
        "LINK_IDN",
        "LINK_SCRIPT_SCHEME",
    ):
        return f"Link: {dest}."
    return ""


def analyze(ctx: EmailContext) -> list[Finding]:
    extra = ctx.org_domains
    by_rule: dict[str, list[Link]] = defaultdict(list)
    for link in ctx.links:
        for rule in _flags_for(link, extra):
            link.flags.append(rule)
            by_rule[rule].append(link)

    out = []
    for rule, hits in by_rule.items():
        title, detail, points = _RULES[rule]
        evidence = tuple(
            (f"'{clean(lk.text, 40)}' → " if rule == "LINK_TEXT_MISMATCH" else "") + defang_url(lk.href, 70)
            for lk in hits[:3]
        )
        specific = _specific(rule, hits[0], extra)
        more = f" ({len(hits) - 1} more link{'s' if len(hits) > 2 else ''} like this.)" if len(hits) > 1 else ""
        out.append(
            Finding(rule, C, title, f"{specific} {detail}{more}" if specific else detail + more, points, evidence)
        )

    if ctx.forms:
        out.append(
            Finding(
                "LINK_EMBEDDED_FORM",
                C,
                "Email contains a form that collects data",
                "The message body includes an input form. Legitimate emails link to a website instead; "
                "forms inside emails are used to harvest passwords and card numbers.",
                25,
            )
        )
    lure_host = _credential_words_host(ctx)
    if lure_host:
        out.append(lure_host)
    bait = _bait_and_switch(ctx)
    if bait:
        out.append(bait)
    if ctx.has_meta_refresh:
        out.append(
            Finding(
                "LINK_META_REFRESH",
                C,
                "Auto-redirect code in the message",
                "The HTML contains a meta-refresh instruction that redirects automatically.",
                10,
            )
        )
    return out


# "Oops, wrong link - it's actually here": a familiar, trustworthy link first (so a glance or a
# scanner sees google.com), then a "correction" pointing somewhere else. The correction is the lure.
_CORRECTION = re.compile(
    r"\b(?:oops|whoops|my bad|sorry,? (?:wrong|that was the wrong|i sent the wrong) link|(?:the )?(?:correct|real|"
    r"actual|right|updated|new) link(?: is)?|use this (?:link|one) instead|it'?s (?:actually )?here)\b"
    r"|הקישור הנכון|סליחה,? (?:טעות|קישור שגוי)|טעיתי בקישור",
    re.IGNORECASE,
)


def _bait_and_switch(ctx: EmailContext) -> Finding | None:
    m = _CORRECTION.search(ctx.text[:50_000])
    if not m:
        return None
    domains = list(dict.fromkeys(lk.host.registrable for lk in ctx.links if lk.host and lk.host.registrable))
    if len(domains) < 2:
        return None
    after = ctx.text[m.end() : m.end() + 400].lower()
    switched = [d for d in domains[1:] if d in after] or domains[1:]
    first = domains[0]
    return Finding(
        "LINK_BAIT_SWITCH",
        C,
        "A 'corrected' link replaces a trusted one",
        f"The email first shows a link to {first}, then says '{clean(m.group(0), 30)}' and points to "
        f"{switched[0]} instead. Showing a familiar link and then 'correcting' it is a trick to get the real "
        "destination clicked without scrutiny.",
        25,
        tuple(clean(d, 60) for d in switched[:3]),
    )


_LURE_WORDS = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "secure",
    "security",
    "verify",
    "verification",
    "update",
    "account",
    "auth",
    "confirm",
    "unlock",
    "recovery",
    "support",
)


def _credential_words_host(ctx: EmailContext) -> Finding | None:
    """'login-update-security.example.com': hosts stuffed with account words on someone else's domain."""
    sender = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""
    for lk in ctx.links:
        if not lk.host or lk.host.is_ip or brand_for_domain(lk.host.registrable):
            continue
        if lk.host.registrable == sender and ctx.sender_authenticated():
            continue  # the sender's own login page
        name = lk.host.host.lower()
        hits = [w for w in _LURE_WORDS if w in name]
        if len(hits) >= 2:
            return Finding(
                "LINK_CREDENTIAL_WORDS",
                C,
                "Link address is stuffed with account words",
                f"The link goes to {clean(lk.host.unicode_host, 60)}, a name built from words like "
                f"'{hits[0]}' and '{hits[1]}' to look official. Real services sign you in on their own "
                "well-known domain.",
                10,
                (defang_url(lk.href, 70),),
            )
    return None
