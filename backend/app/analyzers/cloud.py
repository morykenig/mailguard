"""Attacks on cloud and identity accounts - the keys to production.

Classic phishing steals a password. Modern attacks against tech companies increasingly
steal *tokens* instead, which bypass passwords and MFA entirely:

* Device-code phishing: the attacker starts a sign-in on their own machine, emails you the
  code, and you approve their session on a genuine Microsoft/Google/GitHub/AWS page.
* OAuth consent phishing: a link to a provider's *real* consent screen asks you to grant an
  attacker's app access to mail or files. Every link check passes - the domain is real.
* Cloud-console lures: "your AWS keys were exposed", "billing failed, resources will be
  terminated" - with a sign-in link that leads somewhere else.

This module also finds live secrets (cloud keys, tokens, private keys) in the message.
Those are reported as *exposure*, not maliciousness: a colleague pasting an AWS key is a
security problem to fix, not an attack - so it never changes the score.
"""

from __future__ import annotations

import contextlib
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from ..context import EmailContext, Link
from ..domains import BRANDS, Brand, host_info
from ..redact import find_secrets, mask, strip_format
from ..textutil import clean, defang_url
from .base import Category, Finding

C = Category.CLOUD
_BRANDS_BY_NAME: dict[str, Brand] = {b.name: b for b in BRANDS}

FLAG_LABELS = {
    "CLOUD_DEVICE_CODE": "device-code sign-in",
    "CLOUD_OAUTH_CONSENT": "app consent request",
    "CLOUD_CONSOLE_LURE": "fake cloud sign-in",
}

# ----------------------------------------------------------------------------- device code

# (host suffix, required host prefix, path prefix, provider brand) of genuine device-code pages.
_DEVICE_PAGES = (
    ("microsoft.com", "", "/devicelogin", "Microsoft"),
    ("microsoft.com", "login.", "/device", "Microsoft"),
    ("microsoftonline.com", "login.", "/common/oauth2/deviceauth", "Microsoft"),
    ("aka.ms", "", "/devicelogin", "Microsoft"),
    ("google.com", "", "/device", "Google"),
    ("github.com", "", "/login/device", "GitHub"),
    ("amazonaws.com", "device.sso.", "/", "Amazon"),
)
_DEVICE_TEXT = re.compile(
    r"(?i)\b(?:https?://)?(?:www\.)?(microsoft\.com/devicelogin|login\.microsoft\.com/device|"
    r"login\.microsoftonline\.com/common/oauth2/deviceauth|aka\.ms/devicelogin|google\.com/device|"
    r"github\.com/login/device|device\.sso\.[a-z0-9-]{1,30}\.amazonaws\.com|"
    r"[a-z0-9-]{1,63}\.awsapps\.com/start/?#/device)\b"
)
_TEXT_PROVIDER = (("microsoft", "Microsoft"), ("aka.ms", "Microsoft"), ("google", "Google"), ("github", "GitHub"))
_CODE_WORD = re.compile(r"(?i)\b(?:code|קוד)\b")
_USER_CODE = re.compile(
    r"(?<![A-Za-z0-9-])([A-Z0-9]{4}-[A-Z0-9]{4}|[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}|[A-Z0-9]{8,10})(?![A-Za-z0-9-])"
)


def _device_provider(url: str) -> str | None:
    """Provider brand if ``url`` is a genuine device-code sign-in page, else None."""
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return None
    path, fragment = p.path.lower().rstrip("/"), p.fragment.lower()
    if host.endswith(".awsapps.com") and ("/device" in path or fragment.startswith("/device")):
        return "Amazon"  # IAM Identity Center: https://d-123.awsapps.com/start/#/device
    for suffix, host_prefix, path_prefix, brand in _DEVICE_PAGES:
        # Match on the host suffix, not the registrable domain: AWS regions are private
        # public suffixes (us-east-1.amazonaws.com), so registrable domains vary.
        if not (host == suffix or host.endswith("." + suffix)) or not host.startswith(host_prefix):
            continue
        if path_prefix == "/" or path == path_prefix or path.startswith(path_prefix + "/"):
            return brand
    return None


def _urls_in(link: Link) -> list[str]:
    """The link itself plus URLs carried in its query string (redirectors, wrappers)."""
    urls = [link.href]
    with contextlib.suppress(ValueError):
        urls += [v for _, v in parse_qsl(urlsplit(link.href).query) if re.match(r"(?i)^https?://", v)][:5]
    return urls


def _user_code(text: str) -> str | None:
    """A device user code ('GLD7LJRZX', 'WDJB-MJHT') that appears right after the word 'code'."""
    for i, m in enumerate(_CODE_WORD.finditer(text)):
        if i >= 50:
            break
        window = text[m.end() : m.end() + 60]
        c = _USER_CODE.search(window)
        if not c:
            continue
        code = c.group(1)
        if "-" in code or (re.search(r"\d", code) and re.search(r"[A-Z]", code)):
            return code
    return None


def _sent_by(ctx: EmailContext, brand_name: str) -> bool:
    """The message is authenticated as coming from this provider's own domains."""
    brand = _BRANDS_BY_NAME.get(brand_name)
    dom = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""
    return bool(brand) and ctx.sender_authenticated() and dom in brand.domains  # type: ignore[union-attr]


def _device_code(ctx: EmailContext) -> list[Finding]:
    text = strip_format(f"{ctx.subject}\n{ctx.text[:100_000]}")  # zero-width characters can't hide it
    pages: list[tuple[Link, str, str]] = []
    for lk in ctx.links:
        for url in _urls_in(lk):
            brand = _device_provider(url)
            if brand:
                pages.append((lk, url, brand))
                break
    text_hits = [m.group(1) for m in _DEVICE_TEXT.finditer(text)][:3]
    if not pages and not text_hits:
        return []
    if pages:
        brand, shown = pages[0][2], pages[0][1]
    else:
        hit = text_hits[0].lower()
        brand = next((b for key, b in _TEXT_PROVIDER if key in hit), "Amazon")
        shown = text_hits[0]
    if _sent_by(ctx, brand):
        return []  # the provider's own documentation, not a phish
    for lk, _, _ in pages:
        lk.flags.append("CLOUD_DEVICE_CODE")
    page = defang_url(shown, 70)
    code = _user_code(text)
    detail = (
        f"The email sends you to {page}"
        + (f" and gives you the code {code}" if code else "")
        + ". Device sign-in pages are for codes shown on *your own* TV, terminal or app. Entering a code "
        "someone emailed you signs *them* in: they get a token for your account - no password needed, "
        "and MFA does not stop it."
    )
    return [
        Finding(
            "CLOUD_DEVICE_CODE",
            C,
            "Device-code phishing: asks you to approve a sign-in",
            detail,
            35,
            tuple(x for x in (page, f"code {code}" if code else "") if x),
            floor=70 if code else None,
        )
    ]


# ----------------------------------------------------------------------------- OAuth consent

_RISKY_SCOPE = re.compile(
    r"(?i)(mail\.google\.com|/auth/gmail|/auth/drive(?:\.readonly)?$|/auth/cloud-platform|/auth/admin\."
    r"|^mail\.(?:read|readwrite|send)|^files\.(?:read|readwrite)\.all$|^sites\.|^directory\."
    r"|^full_access_as_user$|^ews\.accessasuser|^user\.readwrite\.all$|\.default$"
    r"|^repo$|^admin:|^delete_repo$|^workflow$|^write:"
    r"|^files:read$|^admin)"
)


def _oauth_provider(link: Link) -> tuple[str, bool] | None:
    """(provider, is_admin_consent) for a link to a genuine OAuth consent endpoint."""
    if link.host is None:
        return None
    host, reg = link.host.host, link.host.registrable
    try:
        path = urlsplit(link.href).path.lower()
    except ValueError:
        return None
    if host == "accounts.google.com" and path.startswith(("/o/oauth2/", "/signin/oauth")):
        return "Google", False
    if reg in ("microsoftonline.com", "microsoft.com", "live.com") and host.startswith("login."):
        if "adminconsent" in path:
            return "Microsoft", True  # tenant-wide consent for the whole organisation
        if "/oauth2/" in path and "authorize" in path:
            return "Microsoft", False
    if host == "github.com" and path.startswith("/login/oauth/authorize"):
        return "GitHub", False
    if host == "slack.com" and path.startswith("/oauth/"):
        return "Slack", False
    if host == "auth.atlassian.com" and path.startswith("/authorize"):
        return "Atlassian", False
    return None


def _oauth_consent(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []
    sender_dom = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""
    for lk in ctx.links:
        found = _oauth_provider(lk)
        if not found:
            continue
        provider, admin = found
        try:
            params = {k.lower(): v for k, v in parse_qsl(urlsplit(lk.href).query)}
        except ValueError:
            continue
        if "client_id" not in params:
            continue
        lk.flags.append("CLOUD_OAUTH_CONSENT")
        scopes = [s for s in re.split(r"[\s,+]+", params.get("scope", "")) if s][:30]
        risky = [s for s in scopes if _RISKY_SCOPE.search(s) or _RISKY_SCOPE.search(s.rsplit("/", 1)[-1])]
        persistent = "offline_access" in scopes or params.get("access_type") == "offline"
        try:
            redirect = host_info(urlsplit(params.get("redirect_uri", "")).hostname or "")
        except ValueError:
            redirect = None
        # A vendor's onboarding mail ("connect your Google account") points the consent back to
        # its own, authenticated domain. Still worth a note, but not an alarm.
        own_app = bool(redirect and sender_dom and redirect.registrable == sender_dom and ctx.sender_authenticated())
        shown = ", ".join(clean(s, 60) for s in (risky or scopes)[:4]) or "unspecified access"
        detail = (
            f"The link opens {provider}'s real consent screen for an app (client id "
            f"{clean(params['client_id'], 40)}) requesting: {shown}"
            + (". It is an ADMIN consent: approving grants the app access for your whole organisation" if admin else "")
            + ". Approving gives that app a token to your data that keeps working after you change your password"
            + (" and survives sign-out (offline access)" if persistent else "")
            + (
                f". The app belongs to the sender's own verified domain ({sender_dom}) - approve only if you "
                "expected to connect it."
                if own_app
                else ". Attackers use this to read mail and files without ever stealing a password - and because "
                f"the page really is {provider}'s, link checkers see nothing wrong."
            )
        )
        points = 10 if own_app and not admin else (35 if risky or admin else 15)
        out.append(
            Finding(
                "CLOUD_OAUTH_CONSENT",
                C,
                f"Asks you to give an app access to your {provider} account",
                detail,
                points,
                tuple([defang_url(lk.href, 70)] + [f"scope: {clean(s, 60)}" for s in risky[:3]]),
                params=(("provider", provider),),
            )
        )
    return out


# ----------------------------------------------------------------------------- console lures

_PROVIDERS: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (label, re.compile(rf"(?i)\b(?:{rx})\b"), brand)
    for label, rx, brand in (
        ("AWS", r"aws|amazon web services", "Amazon"),
        ("Google Cloud", r"google cloud|gcp|google workspace", "Google"),
        ("Microsoft 365", r"microsoft 365|office 365", "Microsoft"),
        ("Azure / Entra ID", r"azure|microsoft entra|entra id", "Microsoft"),
        ("GitHub", r"github", "GitHub"),
        ("GitLab", r"gitlab", "GitLab"),
        ("Okta", r"okta", "Okta"),
        ("Cloudflare", r"cloudflare", "Cloudflare"),
        ("Docker Hub", r"docker hub", "Docker"),
        ("Atlassian", r"atlassian|bitbucket", "Atlassian"),
        ("Slack", r"slack", "Slack"),
    )
)

# Where each provider's real sign-in lives. Deliberately narrower than "every domain the brand
# owns": anyone can host pages on github.io, *.sharepoint.com or *.web.core.windows.net, so a
# "sign in" link there is still off-site. A leading dot means "any subdomain".
_SIGNIN_HOSTS: dict[str, tuple[str, ...]] = {
    "Amazon": (
        "signin.aws.amazon.com",
        "console.aws.amazon.com",
        ".console.aws.amazon.com",
        "aws.amazon.com",
        "www.amazon.com",
        "amazon.com",
    ),
    "Google": (
        "accounts.google.com",
        "console.cloud.google.com",
        "admin.google.com",
        "myaccount.google.com",
        "cloud.google.com",
        "workspace.google.com",
        "mail.google.com",
    ),
    "Microsoft": (
        "login.microsoftonline.com",
        "login.live.com",
        "login.microsoft.com",
        "portal.azure.com",
        "entra.microsoft.com",
        "admin.microsoft.com",
        "account.microsoft.com",
        "myaccount.microsoft.com",
        "mysignins.microsoft.com",
        "www.office.com",
        "office.com",
        "aka.ms",
    ),
    "GitHub": ("github.com",),
    "GitLab": ("gitlab.com",),
    "Okta": (".okta.com",),
    "Cloudflare": ("dash.cloudflare.com", "www.cloudflare.com"),
    "Docker": ("hub.docker.com", "login.docker.com", "app.docker.com"),
    "Atlassian": ("id.atlassian.com", "admin.atlassian.com", "start.atlassian.com"),
    "Slack": ("slack.com", "app.slack.com"),
}

_CLOUD_TOPIC = re.compile(
    r"(?i)("
    r"\b(?:access keys?|api keys?|credentials|secret keys?|tokens?)\W+(?:\w+\W+){0,4}"
    r"(?:exposed|compromised|leaked|publicly available)"
    r"|\b(?:account|subscription|instances?|resources|workloads?|services?|repositor(?:y|ies)|organi[sz]ation|"
    r"workspace|project)\W+(?:\w+\W+){0,3}(?:suspended|terminated|deleted|deactivated|disabled|locked|restricted)"
    r"|\b(?:payment|billing|invoice|charge)\W+(?:\w+\W+){0,3}(?:failed|declined|overdue|past due|unsuccessful)"
    r"|\b(?:unusual|suspicious|new) (?:sign-?in|login|console (?:sign-?in|login)|activity)"
    r"|\b(?:mfa|2fa|multi-factor|two-factor)\W+(?:\w+\W+){0,3}(?:reset|disabled|expir\w*|re-?enroll\w*)"
    r"|\b(?:quota|usage limit|free tier)\W+(?:\w+\W+){0,3}(?:exceeded|reached)"
    r"|\b(?:sso|session|password)\W+(?:\w+\W+){0,2}expir\w*"
    r"|\baction required\b|\bverify your (?:account|identity|organi[sz]ation)"
    r"|(?:המפתח|המפתחות|פרטי הגישה).{0,30}(?:דלפו|נחשפו)|(?:החשבון|המנוי|השירות).{0,20}(?:יושעה|יימחק|ייחסם)"
    r")"
)
_SIGNIN_LIKE = re.compile(
    r"(?i)(sign[\s-]?in|log[\s-]?in|console|verify|review|reactivate|restore|unlock|update (?:billing|payment)"
    r"|confirm|secure|rotate|התחבר|אמת)"
)


def _official_signin(brand_name: str, host: str) -> bool:
    return any(host == h or (h.startswith(".") and host.endswith(h)) for h in _SIGNIN_HOSTS.get(brand_name, ()))


def _console_lure(ctx: EmailContext) -> list[Finding]:
    # Who is the email *about*? Only the subject, the sender's display name and the link texts
    # count: a vendor mail that mentions "sign in with GitHub" in passing is not a GitHub lure.
    head = strip_format(
        f"{ctx.subject}\n{ctx.from_addr.name if ctx.from_addr else ''}\n" + "\n".join(lk.text for lk in ctx.links[:50])
    )
    provider = next(((label, brand) for label, rx, brand in _PROVIDERS if rx.search(head)), None)
    if provider is None:
        return []
    label, brand_name = provider
    if _sent_by(ctx, brand_name):
        return []  # genuinely from the provider
    topic = _CLOUD_TOPIC.search(strip_format(f"{ctx.subject}\n{ctx.text[:20_000]}"))
    if topic is None:
        return []
    for lk in ctx.links:
        if lk.host is None or lk.scheme not in ("http", "https") or _official_signin(brand_name, lk.host.host):
            continue
        try:
            path = urlsplit(lk.href).path
        except ValueError:
            path = ""
        if not (_SIGNIN_LIKE.search(lk.text) or _SIGNIN_LIKE.search(path)):
            continue
        lk.flags.append("CLOUD_CONSOLE_LURE")
        dest = defang_url(lk.href, 70)
        return [
            Finding(
                "CLOUD_CONSOLE_LURE",
                C,
                f"Fake {label} sign-in",
                f"The email is about your {label} account ('{clean(topic.group(0), 60)}'), but its "
                f"'{clean(lk.text, 40) or 'sign-in'}' link goes to {dest}, which is not a {label} sign-in page. "
                "Cloud consoles hold the keys to production, which makes these credentials especially valuable.",
                25,
                (clean(topic.group(0), 60), dest),
                params=(("label", label),),
            )
        ]
    return []


# ----------------------------------------------------------------------------- secrets


def _secret_sources(ctx: EmailContext) -> str:
    parts = [ctx.subject, ctx.text[:200_000]] + [unquote(lk.href)[:2000] for lk in ctx.links[:200]]
    for att in ctx.attachments:
        name = att.filename.lower()
        if name.endswith((".txt", ".env", ".json", ".yaml", ".yml", ".cfg", ".ini", ".pem", ".key")):
            data = ctx.attachment_bytes(att)
            if data:
                parts.append(data[:200_000].decode("utf-8", "replace"))
    return "\n".join(parts)


def _secrets(ctx: EmailContext) -> list[Finding]:
    by_kind: dict[str, list[str]] = {}
    for kind, value in find_secrets(_secret_sources(ctx)):
        masked = mask(value)
        if masked not in by_kind.setdefault(kind, []):
            by_kind[kind].append(masked)
    out = []
    for kind, values in by_kind.items():
        out.append(
            Finding(
                "EXPOSURE_" + re.sub(r"\W+", "_", kind.upper()).strip("_"),
                Category.EXPOSURE,
                f"{kind} in this email",
                f"This email contains what looks like a live {kind} ({values[0]}). Anyone who can read this "
                "mailbox - or the sender's, or any system the email passed through - can use it. Revoke and "
                "rotate it now, and share secrets through a secrets manager, not email.",
                0,
                tuple(values[:3]),
                params=(("kind", kind),),
            )
        )
    return out


def analyze(ctx: EmailContext) -> list[Finding]:
    return _device_code(ctx) + _oauth_consent(ctx) + _console_lure(ctx) + _secrets(ctx)
