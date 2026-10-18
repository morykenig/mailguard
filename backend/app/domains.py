"""Domain utilities: registrable-domain extraction, IDN handling and lookalike detection.

Everything here is pure and offline. The Public Suffix List snapshot bundled with
``tldextract`` is used deliberately: fetching the list at runtime would make the
service depend on a network call it does not need.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),  # never fetch the PSL at runtime
    cache_dir=None,  # never write to disk
    include_psl_private_domains=True,  # treat foo.web.app and bar.web.app as different sites
)


@dataclass(frozen=True)
class Brand:
    """A frequently impersonated organisation."""

    name: str
    domains: tuple[str, ...]  # every registrable domain it owns (mail, links, CDNs, countries)
    protected: tuple[str, ...]  # the subset worth guarding against look-alikes
    keywords: tuple[str, ...]  # lowercase display-name keywords


def _brand(name: str, domains: str, keywords: tuple[str, ...]) -> Brand:
    """``domains`` is space-separated; a leading '~' marks infrastructure that the brand owns
    but that is not itself a look-alike target (short CDN or redirect domains like g.co)."""
    items = domains.split()
    return Brand(
        name,
        tuple(d.lstrip("~") for d in items),
        tuple(d for d in items if not d.startswith("~")),
        keywords,
    )


# Kept intentionally small and curated. Each brand lists the registrable domains it
# owns - including CDN/infrastructure and country domains (marked '~') - so its own mail
# and links are never mistaken for imitations. Free-mail domains (gmail.com, outlook.com, icloud.com) are
# NOT brand domains: "Google Security <x@gmail.com>" must be flagged, because anyone can
# register a gmail.com address.
BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", "paypal.com paypal.me ~paypalobjects.com ~paypal-communication.com", ("paypal",)),
    _brand(
        "Microsoft",
        "microsoft.com office.com office365.com microsoftonline.com sharepoint.com azure.com live.com "
        "~office.net ~msauth.net ~msftauth.net ~microsoft365.com ~onmicrosoft.com ~windows.net ~bing.com ~skype.com",
        ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint"),
    ),
    _brand(
        "Google",
        "google.com youtube.com ~googleusercontent.com ~googleapis.com ~gstatic.com ~googlegroups.com "
        "~withgoogle.com ~google.co.il ~google.co.uk ~google.de ~goo.gl ~g.co ~forms.gle",
        ("google", "gmail", "google workspace"),
    ),
    _brand(
        "Apple", "apple.com ~apple.news ~mzstatic.com ~icloud-content.com", ("apple", "icloud", "itunes", "app store")
    ),
    _brand(
        "Amazon",
        "amazon.com amazon.co.uk amazon.de ~amazon.fr ~amazon.it ~amazon.es ~amazon.ca ~amazon.co.jp ~amazon.in "
        "amazonaws.com ~amazonses.com ~media-amazon.com ~a2z.com",
        ("amazon", "aws", "prime video"),
    ),
    _brand("Netflix", "netflix.com ~nflxext.com ~nflximg.net", ("netflix",)),
    _brand("DHL", "dhl.com dhl.de dhl.co.il", ("dhl",)),
    _brand("FedEx", "fedex.com", ("fedex",)),
    _brand("UPS", "ups.com", ("ups",)),
    _brand("DocuSign", "docusign.com docusign.net", ("docusign",)),
    _brand("Dropbox", "dropbox.com dropboxmail.com ~dropboxusercontent.com ~dropboxstatic.com", ("dropbox",)),
    _brand("LinkedIn", "linkedin.com ~licdn.com ~lnkd.in", ("linkedin",)),
    _brand(
        "Meta",
        "facebook.com facebookmail.com ~fb.com ~fbcdn.net meta.com instagram.com whatsapp.com",
        ("facebook", "instagram", "meta"),
    ),
    _brand("WeTransfer", "wetransfer.com ~we.tl", ("wetransfer",)),
    _brand("Adobe", "adobe.com ~adobesign.com ~acrobat.com", ("adobe",)),
    _brand("GitHub", "github.com ~githubusercontent.com ~githubassets.com ~github.io", ("github",)),
    # Cloud, identity and DevOps providers: their accounts are the keys to production.
    _brand("Okta", "okta.com ~oktapreview.com ~okta-emea.com ~oktacdn.com", ("okta",)),
    _brand("Cloudflare", "cloudflare.com ~cloudflare.net ~cloudflareaccess.com", ("cloudflare",)),
    _brand("GitLab", "gitlab.com ~gitlab.io ~gitlab-static.net", ("gitlab",)),
    _brand("Atlassian", "atlassian.com ~atlassian.net ~bitbucket.org", ("atlassian", "bitbucket")),
    _brand("Slack", "slack.com ~slack-edge.com ~slackb.com", ("slack",)),
    _brand("Docker", "docker.com ~docker.io", ("docker hub",)),
    _brand("Coinbase", "coinbase.com", ("coinbase",)),
    _brand("Binance", "binance.com", ("binance",)),
    # Israeli brands: local lures are common and rarely covered by generic tools.
    _brand("Bank Leumi", "leumi.co.il", ("leumi", "בנק לאומי")),
    _brand("Bank Hapoalim", "bankhapoalim.co.il", ("hapoalim", "בנק הפועלים")),
    _brand("Discount Bank", "discountbank.co.il", ("discount bank", "בנק דיסקונט")),
    _brand("Mizrahi Tefahot", "mizrahi-tefahot.co.il", ("mizrahi", "מזרחי טפחות")),
    _brand("Israel Post", "israelpost.co.il", ("israel post", "דואר ישראל")),
    _brand("Isracard", "isracard.co.il", ("isracard", "ישראכרט")),
)

# Brand labels that are also ordinary words. They are still protected against homoglyph,
# typo and TLD-swap imitation, but not matched as a word inside other domain names
# (live-music.com, office.acme.com, meta.stackexchange.com are not impersonation).
GENERIC_LABELS = frozenset(
    {"live", "meta", "office", "azure", "apple", "mail", "cloud", "github", "bing", "skype", "slack", "docker"}
)

FREE_MAIL_DOMAINS = frozenset(
    """
    aol.com gmail.com gmx.com gmx.de googlemail.com hotmail.com icloud.com live.com mail.ru me.com
    outlook.com proton.me protonmail.com walla.co.il walla.com yahoo.com yandex.com yandex.ru
    zoho.com
    """.split()
)

# Domains we protect against typosquatting in addition to brand domains.
_EXTRA_PROTECTED = frozenset({"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"})

# Visually confusable characters mapped to their Latin look-alike.
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "$": "s",
        "@": "a",
        "|": "l",
        # Cyrillic
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ӏ": "l",
        "ј": "j",
        "ԁ": "d",
        "һ": "h",
        "ѕ": "s",
        "ԛ": "q",
        "ԝ": "w",
        "ь": "b",
        # Greek
        "ο": "o",
        "α": "a",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "ι": "i",
        "κ": "k",
        "υ": "u",
    }
)
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"))


@dataclass(frozen=True)
class HostInfo:
    host: str  # ASCII (punycode) host, lowercase
    unicode_host: str  # human-readable form
    registrable: str  # e.g. "paypal.com"; equals host for IP literals
    sld: str  # registrable minus the public suffix, e.g. "paypal"
    is_ip: bool
    is_idn: bool
    ip_obfuscated: bool = False  # e.g. 3232235777 or 0xC0A80101 for 192.168.1.1


def to_unicode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            # On failure keep the raw label; a malformed IDN is itself suspicious.
            with contextlib.suppress(UnicodeError, ValueError):
                label = label.encode("ascii").decode("idna")
        labels.append(label)
    return ".".join(labels)


def _to_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


_IPV4_PART = re.compile(r"(0x[0-9a-f]*|0[0-7]*|[1-9][0-9]*)")
_MAX_DIGITS = {16: 8, 8: 11, 10: 10}  # more significant digits than this can't fit in 32 bits


def whatwg_ipv4(host: str) -> str | None:
    """Parse a host the way browsers do (WHATWG URL standard), returning a dotted IPv4 or None.

    Attackers write IP addresses as one decimal number, in hex or in octal - with any number
    of leading zeros - so that a link does not *look* like an IP address; every browser still
    resolves it. Leading zeros are stripped *before* converting, so a 600 KB run of zeros
    costs nothing and never hits Python's int-size limit.
    """
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4 or not all(_IPV4_PART.fullmatch(p) for p in parts):
        return None
    nums = []
    for p in parts:
        if p.startswith("0x"):
            base, digits = 16, p[2:]
        elif len(p) > 1 and p.startswith("0"):
            base, digits = 8, p[1:]
        else:
            base, digits = 10, p
        digits = digits.lstrip("0") or "0"
        if len(digits) > _MAX_DIGITS[base]:
            return None
        nums.append(int(digits, base))
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(value))


@lru_cache(maxsize=4096)
def host_info(raw_host: str) -> HostInfo | None:
    """Normalise a host name. Returns None for values that are not host names."""
    host = raw_host.strip().strip(".").lower()
    if not host or len(host) > 253:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return HostInfo(host, host, host, host, is_ip=True, is_idn=False)
    except ValueError:
        pass
    dotted = whatwg_ipv4(host)
    if dotted is not None:  # browsers treat 3232235777, 0xC0A80101, 0300.0250.1.1 as IP addresses
        return HostInfo(dotted, dotted, dotted, dotted, is_ip=True, is_idn=False, ip_obfuscated=dotted != host)
    ascii_host = _to_ascii(host)
    if not re.fullmatch(r"[a-z0-9.\-_]+", ascii_host):
        return None
    ext = _EXTRACT(ascii_host)
    if not ext.suffix or not ext.domain:
        registrable, sld = ascii_host, ascii_host
    else:
        registrable, sld = f"{ext.domain}.{ext.suffix}", ext.domain
    return HostInfo(
        host=ascii_host,
        unicode_host=to_unicode(ascii_host),
        registrable=registrable,
        sld=sld,
        is_ip=False,
        is_idn="xn--" in ascii_host,
    )


def skeleton(text: str) -> str:
    """Collapse visually confusable characters so that 'pаypa1' and 'paypal' compare equal."""
    s = unicodedata.normalize("NFKC", text).lower().translate(_CONFUSABLES)
    for seq, repl in _MULTI_CHAR_CONFUSABLES:
        s = s.replace(seq, repl)
    return s


def damerau_levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Optimal-string-alignment distance; stops early once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def brand_for_domain(registrable: str) -> Brand | None:
    for brand in BRANDS:
        if registrable in brand.domains:
            return brand
    return None


def same_owner(a: str, b: str) -> bool:
    """True if two registrable domains are identical or belong to the same known brand."""
    if a == b:
        return True
    brand = brand_for_domain(a)
    return brand is not None and brand is brand_for_domain(b)


def brands_in_text(text: str) -> list[Brand]:
    """Brands whose keywords appear as whole words in ``text`` (e.g. a display name)."""
    lowered = text.lower()
    found = []
    for brand in BRANDS:
        for kw in brand.keywords:
            if re.search(rf"(?<![\w]){re.escape(kw)}(?![\w])", lowered):
                found.append(brand)
                break
    return found


@dataclass(frozen=True)
class Lookalike:
    target: str  # the legitimate domain being imitated
    technique: str  # homoglyph | typo | brand-in-name | tld-swap

    def describe(self) -> str:
        return {
            "homoglyph": f"uses look-alike characters to imitate {self.target}",
            "typo": f"is one or two characters away from {self.target}",
            "brand-in-name": f"embeds the brand of {self.target} in an unrelated domain",
            "tld-swap": f"copies {self.target} with a different ending",
        }[self.technique]


def protected_domains(extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Domains to protect from imitation, most specific first (org domains, then brands)."""
    out: list[str] = list(extra)
    for brand in BRANDS:
        out.extend(brand.protected)
    out.extend(sorted(_EXTRA_PROTECTED))
    return tuple(dict.fromkeys(out))  # de-duplicate, keep order


def _sld_of(domain: str) -> tuple[str, str]:
    info = host_info(domain)
    if info is None:
        return domain, ""
    return info.sld, info.registrable[len(info.sld) + 1 :]


_RANK = {"tld-swap": 0, "homoglyph": 1, "brand-in-name": 2, "typo": 3}


def _match(candidate: str, tokens: list[str], target_sld: str) -> str | None:
    """Return the imitation technique used by ``candidate`` against ``target_sld``, if any.

    Tuned for precision: a false "look-alike" on a real supplier's domain costs trust in
    the whole tool, so the fuzzy rules are deliberately conservative.
    """
    if candidate == target_sld:
        return "tld-swap"  # paypal.co vs paypal.com
    cand_skel, t_skel = skeleton(candidate), skeleton(target_sld)
    if cand_skel == t_skel:
        return "homoglyph"  # paypa1, rnicrosoft, pаypal (Cyrillic а)
    if len(tokens) > 1:
        if any(skeleton(t) == t_skel and t != target_sld for t in tokens):
            return "homoglyph"  # paypa1-secure
        # Short brands ('dhl', 'ups') only count as the leading word: dhl-express.com yes,
        # start-ups.co.il no.
        leading_ok = len(target_sld) >= 5 or tokens[0] == target_sld
        if target_sld not in GENERIC_LABELS and target_sld in tokens and leading_ok:
            return "brand-in-name"  # paypal-secure, dhl-express
    if len(target_sld) < 6 or target_sld in GENERIC_LABELS:
        return None  # short or dictionary-like names: fuzzy matching is mostly noise
    if candidate.startswith(target_sld) or candidate.endswith(target_sld):
        return "brand-in-name"  # paypalsupport
    # Typosquats almost always keep the first letter (paypall, gooogle, amazno, netflx);
    # requiring it avoids pairs like finance/binance or cloud/icloud.
    limit = 1 if len(target_sld) < 9 else 2
    if cand_skel[:1] == t_skel[:1] and damerau_levenshtein(cand_skel, t_skel, limit) <= limit:
        return "typo"
    return None


def find_lookalike(info: HostInfo, extra_protected: tuple[str, ...] = ()) -> Lookalike | None:
    """Return how ``info`` imitates a protected domain, or None.

    When several targets match, the strongest technique wins (a homoglyph beats a typo),
    and ties go to the earlier, more specific target.
    """
    if info.is_ip:
        return None
    targets = protected_domains(extra_protected)
    if info.registrable in targets or info.registrable in FREE_MAIL_DOMAINS or brand_for_domain(info.registrable):
        return None
    candidate = to_unicode(info.sld)
    tokens = [t for t in re.split(r"[-_.]+", candidate) if t]
    best: Lookalike | None = None
    for target in targets:
        t_sld, _ = _sld_of(target)
        technique = _match(candidate, tokens, t_sld) if t_sld else None
        if technique and (best is None or _RANK[technique] < _RANK[best.technique]):
            best = Lookalike(target, technique)
            if technique == "tld-swap":
                break
    return best
