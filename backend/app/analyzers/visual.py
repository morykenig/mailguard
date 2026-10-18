"""Images, emojis and embedded active content.

* Image-only emails - the lure is a picture of text, so keyword filters (and screen readers)
  see nothing; usually the whole picture is one big link.
* Logo impersonation - a PayPal or bank logo at the top of a mail that does not come from
  PayPal. Attackers often hot-link the *real* logo, so where the image is hosted doesn't help;
  what counts is a brand logo in the header of mail from someone else. Footer icons
  (LinkedIn, Facebook, "Get it on Google Play") are deliberately ignored.
* Risky image sources - images served from raw IP addresses or look-alike domains.
* Active content - SVG data URIs, <object>/<embed>/<iframe>, scripts and on* handlers:
  Gmail strips them, but nobody sends them to a mailbox by accident.
* Emojis - alarm, lock and money emojis are cheap attention-grabbers; a check-mark or shield
  in the sender's *name* imitates a verified badge (email has no such thing in names).
* Image attachments that are not images (a ".jpg" that is really HTML or an archive).
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from ..context import EmailContext
from ..domains import BRANDS, Brand, brands_in_text, find_lookalike, host_info
from ..textutil import clean
from .base import Category, Finding
from .hidden import scan as scan_visibility

C = Category.VISUAL

ALARM_EMOJI = frozenset("⚠🚨❗‼⛔🛑🔴📛❌")
LOCK_EMOJI = frozenset("🔒🔐🔑🛡")
# Celebration emojis (🎉🎊) are everyday marketing and deliberately not lures.
MONEY_EMOJI = frozenset("💰💸💵💶💷💳🤑🎁🏆💎")
DELIVERY_EMOJI = frozenset("📦🚚")
LURE_EMOJI = ALARM_EMOJI | LOCK_EMOJI | MONEY_EMOJI | DELIVERY_EMOJI
BADGE_EMOJI = frozenset("✅✔☑✓🔒🛡")
_BADGE_WORDS = re.compile(r"(?i)\b(verified|official|certified)\b|מאומת|רשמי")

MAX_IMAGES = 200
_IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")
_IMAGE_EXT = frozenset({"jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"})
_SOCIAL = frozenset({"LinkedIn", "Meta", "GitHub", "Slack", "Apple", "Google"})  # common footer badges


@dataclass
class _Img:
    src: str
    label: str  # alt + title + file name, lower-case
    linked: bool
    tiny: bool  # tracking pixel


def _px(value: str) -> int | None:
    m = re.match(r"\s*(\d{1,5})", value or "")
    return int(m.group(1)) if m else None


class _Scanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.images: list[_Img] = []
        self.active: list[str] = []
        self._in_link = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs[:50]}
        handlers = [k for k in a if k.startswith("on")]
        if handlers and len(self.active) < 5:
            self.active.append(f"<{tag} {handlers[0]}=…>")
        if tag in ("script", "object", "embed", "iframe", "applet", "frame") and len(self.active) < 5:
            self.active.append(f"<{tag}>")
        if tag == "a":
            self._in_link += 1
        elif tag == "img" and len(self.images) < MAX_IMAGES:
            src = a.get("src", "").strip()
            if src.lower().startswith("data:image/svg") and len(self.active) < 5:
                self.active.append("SVG image as data: URI")
            style = a.get("style", "")
            w = _px(a.get("width", "")) or _px((re.search(r"width\s*:\s*(\d+)", style) or [None, ""])[1] or "")
            h = _px(a.get("height", "")) or _px((re.search(r"height\s*:\s*(\d+)", style) or [None, ""])[1] or "")
            try:
                name = unquote(urlsplit(src).path.rsplit("/", 1)[-1]) if not src.startswith("data:") else ""
            except ValueError:
                name = ""
            label = f"{a.get('alt', '')} {a.get('title', '')} {re.sub(r'[_.-]+', ' ', name)}".lower()
            self.images.append(
                _Img(
                    src[:2000], label[:300], self._in_link > 0, (w is not None and w <= 2) or (h is not None and h <= 2)
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_link:
            self._in_link -= 1


def _brand_by_name(name: str) -> Brand | None:
    return next((b for b in BRANDS if b.name == name), None)


def _images(ctx: EmailContext) -> list[Finding]:
    if not ctx.html:
        return []
    s = _Scanner()
    with contextlib.suppress(Exception):  # html.parser can raise on pathological input; keep what was parsed
        s.feed(ctx.html[:600_000])
        s.close()
    out: list[Finding] = []
    real = [i for i in s.images if not i.tiny]

    if real:
        visible = scan_visibility(ctx.html[:600_000]).visible_chars
        if visible < 120:
            linked = any(i.linked for i in real)
            out.append(
                Finding(
                    "IMG_ONLY_BODY",
                    C,
                    "The message is mostly a picture",
                    f"The email shows {len(real)} image(s) and only {visible} characters of text"
                    + (", and the picture is a link" if linked else "")
                    + ". Putting the text inside an image hides it from spam filters and keyword checks.",
                    20 if linked else 15,
                    (f"{len(real)} image(s), {visible} characters of text",),
                )
            )

    sender_dom = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""
    for img in real[:2]:  # header logos only - never footer icons
        for brand in brands_in_text(img.label):
            is_logo = "logo" in img.label or img is real[0]
            if not is_logo or (brand.name in _SOCIAL and "logo" not in img.label):
                continue
            if sender_dom in brand.domains or sender_dom in ctx.org_domains:
                continue
            out.append(
                Finding(
                    "IMG_BRAND_LOGO",
                    Category.SENDER,  # a copied logo is a claim of identity, like a brand display name
                    f"Shows the {brand.name} logo but isn't from {brand.name}",
                    f"The email opens with a {brand.name} logo, but it was sent from "
                    f"{sender_dom or 'an unknown domain'}, "
                    f"which is not a {brand.name} domain. Real logos are easy to copy - often hot-linked from the "
                    "brand's own servers - so a familiar logo proves nothing about the sender.",
                    20,
                    (clean(img.label, 60),),
                    params=(("brand", brand.name),),
                )
            )
            break
        if any(f.id == "IMG_BRAND_LOGO" for f in out):
            break

    risky = []
    for img in real[:50]:
        try:
            host = host_info(urlsplit(img.src).hostname or "") if img.src.lower().startswith("http") else None
        except ValueError:
            host = None
        if host and (host.is_ip or host.is_idn or find_lookalike(host, ctx.org_domains)):
            risky.append(host.unicode_host)
    if risky:
        out.append(
            Finding(
                "IMG_RISKY_SOURCE",
                C,
                "Images loaded from a suspicious address",
                f"Images are loaded from {clean(risky[0], 60)} - a raw IP address or a look-alike domain. Loading the "
                "image also tells the sender that you opened the email.",
                10,
                tuple(clean(r, 60) for r in dict.fromkeys(risky)),
            )
        )

    if s.active:
        out.append(
            Finding(
                "IMG_ACTIVE_CONTENT",
                C,
                "Active content embedded in the email",
                f"The email contains {', '.join(dict.fromkeys(s.active))[:120]}. Gmail strips these, but nobody "
                "puts scripts or embedded objects in an email by accident.",
                15,
                tuple(dict.fromkeys(s.active))[:3],
            )
        )
    return out


def _emojis(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []
    name = ctx.from_addr.name if ctx.from_addr else ""
    badge = [c for c in name if c in BADGE_EMOJI] or _BADGE_WORDS.findall(name)
    if badge:
        out.append(
            Finding(
                "SENDER_FAKE_BADGE",
                Category.SENDER,
                "Fake 'verified' badge in the sender's name",
                f"The sender's name '{clean(name, 60)}' contains a check-mark, shield or 'verified' label. Email "
                "has no verified badges in names - anyone can type one - so this exists only to look trustworthy.",
                15,
                (clean(name, 60),),
            )
        )
    in_subject = [c for c in ctx.subject if c in LURE_EMOJI]
    in_body = [c for c in ctx.text[:20_000] if c in LURE_EMOJI]
    # In the subject, one warning/lock emoji is a pressure signal; money or parcel emojis are
    # everyday in marketing, so they count only in combination (two or more).
    alarming_subject = any(c in ALARM_EMOJI or c in LOCK_EMOJI for c in in_subject) or len(in_subject) >= 2
    if alarming_subject or len(in_body) >= 3:
        shown = "".join(dict.fromkeys(in_subject + in_body))[:8]
        out.append(
            Finding(
                "EMOJI_LURE",
                C,
                "Alarm or money emojis",
                f"The {'subject' if alarming_subject else 'message'} uses {shown} - warning, lock, money or parcel "
                "emojis are cheap ways to grab attention and add urgency.",
                8,
                (shown,),
            )
        )
    return out


def _fake_images(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []
    for att in ctx.attachments:
        ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        data = ctx.attachment_bytes(att)
        if ext not in _IMAGE_EXT or not data or data.startswith(b"MZ"):  # MZ: ATT_DISGUISED_EXE covers it
            continue
        if (data[:4] == b"RIFF" and data[8:12] == b"WEBP") or data.startswith(_IMAGE_MAGIC):
            continue
        kind = (
            "a web page"
            if data.lstrip()[:15].lower().startswith((b"<html", b"<!doc", b"<svg", b"<scr"))
            else ("an archive" if data.startswith((b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf")) else "not an image")
        )
        out.append(
            Finding(
                "ATT_FAKE_IMAGE",
                Category.ATTACHMENTS,
                "Attachment pretends to be an image",
                f"'{clean(att.filename, 60)}' has an image extension but is actually {kind}.",
                25,
                (clean(att.filename, 60),),
            )
        )
    return out


def analyze(ctx: EmailContext) -> list[Finding]:
    return _images(ctx) + _emojis(ctx) + _fake_images(ctx)
