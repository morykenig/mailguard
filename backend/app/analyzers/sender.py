"""Who the message claims to be from, versus who actually sent it."""

from __future__ import annotations

import re

from ..context import EmailContext
from ..domains import FREE_MAIL_DOMAINS, brand_for_domain, brands_in_text, find_lookalike, same_owner
from ..textutil import clean, has_hidden_unicode
from .base import Category, Finding

C = Category.SENDER
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]{2,}", re.UNICODE)
_ROLE_WORDS = re.compile(
    r"(?i)\b(ceo|cfo|president|director|manager|hr|payroll|billing|accounts?|finance|"
    r"support|security|admin(istrator)?|it\s*(desk|team|support)|helpdesk|service|team)\b"
    r"|מנכ[\"'\u05f4\u05f3]?ל|כספים|תמיכה|אבטחה|שירות לקוחות"
)


def analyze(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []
    sender = ctx.from_addr
    if sender is None or sender.host is None:
        return [
            Finding(
                "SENDER_INVALID",
                C,
                "Sender address is missing or malformed",
                "The From address could not be parsed, which legitimate mail systems never produce.",
                20,
            )
        ]

    host = sender.host
    domain = host.registrable
    name = sender.name
    display = clean(name, 80)

    # 1. Look-alike / homograph domains.
    extra = ctx.org_domains
    lookalike = find_lookalike(host, extra)
    if lookalike:
        own = " - your own organisation's domain" if lookalike.target in extra else ""
        out.append(
            Finding(
                "SENDER_LOOKALIKE",
                C,
                f"Sender domain imitates {lookalike.target}",
                f"The sender domain {clean(host.unicode_host)} {lookalike.describe()}{own}. "
                "Look-alike domains are registered specifically to deceive.",
                35,
                (clean(host.unicode_host),),
                params=(("target", lookalike.target),),
            )
        )
    elif host.is_idn:
        out.append(
            Finding(
                "SENDER_IDN",
                C,
                "Sender domain uses international characters",
                f"{clean(host.unicode_host)} is written with non-Latin characters (shown to you as "
                f"'{host.host}'), a technique used to imitate familiar domains.",
                15,
            )
        )

    # 2. Display name tricks.
    if name:
        m = _EMAIL_IN_TEXT.search(name)
        if m and m.group(0).lower() != sender.email:
            out.append(
                Finding(
                    "SENDER_NAME_HAS_EMAIL",
                    C,
                    "Display name shows a different address",
                    f"The name shown is '{display}', but the mail actually comes from {sender.email}. "
                    "Showing a fake address in the name field is a common spoofing trick.",
                    25,
                    (display,),
                )
            )
        owner = None if domain in FREE_MAIL_DOMAINS else brand_for_domain(domain)
        claimed = [b for b in brands_in_text(name) if b is not owner]
        # "GitLab <gitlab@gitlab.acme.com>" from your own organisation is a self-hosted tool,
        # not impersonation.
        internal = domain in ctx.org_domains
        if claimed and not lookalike and not internal:
            out.append(
                Finding(
                    "SENDER_BRAND_IMPERSONATION",
                    C,
                    f"Name claims to be {claimed[0].name}",
                    f"The display name says '{display}', but {domain} is not a {claimed[0].name} domain.",
                    30 if domain in FREE_MAIL_DOMAINS else 25,
                    (display,),
                    params=(("brand", claimed[0].name),),
                )
            )
        elif domain in FREE_MAIL_DOMAINS and _ROLE_WORDS.search(name):
            out.append(
                Finding(
                    "SENDER_FREEMAIL_ROLE",
                    C,
                    "Official-sounding name on a free email account",
                    f"'{display}' sounds like an organisation or executive, but it was sent from a "
                    f"personal {domain} account that anyone can create - typical of CEO-fraud (BEC).",
                    15,
                    (display,),
                )
            )
        if has_hidden_unicode(name):
            out.append(
                Finding(
                    "SENDER_HIDDEN_CHARS",
                    C,
                    "Hidden characters in the sender name",
                    "The display name contains invisible or direction-changing Unicode characters.",
                    15,
                )
            )

    # 3. Replies diverted elsewhere.
    for rt in ctx.reply_to:
        if rt.host is None or same_owner(rt.host.registrable, domain):
            continue
        free = rt.host.registrable in FREE_MAIL_DOMAINS
        out.append(
            Finding(
                "SENDER_REPLYTO_MISMATCH",
                C,
                "Replies go to a different address",
                f"If you hit Reply, your answer goes to {rt.email} instead of {sender.email}"
                + (" - a personal mailbox." if free else ".")
                + " Attackers use this to receive replies while spoofing a trusted sender.",
                20 if free else 12,
                (rt.email,),
            )
        )
        break

    # 4. Envelope sender (bounce address) on an unrelated domain - weak on its own,
    # because mailing platforms do this legitimately.
    rp = ctx.return_path
    if rp and rp.host and rp.host.registrable != domain and not ctx.auth_dmarc_passed():
        out.append(
            Finding(
                "SENDER_RETURN_PATH_MISMATCH",
                C,
                "Bounce address on a different domain",
                f"The technical sender ({rp.host.registrable}) differs from the visible sender ({domain}).",
                4,
            )
        )
    return out
