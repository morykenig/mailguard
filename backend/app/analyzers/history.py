"""The user's own relationship with the sender, computed privately by the add-on.

It also remembers verdicts: if MailGuard rated earlier mail from this address as malicious,
if the user reported or blocked the sender, or if Gmail put earlier mail in Spam, that is
reported here. This is context generic scanners do not have: an invoice from a supplier you have
emailed for two years is very different from the same invoice from a stranger.

History is looked up by the From address, which the sender controls. So familiarity
only counts as reassuring when the address is authenticated; a familiar address that
*fails* authentication is the signature of a spoofed colleague - one of the most
damaging BEC patterns - and is reported as such.
"""

from __future__ import annotations

from ..context import EmailContext
from .base import Category, Finding

C = Category.HISTORY
SUSPICIOUS_FLOOR = 30  # = scoring.SUSPICIOUS_AT (not imported, to keep analysers independent of scoring)


def _track_record(ctx: EmailContext) -> list[Finding]:
    """What the user's own mailbox already knows about this sender."""
    h = ctx.history
    assert h is not None
    out: list[Finding] = []
    if h.reported_sender or h.blocked_sender:
        what = " and ".join(x for x, on in (("reported", h.reported_sender), ("blocked", h.blocked_sender)) if on)
        out.append(
            Finding(
                "HISTORY_REPORTED_BEFORE",
                C,
                f"You already {what} this sender",
                f"You {what} this address before. A person's own judgement about a sender is the strongest "
                "evidence there is.",
                40,
                floor=70,
                params=(("what", what),),
            )
        )
    if h.prior_malicious_verdicts:
        n = h.prior_malicious_verdicts
        out.append(
            Finding(
                "HISTORY_PREVIOUSLY_MALICIOUS",
                C,
                "Earlier mail from this sender was malicious",
                f"MailGuard rated {n} earlier email{'s' if n > 1 else ''} from this address as malicious. "
                "Attackers often send several waves from the same address.",
                35,
                (f"{n} earlier malicious verdict{'s' if n > 1 else ''}",),
                floor=SUSPICIOUS_FLOOR,  # never "safe" again by default; the user can still judge
            )
        )
    elif h.prior_suspicious_verdicts >= 2:
        out.append(
            Finding(
                "HISTORY_PREVIOUSLY_SUSPICIOUS",
                C,
                "Earlier mail from this sender was suspicious",
                f"MailGuard rated {h.prior_suspicious_verdicts} earlier emails from this address as suspicious.",
                12,
            )
        )
    if h.prior_spam_messages:
        out.append(
            Finding(
                "HISTORY_GMAIL_SPAM",
                C,
                "Gmail sent earlier mail from this sender to Spam",
                f"{h.prior_spam_messages} earlier email(s) from this address are in your Spam folder - Gmail's own "
                "filters already judged this sender.",
                20,
            )
        )
    if h.domain_prior_malicious:
        domain = ctx.from_addr.domain if ctx.from_addr else ""
        out.append(
            Finding(
                "HISTORY_DOMAIN_MALICIOUS",
                C,
                "Malicious mail came from this domain before",
                f"Other addresses at {domain} sent you mail that MailGuard rated malicious "
                f"({h.domain_prior_malicious} time{'s' if h.domain_prior_malicious > 1 else ''}).",
                15,
                (domain,),
            )
        )
    return out


def _sent_to_self(ctx: EmailContext) -> bool:
    if not ctx.from_addr or not ctx.from_addr.email:
        return False
    me = ctx.from_addr.email.lower().replace("@googlemail.com", "@gmail.com")
    for name in ("Delivered-To", "X-Original-To", "To"):
        value = str(ctx.headers.get(name, "") or "").lower().replace("@googlemail.com", "@gmail.com")
        if me and me in value and name != "To":
            return True
        if name == "To" and value.strip("<> ") == me:
            return True
    return False


def analyze(ctx: EmailContext) -> list[Finding]:
    h = ctx.history
    if h is None or ctx.from_addr is None:
        return []
    known = h.user_has_emailed_sender or h.prior_messages_from_sender >= 3
    record = _track_record(ctx)

    if known and ctx.sender_spoofed():
        return [
            *record,
            Finding(
                "HISTORY_SPOOFED_CONTACT",
                Category.SENDER,
                "Pretends to be someone you know",
                f"You know {ctx.from_addr.email}, but this message failed sender authentication, so it "
                "was probably not sent by them. Spoofing a familiar contact is a classic fraud technique.",
                35,
                (ctx.from_addr.email,),
            ),
        ]
    if h.prior_messages_from_sender == 0 and not h.user_has_emailed_sender:
        return [
            *record,
            Finding(
                "HISTORY_FIRST_CONTACT",
                C,
                "First message from this sender",
                "You have never received mail from this address or written to it. Most phishing "
                "comes from senders you have no history with.",
                10,
            ),
        ]
    if record or not ctx.sender_authenticated() or _sent_to_self(ctx):
        # Familiarity never reassures about a sender with a bad record or no authentication - nor
        # about mail "from yourself": of course you know your own address.
        return record  # familiarity never reassures about a sender with a bad record or no authentication
    if h.user_has_emailed_sender:
        return [
            Finding(
                "HISTORY_KNOWN_CORRESPONDENT",
                C,
                "You have written to this sender before",
                "This address is in your sent mail and the message is authenticated. Still be careful "
                "with unusual requests - real accounts do get compromised.",
                -15,
            )
        ]
    if h.prior_messages_from_sender >= 3:
        return [
            Finding(
                "HISTORY_REGULAR_SENDER",
                C,
                "Regular sender",
                f"You have {h.prior_messages_from_sender}+ earlier messages from this address.",
                -8,
            )
        ]
    return []
