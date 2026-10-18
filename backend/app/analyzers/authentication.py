"""SPF / DKIM / DMARC results, as recorded by Gmail when the message was received."""

from __future__ import annotations

from ..context import EmailContext
from .base import Category, Finding

C = Category.AUTHENTICATION


def analyze(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []

    if ctx.forged_auth_headers:
        out.append(
            Finding(
                "AUTH_FORGED_HEADER",
                C,
                "Fake authentication header inside the message",
                "The message carries an extra Authentication-Results header claiming to come from "
                "Gmail. Legitimate senders never do this; it is an attempt to fool filters. It was ignored.",
                25,
            )
        )

    auth = ctx.auth
    if auth is None:
        out.append(
            Finding(
                "AUTH_MISSING",
                C,
                "Sender authentication could not be verified",
                "Gmail did not record SPF/DKIM/DMARC results for this message, so we cannot "
                "confirm the sender's domain actually sent it.",
                10,
            )
        )
        return out

    from_domain = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""

    if auth.dmarc == "fail":
        policy = f" (the domain's policy is '{auth.dmarc_policy}')" if auth.dmarc_policy else ""
        out.append(
            Finding(
                "AUTH_DMARC_FAIL",
                C,
                "Sender domain failed DMARC",
                f"The message claims to be from {from_domain or 'this domain'} but failed the domain "
                f"owner's anti-spoofing check{policy}. This is the classic sign of a spoofed sender.",
                30,
                (from_domain,) if from_domain else (),
            )
        )
    if auth.spf in ("fail", "permerror"):
        out.append(
            Finding(
                "AUTH_SPF_FAIL",
                C,
                "Sent from a server the domain does not authorise",
                "SPF failed: the sending server is not on the list of servers allowed to send for this domain.",
                15,
            )
        )
    elif auth.spf == "softfail":
        out.append(
            Finding(
                "AUTH_SPF_SOFTFAIL",
                C,
                "SPF soft-fail",
                "The sending server is probably not authorised to send for this domain.",
                8,
            )
        )

    dkim_results = {r for r, _ in auth.dkim}
    if "fail" in dkim_results and "pass" not in dkim_results:
        out.append(
            Finding(
                "AUTH_DKIM_FAIL",
                C,
                "Digital signature is broken",
                "The DKIM signature does not verify: the message was altered or the signature was forged.",
                12,
            )
        )
    elif not auth.dkim or dkim_results <= {"none"}:
        out.append(
            Finding(
                "AUTH_DKIM_NONE",
                C,
                "Message is not digitally signed",
                "Most legitimate organisations sign their mail with DKIM; this message has no signature.",
                5,
            )
        )

    aligned = bool(from_domain) and any(
        d == from_domain or d.endswith("." + from_domain) for d in auth.dkim_pass_domains
    )
    if auth.dmarc == "pass":
        out.append(
            Finding(
                "AUTH_DMARC_PASS",
                C,
                "Sender domain is authenticated",
                f"DMARC passed, so the message really came from {from_domain or 'the sender domain'}. "
                "Note: this proves who sent it, not that they are trustworthy - attackers authenticate "
                "their own look-alike domains too.",
                -8,
                (from_domain,) if from_domain else (),
            )
        )
    elif auth.dmarc in ("none", "") and auth.dkim_pass_domains and not aligned:
        out.append(
            Finding(
                "AUTH_DKIM_UNALIGNED",
                C,
                "Signed by an unrelated domain",
                f"The message is signed by {', '.join(sorted(auth.dkim_pass_domains))}, not by "
                f"{from_domain or 'the domain in the From address'}.",
                5,
                tuple(sorted(auth.dkim_pass_domains))[:3],
            )
        )
    return out
