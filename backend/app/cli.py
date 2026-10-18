"""Score .eml files from the command line.

python -m app.cli ../samples/*.eml            # offline (local rules only)
python -m app.cli --intel ../samples/x.eml    # also query configured threat intel
python -m app.cli --json ../samples/x.eml     # raw API response
python -m app.cli --locale he ../samples/*.eml # explanations in Hebrew
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .analyzers.reputation import IntelClients
from .config import get_settings
from .eml import request_from_eml
from .intel.cache import TTLCache
from .intel.http import make_client
from .intel.providers import Rdap, SafeBrowsing, VirusTotal
from .pipeline import analyze_email
from .schemas import SenderHistory

COLORS = {"safe": "\033[32m", "suspicious": "\033[33m", "malicious": "\033[31m"}
RESET = "\033[0m"


async def _run(
    paths: list[Path], use_intel: bool, as_json: bool, first_contact: bool, org: str, locale: str = "en"
) -> int:
    settings = get_settings()
    client = make_client() if use_intel else None
    intel = None
    if client is not None:
        intel = IntelClients(
            vt=VirusTotal(settings.virustotal_api_key, client, TTLCache()) if settings.virustotal_api_key else None,
            safe_browsing=SafeBrowsing(settings.safe_browsing_api_key, client, TTLCache())
            if settings.safe_browsing_api_key
            else None,
            rdap=Rdap(client, TTLCache()) if settings.enable_rdap else None,
            vt_max_lookups=settings.vt_max_lookups,
        )
    history = SenderHistory(prior_messages_from_sender=0, user_has_emailed_sender=False) if first_contact else None
    try:
        for path in paths:
            req = request_from_eml(path.read_bytes(), history=history, recipient_domain=org)
            req = req.model_copy(update={"locale": locale})
            res = await analyze_email(req, intel, settings.protected_domains)
            if as_json:
                print(res.model_dump_json(indent=2))
                continue
            color = COLORS[res.verdict.value] if sys.stdout.isatty() else ""
            reset = RESET if color else ""
            print(
                f"\n{path.name}\n  {color}{res.score:>3}/100  {res.verdict.value.upper()}{reset}"
                f"  (confidence: {res.confidence.value})"
            )
            if res.subject:
                print(f"  Subject: {res.subject}")
            print(f"  {res.summary}")
            for f in res.findings:
                print(f"    +{f.points:<3} {f.title}")
            for f in res.mitigations:
                print(f"    {f.points:<4} {f.title}")
            for f in res.exposures:
                print(f"    🔑   {f.title}: {', '.join(f.evidence)}")
            if res.attack_techniques:
                print("    MITRE: " + ", ".join(t.id for t in res.attack_techniques))
            for name, status in res.coverage.items():
                if status not in {"checked", "נבדק"}:
                    print(f"    · {name}: {status}")
    finally:
        if client is not None:
            await client.aclose()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Score .eml files with the MailGuard engine")
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--intel", action="store_true", help="query configured threat-intel providers")
    p.add_argument("--json", action="store_true", help="print the raw API response")
    p.add_argument("--first-contact", action="store_true", help="simulate a sender with no prior history")
    p.add_argument("--org", default="", help="recipient organisation domain, e.g. acme.com")
    p.add_argument("--locale", default="en", help="UI language for explanations: en or he")
    args = p.parse_args()
    return asyncio.run(_run(args.files, args.intel, args.json, args.first_contact, args.org, args.locale))


if __name__ == "__main__":
    raise SystemExit(main())
