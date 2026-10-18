"""Shared test helpers."""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT.parent / "samples"
sys.path.insert(0, str(ROOT))

from app.context import build_context  # noqa: E402
from app.schemas import AnalyzeRequest  # noqa: E402

GOOGLE_AUTH_PASS = (
    "Authentication-Results: mx.google.com; dkim=pass header.i=@{d} header.s=s1; "
    "spf=pass smtp.mailfrom=bounce@{d}; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={d}\n"
)


def headers(from_: str, extra: str = "", auth_domain: str | None = None) -> str:
    domain = from_.rsplit("@", 1)[-1].strip(">")
    auth = GOOGLE_AUTH_PASS.format(d=auth_domain or domain)
    return f"{auth}From: {from_}\nSubject: test\n{extra}"


def make_request(**kw) -> AnalyzeRequest:
    kw.setdefault("raw_headers", headers("Alice <alice@example.org>"))
    return AnalyzeRequest(**kw)


def ctx_for(**kw):
    return build_context(make_request(**kw))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(coro):
    return asyncio.run(coro)
