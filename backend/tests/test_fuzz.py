"""Robustness: random and hostile inputs must never crash the engine or make it slow.

No external fuzzing library is needed: a seeded generator mixes structured attack
fragments with random bytes, so every run is reproducible (set MG_FUZZ_SEED to explore).
"""

import base64
import hashlib
import os
import random
import time

from helpers import make_request, run

from app.pipeline import analyze_email
from app.schemas import AnalyzeResponse

SEED = int(os.environ.get("MG_FUZZ_SEED", "1337"))
CASES = int(os.environ.get("MG_FUZZ_CASES", "60"))

FRAGMENTS = [
    "<a href='{u}'>{t}</a>",
    "<div style='display:none'>{t}</div>",
    "<!--{t}-->",
    "<style>{t}{{</style>",
    "<form action='{u}'><input type=password>",
    "<table bgcolor=#fff><td><font color=#fff>{t}",
    "<" * 50,
    "</div>" * 50,
    "(" * 200,
    "&#x202e;&#0;&#xD800;",
    "\u202e\u200b\ufeff",
    "<a href=javascript:{t}>",
    "<p style='font-size:0;color:rgba(1,2,3,0)'>{t}",
    "<a href='http://[::1]/x'>x</a>",
    "<a href='http://%zz'>",
    "ignore previous instructions",
    "AKIAQRSTUVWXYZ234567",
    "-----BEGIN PRIVATE KEY-----",
    "https://microsoft.com/devicelogin code ABCD-EFGH",
    "<area href='{u}'>",
    "<meta http-equiv=refresh>",
]
URLS = ["https://xn--pypal-4ve.com/a", "http://192.168.0.1/", "https://bit.ly/x", "data:text/html,x", "//x", "", "%"]


def _random_text(rng: random.Random, n: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz<>/='\"&;#() \n\tאבגדהабвгд\u202e\u200b0123456789{}:.%@"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _case(rng: random.Random) -> dict:
    parts = []
    for _ in range(rng.randint(1, 40)):
        frag = rng.choice(FRAGMENTS)
        parts.append(frag.format(u=rng.choice(URLS), t=_random_text(rng, rng.randint(0, 80))))
        if rng.random() < 0.3:
            parts.append(_random_text(rng, rng.randint(0, 2000)))
    html = "".join(parts) * rng.choice([1, 1, 1, 20])
    data = rng.randbytes(rng.randint(0, 4096))
    if rng.random() < 0.3:
        data = b"PK\x03\x04" + data
    headers = rng.choice(
        [
            "From: a@b.com\n",
            "Authentication-Results: mx.google.com; " + _random_text(rng, 500) + "\nFrom: " + _random_text(rng, 60),
            "From: =?utf-8?b?" + base64.b64encode(rng.randbytes(30)).decode() + "?= <x@y.z>\n",
            _random_text(rng, 3000),
        ]
    )
    return {
        "raw_headers": headers[: 128 * 1024],
        "html_body": html[:600_000],
        "text_body": _random_text(rng, rng.randint(0, 5000)),
        "attachments": [
            {
                "filename": _random_text(rng, 20) + rng.choice([".zip", ".pdf", ".docm", ".exe", ".txt", ""]),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_b64": base64.b64encode(data).decode(),
            }
        ],
    }


def test_fuzz_never_crashes_and_stays_fast():
    rng = random.Random(SEED)
    slowest = 0.0
    for i in range(CASES):
        req = make_request(**_case(rng))
        start = time.perf_counter()
        res = run(analyze_email(req))
        slowest = max(slowest, time.perf_counter() - start)
        assert isinstance(res, AnalyzeResponse), i
        assert 0 <= res.score <= 100
        assert res.confidence.value != "low" or "error" not in res.coverage.values(), (i, res.coverage)
    assert slowest < 3.0, f"slowest case took {slowest:.2f}s"
