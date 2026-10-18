import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from helpers import headers

from app.config import Settings
from app.main import create_app
from app.security import sign

SECRET = "s" * 40
CLIENT_ID = "ab" * 16


@pytest.fixture
def client():
    settings = Settings(hmac_secret=SECRET, enable_rdap=False, rate_limit_per_minute=5, max_request_bytes=200_000)
    with TestClient(create_app(settings)) as c:
        yield c


def signed(body: bytes, *, ts=None, nonce=None, secret=SECRET):
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or str(uuid.uuid4())
    return {
        "Content-Type": "application/json",
        "X-MG-Timestamp": ts,
        "X-MG-Nonce": nonce,
        "X-MG-Client": CLIENT_ID,
        "X-MG-Signature": sign(secret, ts, nonce, CLIENT_ID, body),
    }


BODY = json.dumps({"raw_headers": headers('"PayPal" <help@paypa1.com>'), "text_body": "verify your account"}).encode()


def test_health(client):
    health = client.get("/healthz").json()
    assert health["status"] == "ok" and health["signing"] in {"on", "off"}


def test_valid_signed_request(client):
    r = client.post("/v1/analyze", content=BODY, headers=signed(BODY))
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in {"suspicious", "malicious"}
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_missing_or_bad_signature(client):
    assert client.post("/v1/analyze", content=BODY).status_code == 401
    assert client.post("/v1/analyze", content=BODY, headers=signed(BODY, secret="x" * 40)).status_code == 401


def test_tampered_body_rejected(client):
    hdrs = signed(BODY)
    assert client.post("/v1/analyze", content=BODY.replace(b"verify", b"VERIFY"), headers=hdrs).status_code == 401


def test_stale_timestamp_rejected(client):
    assert client.post("/v1/analyze", content=BODY, headers=signed(BODY, ts=int(time.time()) - 3600)).status_code == 401


def test_replay_rejected(client):
    hdrs = signed(BODY)
    assert client.post("/v1/analyze", content=BODY, headers=hdrs).status_code == 200
    assert client.post("/v1/analyze", content=BODY, headers=hdrs).status_code == 401


def test_oversized_body_rejected_before_auth(client):
    big = b"{" + b" " * 300_000 + b"}"
    assert client.post("/v1/analyze", content=big, headers=signed(big)).status_code == 413


def test_invalid_payload_does_not_echo_input(client):
    body = json.dumps({"raw_headers": "x", "unexpected": "<script>secret</script>"}).encode()
    r = client.post("/v1/analyze", content=body, headers=signed(body))
    assert r.status_code == 422
    assert "secret" not in r.text and "unexpected" in r.text


def test_rate_limit(client):
    codes = [client.post("/v1/analyze", content=BODY, headers=signed(BODY)).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]


def test_docs_hidden_in_prod():
    with TestClient(create_app(Settings(env="prod", hmac_secret=SECRET, enable_rdap=False))) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404


def test_future_timestamp_beyond_skew_rejected(client):
    assert client.post("/v1/analyze", content=BODY, headers=signed(BODY, ts=int(time.time()) + 300)).status_code == 401


def test_outbound_request_urls_are_not_logged():
    import logging

    create_app(Settings(enable_rdap=False))
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING


def test_response_carries_timing_sender_and_headline(client):
    data = client.post("/v1/analyze", content=BODY, headers=signed(BODY)).json()
    assert isinstance(data["analysis_ms"], float) and data["analysis_ms"] >= 0
    assert data["sender"]["email"] == "help@paypa1.com"
    assert data["sender"]["authenticated"] is True  # DMARC pass for the look-alike domain itself
    assert "paypal.com" in data["headline"]


def test_report_endpoint_is_signed_and_logs_indicators_defanged(client):
    import logging

    from app.main import JsonFormatter

    records = []

    class Collect(logging.Handler):
        def emit(self, record):
            records.append(JsonFormatter().format(record))

    handler = Collect()
    logging.getLogger("mailguard.api").addHandler(handler)
    try:
        body = json.dumps(
            {
                "score": 92,
                "verdict": "malicious",
                "sender_email": "a@evil.example",
                "indicators": ["http://evil.example/login"],
                "message_id_header": "<abc@evil.example>",
            }
        ).encode()
        assert client.post("/v1/report", content=body).status_code == 401
        r = client.post("/v1/report", content=body, headers=signed(body))
    finally:
        logging.getLogger("mailguard.api").removeHandler(handler)
    assert r.status_code == 200 and r.json()["report_id"].startswith("MG-")
    report = next(x for x in records if "secops_report" in x)
    assert "hxxp[://]evil[.]example/login" in report and "http://evil" not in report


def test_report_rejects_unknown_fields(client):
    body = json.dumps({"score": 1, "verdict": "safe", "raw_body": "x"}).encode()
    assert client.post("/v1/report", content=body, headers=signed(body)).status_code == 422


# ----------------------------------------------------------------------------- hardening


def test_response_is_signed_and_bound_to_the_request_nonce(client):
    from app.security import sign_response

    hdrs = signed(BODY)
    r = client.post("/v1/analyze", content=BODY, headers=hdrs)
    sig = r.headers["x-mg-response-signature"]
    assert sig == sign_response(SECRET, hdrs["X-MG-Nonce"], r.content)
    # The same body with any other nonce does not verify: an old "safe" answer can't be replayed.
    assert sig != sign_response(SECRET, "another-nonce-123456", r.content)


def test_secret_rotation_accepts_previous_key_and_signs_with_it():
    from app.security import sign_response

    old = "o" * 40
    settings = Settings(hmac_secret=SECRET, hmac_secret_previous=old, enable_rdap=False)
    with TestClient(create_app(settings)) as c:
        hdrs = signed(BODY, secret=old)
        r = c.post("/v1/analyze", content=BODY, headers=hdrs)
        assert r.status_code == 200
        assert r.headers["x-mg-response-signature"] == sign_response(old, hdrs["X-MG-Nonce"], r.content)
        assert c.post("/v1/analyze", content=BODY, headers=signed(BODY, secret="z" * 40)).status_code == 401


def test_hsts_header(client):
    assert "max-age" in client.get("/healthz").headers["strict-transport-security"]


def test_busy_when_all_analysis_slots_are_taken(client):
    from app import pipeline

    taken = 0
    while pipeline._SLOTS.try_acquire():
        taken += 1
    try:
        r = client.post("/v1/analyze", content=BODY, headers=signed(BODY))
        assert r.status_code == 503 and r.headers["retry-after"] == "2"
    finally:
        for _ in range(taken):
            pipeline._SLOTS.release()
    assert client.post("/v1/analyze", content=BODY, headers=signed(BODY)).status_code == 200


def test_short_previous_secret_is_rejected_at_startup(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("MG_HMAC_SECRET_PREVIOUS", "short")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError):
            get_settings()
    finally:
        get_settings.cache_clear()
