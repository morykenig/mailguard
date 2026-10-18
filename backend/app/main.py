"""HTTP API. Thin by design: auth, limits and logging here; all analysis in ``pipeline``."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError

from .analyzers.reputation import IntelClients
from .config import Settings, get_settings
from .intel.cache import TTLCache
from .intel.http import make_client
from .intel.providers import Rdap, SafeBrowsing, VirusTotal
from .pipeline import ENGINE_VERSION, AnalysisBusy, analyze_email, configure
from .schemas import AnalyzeRequest, AnalyzeResponse, ReportRequest, ReportResponse
from .security import RESPONSE_SIG_HEADER, NonceCache, RateLimiter, Verified, sign_response, verify_request
from .textutil import clean, defang_url

ANALYSIS_TIMEOUT_S = 20.0
T = TypeVar("T", bound=BaseModel)  # Apps Script UrlFetch gives up around 30s


class JsonFormatter(logging.Formatter):
    """One JSON object per line - Cloud Logging parses it into structured fields."""

    _FIELDS = (
        "request_id",
        "client",
        "score",
        "verdict",
        "duration_ms",
        "links",
        "attachments",
        "provider",
        "error",
        "analyser",
        "status",
        "report_id",
        "report",
    )

    def format(self, record: logging.LogRecord) -> str:
        entry = {"severity": record.levelname, "message": record.getMessage(), "logger": record.name}
        entry.update({k: getattr(record, k) for k in self._FIELDS if hasattr(record, k)})
        if record.exc_info:
            entry["exception"] = record.exc_info[0].__name__ if record.exc_info[0] else "unknown"
        return json.dumps(entry)


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    # httpx logs every outbound request URL at INFO. Those URLs embed indicators taken from
    # the email (a VirusTotal URL id is the email's link, base64-encoded), so keep them out.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


log = logging.getLogger("mailguard.api")


async def _read_body_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > limit):
        raise HTTPException(413, "request too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > limit:
            raise HTTPException(413, "request too large")
    return bytes(buf)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    _configure_logging()
    nonces = NonceCache()
    limiter = RateLimiter(settings.rate_limit_per_minute)
    configure(settings.max_parallel_analyses)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = make_client()
        app.state.intel = IntelClients(
            vt=VirusTotal(settings.virustotal_api_key, client, TTLCache()) if settings.virustotal_api_key else None,
            safe_browsing=(
                SafeBrowsing(settings.safe_browsing_api_key, client, TTLCache())
                if settings.safe_browsing_api_key
                else None
            ),
            rdap=Rdap(client, TTLCache()) if settings.enable_rdap else None,
            vt_max_lookups=settings.vt_max_lookups,
            deadline_s=settings.intel_deadline_s,
        )
        if not settings.hmac_secret:
            log.warning(
                "MG_HMAC_SECRET not set - requests are NOT verified and answers are NOT signed, so the Gmail "
                "add-on will reject every answer ('not signed'). Set MG_HMAC_SECRET in backend/.env (dev only)."
            )
        else:
            log.info("request and response signing ON")
        yield
        await client.aclose()

    app = FastAPI(
        title="MailGuard",
        version=ENGINE_VERSION,
        lifespan=lifespan,
        # No interactive docs in production: they advertise the attack surface.
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = uuid.uuid4().hex[:16]
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error", extra={"request_id": request.state.request_id})
            response = JSONResponse({"detail": "internal error"}, status_code=500)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        # "signing" lets the add-on's diagnose() tell a dev backend (no shared secret, so unsigned
        # answers) from a wrong secret. It reveals nothing an unsigned request couldn't learn.
        return {"status": "ok", "version": ENGINE_VERSION, "signing": "on" if settings.hmac_secrets else "off"}

    async def authenticated_body(request: Request) -> tuple[bytes, Verified | None]:
        """Read the capped body, verify its signature and apply the rate limit - in that order,
        so unauthenticated callers never get the service to parse or analyse anything."""
        body = await _read_body_capped(request, settings.max_request_bytes)
        verified: Verified | None = None
        if settings.hmac_secrets:
            verified = verify_request(
                secrets=settings.hmac_secrets,
                headers={k.lower(): v for k, v in request.headers.items()},
                body=body,
                nonces=nonces,
                max_age_s=settings.signature_max_age_s,
            )
        elif settings.is_prod:  # unreachable thanks to config validation; defence in depth
            raise HTTPException(503, "misconfigured")
        if not limiter.allow(verified.client if verified else "dev"):
            raise HTTPException(429, "rate limited")
        return body, verified

    def signed_json(model: BaseModel, verified: Verified | None) -> Response:
        """Serialise once and sign exactly those bytes, bound to the request's nonce."""
        payload = model.model_dump_json().encode()
        headers = {}
        if verified is not None:
            headers[RESPONSE_SIG_HEADER] = sign_response(verified.secret, verified.nonce, payload)
        return Response(content=payload, media_type="application/json", headers=headers)

    def parse(model: type[T], body: bytes) -> T:
        try:
            return model.model_validate_json(body)
        except ValidationError as exc:
            # Report *where* the payload is wrong, never echo the (attacker-controlled) values.
            locs = [".".join(str(p) for p in e["loc"]) for e in exc.errors()[:5]]
            raise HTTPException(422, {"error": "invalid request", "fields": locs}) from None

    @app.post("/v1/analyze", response_model=AnalyzeResponse)
    async def analyze(request: Request) -> Response:
        started = time.perf_counter()
        body, verified = await authenticated_body(request)
        client = verified.client if verified else "dev"
        req = parse(AnalyzeRequest, body)
        try:
            result = await asyncio.wait_for(
                analyze_email(req, request.app.state.intel, settings.protected_domains), ANALYSIS_TIMEOUT_S
            )
        except AnalysisBusy:
            raise HTTPException(503, "busy", headers={"Retry-After": "2"}) from None
        except TimeoutError:
            raise HTTPException(504, "analysis timed out") from None

        # Metadata only: no subject, addresses, URLs or body ever reach the logs.
        log.info(
            "analysed",
            extra={
                "request_id": request.state.request_id,
                "client": client[:12],
                "score": result.score,
                "verdict": result.verdict.value,
                "links": len(result.links),
                "attachments": len(req.attachments),
                "duration_ms": round((time.perf_counter() - started) * 1000),
            },
        )
        return signed_json(result, verified)

    @app.post("/v1/report", response_model=ReportResponse)
    async def report(request: Request) -> Response:
        """User-initiated "Report to SecOps".

        Demo implementation: the report becomes a structured log record (Cloud Logging), which
        a log sink can route to a SIEM or ticketing queue. Unlike analysis logs, a report *does*
        carry indicators (de-fanged URLs, sender) - the user explicitly chose to share them,
        and they are exactly what an analyst needs. The message body is never included.
        """
        body, verified = await authenticated_body(request)
        client = verified.client if verified else "dev"
        rep = parse(ReportRequest, body)
        report_id = "MG-" + uuid.uuid4().hex[:8].upper()
        log.warning(
            "secops_report",
            extra={
                "request_id": request.state.request_id,
                "report_id": report_id,
                "client": client[:12],
                "score": rep.score,
                "verdict": rep.verdict.value,
                "report": {
                    "message_id": clean(rep.message_id_header, 256),
                    "sender": clean(rep.sender_email, 320),
                    "indicators": [defang_url(i, 200) for i in rep.indicators],
                    "note": clean(rep.user_note, 500),
                    "engine_version": clean(rep.engine_version, 32),
                    "attack_techniques": rep.attack_techniques,
                },
            },
        )
        return signed_json(ReportResponse(report_id=report_id, status="received"), verified)

    return app


app = create_app()  # uvicorn entry point: app.main:app
