"""Runtime configuration, read once from environment variables.

Secrets (HMAC key, API keys) are injected by the platform - on Cloud Run from Secret
Manager - and are never committed, logged or returned in responses.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    env: str = "dev"  # dev | prod
    hmac_secret: str = field(default="", repr=False)
    hmac_secret_previous: str = field(default="", repr=False)  # accepted during a key rotation
    max_parallel_analyses: int = 4
    virustotal_api_key: str = field(default="", repr=False)
    safe_browsing_api_key: str = field(default="", repr=False)
    enable_rdap: bool = True
    max_request_bytes: int = 12 * 1024 * 1024
    signature_max_age_s: int = 300
    rate_limit_per_minute: int = 30
    intel_deadline_s: float = 8.0
    vt_max_lookups: int = 4  # free VirusTotal tier: 4 requests/minute
    protected_domains: tuple[str, ...] = ()  # e.g. your company's domains

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @property
    def hmac_secrets(self) -> tuple[str, ...]:
        return tuple(x for x in (self.hmac_secret, self.hmac_secret_previous) if x)


DOTENV = Path(__file__).resolve().parents[1] / ".env"


def load_dotenv(path: Path = DOTENV) -> list[str]:
    """Local development: read backend/.env so `uvicorn app.main:app` works without `make run`
    (and on Windows). Real environment variables always win, so on Cloud Run - where .env is
    excluded from the image anyway - nothing changes. Returns the names that were loaded."""
    if os.environ.get("MG_LOAD_DOTENV", "1") == "0" or not path.is_file():
        return []
    loaded = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key.startswith("MG_") and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv()
    s = Settings(
        env=os.environ.get("MG_ENV", "dev").strip().lower(),
        hmac_secret=os.environ.get("MG_HMAC_SECRET", "").strip(),  # a pasted newline must not break signing
        hmac_secret_previous=os.environ.get("MG_HMAC_SECRET_PREVIOUS", "").strip(),
        max_parallel_analyses=_int("MG_MAX_PARALLEL_ANALYSES", 4),
        virustotal_api_key=os.environ.get("MG_VIRUSTOTAL_API_KEY", ""),
        safe_browsing_api_key=os.environ.get("MG_SAFE_BROWSING_API_KEY", ""),
        enable_rdap=_bool("MG_ENABLE_RDAP", True),
        max_request_bytes=_int("MG_MAX_REQUEST_BYTES", 12 * 1024 * 1024),
        signature_max_age_s=_int("MG_SIGNATURE_MAX_AGE_S", 300),
        rate_limit_per_minute=_int("MG_RATE_LIMIT_PER_MINUTE", 30),
        vt_max_lookups=_int("MG_VT_MAX_LOOKUPS", 4),
        protected_domains=tuple(
            d.strip().lower() for d in os.environ.get("MG_PROTECTED_DOMAINS", "").split(",") if d.strip()
        ),
    )
    if s.is_prod and len(s.hmac_secret) < 32:
        raise RuntimeError("MG_HMAC_SECRET must be set (>= 32 chars) when MG_ENV=prod")
    if s.hmac_secret_previous and len(s.hmac_secret_previous) < 32:
        raise RuntimeError("MG_HMAC_SECRET_PREVIOUS, when set, must be >= 32 chars")
    return s
