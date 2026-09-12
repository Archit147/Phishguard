"""Pydantic models — the wire contract between the extension and the engine."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

MAX_HTML_BYTES = 3_000_000  # ~3 MB of DOM is plenty; anything larger is truncated client-side


class Verdict(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    DANGEROUS = "Dangerous"
    WHITELISTED = "Whitelisted"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    FORM = "form"
    CLOAKING = "cloaking"
    SCRIPT = "script"
    BRAND = "brand"
    TRANSPORT = "transport"


class Signal(BaseModel):
    """One triggered heuristic. `weight` is this signal's standalone risk (0-100)."""

    id: str
    title: str
    detail: str
    category: Category
    severity: Severity
    weight: float = Field(ge=0, le=100)
    evidence: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    url: str
    html: str = ""
    # Optional client hints
    title: str | None = None
    referrer: str | None = None
    top_level: bool = True

    @field_validator("html")
    @classmethod
    def _cap_html(cls, v: str) -> str:
        return v[:MAX_HTML_BYTES] if len(v) > MAX_HTML_BYTES else v

    @field_validator("url")
    @classmethod
    def _url_present(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v[:4096]


class ScanResponse(BaseModel):
    url: str
    hostname: str
    registered_domain: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    whitelisted: bool = False
    block: bool = False
    headline: str
    summary: str
    signals: list[Signal]
    impersonated_brand: str | None = None
    impersonated_brand_label: str | None = None
    scanned_at: str
    engine_version: str
    duration_ms: float


class WhitelistEntry(BaseModel):
    domain: str
    added_at: str
    note: str | None = None
    scope: Literal["domain", "exact"] = "domain"


class WhitelistRequest(BaseModel):
    # Accepts either a bare domain or a full URL; normalised server-side.
    domain: str
    note: str | None = None
    scope: Literal["domain", "exact"] = "domain"


class WhitelistResponse(BaseModel):
    ok: bool
    domain: str
    entries: list[WhitelistEntry]
