"""PhishGuard API — FastAPI analysis engine for the Chrome extension.

Run:  uvicorn backend.main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import (
    ENGINE_VERSION,
    analyze,
    is_trusted_host,
    parse_url,
)
from .brands import brand_label
from .models import (
    ScanRequest,
    ScanResponse,
    Verdict,
    WhitelistRequest,
    WhitelistResponse,
)
from .scoring import (
    DANGEROUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    aggregate,
    summarize,
    verdict_for,
)
from .whitelist import WhitelistStore, normalize_domain

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s"
)
log = logging.getLogger("phishguard")

app = FastAPI(
    title="PhishGuard API",
    version=ENGINE_VERSION,
    description=(
        "Real-time phishing and credential-harvesting detection. Accepts a URL plus the "
        "rendered DOM and returns a risk score, verdict and per-signal explanation."
    ),
)

# The extension calls this from arbitrary page origins, and a content script's
# fetch carries that page's Origin header. Credentials are never used, so a
# permissive origin policy is safe here and avoids a class of confusing CORS
# failures during a demo. Tighten (or drop the middleware and call only from the
# service worker) before exposing this beyond localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,
)

store = WhitelistStore()


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "thresholds": {
            "suspicious": SUSPICIOUS_THRESHOLD,
            "dangerous": DANGEROUS_THRESHOLD,
        },
        "whitelist_entries": len(store.all()),
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


@app.post("/scan", response_model=ScanResponse, tags=["analysis"])
def scan(req: ScanRequest) -> ScanResponse:
    """Analyse a URL and its DOM. This is the endpoint the extension calls."""
    started = time.perf_counter()

    try:
        facts = parse_url(req.url)
    except Exception as exc:  # malformed input should not 500
        raise HTTPException(status_code=422, detail=f"could not parse url: {exc}") from exc

    # Never warn on the browser's own surfaces or local development hosts.
    if facts.scheme in ("chrome", "chrome-extension", "about", "edge", "moz-extension", "devtools"):
        raise HTTPException(status_code=422, detail="internal browser page; nothing to scan")

    whitelisted = store.contains(req.url)

    signals = []
    brand = None
    if not whitelisted:
        facts, signals, brand = analyze(req.url, req.html)

    if whitelisted:
        score, confidence = 0, 0.99
        verdict = Verdict.WHITELISTED
    else:
        score, confidence = aggregate(signals)
        verdict = verdict_for(score)

    headline, summary = summarize(verdict, score, signals, brand)
    signals.sort(key=lambda s: s.weight, reverse=True)
    duration = (time.perf_counter() - started) * 1000

    log.info(
        "scan host=%s verdict=%s score=%d signals=%d %.1fms",
        facts.host or "?", verdict.value, score, len(signals), duration,
    )

    return ScanResponse(
        url=req.url,
        hostname=facts.host,
        registered_domain=facts.registered_domain,
        verdict=verdict,
        risk_score=score,
        confidence=confidence,
        whitelisted=whitelisted,
        block=(verdict is Verdict.DANGEROUS),
        headline=headline,
        summary=summary,
        signals=signals,
        impersonated_brand=brand,
        impersonated_brand_label=brand_label(brand) or None,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        engine_version=ENGINE_VERSION,
        duration_ms=round(duration, 2),
    )


@app.get("/whitelist", response_model=WhitelistResponse, tags=["whitelist"])
def whitelist_list() -> WhitelistResponse:
    entries = store.all()
    return WhitelistResponse(ok=True, domain="", entries=entries)


@app.post("/whitelist", response_model=WhitelistResponse, tags=["whitelist"])
def whitelist_add(req: WhitelistRequest) -> WhitelistResponse:
    """Trust a domain. Accepts a bare host or a full URL; stored as the registrable domain."""
    try:
        domain = store.add(req.domain, note=req.note, scope=req.scope)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    log.info("whitelist add %s", domain)
    return WhitelistResponse(ok=True, domain=domain, entries=store.all())


@app.delete("/whitelist", response_model=WhitelistResponse, tags=["whitelist"])
def whitelist_remove(
    domain: str = Query(..., description="Domain or URL to stop trusting")
) -> WhitelistResponse:
    removed = store.remove(domain)
    log.info("whitelist remove %s", removed)
    return WhitelistResponse(ok=True, domain=removed, entries=store.all())


@app.get("/whitelist/check", tags=["whitelist"])
def whitelist_check(url: str = Query(..., description="URL or domain to test")) -> dict:
    return {
        "domain": normalize_domain(url),
        "whitelisted": store.contains(url),
    }


@app.post("/whitelist/clear", response_model=WhitelistResponse, tags=["whitelist"])
def whitelist_clear() -> WhitelistResponse:
    store.clear()
    return WhitelistResponse(ok=True, domain="", entries=[])


@app.post("/explain", tags=["analysis"])
def explain(payload: dict = Body(...)) -> JSONResponse:
    """Debug helper: full signal breakdown plus the parsed URL facts."""
    url = (payload or {}).get("url", "")
    if not url:
        raise HTTPException(status_code=422, detail="url is required")
    facts, all_signals, brand = analyze(url, (payload or {}).get("html", "") or "")
    score, confidence = aggregate(all_signals)
    return JSONResponse(
        {
            "facts": {
                "scheme": facts.scheme,
                "host": facts.host,
                "registered_domain": facts.registered_domain,
                "subdomain": facts.subdomain,
                "suffix": facts.suffix,
                "is_ip": facts.is_ip,
                "labels": facts.labels,
                "trusted_host": is_trusted_host(facts),
            },
            "impersonated_brand": brand,
            "risk_score": score,
            "confidence": confidence,
            "verdict": verdict_for(score).value,
            "signals": [s.model_dump() for s in all_signals],
        }
    )
