"""Risk aggregation.

Combining rule
--------------
A naive sum saturates instantly (any three medium signals would read 100) and a
plain max throws away corroboration. Instead we use a damped noisy-OR:

    combined = 1 - Π (1 - wᵢ/100 · dᵢ)

where `dᵢ` damps the i-th signal *within its own category*, so five domain-shape
quirks corroborate each other without stacking like five independent proofs.
Cross-category agreement is left undamped — a bad domain plus an off-site
credential POST genuinely is much worse than either alone.
"""

from __future__ import annotations

from .brands import brand_label
from .models import Category, Severity, Signal, Verdict

DANGEROUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30

# Per-category damping applied to the 2nd, 3rd, ... signal in that category.
_CATEGORY_DECAY = 0.55

# Categories that mean "data is actively leaving" — these get a boost when they
# co-occur with brand impersonation, since that combination is the actual attack.
_EXFIL_IDS = {
    "form.external_action",
    "form.data_uri_action",
    "form.hidden_exfil_target",
    "script.exfil_to_bot_sink",
    "script.keystroke_exfiltration",
    "form.seed_phrase_capture",
}
_IMPERSONATION_IDS = {
    "brand.exact_domain_not_owned",
    "domain.typosquat",
    "brand.token_in_unowned_host",
    "brand.hotlinked_assets",
    "brand.title_mismatch",
    "domain.mixed_script",
    "domain.punycode",
}


def aggregate(signals: list[Signal]) -> tuple[int, float]:
    """Return (risk_score 0-100, confidence 0-1)."""
    if not signals:
        return 0, 0.55

    ordered = sorted(signals, key=lambda s: s.weight, reverse=True)
    seen_per_category: dict[Category, int] = {}
    inverse = 1.0

    for s in ordered:
        n = seen_per_category.get(s.category, 0)
        damp = _CATEGORY_DECAY**n
        seen_per_category[s.category] = n + 1
        p = max(0.0, min(s.weight / 100.0, 0.97)) * damp
        inverse *= 1.0 - p

    score = (1.0 - inverse) * 100.0

    ids = {s.id for s in signals}
    # Impersonation + active exfiltration is the canonical credential-harvest
    # pattern; make sure it lands unambiguously in the blocking band.
    if ids & _IMPERSONATION_IDS and ids & _EXFIL_IDS:
        score = max(score, 82.0)

    # A single CRITICAL finding should never be diluted into "Safe".
    if any(s.severity is Severity.CRITICAL for s in signals):
        score = max(score, 62.0)

    score = max(0.0, min(score, 100.0))

    # Confidence grows with corroboration across distinct categories.
    categories = len({s.category for s in signals})
    strong = sum(1 for s in signals if s.severity in (Severity.HIGH, Severity.CRITICAL))
    confidence = min(0.5 + 0.11 * categories + 0.07 * strong, 0.98)
    if len(signals) == 1 and signals[0].severity in (Severity.LOW, Severity.INFO):
        confidence = min(confidence, 0.6)

    return int(round(score)), round(confidence, 2)


def verdict_for(score: int) -> Verdict:
    if score >= DANGEROUS_THRESHOLD:
        return Verdict.DANGEROUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def summarize(
    verdict: Verdict, score: int, signals: list[Signal], brand: str | None
) -> tuple[str, str]:
    """Produce a headline and a one-paragraph plain-language summary."""
    if verdict is Verdict.WHITELISTED:
        return (
            "Trusted by you",
            "You added this site to your PhishGuard whitelist, so scanning is skipped here.",
        )

    if not signals:
        return (
            "No phishing indicators found",
            "PhishGuard checked the address, page structure, forms and scripts and found "
            "nothing matching known credential-harvesting patterns.",
        )

    top = sorted(signals, key=lambda s: s.weight, reverse=True)[:3]
    critical = [s for s in signals if s.severity is Severity.CRITICAL]
    steals_creds = any(s.id in _EXFIL_IDS for s in signals)

    if verdict is Verdict.DANGEROUS:
        if brand and steals_creds:
            headline = f"Credential theft: fake {brand_label(brand)} page"
        elif brand:
            headline = f"Likely {brand_label(brand)} impersonation"
        elif steals_creds:
            headline = "Active credential-harvesting behaviour"
        else:
            headline = "Multiple strong phishing indicators"
    elif verdict is Verdict.SUSPICIOUS:
        headline = f"{brand_label(brand)}-related warning signs" if brand else "Some phishing warning signs"
    else:
        headline = "Minor observations only"

    lead = {
        Verdict.DANGEROUS: "Do not enter any information on this page.",
        Verdict.SUSPICIOUS: "Treat this page with caution.",
        Verdict.SAFE: "Nothing here is conclusive.",
    }[verdict]

    reasons = "; ".join(s.title[0].lower() + s.title[1:] for s in top)
    summary = (
        f"{lead} PhishGuard scored this page {score}/100 based on "
        f"{len(signals)} indicator{'s' if len(signals) != 1 else ''}"
        f"{f', {len(critical)} of them critical' if critical else ''}. "
        f"Chiefly: {reasons}."
    )
    return headline, summary
