"""PhishGuard heuristic analysis engine.

Design notes
------------
* Zero network calls at scan time. `tldextract` is constructed with an empty
  `suffix_list_urls` so it uses the bundled PSL snapshot — a scan must never
  block on DNS or HTTP while a user stares at a page.
* HTML is scanned with compiled regexes rather than a full DOM parse. We are
  handed up to ~3 MB of potentially hostile markup and need a verdict in
  milliseconds; a tolerant tag/attribute scanner is both faster and safer than
  building a tree we would only walk once.
* Scores combine via noisy-OR so independent weak signals accumulate without
  any single heuristic being able to slam the score to 100 on its own, while
  correlated signals in the same category get damped to avoid double-counting.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

import tldextract

from .brands import (
    BRANDS,
    brand_label,
    CREDENTIAL_KEYWORDS,
    DIGRAPH_HOMOGLYPHS,
    HIGH_RISK_TLDS,
    HOMOGLYPHS,
    KNOWN_GOOD_DOMAINS,
    SENSITIVE_FIELD_HINTS,
    URGENCY_PHRASES,
    URL_SHORTENERS,
)
from .models import Category, Severity, Signal

ENGINE_VERSION = "1.2.0"

# Offline extractor: bundled snapshot, no live PSL fetch, no cache writes.
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

DANGEROUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def _levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Bounded edit distance. Returns `cap + 1` once it provably exceeds `cap`."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,          # deletion
                cur[j - 1] + 1,       # insertion
                prev[j - 1] + (ca != cb),  # substitution
            )
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _deconfuse(s: str) -> str:
    """Fold a label to its visual/keyboard skeleton so `paypa1` -> `paypal`."""
    s = unicodedata.normalize("NFKD", s.lower())
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    for src, dst in DIGRAPH_HOMOGLYPHS:
        s = s.replace(src, dst)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in s)


def _is_ip_literal(host: str) -> tuple[bool, str | None]:
    h = host.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
        return True, ip.version == 4 and "IPv4" or "IPv6"
    except ValueError:
        pass
    # Dotless / octal / hex integer forms, e.g. http://3232235777/ or 0x7f000001
    if re.fullmatch(r"0x[0-9a-f]+", h, re.I):
        return True, "hex-encoded"
    if re.fullmatch(r"\d{8,12}", h):
        try:
            ipaddress.ip_address(int(h))
            return True, "integer-encoded"
        except ValueError:
            return False, None
    if re.fullmatch(r"(0\d{1,3}\.){3}0\d{1,3}", h):
        return True, "octal-encoded"
    return False, None


def _split_labels(host: str) -> list[str]:
    return [p for p in re.split(r"[.\-_]+", host.lower()) if p]


@dataclass
class UrlFacts:
    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    userinfo: str | None
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    is_ip: bool
    ip_kind: str | None
    labels: list[str]


def parse_url(url: str) -> UrlFacts:
    candidate = url if "//" in url.split("?", 1)[0][:12] else f"http://{url}"
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower().rstrip(".")
    ext = _extract(host)
    is_ip, ip_kind = _is_ip_literal(host)
    reg = ext.registered_domain or (host if is_ip else host)
    try:
        port = parts.port
    except ValueError:
        port = None
    return UrlFacts(
        raw=url,
        scheme=(parts.scheme or "").lower(),
        host=host,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        fragment=parts.fragment or "",
        userinfo=parts.username,
        subdomain=ext.subdomain or "",
        domain=ext.domain or "",
        suffix=ext.suffix or "",
        registered_domain=reg,
        is_ip=is_ip,
        ip_kind=ip_kind,
        labels=_split_labels(host),
    )


def _same_site(a: str, b: str) -> bool:
    """True if two hosts share a registrable domain."""
    if not a or not b:
        return False
    if a == b:
        return True
    ra = _extract(a).registered_domain or a
    rb = _extract(b).registered_domain or b
    return bool(ra) and ra == rb


# --------------------------------------------------------------------------- #
# Brand impersonation / typosquatting
# --------------------------------------------------------------------------- #
def is_trusted_host(f: UrlFacts) -> bool:
    """True for well-known legitimate domains and local development hosts.

    Trusted hosts still get scanned — a compromised real site must be catchable —
    but weak, shape-based heuristics are not allowed to accumulate against them.
    """
    if f.host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or f.host.endswith(".localhost"):
        return True
    if f.is_ip:
        try:
            return ipaddress.ip_address(f.host.strip("[]")).is_private
        except ValueError:
            return False
    reg = f.registered_domain.lower()
    if not reg:
        return False
    return reg in KNOWN_GOOD_DOMAINS or any(_same_site(reg, g) for g in KNOWN_GOOD_DOMAINS)


def detect_brand_impersonation(f: UrlFacts) -> tuple[list[Signal], str | None]:
    """Look for a brand token anywhere in the hostname that the host does not own."""
    signals: list[Signal] = []
    if not f.host or f.is_ip:
        return signals, None

    # A domain that is itself a known-good property is never impersonating anyone.
    # Without this guard, legitimate sites collide with each other in edit-distance
    # space — 'github.com' is exactly 2 edits from 'gitlab' and would self-flag.
    if is_trusted_host(f):
        return signals, None

    host_skel = _deconfuse(f.host)
    domain_skel = _deconfuse(f.domain)
    reg = f.registered_domain.lower()
    labels = {_deconfuse(l) for l in f.labels}
    best: tuple[int, str, str] | None = None  # (priority, brand, detail)

    for brand, owners in BRANDS.items():
        if reg in owners or any(_same_site(reg, o) for o in owners):
            continue  # legitimately operated by the brand
        b_skel = _deconfuse(brand)

        # 1) Exact brand token as its own label in the domain itself.
        if b_skel == domain_skel and reg not in owners:
            sig = Signal(
                id="brand.exact_domain_not_owned",
                title=f"Domain impersonates {brand_label(brand)}",
                detail=(
                    f"The registrable domain '{reg}' resolves to the brand name "
                    f"'{brand}' but is not one of its official domains "
                    f"({', '.join(sorted(owners)[:3])})."
                ),
                category=Category.BRAND,
                severity=Severity.CRITICAL,
                weight=72,
                evidence=[f"registrable domain: {reg}", f"brand token: {brand}"],
            )
            if best is None or 0 < best[0]:
                best = (0, brand, "exact")
            signals.append(sig)
            continue

        # 2) Near-miss typosquat of the brand token inside the domain label.
        dist = _levenshtein(b_skel, domain_skel, cap=2)
        if 0 < dist <= (1 if len(b_skel) <= 5 else 2) and len(domain_skel) >= 4:
            signals.append(
                Signal(
                    id="domain.typosquat",
                    title=f"Domain is a near-miss of {brand_label(brand)}",
                    detail=(
                        f"'{f.domain}' is {dist} character edit(s) away from '{brand}' "
                        "once look-alike characters are normalised. This is the classic "
                        "typosquatting pattern."
                    ),
                    category=Category.DOMAIN,
                    severity=Severity.CRITICAL,
                    weight=70,
                    evidence=[f"observed: {f.domain}", f"target: {brand}", f"edit distance: {dist}"],
                )
            )
            if best is None or 1 < best[0]:
                best = (1, brand, "typo")
            continue

        # 3) Brand appears as a subdomain or hyphenated component of another domain,
        #    e.g. paypal.com.security-check.tk or login-paypal.example.xyz
        if b_skel in labels or re.search(rf"(?<![a-z0-9]){re.escape(b_skel)}(?![a-z0-9])", host_skel):
            where = "subdomain" if b_skel in _deconfuse(f.subdomain) else "hostname"
            signals.append(
                Signal(
                    id="brand.token_in_unowned_host",
                    title=f"'{brand_label(brand)}' used in a hostname it does not own",
                    detail=(
                        f"The {where} contains '{brand}', but the page is actually served "
                        f"from '{reg}'. Only the part immediately left of the TLD "
                        "determines site identity — everything else is attacker-controlled."
                    ),
                    category=Category.BRAND,
                    severity=Severity.HIGH,
                    weight=58,
                    evidence=[f"hostname: {f.host}", f"actually served by: {reg}"],
                )
            )
            if best is None or 2 < best[0]:
                best = (2, brand, "token")

    # Deduplicate: keep at most the two strongest brand signals to avoid a
    # hostname stuffed with brand names inflating the score linearly.
    signals.sort(key=lambda s: s.weight, reverse=True)
    return signals[:2], (best[1] if best else None)


# --------------------------------------------------------------------------- #
# URL-layer heuristics
# --------------------------------------------------------------------------- #
def analyze_url(f: UrlFacts) -> tuple[list[Signal], str | None]:
    out: list[Signal] = []
    add = out.append

    brand_signals, brand = detect_brand_impersonation(f)
    out.extend(brand_signals)

    # --- IP-literal host -------------------------------------------------- #
    if f.is_ip:
        private = False
        try:
            private = ipaddress.ip_address(f.host.strip("[]")).is_private
        except ValueError:
            pass
        add(
            Signal(
                id="url.ip_host",
                title="Site is served from a raw IP address",
                detail=(
                    f"The host is an {f.ip_kind} literal rather than a domain name. "
                    "Legitimate consumer-facing services essentially always use a "
                    "named domain with a matching TLS certificate; raw IPs are typical "
                    "of disposable phishing infrastructure."
                    + (" The address is in private range, which suggests a lab or dev host." if private else "")
                ),
                category=Category.URL,
                severity=Severity.LOW if private else Severity.HIGH,
                weight=12 if private else 55,
                evidence=[f"host: {f.host}"],
            )
        )

    # --- Transport -------------------------------------------------------- #
    if f.scheme == "http" and not f.is_ip and f.host not in ("localhost", "127.0.0.1"):
        add(
            Signal(
                id="transport.no_tls",
                title="Connection is not encrypted (HTTP)",
                detail=(
                    "Data typed into this page travels in clear text and can be read or "
                    "modified by anyone on the network path. Any page requesting "
                    "credentials over plain HTTP should be treated as compromised."
                ),
                category=Category.TRANSPORT,
                severity=Severity.MEDIUM,
                weight=30,
                evidence=[f"scheme: {f.scheme}"],
            )
        )

    # --- Embedded credentials in the authority --------------------------- #
    if f.userinfo:
        add(
            Signal(
                id="url.userinfo_obfuscation",
                title="URL hides the real destination behind an '@'",
                detail=(
                    f"Everything before the '@' ('{f.userinfo}') is a username, not a "
                    f"hostname. The browser actually connects to '{f.host}'. This trick "
                    "makes a hostile link read like a trusted one."
                ),
                category=Category.URL,
                severity=Severity.CRITICAL,
                weight=68,
                evidence=[f"userinfo: {f.userinfo}", f"real host: {f.host}"],
            )
        )

    # --- Punycode / mixed script ----------------------------------------- #
    if f.host.startswith("xn--") or ".xn--" in f.host:
        add(
            Signal(
                id="domain.punycode",
                title="Internationalised (punycode) domain",
                detail=(
                    "The hostname uses non-ASCII characters encoded as punycode. This is "
                    "legitimate for many languages but is also the standard way to build "
                    "a homograph attack where 'аpple.com' (Cyrillic а) renders identically "
                    "to the real thing."
                ),
                category=Category.DOMAIN,
                severity=Severity.HIGH,
                weight=45,
                evidence=[f"host: {f.host}"],
            )
        )

    scripts = {unicodedata.name(ch, "").split(" ")[0] for ch in f.domain if ch.isalpha()}
    if len({s for s in scripts if s in {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN"}}) > 1:
        add(
            Signal(
                id="domain.mixed_script",
                title="Domain mixes multiple alphabets",
                detail=(
                    "The domain label combines characters from more than one writing "
                    "system, which is almost exclusively used to build look-alike domains."
                ),
                category=Category.DOMAIN,
                severity=Severity.CRITICAL,
                weight=62,
                evidence=[f"scripts: {', '.join(sorted(scripts))}"],
            )
        )

    # --- Suspicious keyword density in the hostname ---------------------- #
    if not f.is_ip and f.labels:
        hits = sorted({l for l in (_deconfuse(x) for x in f.labels) if l in CREDENTIAL_KEYWORDS})
        density = len(hits) / max(len(f.labels), 1)
        if hits and f.registered_domain not in KNOWN_GOOD_DOMAINS:
            if len(hits) >= 2 or density >= 0.5:
                add(
                    Signal(
                        id="domain.keyword_density",
                        title="Hostname is stuffed with credential-related words",
                        detail=(
                            f"{len(hits)} of {len(f.labels)} hostname components are "
                            f"security/urgency words ({', '.join(hits)}). Real services put "
                            "these in the path (example.com/login), not in the domain, "
                            "because the domain is what users are taught to check."
                        ),
                        category=Category.DOMAIN,
                        severity=Severity.HIGH if len(hits) >= 3 else Severity.MEDIUM,
                        weight=min(20 + 14 * len(hits), 55),
                        evidence=[f"keywords: {', '.join(hits)}", f"density: {density:.0%}"],
                    )
                )
            elif hits:
                add(
                    Signal(
                        id="domain.keyword_present",
                        title="Hostname contains a credential-related word",
                        detail=(
                            f"The hostname includes '{hits[0]}'. On its own this is weak, "
                            "but it is a common component of harvesting domains."
                        ),
                        category=Category.DOMAIN,
                        severity=Severity.LOW,
                        weight=14,
                        evidence=[f"keyword: {hits[0]}"],
                    )
                )

    # --- Structural oddities --------------------------------------------- #
    depth = f.host.count(".")
    if depth >= 4 and not f.is_ip:
        add(
            Signal(
                id="domain.excessive_subdomains",
                title="Unusually deep subdomain chain",
                detail=(
                    f"The hostname has {depth + 1} labels. Long chains are used to push the "
                    "real domain off the right-hand edge of the address bar, especially on "
                    "mobile, so the leftmost (attacker-chosen) part is all the user sees."
                ),
                category=Category.DOMAIN,
                severity=Severity.MEDIUM,
                weight=22 + min(depth - 4, 3) * 6,
                evidence=[f"host: {f.host}", f"labels: {depth + 1}"],
            )
        )

    if f.suffix in HIGH_RISK_TLDS or any(f.host.endswith(t) for t in HIGH_RISK_TLDS if "." in t):
        matched = f.suffix if f.suffix in HIGH_RISK_TLDS else next(
            (t for t in HIGH_RISK_TLDS if "." in t and f.host.endswith(t)), f.suffix
        )
        add(
            Signal(
                id="domain.high_risk_tld",
                title=f"High-abuse TLD / free hosting ('.{matched}')",
                detail=(
                    f"'.{matched}' is available at zero or near-zero cost and carries a "
                    "disproportionately high share of abuse reports. This alone is not "
                    "proof of malice, but it lowers the bar for the other signals."
                ),
                category=Category.DOMAIN,
                severity=Severity.MEDIUM,
                weight=26,
                evidence=[f"suffix: {matched}"],
            )
        )

    if f.registered_domain in URL_SHORTENERS:
        add(
            Signal(
                id="url.shortener",
                title="Link shortener conceals the destination",
                detail=(
                    "The real target is hidden behind a redirect service, so nothing about "
                    "the destination can be judged before the click resolves."
                ),
                category=Category.URL,
                severity=Severity.MEDIUM,
                weight=28,
                evidence=[f"service: {f.registered_domain}"],
            )
        )

    if f.port and f.port not in (80, 443, 8000, 8080, 3000, 5173):
        add(
            Signal(
                id="url.nonstandard_port",
                title=f"Non-standard port ({f.port})",
                detail="Public services rarely listen on unusual ports; this is common for ad-hoc kits.",
                category=Category.URL,
                severity=Severity.LOW,
                weight=16,
                evidence=[f"port: {f.port}"],
            )
        )

    if len(f.raw) > 110:
        add(
            Signal(
                id="url.excessive_length",
                title="Abnormally long URL",
                detail=(
                    f"The URL is {len(f.raw)} characters. Padding is used to bury the true "
                    "host and to defeat visual inspection in the address bar."
                ),
                category=Category.URL,
                severity=Severity.LOW,
                weight=12 + min((len(f.raw) - 110) // 60, 3) * 5,
                evidence=[f"length: {len(f.raw)}"],
            )
        )

    if f.host.count("-") >= 3 and not f.is_ip:
        add(
            Signal(
                id="domain.hyphen_stuffing",
                title="Hyphen-stuffed hostname",
                detail=(
                    f"The hostname contains {f.host.count('-')} hyphens, a hallmark of "
                    "generated look-alike domains such as 'secure-login-account-verify'."
                ),
                category=Category.DOMAIN,
                severity=Severity.MEDIUM,
                weight=22,
                evidence=[f"host: {f.host}"],
            )
        )

    if f.domain and len(f.domain) >= 12 and _shannon_entropy(f.domain) > 3.6:
        add(
            Signal(
                id="domain.random_looking",
                title="Domain looks machine-generated",
                detail=(
                    "High character entropy with no pronounceable structure is typical of "
                    "algorithmically registered throwaway domains."
                ),
                category=Category.DOMAIN,
                severity=Severity.MEDIUM,
                weight=24,
                evidence=[f"domain: {f.domain}", f"entropy: {_shannon_entropy(f.domain):.2f} bits/char"],
            )
        )

    # --- Redirect chains and nested URLs in the query ------------------- #
    decoded_q = unqu = unquote(f.query + "&" + f.fragment)
    nested = re.findall(r"(?:https?%3a%2f%2f|https?://)([\w.-]+)", unqu, re.I)
    external_nested = [h for h in nested if h and not _same_site(h, f.host)]
    if external_nested:
        add(
            Signal(
                id="url.open_redirect_param",
                title="URL carries another site's address as a parameter",
                detail=(
                    f"A full URL pointing at '{external_nested[0]}' is embedded in the query "
                    "string. This is the shape of an open-redirect abuse or a credential "
                    "post-back to a third party."
                ),
                category=Category.URL,
                severity=Severity.MEDIUM,
                weight=30,
                evidence=[f"nested host: {h}" for h in external_nested[:3]],
            )
        )

    if re.search(r"%25[0-9a-f]{2}", f.raw, re.I) or re.search(r"(%[0-9a-f]{2}){6,}", f.raw, re.I):
        add(
            Signal(
                id="url.encoding_obfuscation",
                title="URL uses heavy or double percent-encoding",
                detail=(
                    "Long runs of escaped characters (or double-escaping) are used to hide "
                    "keywords and paths from both users and naive filters."
                ),
                category=Category.URL,
                severity=Severity.MEDIUM,
                weight=26,
                evidence=[f"url: {f.raw[:120]}"],
            )
        )

    # Credential-looking values sitting in the query string.
    if f.query:
        qs = parse_qs(f.query)
        leaky = [k for k in qs if _deconfuse(k) in {"password", "passwd", "pwd", "token", "otp", "pin"}]
        if leaky:
            add(
                Signal(
                    id="url.credentials_in_query",
                    title="Secret-looking value passed in the URL",
                    detail=(
                        f"Parameter(s) {', '.join(leaky)} appear in the query string, where they "
                        "are written to browser history, proxies and server logs."
                    ),
                    category=Category.URL,
                    severity=Severity.MEDIUM,
                    weight=28,
                    evidence=[f"parameters: {', '.join(leaky)}"],
                )
            )

    # Path pretending to be a different file type or domain.
    if re.search(r"/(?:https?:?/?/?)?(?:www\.)?[\w-]+\.(?:com|net|org|co\.uk)/", f.path, re.I):
        add(
            Signal(
                id="url.domain_in_path",
                title="Another domain name appears inside the path",
                detail=(
                    "A domain-like string in the path is used to make the URL read as if it "
                    "belongs to a trusted site while it is actually served elsewhere."
                ),
                category=Category.URL,
                severity=Severity.MEDIUM,
                weight=24,
                evidence=[f"path: {f.path[:120]}"],
            )
        )

    return out, brand


# --------------------------------------------------------------------------- #
# HTML / DOM heuristics
# --------------------------------------------------------------------------- #
_TAG_RE = re.compile(r"<\s*(?P<name>[a-zA-Z][\w:-]*)(?P<attrs>[^>]*?)/?>", re.S)
# Matches double-quoted, single-quoted, unquoted, and valueless (boolean) attributes.
# Explicit alternation rather than a conditional group: `["']?` always
# *participates* in the match even when empty, so `(?(quote)\2|...)` would always
# take the backreference branch and capture nothing for unquoted values.
_ATTR_RE = re.compile(
    r"""(?P<key>[\w:.@-]+)
        (?:\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<uq>[^\s"'>=`]+)))?""",
    re.S | re.X,
)
_STYLE_HIDDEN_RE = re.compile(
    r"(?:display\s*:\s*none)"
    r"|(?:visibility\s*:\s*hidden)"
    r"|(?:opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!))"
    r"|(?:(?:width|height)\s*:\s*0(?:px|%|em|rem)?\s*(?:;|$|!))"
    r"|(?:clip-path\s*:\s*inset\(\s*(?:100%|50%\s+50%))"
    r"|(?:(?:left|top)\s*:\s*-\s*\d{4,}\s*px)",
    re.I,
)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def _attrs_of(chunk: str) -> dict[str, str]:
    """Tolerant attribute scanner. A valueless attribute maps to "" (present)."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(chunk or ""):
        key = m.group("key").lower()
        if not key or key == "/":
            continue
        val = m.group("dq")
        if val is None:
            val = m.group("sq")
        if val is None:
            val = m.group("uq")
        out[key] = (val or "").strip()
    return out


def _is_visually_hidden(a: dict[str, str]) -> tuple[bool, str | None]:
    if "hidden" in a and a.get("hidden", "") not in ("false",):
        return True, "hidden attribute"
    style = a.get("style", "")
    if style and _STYLE_HIDDEN_RE.search(style):
        return True, f"style: {style[:90]}"
    def _num(key: str) -> float | None:
        raw = re.sub(r"[^\d.]", "", a.get(key, ""))
        try:
            return float(raw) if raw else None
        except ValueError:
            return None

    w, h = _num("width"), _num("height")
    # Either dimension collapsed to zero, or both are sub-pixel tracker size.
    if (w == 0 or h == 0) or (w is not None and h is not None and w <= 2 and h <= 2):
        return True, f"size: {a.get('width', '?')}x{a.get('height', '?')}"
    if a.get("type", "").lower() == "hidden":
        return True, "input type=hidden"
    return False, None


def _iter_tags(html: str, names: set[str]):
    """Yield (tag_name, attr_dict, span) for the requested tag names."""
    for m in _TAG_RE.finditer(html):
        name = m.group("name").lower()
        if name in names:
            yield name, _attrs_of(m.group("attrs")), m.span()


def analyze_html(html: str, f: UrlFacts) -> list[Signal]:
    out: list[Signal] = []
    add = out.append
    if not html or len(html) < 40:
        return out

    body = _COMMENT_RE.sub(" ", html)
    lowered = body.lower()

    forms = list(_iter_tags(body, {"form"}))
    inputs = list(_iter_tags(body, {"input", "textarea", "select"}))
    iframes = list(_iter_tags(body, {"iframe", "frame", "embed", "object"}))
    scripts = list(_iter_tags(body, {"script"}))
    links = list(_iter_tags(body, {"a"}))

    # ---------------- Credential capture inventory ---------------------- #
    captured: dict[str, list[str]] = {}
    password_fields = 0
    for _, a, _span in inputs:
        itype = a.get("type", "text").lower()
        ident = " ".join(
            filter(None, [a.get("name", ""), a.get("id", ""), a.get("placeholder", ""),
                          a.get("autocomplete", ""), a.get("aria-label", "")])
        ).lower()
        flat = re.sub(r"[^a-z0-9]", "", ident)

        if itype == "password":
            password_fields += 1
            captured.setdefault("password", []).append(a.get("name") or a.get("id") or "(unnamed)")

        for hint, label in SENSITIVE_FIELD_HINTS.items():
            if hint in flat or hint in ident:
                captured.setdefault(label, []).append(a.get("name") or a.get("id") or f"type={itype}")
                break

        # numeric PIN/OTP field: short maxlength + numeric mode
        if itype in ("text", "tel", "number", "password"):
            ml = a.get("maxlength", "")
            if ml.isdigit() and 3 <= int(ml) <= 8 and re.search(r"pin|code|otp|token|digit", ident):
                captured.setdefault("PIN / one-time code", []).append(a.get("name") or a.get("id") or "(unnamed)")

    if password_fields:
        add(
            Signal(
                id="form.password_field",
                title=f"Page collects a password ({password_fields} field"
                      f"{'s' if password_fields > 1 else ''})",
                detail=(
                    "A password input is present. This is normal for a real login page, but it "
                    "is what makes every other signal on this page consequential — it is the "
                    "difference between a suspicious site and an active credential harvester."
                ),
                category=Category.FORM,
                severity=Severity.INFO if not f.is_ip else Severity.MEDIUM,
                weight=10,
                evidence=[f"password inputs: {password_fields}"],
            )
        )

    high_value = {k: v for k, v in captured.items() if k != "password"}
    if high_value:
        add(
            Signal(
                id="form.sensitive_fields",
                title="Page requests high-value personal data",
                detail=(
                    "The form asks for: " + ", ".join(sorted(high_value)) + ". "
                    "Requesting these alongside a password — particularly card details, a PIN, "
                    "an OTP or a wallet seed phrase — is characteristic of a harvesting kit "
                    "rather than a genuine sign-in screen."
                ),
                category=Category.FORM,
                severity=Severity.HIGH if len(high_value) >= 2 else Severity.MEDIUM,
                weight=min(24 + 12 * len(high_value), 60),
                evidence=[f"{k}: {', '.join(v[:2])}" for k, v in sorted(high_value.items())][:6],
            )
        )

    if any(k in captured for k in ("wallet seed phrase", "private key", "wallet keystore")):
        add(
            Signal(
                id="form.seed_phrase_capture",
                title="Page asks for a crypto wallet seed phrase or private key",
                detail=(
                    "No legitimate wallet, exchange or support desk will ever ask for a "
                    "recovery phrase or private key in a web form. Entering it hands over "
                    "irreversible control of the wallet."
                ),
                category=Category.FORM,
                severity=Severity.CRITICAL,
                weight=85,
                evidence=["seed phrase / private key input detected"],
            )
        )

    # ---------------- External / off-site form submission --------------- #
    for _, a, _span in forms:
        action = (a.get("action") or "").strip()
        if not action or action.startswith(("#", "javascript:", "/", "?", ".")):
            continue
        if action.startswith(("data:", "blob:")):
            add(
                Signal(
                    id="form.data_uri_action",
                    title="Form submits to a data: or blob: URI",
                    detail="An inline URI target is a known exfiltration and sandbox-evasion trick.",
                    category=Category.FORM,
                    severity=Severity.HIGH,
                    weight=50,
                    evidence=[f"action: {action[:100]}"],
                )
            )
            continue
        target_host = urlsplit(action if "//" in action else f"//{action}").hostname or ""
        if target_host and not _same_site(target_host, f.host):
            has_secret = password_fields > 0 or bool(high_value)
            add(
                Signal(
                    id="form.external_action",
                    title="Form posts your data to a different domain",
                    detail=(
                        f"Data typed into this page is sent to '{target_host}', which is not "
                        f"'{f.registered_domain}'. "
                        + (
                            "Because the form also collects credentials, this is a direct "
                            "credential-exfiltration path."
                            if has_secret
                            else "Cross-origin form posts are uncommon outside of payment iframes."
                        )
                    ),
                    category=Category.FORM,
                    severity=Severity.CRITICAL if has_secret else Severity.MEDIUM,
                    weight=78 if has_secret else 34,
                    evidence=[f"page host: {f.host}", f"form target: {target_host}"],
                )
            )
        if action.startswith("http://") and (password_fields or high_value):
            add(
                Signal(
                    id="form.insecure_action",
                    title="Credentials submitted over unencrypted HTTP",
                    detail="The form target is plain HTTP, so submitted secrets cross the network in clear text.",
                    category=Category.FORM,
                    severity=Severity.HIGH,
                    weight=52,
                    evidence=[f"action: {action[:100]}"],
                )
            )

    # A password field with no enclosing form => JS-driven capture.
    if password_fields and not forms:
        add(
            Signal(
                id="form.password_without_form",
                title="Password field sits outside any <form>",
                detail=(
                    "The credential input is not inside a form element, so submission is "
                    "handled entirely by script. This is how kits post to an attacker "
                    "endpoint without leaving a visible action attribute."
                ),
                category=Category.FORM,
                severity=Severity.MEDIUM,
                weight=32,
                evidence=["password input present, 0 form elements"],
            )
        )

    # ---------------- Hidden iframes / clickjacking --------------------- #
    hidden_frames: list[str] = []
    cross_origin_frames: list[str] = []
    for name, a, _span in iframes:
        src = a.get("src") or a.get("data") or ""
        hidden, why = _is_visually_hidden(a)
        host = urlsplit(src if "//" in src else f"//{src}").hostname or ""
        if hidden and (src or name == "iframe"):
            hidden_frames.append(f"<{name} src={src[:60] or '(none)'}> — {why}")
        if host and not _same_site(host, f.host):
            cross_origin_frames.append(host)

    if hidden_frames:
        add(
            Signal(
                id="cloaking.hidden_iframe",
                title=f"{len(hidden_frames)} hidden frame(s) embedded in the page",
                detail=(
                    "Invisible frames are used to load an attacker-controlled document "
                    "silently, to overlay real controls for clickjacking, or to keep a "
                    "session alive against the impersonated site while you type."
                ),
                category=Category.CLOAKING,
                severity=Severity.HIGH,
                weight=min(38 + 10 * (len(hidden_frames) - 1), 62),
                evidence=hidden_frames[:4],
            )
        )

    if cross_origin_frames and (password_fields or high_value):
        add(
            Signal(
                id="cloaking.cross_origin_frame_with_form",
                title="Third-party frame on a page that collects credentials",
                detail=(
                    "Content from " + ", ".join(sorted(set(cross_origin_frames))[:3]) +
                    " is framed into a page that asks for secrets. Real sign-in pages keep "
                    "the credential surface on their own origin."
                ),
                category=Category.CLOAKING,
                severity=Severity.MEDIUM,
                weight=30,
                evidence=[f"frame host: {h}" for h in sorted(set(cross_origin_frames))[:4]],
            )
        )

    # Full-viewport transparent overlay => clickjacking.
    if re.search(
        r"position\s*:\s*(?:fixed|absolute)[^}\"']{0,200}?(?:opacity\s*:\s*0(?:\.0+)?\b"
        r"|z-index\s*:\s*\d{4,})",
        lowered,
    ) and re.search(r"(?:width|height)\s*:\s*(?:100%|100vw|100vh)", lowered):
        add(
            Signal(
                id="cloaking.transparent_overlay",
                title="Full-screen transparent overlay detected",
                detail=(
                    "A viewport-sized, near-invisible, high-z-index element covers the page. "
                    "This intercepts clicks intended for the content underneath (clickjacking)."
                ),
                category=Category.CLOAKING,
                severity=Severity.HIGH,
                weight=44,
                evidence=["fixed/absolute full-size element with opacity:0 or extreme z-index"],
            )
        )

    # Hidden inputs pre-seeded with an exfiltration address.
    for _, a, _span in inputs:
        if a.get("type", "").lower() == "hidden":
            val = a.get("value", "")
            if re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", val) or re.search(r"https?://", val):
                host = urlsplit(val if "//" in val else f"//{val}").hostname or ""
                if "@" in val or (host and not _same_site(host, f.host)):
                    add(
                        Signal(
                            id="form.hidden_exfil_target",
                            title="Hidden field pre-filled with an off-site destination",
                            detail=(
                                "A hidden input carries an email address or external URL — the "
                                "standard way phishing kits configure where stolen data is sent."
                            ),
                            category=Category.FORM,
                            severity=Severity.HIGH,
                            weight=48,
                            evidence=[f"{a.get('name', 'hidden')} = {val[:80]}"],
                        )
                    )
                    break

    # ---------------- Anti-inspection behaviour ------------------------- #
    anti = []
    if re.search(r"addEventListener\s*\(\s*['\"]contextmenu['\"]", body, re.I) or \
       re.search(r"oncontextmenu\s*=\s*['\"]?\s*return\s+false", body, re.I):
        anti.append("right-click disabled")
    if re.search(r"(?:key(?:down|press|up)[^{]{0,80}?(?:123|'F12'|\"F12\")|devtools)", body, re.I):
        anti.append("developer-tools / F12 blocked")
    if re.search(r"document\.addEventListener\s*\(\s*['\"]copy['\"]", body, re.I) or \
       re.search(r"user-select\s*:\s*none", lowered):
        anti.append("text selection or copy blocked")
    if re.search(r"\bdebugger\b\s*;?", body) and len(re.findall(r"\bdebugger\b", body)) >= 2:
        anti.append("anti-debugger loop")
    if anti:
        add(
            Signal(
                id="script.anti_inspection",
                title="Page actively blocks inspection",
                detail=(
                    "Detected: " + "; ".join(anti) + ". Legitimate sites have no reason to stop "
                    "you viewing source or copying text; kits do it to slow analysis and stop "
                    "users reading the real URL."
                ),
                category=Category.SCRIPT,
                severity=Severity.MEDIUM,
                weight=20 + 8 * (len(anti) - 1),
                evidence=anti,
            )
        )

    # Obfuscated script payloads.
    obf_hits = []
    if len(re.findall(r"\\x[0-9a-f]{2}", body, re.I)) > 60:
        obf_hits.append("dense \\xNN hex escapes")
    if len(re.findall(r"\\u00[0-9a-f]{2}", body, re.I)) > 60:
        obf_hits.append("dense \\uXXXX escapes")
    if re.search(r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)", body, re.I):
        obf_hits.append("eval() over a decoder")
    if re.search(r"(?:atob|fromCharCode)\s*\(\s*['\"][A-Za-z0-9+/=]{200,}", body):
        obf_hits.append("large base64 blob decoded at runtime")
    if re.search(r"document\.write\s*\(\s*(?:unescape|atob|decodeURI)", body, re.I):
        obf_hits.append("document.write of decoded content")
    if obf_hits:
        add(
            Signal(
                id="script.obfuscated_payload",
                title="Heavily obfuscated JavaScript",
                detail=(
                    "Found: " + "; ".join(obf_hits) + ". Encoding a payload so it cannot be read "
                    "is a deliberate evasion measure, not a build-tool artefact."
                ),
                category=Category.SCRIPT,
                severity=Severity.HIGH,
                weight=min(30 + 10 * len(obf_hits), 56),
                evidence=obf_hits,
            )
        )

    # Keystroke capture wired directly to a network call.
    if re.search(r"['\"](?:keydown|keypress|keyup)['\"]", body, re.I) and \
       re.search(r"(?:fetch|XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket)", body):
        if password_fields or high_value:
            add(
                Signal(
                    id="script.keystroke_exfiltration",
                    title="Keystroke listeners alongside network calls",
                    detail=(
                        "The page listens on key events and also opens outbound requests. On a "
                        "page that collects secrets this is the signature of live keylogging — "
                        "data leaves before you ever press submit."
                    ),
                    category=Category.SCRIPT,
                    severity=Severity.HIGH,
                    weight=46,
                    evidence=["key event listener + fetch/XHR/beacon/WebSocket"],
                )
            )

    # Exfiltration endpoints inside script bodies.
    exfil_hosts: set[str] = set()
    for m in re.finditer(
        r"(?:fetch|open|sendBeacon|axios(?:\.\w+)?)\s*\(\s*['\"](https?://[^'\"]+)['\"]", body, re.I
    ):
        h = urlsplit(m.group(1)).hostname or ""
        if h and not _same_site(h, f.host):
            exfil_hosts.add(h)
    suspicious_sinks = {h for h in exfil_hosts if re.search(
        r"(?:telegram|api\.telegram\.org|discord(?:app)?\.com/api/webhooks|pastebin|"
        r"webhook\.site|requestbin|ngrok|glitch\.me|000webhost|formspree|getform|"
        r"pipedream|hookb\.in|beeceptor)", h, re.I)}
    if suspicious_sinks:
        add(
            Signal(
                id="script.exfil_to_bot_sink",
                title="Script posts data to a bot/webhook collector",
                detail=(
                    "Outbound calls target " + ", ".join(sorted(suspicious_sinks)[:3]) + ". "
                    "Telegram bots, Discord webhooks and paste services are the most common "
                    "drop points for stolen credentials because they need no server."
                ),
                category=Category.SCRIPT,
                severity=Severity.CRITICAL,
                weight=74,
                evidence=sorted(suspicious_sinks)[:4],
            )
        )
    elif exfil_hosts and (password_fields or high_value):
        add(
            Signal(
                id="script.cross_origin_post",
                title="Credential page sends data to third-party hosts",
                detail=(
                    "Script-level requests go to " + ", ".join(sorted(exfil_hosts)[:3]) +
                    " from a page that collects secrets."
                ),
                category=Category.SCRIPT,
                severity=Severity.MEDIUM,
                weight=28,
                evidence=sorted(exfil_hosts)[:4],
            )
        )

    # ---------------- Brand assets loaded from the real site ----------- #
    remote_assets = set()
    for _, a, _span in _iter_tags(body, {"img", "link", "script"}):
        src = a.get("src") or a.get("href") or ""
        h = urlsplit(src if "//" in src else "").hostname or ""
        if h and not _same_site(h, f.host):
            remote_assets.add(h)
    brand_assets = {h for h in remote_assets
                    if any(_same_site(h, owned) for owners in BRANDS.values() for owned in owners)}
    if brand_assets and (password_fields or high_value) and \
       f.registered_domain not in KNOWN_GOOD_DOMAINS:
        add(
            Signal(
                id="brand.hotlinked_assets",
                title="Logos and styling hotlinked from the impersonated brand",
                detail=(
                    "Images or stylesheets are pulled directly from " +
                    ", ".join(sorted(brand_assets)[:3]) +
                    " to make this page look authentic, while the credential form itself "
                    "belongs to a different domain. Cloned kits do this because copying "
                    "assets is more work than linking them."
                ),
                category=Category.BRAND,
                severity=Severity.HIGH,
                weight=42,
                evidence=sorted(brand_assets)[:4],
            )
        )

    # ---------------- Urgency / social-engineering copy ---------------- #
    text = re.sub(r"<(?:script|style)\b.*?</(?:script|style)\s*>", " ", lowered, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    found_phrases = [p for p in URGENCY_PHRASES if p in text]
    if found_phrases:
        add(
            Signal(
                id="content.urgency_pressure",
                title="High-pressure or scare wording",
                detail=(
                    "The page uses coercive phrasing such as: "
                    + "; ".join(f"“{p}”" for p in found_phrases[:3])
                    + ". Manufactured urgency is the core social-engineering lever — it exists "
                    "to stop you checking the address bar."
                ),
                category=Category.CLOAKING,
                severity=Severity.MEDIUM if len(found_phrases) < 3 else Severity.HIGH,
                weight=min(16 + 9 * len(found_phrases), 46),
                evidence=found_phrases[:5],
            )
        )

    # Title/brand mismatch.
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip().lower()
        for brand, owners in BRANDS.items():
            if brand in title and f.registered_domain not in owners and \
               not any(_same_site(f.registered_domain, o) for o in owners) and \
               (password_fields or high_value):
                add(
                    Signal(
                        id="brand.title_mismatch",
                        title=f"Page titled as {brand_label(brand)} but served elsewhere",
                        detail=(
                            f"The document title claims '{tm.group(1).strip()[:60]}' while the "
                            f"page is served from '{f.registered_domain}'."
                        ),
                        category=Category.BRAND,
                        severity=Severity.HIGH,
                        weight=40,
                        evidence=[f"title: {tm.group(1).strip()[:80]}", f"host: {f.registered_domain}"],
                    )
                )
                break

    # Deceptive outbound links (visible text says one domain, href another).
    mismatched = 0
    for m in re.finditer(r"<a\b([^>]*)>(.*?)</a>", body, re.I | re.S):
        a = _attrs_of(m.group(1))
        href = a.get("href", "")
        label = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        if not href.startswith("http"):
            continue
        lm = re.search(r"\b((?:[\w-]+\.)+(?:com|net|org|io|co|gov|uk|de))\b", label, re.I)
        if lm:
            href_host = urlsplit(href).hostname or ""
            if href_host and not _same_site(lm.group(1), href_host):
                mismatched += 1
    if mismatched >= 2:
        add(
            Signal(
                id="content.deceptive_link_text",
                title=f"{mismatched} links display a domain different from their target",
                detail=(
                    "Link text advertises one domain while the href points somewhere else — "
                    "straightforward misdirection."
                ),
                category=Category.CLOAKING,
                severity=Severity.MEDIUM,
                weight=min(18 + 6 * mismatched, 38),
                evidence=[f"mismatched links: {mismatched}"],
            )
        )

    # Meta refresh redirect off-site.
    for _, a, _span in _iter_tags(body, {"meta"}):
        if a.get("http-equiv", "").lower() == "refresh":
            cm = re.search(r"url\s*=\s*([^;\"']+)", a.get("content", ""), re.I)
            if cm:
                h = urlsplit(cm.group(1).strip() if "//" in cm.group(1) else "").hostname or ""
                if h and not _same_site(h, f.host):
                    add(
                        Signal(
                            id="cloaking.meta_refresh_offsite",
                            title="Automatic redirect to another domain",
                            detail=f"A meta-refresh sends the browser to '{h}' without interaction.",
                            category=Category.CLOAKING,
                            severity=Severity.MEDIUM,
                            weight=30,
                            evidence=[f"target: {cm.group(1).strip()[:80]}"],
                        )
                    )

    # A login page with essentially no other content = single-purpose harvester.
    if password_fields and len(text) < 900 and len(links) <= 3:
        add(
            Signal(
                id="form.bare_credential_page",
                title="Login form with almost no surrounding site",
                detail=(
                    "The page holds a credential form but virtually no navigation, footer, "
                    "legal links or other content. Real sign-in pages sit inside a real site."
                ),
                category=Category.FORM,
                severity=Severity.MEDIUM,
                weight=26,
                evidence=[f"visible text: ~{len(text)} chars", f"links: {len(links)}"],
            )
        )

    # Autocomplete suppression on credential fields (kit hygiene, not UX).
    if password_fields and re.search(r"autocomplete\s*=\s*['\"]?off", body, re.I) and \
       re.search(r"<form[^>]*\bautocomplete\s*=\s*['\"]?off", body, re.I):
        add(
            Signal(
                id="form.autocomplete_suppressed",
                title="Credential form suppresses autofill",
                detail=(
                    "Disabling autocomplete stops a password manager from noticing that the "
                    "origin does not match the saved entry — one of the strongest phishing "
                    "defences a user has."
                ),
                category=Category.FORM,
                severity=Severity.LOW,
                weight=16,
                evidence=["autocomplete=off on credential form"],
            )
        )

    return out


# --------------------------------------------------------------------------- #
# Trust-based suppression
# --------------------------------------------------------------------------- #
# Signals that describe *page shape* rather than hostile behaviour. On a
# well-known legitimate domain these produce noise (a real bank login page is a
# sparse credential form served over TLS), so they are dropped for trusted hosts.
# Anything describing actual exfiltration is intentionally absent from this set:
# a compromised real site must still be catchable.
_SHAPE_ONLY_SIGNALS = frozenset({
    "form.bare_credential_page",
    "form.password_field",
    "form.password_without_form",
    "form.autocomplete_suppressed",
    "form.sensitive_fields",
    "domain.keyword_present",
    "domain.keyword_density",
    "domain.excessive_subdomains",
    "domain.high_risk_tld",
    "domain.random_looking",
    "domain.hyphen_stuffing",
    "url.excessive_length",
    "url.nonstandard_port",
    "url.shortener",
    "content.urgency_pressure",
    "cloaking.cross_origin_frame_with_form",
    "transport.no_tls",
    "script.anti_inspection",
})


def filter_for_trust(signals: list[Signal], f: UrlFacts) -> list[Signal]:
    """Drop shape-only signals on trusted hosts; leave behaviour signals intact."""
    if not is_trusted_host(f):
        return signals
    return [s for s in signals if s.id not in _SHAPE_ONLY_SIGNALS]


def analyze(url: str, html: str = "") -> tuple[UrlFacts, list[Signal], str | None]:
    """Full pipeline: parse, run URL + DOM heuristics, apply trust suppression."""
    facts = parse_url(url)
    signals, brand = analyze_url(facts)
    if html:
        signals = signals + analyze_html(html, facts)
    signals = filter_for_trust(signals, facts)
    signals.sort(key=lambda s: s.weight, reverse=True)
    return facts, signals, brand
