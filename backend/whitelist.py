"""Local, file-backed whitelist so users can dismiss false positives.

Deliberately a flat JSON file rather than a database: it is inspectable, easy to
reset during a demo, and carries no migration burden. Writes are atomic
(temp file + os.replace) and guarded by a lock so concurrent scans from several
tabs cannot corrupt it.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import tldextract

from .models import WhitelistEntry

_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

STORE_PATH = Path(
    os.environ.get("PHISHGUARD_WHITELIST", Path.home() / ".phishguard" / "whitelist.json")
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value: str) -> str:
    """Accept a URL or bare host; return the registrable domain (or the host if IP)."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "//" in v:
        v = urlsplit(v).hostname or ""
    else:
        v = urlsplit(f"//{v}").hostname or v
    v = v.strip(".").removeprefix("www.")
    ext = _extract(v)
    return ext.registered_domain or v


class WhitelistStore:
    def __init__(self, path: Path = STORE_PATH) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cache: dict[str, WhitelistEntry] = {}
        self._load()

    # ----------------------------------------------------------------- I/O
    def _load(self) -> None:
        with self._lock:
            self._cache = {}
            try:
                raw = json.loads(self.path.read_text("utf-8"))
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                return
            for item in raw.get("entries", []):
                try:
                    entry = WhitelistEntry(**item)
                except (TypeError, ValueError):
                    continue
                self._cache[entry.domain] = entry

    def _flush(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "updated_at": _now(),
                "entries": [e.model_dump() for e in self._cache.values()],
            }
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2)
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    # ----------------------------------------------------------------- API
    def all(self) -> list[WhitelistEntry]:
        with self._lock:
            return sorted(self._cache.values(), key=lambda e: e.added_at, reverse=True)

    def contains(self, url_or_domain: str) -> bool:
        domain = normalize_domain(url_or_domain)
        if not domain:
            return False
        with self._lock:
            return domain in self._cache

    def add(self, url_or_domain: str, note: str | None = None, scope: str = "domain") -> str:
        domain = normalize_domain(url_or_domain)
        if not domain:
            raise ValueError("could not derive a domain from the supplied value")
        with self._lock:
            self._cache[domain] = WhitelistEntry(
                domain=domain, added_at=_now(), note=note, scope=scope  # type: ignore[arg-type]
            )
            self._flush()
        return domain

    def remove(self, url_or_domain: str) -> str:
        domain = normalize_domain(url_or_domain)
        with self._lock:
            self._cache.pop(domain, None)
            self._flush()
        return domain

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._flush()
