/**
 * PhishGuard — content script.
 *
 * Extracts the page URL and full DOM, sends them to the FastAPI backend, and
 * raises the blocking overlay when the verdict is Dangerous.
 *
 * Transport: a direct POST from the page context is attempted first (as the
 * simple, obvious path), but a content script's fetch carries the *page's*
* origin, so a page calling the backend can be refused
 * mixed content. When that happens we relay through the service worker, whose
 * extension origin is covered by host_permissions. The first successful method
 * is remembered for the rest of the page's life.
 */

(() => {
  "use strict";

  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  const API_BASE = "https://phishguard-phi-roan.vercel.app";
  const DANGEROUS_THRESHOLD = 60;
  const MAX_HTML_CHARS = 2_000_000;
  const RESCAN_DEBOUNCE_MS = 1200;

  let lastScanUrl = null;
  let scanning = false;
  let transport = null; // "direct" | "relay"
  let pageOverrideUrl = null;
  let pageOverrideUntil = 0;

  function setPageOverride(url) {
    try {
      pageOverrideUrl = new URL(url || location.href).href;
    } catch {
      pageOverrideUrl = String(url || location.href || "");
    }
    pageOverrideUntil = Date.now() + 60_000;
  }

  function isPageOverrideActive(url) {
    if (!pageOverrideUrl || Date.now() > pageOverrideUntil) {
      pageOverrideUrl = null;
      pageOverrideUntil = 0;
      return false;
    }
    try {
      return new URL(url || location.href).href === pageOverrideUrl;
    } catch {
      return String(url || location.href || "") === pageOverrideUrl;
    }
  }

  /* --------------------------------------------------------------- helpers */

  const isTop = window.top === window.self;

  function collectDom() {
    let html = "";
    try {
      html = document.documentElement ? document.documentElement.outerHTML : "";
    } catch {
      html = document.body ? document.body.innerHTML : "";
    }
    if (html.length > MAX_HTML_CHARS) {
      // Keep both ends: <head> carries title/meta/brand assets, the tail usually
      // carries the injected credential form and exfiltration script.
      const half = Math.floor(MAX_HTML_CHARS / 2);
      html = `${html.slice(0, half)}\n<!-- phishguard: truncated -->\n${html.slice(-half)}`;
    }
    return html;
  }

  /** Direct POST from the page context (the documented happy path). */
  async function scanDirect(payload) {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      mode: "cors",
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`backend ${res.status}`);
    return res.json();
  }

  /** Relay through the service worker (works on https pages and when CORS bites). */
  function scanViaWorker(payload) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: "PG_SCAN", ...payload }, (reply) => {
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        if (!reply) return reject(new Error("no response from PhishGuard worker"));
        if (reply.ok === false && reply.error) return reject(new Error(reply.error));
        resolve(reply);
      });
    });
  }

  async function requestScan(payload) {
    if (transport === "relay") return scanViaWorker(payload);
    if (transport === "direct") {
      try {
        return await scanDirect(payload);
      } catch {
        transport = "relay";
        return scanViaWorker(payload);
      }
    }
    // First scan of this page: try direct, fall back and remember the winner.
    try {
      const out = await scanDirect(payload);
      transport = "direct";
      return out;
    } catch (directErr) {
      console.debug("PhishGuard: direct POST unavailable, relaying via worker.", directErr);
      const out = await scanViaWorker(payload);
      transport = "relay";
      return out;
    }
  }

  /* ------------------------------------------------------------------ core */

  async function scan({ force = false } = {}) {
    if (!isTop) return null;
    if (!/^https?:$/i.test(location.protocol)) return null;
    if (scanning) return null;
    if (isPageOverrideActive(location.href)) {
      return {
        ok: true,
        url: location.href,
        verdict: "Whitelisted",
        whitelisted: true,
        block: false,
        risk_score: 0,
      };
    }
    if (!force && lastScanUrl === location.href) return null;

    scanning = true;
    lastScanUrl = location.href;

    const payload = {
      url: location.href,
      html: collectDom(),
      title: document.title || null,
      referrer: document.referrer || null,
      top_level: true,
    };

    try {
      const result = await requestScan(payload);
      handleVerdict(result);
      return result;
    } catch (err) {
      // Fail open: a detector that breaks pages when its backend is down is
      // worse than one that quietly stops protecting. Surfaced in the popup.
      console.warn("PhishGuard: scan failed —", err.message);
      chrome.runtime.sendMessage({ type: "PG_SCAN_FAILED", error: err.message }).catch(() => {});
      return null;
    } finally {
      scanning = false;
    }
  }

  function handleVerdict(result) {
    if (!result) return;
    if (result.whitelisted || isPageOverrideActive(result.url || location.href)) return;
    const score = Number(result.risk_score) || 0;
    const dangerous =
      result.block === true || (result.verdict === "Dangerous" && score >= DANGEROUS_THRESHOLD);

    if (dangerous && window.PhishGuardWarning) {
      window.PhishGuardWarning.show(result);
    } else if (window.PhishGuardWarning) {
      window.PhishGuardWarning.hide();
    }
  }

  /* -------------------------------------------------------------- triggers */

  // Initial scan. document_idle already means the DOM is parsed; a short delay
  // lets client-rendered login forms mount before we snapshot.
  const initialDelay = document.readyState === "complete" ? 250 : 700;
  setTimeout(() => scan(), initialDelay);

  // SPA navigation: history API changes the URL without a document load.
  let debounce = null;
  function onUrlMaybeChanged() {
    if (location.href === lastScanUrl) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => scan({ force: true }), RESCAN_DEBOUNCE_MS);
  }

  for (const method of ["pushState", "replaceState"]) {
    const original = history[method];
    history[method] = function patched(...args) {
      const out = original.apply(this, args);
      onUrlMaybeChanged();
      return out;
    };
  }
  window.addEventListener("popstate", onUrlMaybeChanged);
  window.addEventListener("hashchange", onUrlMaybeChanged);

  // A password field appearing after load is the single most important change to
  // react to — many kits inject the credential form only after user interaction.
  const observer = new MutationObserver((records) => {
    for (const rec of records) {
      for (const node of rec.addedNodes) {
        if (node.nodeType !== 1) continue;
        const el = /** @type {Element} */ (node);
        if (
          el.matches?.('input[type="password"], iframe, form') ||
          el.querySelector?.('input[type="password"], iframe')
        ) {
          clearTimeout(debounce);
          debounce = setTimeout(() => scan({ force: true }), RESCAN_DEBOUNCE_MS);
          return;
        }
      }
    }
  });
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

  /* -------------------------------------------------------------- messages */

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    switch (msg.type) {
      case "PG_RESCAN":
        scan({ force: true }).then((r) => sendResponse(r || { ok: false }));
        return true;

      case "PG_VERDICT":
        handleVerdict(msg.result);
        sendResponse({ ok: true });
        return false;

      case "PG_DISMISS_WARNING":
        if (msg.url) setPageOverride(msg.url);
        window.PhishGuardWarning?.hide();
        sendResponse({ ok: true });
        return false;

      case "PG_SET_OVERRIDE":
        setPageOverride(msg.url || location.href);
        window.PhishGuardWarning?.hide();
        sendResponse({ ok: true });
        return false;

      case "PG_PING":
        sendResponse({ ok: true, url: location.href, transport });
        return false;

      default:
        return false;
    }
  });
})();
