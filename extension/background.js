/**
 * PhishGuard — MV3 service worker.
 *
 * Responsibilities:
 *   1. Relay /scan requests on behalf of content scripts. A content script's
 *      fetch inherits the *page's* origin, so calling the backend from
 *      an https:// page can be refused as mixed content or blocked by CORS
 *      depending on Chrome version and policy. Fetching from the worker uses the
 *      extension origin covered by host_permissions, which sidesteps both.
 *   2. Own the per-tab verdict cache that the popup reads.
 *   3. Keep the toolbar badge in sync with the active tab.
 *   4. Own the whitelist (chrome.storage.local) and mirror it to the backend.
 *
 * The worker is non-persistent: it may be torn down at any moment, so all state
 * lives in chrome.storage / chrome.action rather than in module variables.
 */

const API_BASE_DEFAULT = "https://phishguard-phi-roan.vercel.app";
const DANGEROUS_THRESHOLD = 60;
const SUSPICIOUS_THRESHOLD = 30;
const SCAN_TIMEOUT_MS = 8000;
const CACHE_TTL_MS = 5 * 60 * 1000;

const BADGE = {
  Safe: { text: "OK", color: "#0f9d58" },
  Suspicious: { text: "!", color: "#f4a100" },
  Dangerous: { text: "!!", color: "#d93025" },
  Whitelisted: { text: "\u2713", color: "#5f6368" },
  Error: { text: "?", color: "#5f6368" },
  Scanning: { text: "\u2026", color: "#1a73e8" },
};

/* ------------------------------------------------------------------ utils */

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return {
    apiBase: API_BASE_DEFAULT,
    autoScan: true,
    blockDangerous: true,
    ...(settings || {}),
  };
}

/** Registrable-domain approximation. Handles common multi-part suffixes. */
function baseDomain(hostname) {
  if (!hostname) return "";
  const host = hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const twoPartSuffixes = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "com.cn", "com.mx", "com.tr", "com.tw", "com.sg", "com.hk",
    "co.in", "co.nz", "co.za", "co.kr", "com.ar", "com.co", "com.pl",
    "co.il", "com.ua", "com.my", "com.ph", "com.vn", "com.sa", "com.eg",
    "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "web.app", "firebaseapp.com", "duckdns.org", "ngrok.io", "trycloudflare.com",
    "blogspot.com", "myshopify.com", "wixsite.com", "repl.co", "glitch.me",
    "onrender.com", "herokuapp.com", "azurewebsites.net", "s3.amazonaws.com",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (twoPartSuffixes.has(lastTwo)) return parts.slice(-3).join(".");
  if (twoPartSuffixes.has(lastThree)) return parts.slice(-4).join(".");
  return lastTwo;
}

function domainOf(url) {
  try {
    return baseDomain(new URL(url).hostname);
  } catch {
    return "";
  }
}

function isScannable(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

/* -------------------------------------------------------------- whitelist */

async function getWhitelist() {
  const { whitelist } = await chrome.storage.local.get("whitelist");
  return Array.isArray(whitelist) ? whitelist : [];
}

async function isWhitelisted(url) {
  const domain = domainOf(url);
  if (!domain) return false;
  const list = await getWhitelist();
  return list.some((e) => e.domain === domain);
}

async function addToWhitelist(url, note) {
  const domain = domainOf(url);
  if (!domain) throw new Error("could not determine the domain for this page");
  const list = await getWhitelist();
  if (!list.some((e) => e.domain === domain)) {
    list.unshift({ domain, addedAt: new Date().toISOString(), note: note || null });
    await chrome.storage.local.set({ whitelist: list });
  }
  // Mirror to the backend so server-side scans agree. Best-effort only: the
  // extension must keep working with the server down.
  try {
    const { apiBase } = await getSettings();
    await fetch(`${apiBase}/whitelist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, note: note || "added from extension" }),
    });
  } catch (err) {
    console.debug("PhishGuard: backend whitelist sync failed (offline?)", err);
  }
  return domain;
}

async function removeFromWhitelist(domain) {
  const list = (await getWhitelist()).filter((e) => e.domain !== domain);
  await chrome.storage.local.set({ whitelist: list });
  try {
    const { apiBase } = await getSettings();
    await fetch(`${apiBase}/whitelist?domain=${encodeURIComponent(domain)}`, {
      method: "DELETE",
    });
  } catch (err) {
    console.debug("PhishGuard: backend whitelist removal failed", err);
  }
  return domain;
}

/* ------------------------------------------------------------ result cache */

const resultKey = (tabId) => `result:${tabId}`;

async function saveResult(tabId, result) {
  await chrome.storage.session
    .set({ [resultKey(tabId)]: { ...result, cachedAt: Date.now() } })
    .catch(() => {});
}

async function loadResult(tabId) {
  try {
    const data = await chrome.storage.session.get(resultKey(tabId));
    const hit = data[resultKey(tabId)];
    if (!hit) return null;
    if (Date.now() - (hit.cachedAt || 0) > CACHE_TTL_MS) return null;
    return hit;
  } catch {
    return null;
  }
}

async function clearResult(tabId) {
  await chrome.storage.session.remove(resultKey(tabId)).catch(() => {});
}

/* ------------------------------------------------------------------ badge */

async function setBadge(tabId, state) {
  const cfg = BADGE[state] || BADGE.Error;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  } catch {
    /* tab closed mid-flight */
  }
}

/* ------------------------------------------------------------- scan relay */

async function callScanApi({ url, html, title }) {
  const { apiBase } = await getSettings();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  try {
    const res = await fetch(`${apiBase}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, html: html || "", title: title || null }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`backend returned ${res.status}${detail ? `: ${detail.slice(0, 160)}` : ""}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Full scan for one tab: check the local whitelist, call the API, cache the
 * verdict, update the badge, and tell the content script whether to block.
 */
async function performScan({ tabId, url, html, title }) {
  if (!isScannable(url)) {
    return { ok: false, error: "This page cannot be scanned (not an http/https URL)." };
  }

  await setBadge(tabId, "Scanning");

  if (await isWhitelisted(url)) {
    const result = {
      ok: true,
      url,
      verdict: "Whitelisted",
      risk_score: 0,
      confidence: 1,
      whitelisted: true,
      block: false,
      headline: "Trusted by you",
      summary: "You added this site to your PhishGuard whitelist, so warnings are suppressed here.",
      signals: [],
      hostname: (() => { try { return new URL(url).hostname; } catch { return ""; } })(),
      registered_domain: domainOf(url),
      scanned_at: new Date().toISOString(),
    };
    await saveResult(tabId, result);
    await setBadge(tabId, "Whitelisted");
    return result;
  }

  try {
    const data = await callScanApi({ url, html, title });
    const result = {
      ok: true,
      ...data,
      block: data.risk_score >= DANGEROUS_THRESHOLD && data.verdict === "Dangerous",
    };
    const { blockDangerous } = await getSettings();
    result.block = result.block && blockDangerous !== false;
    await saveResult(tabId, result);
    await setBadge(tabId, data.verdict);
    return result;
  } catch (err) {
    const offline = /Failed to fetch|NetworkError|abort/i.test(String(err));
    const result = {
      ok: false,
      url,
      verdict: "Error",
      risk_score: 0,
      block: false,
      error: offline
        ? "Cannot reach the PhishGuard backend. Start it with: uvicorn backend.main:app --port 8000"
        : `Scan failed: ${err.message}`,
      hostname: (() => { try { return new URL(url).hostname; } catch { return ""; } })(),
      registered_domain: domainOf(url),
      scanned_at: new Date().toISOString(),
    };
    await saveResult(tabId, result);
    await setBadge(tabId, "Error");
    return result;
  }
}

/* --------------------------------------------------------------- messaging */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const tabId = msg.tabId ?? sender.tab?.id;

    switch (msg.type) {
      case "PG_SCAN": {
        const result = await performScan({
          tabId,
          url: msg.url || sender.tab?.url,
          html: msg.html,
          title: msg.title,
        });
        // Push the verdict to the content script so it can raise the overlay
        // even when the scan was initiated from the popup.
        if (tabId != null && result.ok) {
          chrome.tabs.sendMessage(tabId, { type: "PG_VERDICT", result }).catch(() => {});
        }
        sendResponse(result);
        break;
      }

      case "PG_GET_RESULT": {
        sendResponse((await loadResult(tabId)) || null);
        break;
      }

      case "PG_IS_WHITELISTED": {
        sendResponse({ whitelisted: await isWhitelisted(msg.url), domain: domainOf(msg.url) });
        break;
      }

      case "PG_WHITELIST_ADD": {
        try {
          const domain = await addToWhitelist(msg.url, msg.note);
          await clearResult(tabId);
          await setBadge(tabId, "Whitelisted");
          if (tabId != null) {
            const url = msg.url || sender.tab?.url || "";
            chrome.tabs.sendMessage(tabId, { type: "PG_SET_OVERRIDE", url }).catch(() => {});
            chrome.tabs.sendMessage(tabId, { type: "PG_DISMISS_WARNING", url }).catch(() => {});
          }
          sendResponse({ ok: true, domain });
        } catch (err) {
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }

      case "PG_WHITELIST_REMOVE": {
        sendResponse({ ok: true, domain: await removeFromWhitelist(msg.domain) });
        break;
      }

      case "PG_WHITELIST_LIST": {
        sendResponse({ entries: await getWhitelist() });
        break;
      }

      case "PG_GET_SETTINGS": {
        sendResponse(await getSettings());
        break;
      }

      case "PG_SET_SETTINGS": {
        const merged = { ...(await getSettings()), ...(msg.settings || {}) };
        await chrome.storage.local.set({ settings: merged });
        sendResponse(merged);
        break;
      }

      case "PG_GO_BACK": {
        // Prefer real history; fall back to a neutral page if this tab has none.
        if (tabId != null) {
          try {
            await chrome.tabs.goBack(tabId);
          } catch {
            await chrome.tabs.update(tabId, { url: "about:blank" }).catch(() => {});
          }
        }
        sendResponse({ ok: true });
        break;
      }

      case "PG_HEALTH": {
        try {
          const { apiBase } = await getSettings();
          const res = await fetch(`${apiBase}/health`);
          sendResponse({ ok: res.ok, data: res.ok ? await res.json() : null });
        } catch {
          sendResponse({ ok: false });
        }
        break;
      }

      default:
        sendResponse({ ok: false, error: `unknown message type: ${msg.type}` });
    }
  })();

  return true; // keep the channel open for the async reply
});

/* ----------------------------------------------------------- tab lifecycle */

// Reset badge and drop the stale verdict as soon as a tab commits a new document.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    await clearResult(tabId);
    await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => clearResult(tabId));

// Re-paint the badge when switching tabs (badges are per-tab but the worker may
// have restarted since the scan).
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const cached = await loadResult(tabId);
  if (cached) await setBadge(tabId, cached.verdict || "Error");
});

chrome.runtime.onInstalled.addListener(async (details) => {
  const current = await getSettings();
  await chrome.storage.local.set({ settings: current });
  if (details.reason === "install") {
    console.info("PhishGuard installed. Backend expected at", current.apiBase);
  }
});
