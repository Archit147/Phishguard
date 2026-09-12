/**
 * PhishGuard — popup dashboard controller.
 *
 * Reads the cached verdict for the active tab from the service worker, renders
 * the gauge / verdict / signal breakdown, and drives the re-scan and whitelist
 * actions. All DOM is built with textContent or explicit escaping — never with
 * raw innerHTML from backend strings, since signal text is derived from
 * attacker-controlled page content.
 */

(() => {
  "use strict";

  const DANGEROUS = 60;
  const SUSPICIOUS = 30;
  const CIRC = 2 * Math.PI * 50; // r=50 in the popup gauge

  const el = (id) => document.getElementById(id);
  const ui = {
    hero: el("hero"),
    score: el("score"),
    gaugeFill: document.querySelector(".g-fill"),
    badge: el("badge"),
    badgeText: el("badge-text"),
    headline: el("headline"),
    host: el("host"),
    summary: el("summary"),
    meta: el("meta"),
    mCount: el("m-count"),
    mConf: el("m-conf"),
    mTime: el("m-time"),
    signalsSection: el("signals-section"),
    sigToggle: el("sig-toggle"),
    signalsList: el("signals-list"),
    rescan: el("rescan"),
    rescanLabel: el("rescan-label"),
    whitelist: el("whitelist"),
    whitelistLabel: el("whitelist-label"),
    wlToggle: el("wl-toggle"),
    wlList: el("wl-list"),
    wlCount: el("wl-count"),
    apiDot: el("api-dot"),
    apiLabel: el("api-label"),
    engine: el("engine"),
    toast: el("toast"),
  };

  let activeTab = null;
  let currentResult = null;

  /* ---------------------------------------------------------------- helpers */

  function send(msg) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(msg, (reply) => {
        void chrome.runtime.lastError; // swallow "no receiver" noise
        resolve(reply);
      });
    });
  }

  function sendToTab(tabId, msg) {
    return new Promise((resolve) => {
      chrome.tabs.sendMessage(tabId, msg, (reply) => {
        void chrome.runtime.lastError;
        resolve(reply);
      });
    });
  }

  let toastTimer = null;
  function toast(message, kind = "") {
    ui.toast.textContent = message;
    ui.toast.className = `toast show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { ui.toast.className = "toast"; }, 2600);
  }

  function stateOf(result) {
    if (!result) return "loading";
    if (result.ok === false || result.verdict === "Error") return "error";
    const v = String(result.verdict || "").toLowerCase();
    if (v === "whitelisted" || result.whitelisted) return "whitelisted";
    if (v === "dangerous") return "dangerous";
    if (v === "suspicious") return "suspicious";
    if (v === "safe") return "safe";
    const s = Number(result.risk_score) || 0;
    return s >= DANGEROUS ? "dangerous" : s >= SUSPICIOUS ? "suspicious" : "safe";
  }

  const BADGE_LABEL = {
    safe: "Safe",
    suspicious: "Suspicious",
    dangerous: "Dangerous",
    whitelisted: "Trusted",
    error: "Unavailable",
    loading: "Scanning",
  };

  function setGauge(score) {
    const pct = Math.max(0, Math.min(Number(score) || 0, 100)) / 100;
    ui.gaugeFill.style.strokeDashoffset = String(CIRC * (1 - pct));
    // stroke-linecap:round still paints a dot at zero length, which reads as a
    // stray mark on a clean 0-risk gauge.
    ui.gaugeFill.style.opacity = pct === 0 ? "0" : "1";
  }

  /* ----------------------------------------------------------------- render */

  function render(result) {
    currentResult = result;
    const state = stateOf(result);
    ui.hero.dataset.state = state;
    ui.badgeText.textContent = BADGE_LABEL[state] || "Unknown";

    if (state === "error") {
      ui.score.textContent = "--";
      setGauge(0);
      ui.headline.textContent = "Backend unreachable";
      ui.summary.textContent =
        result?.error ||
        "PhishGuard could not reach the analysis engine. Start it with: " +
        "uvicorn backend.main:app --reload --port 8000";
      ui.meta.hidden = true;
      ui.signalsSection.hidden = true;
    } else if (state === "loading") {
      ui.score.textContent = "--";
      setGauge(0);
      ui.headline.textContent = "Analysing this page\u2026";
      ui.summary.textContent = "Inspecting the address, page structure, forms and scripts.";
      ui.meta.hidden = true;
      ui.signalsSection.hidden = true;
    } else {
      const score = Math.round(Number(result.risk_score) || 0);
      ui.score.textContent = String(score);
      setGauge(score);
      ui.headline.textContent = result.headline || BADGE_LABEL[state];
      ui.summary.textContent = result.summary || "";

      const signals = result.signals || [];
      ui.mCount.textContent = String(signals.length);
      ui.mConf.textContent = result.confidence != null
        ? `${Math.round(result.confidence * 100)}%` : "--";
      ui.mTime.textContent = result.duration_ms != null
        ? `${Math.round(result.duration_ms)} ms` : "--";
      ui.meta.hidden = false;

      renderSignals(signals);
      ui.signalsSection.hidden = signals.length === 0;
    }

    const host = result?.hostname || (() => {
      try { return new URL(activeTab?.url || "").hostname; } catch { return ""; }
    })();
    ui.host.textContent = host || "\u2014";
    ui.host.title = result?.url || activeTab?.url || "";

    if (result?.engine_version) ui.engine.textContent = `engine ${result.engine_version}`;
    updateWhitelistButton(Boolean(result?.whitelisted) || state === "whitelisted");
  }

  function renderSignals(signals) {
    ui.signalsList.replaceChildren();
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...signals].sort((a, b) => {
      const d = (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
      return d !== 0 ? d : (b.weight || 0) - (a.weight || 0);
    });

    for (const s of sorted) {
      const li = document.createElement("li");
      li.className = "sig-item";

      const sev = document.createElement("span");
      sev.className = `sev ${s.severity || "medium"}`;

      const body = document.createElement("div");
      body.className = "sig-body";

      const head = document.createElement("div");
      head.className = "sig-head";
      const title = document.createElement("div");
      title.className = "sig-title";
      title.textContent = s.title || s.id || "Indicator";
      const w = document.createElement("span");
      w.className = "sig-w";
      w.textContent = s.weight != null ? `+${Math.round(s.weight)}` : "";
      head.append(title, w);

      const detail = document.createElement("div");
      detail.className = "sig-detail";
      detail.textContent = s.detail || "";

      body.append(head, detail);

      if (Array.isArray(s.evidence) && s.evidence.length) {
        const ev = document.createElement("div");
        ev.className = "sig-ev";
        for (const item of s.evidence.slice(0, 3)) {
          const code = document.createElement("code");
          code.textContent = String(item);
          ev.appendChild(code);
        }
        body.appendChild(ev);
      }

      li.append(sev, body);
      ui.signalsList.appendChild(li);
    }
  }

  function updateWhitelistButton(isTrusted) {
    ui.whitelist.classList.toggle("on", isTrusted);
    ui.whitelistLabel.textContent = isTrusted ? "Trusted \u2713" : "Whitelist this site";
    ui.whitelist.disabled = false;
  }

  async function renderWhitelist() {
    const { entries } = (await send({ type: "PG_WHITELIST_LIST" })) || { entries: [] };
    ui.wlCount.textContent = String(entries.length);
    ui.wlList.replaceChildren();

    if (!entries.length) {
      const li = document.createElement("li");
      li.className = "wl-empty";
      li.textContent = "No trusted sites yet.";
      ui.wlList.appendChild(li);
      return;
    }

    for (const entry of entries) {
      const li = document.createElement("li");
      li.className = "wl-item";

      const domain = document.createElement("span");
      domain.className = "wl-domain";
      domain.textContent = entry.domain;
      domain.title = entry.note ? `${entry.domain} — ${entry.note}` : entry.domain;

      const remove = document.createElement("button");
      remove.className = "wl-remove";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        await send({ type: "PG_WHITELIST_REMOVE", domain: entry.domain });
        toast(`${entry.domain} removed`, "ok");
        await renderWhitelist();
        if (activeTab) doScan({ silent: true });
      });

      li.append(domain, remove);
      ui.wlList.appendChild(li);
    }
  }

  /* ----------------------------------------------------------------- health */

  async function checkHealth() {
    const res = await send({ type: "PG_HEALTH" });
    const up = Boolean(res?.ok);
    ui.apiDot.className = `dot ${up ? "up" : "down"}`;
    ui.apiLabel.textContent = up ? "connected" : "offline";
    if (up && res.data?.engine_version) {
      ui.engine.textContent = `engine ${res.data.engine_version}`;
    }
    return up;
  }

  /* ------------------------------------------------------------------- scan */

  async function doScan({ silent = false } = {}) {
    if (!activeTab) return;

    if (!/^https?:\/\//i.test(activeTab.url || "")) {
      ui.hero.dataset.state = "whitelisted";
      ui.badgeText.textContent = "N/A";
      ui.score.textContent = "--";
      setGauge(0);
      ui.headline.textContent = "Nothing to scan here";
      ui.summary.textContent =
        "PhishGuard only analyses http:// and https:// pages. Browser and extension " +
        "pages are skipped.";
      ui.meta.hidden = true;
      ui.signalsSection.hidden = true;
      ui.rescan.disabled = true;
      ui.whitelist.disabled = true;
      return;
    }

    ui.rescan.classList.add("busy");
    ui.rescan.disabled = true;
    ui.rescanLabel.textContent = "Scanning\u2026";
    if (!silent) render(null);

    // Ask the content script to re-collect the DOM, since it has the live page.
    let result = await sendToTab(activeTab.id, { type: "PG_RESCAN" });

    // Content script missing (installed after page load, or a restricted page):
    // inject it on demand using the scripting permission, then retry.
    if (!result) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: activeTab.id },
          files: ["warning.js", "content.js"],
        });
        await new Promise((r) => setTimeout(r, 350));
        result = await sendToTab(activeTab.id, { type: "PG_RESCAN" });
      } catch (err) {
        console.debug("PhishGuard: injection failed", err);
      }
    }

    // Last resort: scan the URL alone from the worker (no DOM heuristics).
    if (!result || result.ok === false) {
      result = await send({ type: "PG_SCAN", tabId: activeTab.id, url: activeTab.url, html: "" });
    }

    ui.rescan.classList.remove("busy");
    ui.rescan.disabled = false;
    ui.rescanLabel.textContent = "Re-scan page";

    render(result);
    if (!silent && result?.ok !== false) {
      toast(`Scan complete \u2014 ${result.verdict || "done"}`, "ok");
    }
  }

  /* ---------------------------------------------------------------- actions */

  ui.rescan.addEventListener("click", () => doScan());

  ui.whitelist.addEventListener("click", async () => {
    if (!activeTab?.url) return;
    const alreadyTrusted = ui.whitelist.classList.contains("on");

    if (alreadyTrusted) {
      const domain = currentResult?.registered_domain ||
        (() => { try { return new URL(activeTab.url).hostname.replace(/^www\./, ""); }
                 catch { return ""; } })();
      await send({ type: "PG_WHITELIST_REMOVE", domain });
      toast(`${domain} is no longer trusted`);
      await renderWhitelist();
      doScan({ silent: true });
      return;
    }

    ui.whitelist.disabled = true;
    const res = await send({
      type: "PG_WHITELIST_ADD",
      tabId: activeTab.id,
      url: activeTab.url,
      note: "added from popup",
    });
    ui.whitelist.disabled = false;

    if (res?.ok) {
      toast(`${res.domain} added to trusted sites`, "ok");
      updateWhitelistButton(true);
      await renderWhitelist();
      doScan({ silent: true });
    } else {
      toast(res?.error || "Could not whitelist this site", "err");
    }
  });

  function wireToggle(button, panel) {
    button.addEventListener("click", () => {
      const open = button.getAttribute("aria-expanded") === "true";
      button.setAttribute("aria-expanded", String(!open));
      panel.hidden = open;
    });
  }
  wireToggle(ui.sigToggle, ui.signalsList);
  wireToggle(ui.wlToggle, ui.wlList);

  /* -------------------------------------------------------------- bootstrap */

  (async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tab || null;

    await Promise.all([checkHealth(), renderWhitelist()]);

    if (!activeTab) {
      render({ ok: false, verdict: "Error", error: "No active tab." });
      return;
    }

    // Show the cached verdict instantly, then refresh in the background so the
    // popup never appears to hang on open.
    const cached = await send({ type: "PG_GET_RESULT", tabId: activeTab.id });
    if (cached) {
      render(cached);
      // Auto-expand the breakdown when there is something worth reading.
      if ((cached.signals || []).length && (Number(cached.risk_score) || 0) >= SUSPICIOUS) {
        ui.sigToggle.setAttribute("aria-expanded", "true");
        ui.signalsList.hidden = false;
      }
    } else {
      render(null);
      doScan({ silent: true });
    }
  })();
})();
