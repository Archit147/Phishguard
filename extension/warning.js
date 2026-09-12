/**
 * PhishGuard — full-screen blocking warning overlay.
 *
 * Exposes window.PhishGuardWarning = { show(result), hide(), isVisible() }.
 *
 * Hardening notes — the overlay has to survive a *hostile* page:
 *   - Rendered inside a shadow root so the page's CSS cannot restyle or hide it.
 *     All overlay styles live in the shadow tree, immune to page selectors.
 *   - The host element's critical properties are re-asserted by a MutationObserver
 *     and re-appended if the page removes the node.
 *   - Page scrolling and keyboard interaction with the document underneath are
 *     suppressed while the warning is up, and focus is trapped in the dialog, so
 *     a user cannot tab into a credential field hidden behind the overlay.
 *   - Injected as its own content-script file (loaded before content.js) rather
 *     than via a string, so there is no CSP-sensitive eval and no inline script.
 */

(() => {
  "use strict";

  if (window.PhishGuardWarning) return;

  const HOST_ID = "phishguard-warning-root";
  const Z = "2147483647"; // max 32-bit signed int — above any page stacking context

  let hostEl = null;
  let shadow = null;
  let guardObserver = null;
  let savedOverflow = null;
  let savedFocus = null;
  let keyTrapHandler = null;

  /* --------------------------------------------------------------- styling */

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }

    .backdrop {
      position: fixed; inset: 0;
      z-index: ${Z};
      display: flex; align-items: center; justify-content: center;
      padding: 24px;
      background:
        radial-gradient(ellipse at 50% 0%, rgba(255,64,64,.28), transparent 60%),
        rgba(52, 4, 6, .93);
      backdrop-filter: blur(7px) saturate(115%);
      -webkit-backdrop-filter: blur(7px) saturate(115%);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   "Helvetica Neue", Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      animation: fade .22s ease-out both;
      overflow-y: auto;
    }
    @keyframes fade { from { opacity: 0 } to { opacity: 1 } }
    @keyframes rise { from { opacity: 0; transform: translateY(14px) scale(.985) }
                      to   { opacity: 1; transform: none } }
    @keyframes pulse { 0%,100% { transform: scale(1); opacity: 1 }
                       50%     { transform: scale(1.06); opacity: .82 } }
    @keyframes sweep { to { stroke-dashoffset: var(--dash-final) } }

    .card {
      position: relative;
      width: 100%; max-width: 680px;
      background: linear-gradient(168deg, #2a0508 0%, #1a0304 100%);
      border: 1px solid rgba(255,120,120,.34);
      border-radius: 18px;
      box-shadow: 0 34px 90px -18px rgba(0,0,0,.85),
                  0 0 0 1px rgba(255,255,255,.05) inset,
                  0 0 70px -30px rgba(255,60,60,.5);
      color: #fff;
      overflow: hidden;
      animation: rise .3s cubic-bezier(.16,.84,.44,1) both;
    }
    .stripe {
      height: 5px;
      background: linear-gradient(90deg, #ff2d2d, #ff7847, #ff2d2d);
      background-size: 200% 100%;
      animation: slide 2.6s linear infinite;
    }
    @keyframes slide { to { background-position: -200% 0 } }

    .head { display: flex; gap: 16px; padding: 26px 28px 20px; align-items: flex-start; }
    .siren {
      flex: none; width: 46px; height: 46px; border-radius: 50%;
      background: rgba(255,45,45,.14);
      border: 1.5px solid rgba(255,90,90,.55);
      display: grid; place-items: center;
      animation: pulse 1.9s ease-in-out infinite;
    }
    .siren svg { width: 25px; height: 25px; }
    .htext { min-width: 0; flex: 1; }
    .kicker {
      font-size: 10.5px; font-weight: 800; letter-spacing: .16em;
      text-transform: uppercase; color: #ff9d9d; margin-bottom: 5px;
    }
    h1 { font-size: 25px; line-height: 1.2; font-weight: 750; letter-spacing: -.015em; }
    .host {
      margin-top: 11px; display: inline-flex; align-items: center; gap: 7px;
      max-width: 100%;
      font: 500 12.5px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: rgba(0,0,0,.42); border: 1px solid rgba(255,255,255,.12);
      padding: 6px 11px; border-radius: 7px; color: #ffd9d9;
      word-break: break-all; overflow-wrap: anywhere;
    }
    .host svg { flex: none; width: 12px; height: 12px; opacity: .75; }

    .body { padding: 0 28px 6px; }
    .summary { font-size: 14.5px; line-height: 1.6; color: #ffdcdc; }

    .meter { margin: 20px 0 6px; display: flex; align-items: center; gap: 18px; }
    .gauge { flex: none; position: relative; width: 96px; height: 96px; }
    .gauge svg { transform: rotate(-90deg); }
    .gauge .track { stroke: rgba(255,255,255,.11); }
    .gauge .fill  { stroke: #ff3d3d; stroke-linecap: round;
                    filter: drop-shadow(0 0 7px rgba(255,60,60,.75));
                    animation: sweep 1s cubic-bezier(.2,.8,.2,1) both; }
    .gauge .num {
      position: absolute; inset: 0; display: grid; place-items: center;
      font-size: 27px; font-weight: 800; letter-spacing: -.03em;
    }
    .gauge .num small { display: block; font-size: 9px; font-weight: 700;
                        letter-spacing: .12em; color: #ff9d9d; margin-top: 1px; }
    .mlabel { min-width: 0; }
    .mlabel .t { font-size: 12.5px; font-weight: 700; letter-spacing: .1em;
                 text-transform: uppercase; color: #ff8f8f; }
    .mlabel .d { margin-top: 5px; font-size: 13px; line-height: 1.55; color: #ffcaca; }

    .why { margin: 14px 0 4px; }
    .why > .t {
      font-size: 10.5px; font-weight: 800; letter-spacing: .14em;
      text-transform: uppercase; color: #ff9d9d;
      padding-bottom: 9px; border-bottom: 1px solid rgba(255,255,255,.1);
      display: flex; justify-content: space-between; align-items: baseline;
    }
    .why .count { font-weight: 600; letter-spacing: .04em; color: #ffb9b9; }
    ul { list-style: none; max-height: 232px; overflow-y: auto; }
    ul::-webkit-scrollbar { width: 7px; }
    ul::-webkit-scrollbar-thumb { background: rgba(255,255,255,.2); border-radius: 4px; }
    li { display: flex; gap: 11px; padding: 12px 2px; border-bottom: 1px solid rgba(255,255,255,.06); }
    li:last-child { border-bottom: 0; }
    .sev {
      flex: none; margin-top: 2px; width: 8px; height: 8px; border-radius: 50%;
      box-shadow: 0 0 0 3px rgba(255,255,255,.06);
    }
    .sev.critical { background: #ff2d2d; box-shadow: 0 0 0 3px rgba(255,45,45,.2); }
    .sev.high     { background: #ff7a3d; box-shadow: 0 0 0 3px rgba(255,122,61,.18); }
    .sev.medium   { background: #ffc53d; box-shadow: 0 0 0 3px rgba(255,197,61,.16); }
    .sev.low, .sev.info { background: #9aa4b2; }
    .sig { min-width: 0; flex: 1; }
    .sig .st { font-size: 13.5px; font-weight: 650; line-height: 1.35; }
    .sig .sd { margin-top: 3px; font-size: 12.5px; line-height: 1.55; color: #e8b9b9; }
    .sig .ev {
      margin-top: 6px; display: flex; flex-wrap: wrap; gap: 5px;
    }
    .sig .ev code {
      font: 500 10.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.1);
      padding: 2.5px 6px; border-radius: 5px; color: #ffc9c9;
      word-break: break-all; overflow-wrap: anywhere; max-width: 100%;
    }

    .foot {
      margin-top: 8px; padding: 18px 28px 24px;
      background: rgba(0,0,0,.34); border-top: 1px solid rgba(255,255,255,.09);
      display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    }
    button {
      font: inherit; cursor: pointer; border-radius: 10px;
      transition: transform .12s ease, filter .18s ease, background .18s ease;
      display: inline-flex; align-items: center; gap: 8px;
    }
    button:active { transform: translateY(1px) scale(.995); }
    button:focus-visible { outline: 2.5px solid #fff; outline-offset: 2.5px; }
    .primary {
      flex: 1 1 210px; justify-content: center;
      padding: 13px 20px; font-size: 14.5px; font-weight: 700;
      color: #fff; border: 0;
      background: linear-gradient(180deg, #33c76a, #1e9b4e);
      box-shadow: 0 5px 18px -5px rgba(30,155,78,.75);
    }
    .primary:hover { filter: brightness(1.09); }
    .ghost {
      padding: 13px 17px; font-size: 13px; font-weight: 600;
      color: #ffc7c7; background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.17);
    }
    .ghost:hover { background: rgba(255,255,255,.12); color: #fff; }
    .danger {
      padding: 13px 17px; font-size: 12.5px; font-weight: 600;
      color: #ff9e9e; background: transparent;
      border: 1px dashed rgba(255,120,120,.45);
    }
    .danger:hover { background: rgba(255,45,45,.12); color: #fff;
                    border-color: rgba(255,120,120,.8); }
    .note {
      flex: 1 1 100%; margin-top: 4px; font-size: 11px; line-height: 1.5;
      color: #c99; text-align: center;
    }
    .brandmark {
      position: absolute; top: 15px; right: 18px;
      font-size: 10px; font-weight: 800; letter-spacing: .17em;
      text-transform: uppercase; color: rgba(255,255,255,.32);
    }

    /* Confirmation step for "proceed anyway" — a single click must not be enough
       to walk past a critical warning. */
    .confirm { display: none; flex: 1 1 100%; gap: 10px; flex-wrap: wrap; align-items: center; }
    .confirm.on { display: flex; }
    .confirm p { flex: 1 1 100%; font-size: 12.5px; line-height: 1.5; color: #ffd0d0; }
    .actions.off { display: none; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; flex: 1 1 100%; }

    @media (max-width: 560px) {
      .backdrop { padding: 12px; }
      h1 { font-size: 21px; }
      .head, .body { padding-left: 19px; padding-right: 19px; }
      .foot { padding: 16px 19px 20px; }
      .meter { flex-direction: column; align-items: flex-start; gap: 12px; }
    }
    @media (prefers-reduced-motion: reduce) {
      * { animation: none !important; transition: none !important; }
    }
  `;

  /* --------------------------------------------------------------- helpers */

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function svgShield() {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="#ff5252" stroke-width="2.1"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M12 2 4 5.5v6c0 5 3.4 9.2 8 10.5 4.6-1.3 8-5.5 8-10.5v-6L12 2Z"/>
      <line x1="12" y1="8.5" x2="12" y2="13"/><circle cx="12" cy="16.4" r="1.15" fill="#ff5252"/>
    </svg>`;
  }

  function svgLockOpen() {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
      stroke-linecap="round" aria-hidden="true">
      <rect x="4" y="10.5" width="16" height="10.5" rx="2.2"/>
      <path d="M8 10.5V7a4 4 0 0 1 7.4-2"/>
    </svg>`;
  }

  function gauge(score) {
    const r = 40, c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(Number(score) || 0, 100)) / 100;
    const finalOffset = c * (1 - pct);
    return `
      <div class="gauge">
        <svg width="96" height="96" viewBox="0 0 96 96" aria-hidden="true">
          <circle class="track" cx="48" cy="48" r="${r}" fill="none" stroke-width="8"/>
          <circle class="fill" cx="48" cy="48" r="${r}" fill="none" stroke-width="8"
            stroke-dasharray="${c.toFixed(2)}"
            stroke-dashoffset="${c.toFixed(2)}"
            style="--dash-final:${finalOffset.toFixed(2)};opacity:${pct === 0 ? 0 : 1}"/>
        </svg>
        <div class="num">${Math.round(Number(score) || 0)}<small>RISK</small></div>
      </div>`;
  }

  function signalList(signals) {
    const sorted = [...(signals || [])].sort((a, b) => {
      const s = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
      return s !== 0 ? s : (b.weight || 0) - (a.weight || 0);
    });
    if (!sorted.length) {
      return `<li><div class="sig"><div class="sd">No individual indicators were returned.</div></div></li>`;
    }
    return sorted.slice(0, 9).map((s) => `
      <li>
        <span class="sev ${esc(s.severity || "medium")}"></span>
        <div class="sig">
          <div class="st">${esc(s.title || s.id || "Indicator")}</div>
          <div class="sd">${esc(s.detail || "")}</div>
          ${(s.evidence || []).length
            ? `<div class="ev">${s.evidence.slice(0, 3)
                .map((e) => `<code>${esc(e)}</code>`).join("")}</div>`
            : ""}
        </div>
      </li>`).join("");
  }

  /* ----------------------------------------------------------- page locking */

  function lockPage() {
    if (savedOverflow === null) {
      savedOverflow = document.documentElement.style.overflow || "";
      document.documentElement.style.setProperty("overflow", "hidden", "important");
    }
    savedFocus = document.activeElement;

    // Trap keyboard focus inside the dialog: without this, Tab would walk into
    // the credential fields sitting behind the overlay.
    keyTrapHandler = (ev) => {
      if (!hostEl || !shadow) return;
      if (ev.key === "Tab") {
        const focusables = shadow.querySelectorAll("button");
        if (!focusables.length) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = shadow.activeElement;
        if (ev.shiftKey && (active === first || !active)) {
          ev.preventDefault();
          last.focus();
        } else if (!ev.shiftKey && active === last) {
          ev.preventDefault();
          first.focus();
        } else if (!shadow.contains(active)) {
          ev.preventDefault();
          first.focus();
        }
      }
      // Escape must not silently dismiss a block.
      if (ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
      }
    };
    window.addEventListener("keydown", keyTrapHandler, true);
  }

  function unlockPage() {
    if (savedOverflow !== null) {
      document.documentElement.style.overflow = savedOverflow;
      savedOverflow = null;
    }
    if (keyTrapHandler) {
      window.removeEventListener("keydown", keyTrapHandler, true);
      keyTrapHandler = null;
    }
    try {
      savedFocus?.focus?.();
    } catch { /* element may be gone */ }
    savedFocus = null;
  }

  /* ------------------------------------------------------------ host guard */

  const HOST_STYLE = {
    position: "fixed",
    inset: "0px",
    top: "0px",
    left: "0px",
    width: "100vw",
    height: "100vh",
    "z-index": Z,
    display: "block",
    visibility: "visible",
    opacity: "1",
    "pointer-events": "auto",
    margin: "0px",
    padding: "0px",
    border: "0px",
    transform: "none",
    filter: "none",
    "clip-path": "none",
  };

  function applyHostStyle(el) {
    for (const [k, v] of Object.entries(HOST_STYLE)) {
      el.style.setProperty(k, v, "important");
    }
  }

  /** Re-assert the overlay if the page tries to hide or remove it. */
  function startGuard() {
    stopGuard();
    guardObserver = new MutationObserver(() => {
      if (!hostEl) return;
      if (!hostEl.isConnected) {
        (document.body || document.documentElement).appendChild(hostEl);
      }
      applyHostStyle(hostEl);
    });
    guardObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden"],
    });
  }

  function stopGuard() {
    guardObserver?.disconnect();
    guardObserver = null;
  }

  /* ------------------------------------------------------------------- API */

  function hide() {
    stopGuard();
    unlockPage();
    hostEl?.remove();
    hostEl = null;
    shadow = null;
  }

  function show(result) {
    const score = Math.round(Number(result?.risk_score) || 0);
    const brand = result?.impersonated_brand_label || result?.impersonated_brand;
    const headline =
      result?.headline ||
      (brand ? `This page is impersonating ${brand}` : "Phishing page blocked");
    const hostname = result?.hostname || (() => {
      try { return new URL(result?.url || location.href).hostname; } catch { return location.hostname; }
    })();
    const summary =
      result?.summary ||
      "PhishGuard detected patterns consistent with credential harvesting on this page.";
    const signals = result?.signals || [];
    const criticalCount = signals.filter((s) => s.severity === "critical").length;

    hide(); // idempotent re-render

    hostEl = document.createElement("div");
    hostEl.id = HOST_ID;
    applyHostStyle(hostEl);

    // Closed shadow root: page scripts cannot reach in via .shadowRoot to
    // restyle or strip the warning.
    shadow = hostEl.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = CSS;

    const wrap = document.createElement("div");
    wrap.className = "backdrop";
    wrap.setAttribute("role", "alertdialog");
    wrap.setAttribute("aria-modal", "true");
    wrap.setAttribute("aria-labelledby", "pg-title");
    wrap.setAttribute("aria-describedby", "pg-summary");

    wrap.innerHTML = `
      <div class="card">
        <div class="stripe"></div>
        <span class="brandmark">PhishGuard</span>

        <div class="head">
          <div class="siren">${svgShield()}</div>
          <div class="htext">
            <div class="kicker">Dangerous site blocked</div>
            <h1 id="pg-title">${esc(headline)}</h1>
            <div class="host">${svgLockOpen()}<span>${esc(hostname)}</span></div>
          </div>
        </div>

        <div class="body">
          <p class="summary" id="pg-summary">${esc(summary)}</p>

          <div class="meter">
            ${gauge(score)}
            <div class="mlabel">
              <div class="t">Risk score ${score}/100</div>
              <div class="d">
                ${brand
                  ? `This page appears designed to look like <strong>${esc(brand)}</strong> while
                     sending anything you type somewhere else.`
                  : `Scores of 60 and above indicate strong evidence of phishing or
                     credential theft.`}
                Do not enter passwords, card details or one-time codes here.
              </div>
            </div>
          </div>

          <div class="why">
            <div class="t">
              <span>Why this was flagged</span>
              <span class="count">${signals.length} indicator${signals.length === 1 ? "" : "s"}${
                criticalCount ? ` &middot; ${criticalCount} critical` : ""
              }</span>
            </div>
            <ul>${signalList(signals)}</ul>
          </div>
        </div>

        <div class="foot">
          <div class="actions" id="pg-actions">
            <button class="primary" id="pg-back" type="button">
              &#8592;&nbsp; Go back to safety
            </button>
            <button class="ghost" id="pg-details" type="button">Copy report</button>
            <button class="danger" id="pg-proceed" type="button">Proceed at own risk</button>
            <div class="note">
              PhishGuard blocked this page locally. Nothing you typed has been sent by
              this extension.
            </div>
          </div>

          <div class="confirm" id="pg-confirm">
            <p><strong>Are you sure?</strong> Continuing adds
              <code>${esc(result?.registered_domain || hostname)}</code> to your whitelist and
              stops all future warnings for it. Only do this if you are certain the site
              is genuine.</p>
            <button class="danger" id="pg-confirm-yes" type="button">
              Yes, whitelist and continue
            </button>
            <button class="ghost" id="pg-confirm-no" type="button">Cancel</button>
          </div>
        </div>
      </div>`;

    shadow.append(style, wrap);
    (document.body || document.documentElement).appendChild(hostEl);

    // Block interaction with the page beneath.
    for (const evt of ["click", "mousedown", "mouseup", "submit", "wheel", "touchstart"]) {
      wrap.addEventListener(evt, (ev) => ev.stopPropagation(), true);
    }

    const $ = (id) => shadow.getElementById(id);

    $("pg-back").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "PG_GO_BACK" }).catch(() => {
        history.length > 1 ? history.back() : window.location.replace("about:blank");
      });
    });

    $("pg-details").addEventListener("click", (ev) => {
      const report = [
        "PhishGuard report",
        `URL:      ${result?.url || location.href}`,
        `Host:     ${hostname}`,
        `Verdict:  ${result?.verdict || "Dangerous"} (${score}/100)`,
        brand ? `Imitates: ${brand}` : null,
        `Scanned:  ${result?.scanned_at || new Date().toISOString()}`,
        "",
        "Indicators:",
        ...signals.map((s) => `  [${(s.severity || "").toUpperCase()}] ${s.title} — ${s.detail}`),
      ].filter(Boolean).join("\n");

      navigator.clipboard?.writeText(report).then(
        () => { ev.target.textContent = "Copied \u2713"; },
        () => { ev.target.textContent = "Copy failed"; },
      );
      setTimeout(() => { ev.target.textContent = "Copy report"; }, 2200);
    });

    // Two-step escape hatch.
    $("pg-proceed").addEventListener("click", () => {
      $("pg-actions").classList.add("off");
      $("pg-confirm").classList.add("on");
      $("pg-confirm-no").focus();
    });

    $("pg-confirm-no").addEventListener("click", () => {
      $("pg-confirm").classList.remove("on");
      $("pg-actions").classList.remove("off");
      $("pg-back").focus();
    });

    $("pg-confirm-yes").addEventListener("click", () => {
      chrome.runtime.sendMessage(
        { type: "PG_WHITELIST_ADD", url: result?.url || location.href, note: "user override from warning" },
        () => hide(),
      );
      // If the worker never replies (torn down), still let the user through.
      setTimeout(hide, 900);
    });

    lockPage();
    startGuard();
    setTimeout(() => $("pg-back")?.focus(), 60);
  }

  window.PhishGuardWarning = {
    show,
    hide,
    isVisible: () => Boolean(hostEl?.isConnected),
  };
})();
