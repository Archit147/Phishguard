# 🛡️ PhishGuard

**Real-time phishing detection, fully local.**

PhishGuard is a free, open-source browser extension that detects phishing and credential-harvesting attacks the instant you land on a page — using local heuristic analysis instead of blacklists that lag behind new attacks. No data ever leaves your machine.

[Add to Chrome](#) · [Features](#features) · [How It Works](#how-it-works) · [FAQ](#faq)

---

## Why PhishGuard

Most phishing extensions rely on a central blacklist — which means they only catch a threat *after* it's already been reported. PhishGuard doesn't wait. It runs a local heuristic engine on every page load and makes a decision in milliseconds, entirely on-device.

| | PhishGuard | Blacklist Extensions |
|---|---|---|
| Detection method | Local heuristic analysis | Cloud blacklist lookup |
| Zero-day protection | ✅ Catches new, unlisted attacks | ❌ Waits for a blacklist entry |
| Data sent to a server | None — 100% on-device | URLs & browsing activity |
| Works offline | ✅ Yes | ❌ Requires a live connection |
| Response time | Instant — no network round-trip | Depends on network latency |
| Cost | Free & open source | Often freemium |

## Features

- **Heuristic DOM & URL Analysis** — scans page DOM, URLs, SSL certificates, and domain patterns in real time to catch typosquatting and other suspicious signals
- **Instant Warning Overlay** — blocks page interaction with a high-visibility warning the moment a threat is detected
- **Zero-Day Detection** — no blacklist dependency; catches new, never-before-seen phishing attacks
- **Local Whitelisting** — trust a site with one click; saved locally for next time
- **Privacy-First Local Processing** — no cloud transmission, no tracking, no data collection, ever
- **Real-Time Analysis** — checks complete in milliseconds, so it never slows down your browsing

## How It Works

1. **Page load** — PhishGuard's content script activates automatically
2. **Capture** — the DOM structure and full URL are read locally, in memory only
3. **Analyze** — a local heuristic engine scores dozens of signals (URL patterns, DOM structure, SSL chain, keyword density, domain age)
4. **Score** — every signal contributes weighted points to a single 0–100 risk score
5. **Decide** — the score maps directly to an action, no server round-trip required
   - `0–30` → Safe, stays silent
   - `30–60` → Suspicious, shows a warning banner
   - `60–100` → Dangerous, blocks interaction with a full-screen warning
6. **Protect** — dangerous pages are blocked before you can enter a password or click a malicious link

## Installation

1. Clone this repository
2. Open `chrome://extensions` (or `edge://extensions`)
3. Enable **Developer mode**
4. Click **Load unpacked** and select the extension folder

*(Or install directly from the Chrome Web Store — link coming soon.)*

## Privacy

PhishGuard performs all analysis locally on your machine. No URLs, page content, or any other data is ever sent to an external server, tracked, logged, or sold.

## Compatibility

Works alongside your other extensions on Chrome and Edge without interfering with browser functionality.

## Contributing

Issues and pull requests are welcome — especially reports of false positives/negatives to help tune the heuristic engine.

## License

MIT License — free to use, modify, and distribute.