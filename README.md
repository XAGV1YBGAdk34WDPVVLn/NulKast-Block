# 🛡️ AegisBlock — Zero-Leak Microsoft Edge MV3 AdBlocker & Telemetry Lab

A fast, zero-leak **Manifest V3** ad and tracker blocker for **Microsoft Edge** with a built-in **Blocker Telemetry, Heuristic Evasion Sensor, and Automated DNR Rule Synthesizer**.

---

## 🔒 Security & Zero-Leak Guarantees

1. **Browser-Enforced Zero-Outbound-Network CSP**:
   - [`extension/manifest.json`](extension/manifest.json) enforces `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';" }`.
   - The extension **cannot** make outbound `fetch()`, `XMLHttpRequest`, `WebSocket`, or `sendBeacon` calls to any external server.
2. **100% Local Storage (`chrome.storage.local` + SQLite WAL)**:
   - Never uses `chrome.storage.sync` (so your browsing/blocking stats are never uploaded to cloud sync servers).
3. **C++ Network-Layer Blocking (`declarativeNetRequest`)**:
   - Blocks ad networks, RTB auctions, session-replay scripts, and third-party `<a ping>` / `csp_report` beacons before any TCP/TLS socket or cookie header is transmitted.
   - Strips **48+ tracking query parameters** (`utm_*`, `fbclid`, `gclid`, `msclkid`, `twclid`, `ttclid`, `mc_eid`, `igshid`, `_ga`, `_gl`) and removes `Sec-Browsing-Topics`, `X-Client-Data`, `NEL`, and `Report-To` headers inline.

---

## 🔬 Blocker Research, Telemetry & Self-Learning Rule Lab

AegisBlock collects **100% local telemetry** on both **blocked requests** and **unblocked suspect third-party resources** so you can analyze blocker performance and automatically synthesize stronger rules:

- **Real-Time DNR Match Telemetry (`onRuleMatchedDebug`)**:
  - Tracks rule hit counts, blocked domains, resource types (`script`, `xmlhttprequest`, `sub_frame`, `ping`, `image`, `media`), cross-site tracker spread, and most tracker-heavy first-party websites.
- **Heuristic Evasion Sensor (`content.js`)**:
  - Passively inspects unblocked third-party resources using `PerformanceObserver` and DOM iframe scanning (checking standard IAB ad sizes like `300x250`/`728x90`, OpenRTB/Prebid/VAST URL tokens, beacon initiators, and cross-site prevalence).
  - Calculates an explainable **Confidence Score (`0–99%`)** with signal tags (`IAB_AD_IFRAME_300x250`, `AD_SUBDOMAIN_PREFIX`, `URL_ADTECH_ENDPOINT`, `CROSS_SITE_PREVALENCE`).
- **1-Click & Auto-Learn Rule Promotion**:
  - Promote any discovered evasion candidate directly into Chromium's dynamic `declarativeNetRequest` engine from the Popup or the full-page **Research & Analytics Studio (`dashboard.html`)**, or export a telemetry snapshot to compile permanently into the static ruleset via `python3 cli.py ingest`.

---

## 🚀 Loading in Microsoft Edge

1. Run `make` (or `python3 cli.py sync`) to sync the unpacked extension to Windows:
   - **Windows Path**: `C:\Users\oz_co\code\extensions\adblocker`
   - **WSL Path**: `/mnt/c/Users/oz_co/code/extensions/adblocker`
2. Open Microsoft Edge and navigate to `edge://extensions`.
3. Enable **Developer mode** (toggle in the left sidebar).
4. Click **Load unpacked** and select:
   ```text
   C:\Users\oz_co\code\extensions\adblocker
   ```
5. Click the **AegisBlock** shield icon in the toolbar to toggle protection per site, launch the **Element Zapper (`Alt+Shift+Z`)**, or open the **Analytics & Rule Lab**.

---

## 🛠️ CLI Commands (`cli.py`)

```bash
# Compile static DNR rulesets, rule catalog, and SQLite learned rules
python3 cli.py build

# Seed representative multi-site research telemetry & auto-synthesize rules
python3 cli.py simulate-research

# View blocker telemetry & rule coverage stats in the terminal
python3 cli.py stats

# Ingest an exported telemetry JSON snapshot from the browser Research Studio
python3 cli.py ingest path/to/aegisblock-telemetry.json --auto-synthesize --min-confidence 80

# Sync unpacked extension to C:\Users\oz_co\code\extensions\adblocker
python3 cli.py sync

# Run the 6-Gate Pre-Flight QA Validator
python3 cli.py validate
```
