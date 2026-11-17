# 🛡️ NulKast-Block — Zero-Leak Manifest V3 AdBlocker & Telemetry Lab

> [!IMPORTANT]
> **Hobby / Vibe-Coded Project — Provided As-Is With No Support**
> This repository is a personal, vibe-coded hobby experiment for browser privacy hardening, native C++ `declarativeNetRequest` filtering, and local-only blocker research. **No support, warranty, issue tracking, or maintenance is provided.** Use or fork entirely at your own risk.

---

## Overview

**NulKast-Block** (part of the **NulKast** privacy suite alongside `NulKast Wall`, `NulKast Audit`, `NulKast Scrub`, and `NulKast ChromeOS`) is a fast, zero-bloat **Manifest V3** ad, tracker, and anti-adblock wall blocker for **Microsoft Edge** and **Google Chrome** paired with a **100% local Blocker Telemetry, Heuristic Evasion Sensor, False-Positive Breakage Correlator, C++ Surrogate Redirector, and Automated DNR Rule Synthesizer**.

---

## ✨ Key Capabilities

### 1. Native C++ Network-Layer Blocking (`declarativeNetRequest`)
- **4 Modular Static Rulesets (57 Rules / 410+ Ad & Tracker Domains)**:
  - `ads_core.json`: Blocks programmatic RTB exchanges, DoubleClick/AdSense, Amazon AAX, Xandr/AppNexus, Criteo, VAST/VPAID video ad servers, and popunder networks before any TCP/TLS connection or cookie header is sent.
  - `trackers_privacy.json`: Blocks behavioral analytics, session-replay/keystroke recorders (`hotjar`, `fullstory`, `clarity.ms`, `mouseflow`, `logrocket`), device fingerprinting scripts, Adobe DTM (`adobedtm.com`), and all third-party `<a ping>` / `csp_report` beacons while surgically sparing dual-use functional widgets.
  - `url_privacy_clean.json`: Uses Chromium's native C++ `queryTransform.removeParams` to strip **53 tracking & attribution query parameters** (`utm_*`, `fbclid`, `gclid`, `srsltid`, `irclickid`, `cjevent`, `epik`, `rdt_cid`, `sccid`, `msclkid`, `twclid`, `ttclid`, `mc_eid`, `igshid`, `_ga`, `_gl`, etc.) and strips `Sec-Browsing-Topics`, `Sec-Ad-Auction-Fetch`, `X-Client-Data`, `NEL`, and `Report-To` headers inline.
  - `annoyances_social.json`: Blocks native recommendation chumboxes (`taboola`, `outbrain`, `revcontent`, `mgid`), web-push notification nags, and **Anti-Adblock / Visitor Recovery walls** (`getadmiral.com`, `chalkdream.com`, `succeedscene.com`, `fundingchoicesmessages.google.com`, `blockthrough.com`, `pagefair.com`, `adrecover.com`).

### 2. Zero-Latency Local C++ Surrogate Shims (`extension/surrogates/*.js`)
Redirects blocked ad/analytics/anti-adblock SDK script requests to local, inert JavaScript shims at priority `30` so publisher pages and video players never hang or throw `ReferenceError`s:
- `googletag_gpt.js` — Google Publisher Tags (`gpt.js` / `pubads_impl.js`) mock with synthetic `slotRenderEnded` completion events.
- `google_ima3.js` — Google IMA3 Video SDK (`ima3.js`) shim that immediately fires `ALL_ADS_COMPLETED` and `CONTENT_RESUME_REQUESTED`.
- `adsbygoogle.js` — AdSense (`adsbygoogle.js`) stub marking slots as done.
- `google_analytics.js` — `analytics.js` / `gtag/js` stub that immediately invokes `hitCallback` so link navigation never stalls.
- `fbevents.js` — Meta Pixel (`fbevents.js`) no-op shim.
- `anti_adblock_noop.js` — Disarms Admiral (`window.admiral`), Google Funding Choices (`window.googlefc`), and `BlockAdBlock` / `FuckAdBlock`.

### 3. `MAIN`-World Anti-Adblock & Scroll-Lock Defuser (`page_defuser.js` + `content.js`)
- Runs at `document_start` in the page's `MAIN` JavaScript world to trap `window.admiral`, `window.BlockAdBlock`, `window.FuckAdBlock`, `window.canRunAds = true`, and `window.isAdBlockActive = false` before inline or tag-manager scripts can initialize them.
- Intercepts dynamic `<script>` injection (`appendChild` / `insertBefore`) matching Admiral or anti-adblock bootstrapper patterns.
- Automatically removes injected `"Powered by Admiral"` or anti-adblock modal overlays and unlocks `overflow: hidden` / `position: fixed` scroll-locks on `<html>` and `<body>`.

### 4. Passive False-Positive & Leak Detection + Self-Learning Rule Lab
- **False-Positive & Breakage Sensor**: Detects blocked script load errors, missing SDK globals, rapid tab reloads (frustration signal), and site pauses, correlates them with the exact DNR rule ID that fired in that tab, and offers **1-click surgical per-site domain exceptions** (priority `6000`).
- **Heuristic Evasion & First-Party Ad Cloaking Sensor**: Passively scores unblocked third-party resources and first-party cloaked ad paths (`/adserver/`, `/openrtb2/`, `/prebid`, `/vast`) and promotes high-confidence suspects into dynamic or static DNR rules.
- **Interactive Shadow-DOM Element Zapper (`Alt+Shift+Z`)**: Point-and-click visual element blocker isolated inside a closed Shadow DOM root.

### 5. Strict Zero-Outbound-Network Guarantee
- `extension/manifest.json` enforces `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';" }`.
- Uses `chrome.storage.local` exclusively (never `chrome.storage.sync`). Zero telemetry ever leaves your machine.

---

## 🚀 Quick Start (Microsoft Edge & Google Chrome)

### 1. Build, Package & Validate
Requires Python 3.10+ (standard library only) and Node.js (for syntax/runtime tests):
```bash
make
```

### 2. Load Unpacked Extension (Developer Mode)
1. Open `edge://extensions` (Microsoft Edge) or `chrome://extensions` (Google Chrome).
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder (or your synced Windows unpacked directory).
4. Click the **NulKast-Block** shield icon in the toolbar to view live blocked/surrogate/false-positive counters, launch the **Element Zapper (`Alt+Shift+Z`)**, or open the full-page **Research & Analytics Studio**.

### 3. Build a Store-Ready `.zip` (Chrome Web Store / Edge Add-ons)
```bash
make package-store
```
Produces `dist/nulkast-block-store-v1.0.0.zip` (with `manifest.json` at the archive root and unpacked-only `declarativeNetRequestFeedback` automatically stripped) alongside `dist/STORE_SUBMISSION_GUIDE.md` containing copy-paste permission justifications.

---

## 🛠️ CLI Reference (`cli.py`)

```bash
# Compile static DNR rulesets, rule catalog, icons, and SQLite learned rules
python3 cli.py build

# Seed benchmark multi-site telemetry into SQLite and synthesize rules
python3 cli.py simulate-research

# View blocker telemetry, surrogate counts, and heuristic candidates
python3 cli.py stats

# Ingest an exported browser telemetry JSON snapshot and auto-synthesize rules (>=80% confidence)
python3 cli.py ingest path/to/nulkast-block-telemetry.json --auto-synthesize --min-confidence 80

# Sync unpacked extension to target directory (or set NULKAST_BLOCK_WIN_DIR=/path/to/dir)
python3 cli.py sync

# Build Chrome Web Store & Microsoft Edge Add-ons .zip archive + submission guide
python3 cli.py package-store

# Run the deterministic 6-Gate Pre-Flight QA Validator
python3 cli.py validate

# Run the automated Python + Node.js MV3 test suite
make test
```

---

## 📂 Project Structure

```text
NulKast-Block/
├── cli.py                           # Research DB, DNR rule synthesizer, Store Packager & 6-Gate QA CLI
├── Makefile                         # Build, sync, package-store, validate, and test targets
├── scripts/
│   └── build_rules.py               # Static DNR ruleset compiler, Chromium urlFilter validator & PNG generator
├── extension/                       # Complete Manifest V3 unpacked browser extension
│   ├── manifest.json                # MV3 configuration with strict connect-src 'self' CSP
│   ├── background.js                # Event-driven Service Worker (DNR telemetry, false-positive correlator)
│   ├── page_defuser.js              # MAIN-world document_start anti-adblock & Admiral defuser
│   ├── content.js                   # Cosmetic filter, modal killer, scroll unlocker, heuristic sensor & Zapper
│   ├── content.css                  # Pre-paint ad hiding & scroll-unlock stylesheet
│   ├── popup.html / popup.js        # Toolbar control deck
│   ├── dashboard.html / dashboard.js# Full-page Research & Analytics Studio
│   ├── surrogates/                  # Local zero-latency C++ DNR redirect shims
│   ├── rules/                       # Compiled static DNR JSON rulesets & rule_catalog.json
│   └── icons/                       # Generated RGBA PNG shield icons (16, 32, 48, 128)
└── tests/
    └── test_adblocker.py            # Automated unit + Node.js MV3 Service Worker simulation suite
```
