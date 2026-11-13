---
name: edge-adblocker-telemetry-lab
description: Use this skill when building, updating, auditing, or analyzing the AegisBlock Microsoft Edge Manifest V3 AdBlocker & Self-Learning Telemetry Lab in /home/user/code/extensions/adblocker (synced to C:\Users\oz_co\code\extensions\adblocker), including static & dynamic declarativeNetRequest rulesets, URL tracking parameter & header sanitizers, cosmetic DOM/video ad guards, Shadow-DOM Element Zapper, heuristic evasion discovery, and SQLite rule synthesis via cli.py.
version: "1.2.0"
last_updated: "2026-11-13"
target_modules:
  - "cli.py"
  - "scripts/build_rules.py"
  - "extension/manifest.json"
  - "extension/background.js"
  - "extension/content.js"
  - "extension/content.css"
  - "extension/page_defuser.js"
  - "extension/popup.html"
  - "extension/popup.js"
  - "extension/dashboard.html"
  - "extension/dashboard.js"
  - "extension/surrogates/googletag_gpt.js"
  - "extension/surrogates/google_ima3.js"
  - "extension/surrogates/adsbygoogle.js"
  - "extension/surrogates/google_analytics.js"
  - "extension/surrogates/fbevents.js"
  - "extension/surrogates/anti_adblock_noop.js"
  - "tests/test_adblocker.py"
---

# Edge AdBlocker & Self-Learning Telemetry Lab (`edge-adblocker-telemetry-lab`)

## Overview

`AegisBlock` (`/home/user/code/extensions/adblocker`) is a zero-leak **Manifest V3** ad and tracker blocker for **Microsoft Edge** paired with a **100% local Blocker Telemetry, Heuristic Evasion Sensor, False-Positive Breakage Correlator, C++ Surrogate Shim Redirector, and Automated DNR Rule Synthesizer**.

- **WSL Source Path**: `/home/user/code/extensions/adblocker`
- **Windows Unpacked Extension Path**: `C:\Users\oz_co\code\extensions\adblocker` (`/mnt/c/Users/oz_co/code/extensions/adblocker`)
- **SQLite WAL Research DB**: `/home/user/code/extensions/adblocker/data/adblock_research.db`

---

## Core Architecture & Security Guardrails

1. **Zero-Outbound-Network CSP (`connect-src 'self'`)**:
   - [`extension/manifest.json`](file:///home/user/code/extensions/adblocker/extension/manifest.json) enforces `connect-src 'self'` and `object-src 'none'`. No extension page or service worker can transmit telemetry externally.
   - Uses `chrome.storage.local` exclusively (never `chrome.storage.sync`).
2. **4 Static `declarativeNetRequest` Rulesets + Local C++ Surrogate Redirects + Dynamic Rule Pool**:
   - `ads_core` (`rules/ads_core.json`): High-efficiency `requestDomains` + `urlFilter` rules for ad networks, RTB auctions, VAST/IMA video ads, popunders, and learned SQLite domains (Rule `#1900`), plus priority-30 `redirect.extensionPath` surrogates for Google Publisher Tags (`googletag_gpt.js`), IMA3 Video SDK (`google_ima3.js`), and AdSense (`adsbygoogle.js`).
   - `trackers_privacy` (`rules/trackers_privacy.json`): Cross-site trackers, session replay (`hotjar`, `clarity.ms`, `fullstory`), fingerprinting scripts, third-party `ping`/`csp_report` beacons, surgical rules sparing dual-use functional domains (`intercom.io`, `hubspot.com`, `t.co`, `sc-static.net`, `sentry-cdn.com`), and priority-30 local surrogates for `analytics.js`/`gtag/js` (`google_analytics.js`) and `fbevents.js`.
   - `url_privacy_clean` (`rules/url_privacy_clean.json`): Native C++ `redirect.transform.queryTransform.removeParams` stripping 53 tracking parameters (`utm_*`, `fbclid`, `gclid`, `srsltid`, `irclickid`, `cjevent`, `epik`, `rdt_cid`, `sccid`, `msclkid`, `twclid`, `mc_eid`, etc.) + `modifyHeaders` removing `Sec-Browsing-Topics`, `X-Client-Data`, `NEL`, and `Report-To`.
   - `annoyances_social` (`rules/annoyances_social.json`): Sponsored chumboxes (`taboola`, `outbrain`, `revcontent`, `mgid`), marketing push popups, and Anti-Adblock / Visitor Recovery walls (`getadmiral.com`, `chalkdream.com`, `succeedscene.com`, `fundingchoicesmessages.google.com`, `blockthrough.com`, `pagefair.com`, `adrecover.com`) + priority-30 surrogate redirects (`anti_adblock_noop.js`) for Adobe Launch / Admiral bootstrapper scripts (`RCe0c7c73598674c2288fae1d365c8dd9d`, `/admiral*.js`, `/fuckadblock`, `/blockadblock`).
3. **Pre-Paint Cosmetic Filter, MAIN-World Anti-Adblock Defuser, Scroll-Lock Unlocker & Element Zapper**:
   - [`extension/page_defuser.js`](file:///home/user/code/extensions/adblocker/extension/page_defuser.js) runs at `document_start` in the page's `MAIN` JS world to trap `window.admiral`, `window.BlockAdBlock`, `window.FuckAdBlock`, `window.canRunAds = true`, and `window.isAdBlockActive = false`, and intercepts dynamic `<script>` injection (`appendChild`/`insertBefore`) for Admiral/anti-adblock script URLs before they execute.
   - [`extension/content.css`](file:///home/user/code/extensions/adblocker/extension/content.css) scopes all rules under `:root:not([data-aegisblock-paused="true"])` (including `.fc-ab-root`, `[class^="admiral-"]`, `[class*="fEy1Z2XT"]`, and `[data-aegis-scroll-unlocked="true"]` scroll-unlock overrides) so per-site pause disarms cosmetic hiding immediately without page reload.
   - [`extension/content.js`](file:///home/user/code/extensions/adblocker/extension/content.js) includes `neutralizeAntiAdblockWallsAndUnlockScroll()` (automatically removing `"Powered by Admiral"` / anti-adblock modals and unlocking `overflow: hidden` / `position: fixed` scroll locks on `<html>` and `<body>`), an interactive Shadow-DOM **Element Zapper** (`Alt+Shift+Z`), and automatic video pre-roll skip/fast-forward guard.
4. **Heuristic Evasion, First-Party Cloaking & False-Positive Breakage Sensors**:
   - Passively inspects unblocked third-party resources and first-party cloaked ad endpoints (`FIRST_PARTY_CLOAKED_AD`) via `PerformanceObserver`, DOM iframe scanning (IAB standard ad dimensions `300x250`/`728x90`), and visible filled ad-slot leak detection (`REPORT_VISUAL_AD_LEAK`).
   - Passively detects page breakage (`SCRIPT_LOAD_BLOCKED`, `MISSING_SDK_GLOBAL`, `ANTI_ADBLOCK_WALL_DETECTED`, `RAPID_TAB_RELOAD`, and `USER_PAUSED_SITE`), correlates the failure with the exact DNR rule ID that fired on that tab, and enables 1-click surgical per-site domain exceptions (`ALLOW_DOMAIN_ON_SITE`, priority `6000`).

---

## Standard Workflows (`Makefile` & `cli.py`)

```bash
# Full build, research simulation, Windows unpacked sync, and 6-Gate QA validation
make

# Compile static DNR rulesets, icons, and merge SQLite learned rules
python3 cli.py build

# Ingest an exported browser telemetry JSON snapshot and auto-synthesize rules (>=80% confidence)
python3 cli.py ingest path/to/aegisblock-telemetry.json --auto-synthesize --min-confidence 80

# Inspect blocker telemetry & heuristic evasion candidates in SQLite
python3 cli.py stats

# Sync unpacked extension to C:\Users\oz_co\code\extensions\adblocker
python3 cli.py sync

# Run the deterministic 6-Gate Pre-Flight QA Validator
python3 cli.py validate

# Run the automated Python + Node.js MV3 test suite
make test
```
