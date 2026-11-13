/**
 * AegisBlock — Content Script (ISOLATED World)
 * 1. Pre-paint & Dynamic Cosmetic Filtering + Video Ad Skipper
 * 2. Heuristic Evasion Sensor (discovers unblocked 3rd-party ads/trackers for Research Lab)
 * 3. Shadow-DOM Interactive Element Zapper (Alt+Shift+Z or triggered from Popup)
 */

(() => {
  if (window.__aegisBlockContentLoaded) return;
  window.__aegisBlockContentLoaded = true;

  const CURRENT_HOST = (location.hostname || "").toLowerCase().replace(/^www\./, "");
  if (!CURRENT_HOST || location.protocol === "chrome-extension:" || location.protocol === "edge:") {
    return;
  }

  let isSitePaused = false;
  let customSelectors = [];
  const countedCosmeticNodes = new WeakSet();
  const inspectedResourceUrls = new Set();
  const inspectedIframes = new WeakSet();

  // Standard IAB Ad Unit Dimensions (width x height)
  const IAB_AD_SIZES = new Set([
    "300x250", // Medium Rectangle
    "336x280", // Large Rectangle
    "728x90",  // Leaderboard
    "970x90",  // Large Leaderboard
    "970x250", // Billboard
    "160x600", // Wide Skyscraper
    "120x600", // Skyscraper
    "300x600", // Half Page
    "300x1050",// Portrait
    "320x50",  // Mobile Leaderboard
    "320x100", // Large Mobile Banner
    "468x60",  // Full Banner
    "234x60",  // Half Banner
    "250x250", // Square
    "200x200"  // Small Square
  ]);

  const BUILTIN_COSMETIC_SELECTORS = [
    "ins.adsbygoogle",
    '[id^="google_ads_iframe_"]',
    '[id^="div-gpt-ad-"]',
    "[data-google-query-id]",
    "[data-ad-client]",
    "[data-ad-slot]",
    "[data-ad-unit]",
    'iframe[src*="doubleclick.net"]',
    'iframe[src*="googlesyndication.com"]',
    'iframe[src*="amazon-adsystem.com"]',
    'iframe[src*="adnxs.com"]',
    'iframe[src*="rubiconproject.com"]',
    'iframe[src*="criteo.com"]',
    ".taboola-widget",
    '[id^="taboola-"]',
    ".OUTBRAIN",
    '[data-widget-id^="outbrain"]',
    ".ad-leaderboard",
    ".ad-billboard",
    ".ad-slot-container",
    ".dfp-ad-unit",
    ".sponsored-banner",
    '[aria-label="Advertisement"]',
    "ytd-ad-slot-renderer",
    "ytd-in-feed-ad-layout-renderer",
    "ytd-promoted-sparkles-web-renderer",
    "ytd-display-ad-renderer",
    "#masthead-ad",
    "#player-ads"
  ];

  function extractBaseDomain(hostname) {
    const clean = (hostname || "").toLowerCase().replace(/^www\./, "");
    const parts = clean.split(".");
    if (parts.length <= 2) return clean;
    const twoPartTlds = new Set(["co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in"]);
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  const FIRST_PARTY_BASE = extractBaseDomain(CURRENT_HOST);

  function isThirdPartyHost(targetHost) {
    if (!targetHost) return false;
    const targetBase = extractBaseDomain(targetHost);
    return targetBase !== "" && targetBase !== FIRST_PARTY_BASE;
  }

  function applyPauseState(paused) {
    isSitePaused = Boolean(paused);
    const root = document.documentElement;
    if (!root) return;
    if (isSitePaused) {
      root.setAttribute("data-aegisblock-paused", "true");
    } else {
      root.removeAttribute("data-aegisblock-paused");
    }
  }

  function applyCustomSelectors(selectors) {
    customSelectors = Array.isArray(selectors) ? selectors : [];
    let styleEl = document.getElementById("aegisblock-custom-cosmetics");
    if (customSelectors.length === 0) {
      if (styleEl) styleEl.remove();
      return;
    }
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = "aegisblock-custom-cosmetics";
      (document.head || document.documentElement).appendChild(styleEl);
    }
    const rules = customSelectors
      .map((sel) => `:root:not([data-aegisblock-paused="true"]) ${sel}`)
      .join(",\n");
    styleEl.textContent = `${rules} { display: none !important; visibility: hidden !important; height: 0 !important; min-height: 0 !important; margin: 0 !important; padding: 0 !important; pointer-events: none !important; }`;
  }

  // ============================================================================
  // 1. Cosmetic DOM Scanner & Video Ad Guard
  // ============================================================================
  let pendingCosmeticBatch = [];
  let cosmeticFlushTimer = null;

  function queueCosmeticTelemetry(selector, tagName) {
    pendingCosmeticBatch.push({ selector, tagName, ts: Date.now() });
    if (!cosmeticFlushTimer) {
      cosmeticFlushTimer = setTimeout(() => {
        const batch = pendingCosmeticBatch.splice(0, pendingCosmeticBatch.length);
        cosmeticFlushTimer = null;
        if (batch.length > 0 && !isSitePaused) {
          chrome.runtime.sendMessage({
            type: "REPORT_COSMETIC_TELEMETRY",
            site: CURRENT_HOST,
            count: batch.length,
            samples: batch.slice(0, 10)
          }).catch(() => {});
        }
      }, 900);
    }
  }

  function scanCosmeticElements() {
    if (isSitePaused || !document.body) return;
    const allSelectors = [...BUILTIN_COSMETIC_SELECTORS, ...customSelectors];
    for (const sel of allSelectors) {
      try {
        const nodes = document.querySelectorAll(sel);
        for (const node of nodes) {
          if (!countedCosmeticNodes.has(node)) {
            countedCosmeticNodes.add(node);
            node.setAttribute("data-aegis-hidden", "true");
            queueCosmeticTelemetry(sel, (node.tagName || "DIV").toLowerCase());
          }
        }
      } catch (_) {
        // Ignore invalid user selector
      }
    }
  }

  let lastVideoSkipTs = 0;
  function guardVideoAds() {
    if (isSitePaused || !document.body) return;

    // Click known video ad skip buttons automatically
    const skipSelectors = [
      ".ytp-ad-skip-button",
      ".ytp-ad-skip-button-modern",
      ".ytp-skip-ad-button",
      ".videoAdUiSkipButton",
      '[class*="ad-skip-button"]'
    ];
    for (const sel of skipSelectors) {
      const btn = document.querySelector(sel);
      if (btn && typeof btn.click === "function") {
        btn.click();
        if (Date.now() - lastVideoSkipTs > 2500) {
          lastVideoSkipTs = Date.now();
          chrome.runtime.sendMessage({
            type: "REPORT_VIDEO_AD_MITIGATED",
            site: CURRENT_HOST,
            method: `Auto-Skip (${sel})`
          }).catch(() => {});
        }
      }
    }

    // Fast-forward active pre-roll/mid-roll video ad container (.ad-showing video)
    const adPlayer = document.querySelector(".ad-showing video, .ima-ad-container video");
    if (adPlayer && Number.isFinite(adPlayer.duration) && adPlayer.duration > 0.5) {
      if (adPlayer.currentTime < adPlayer.duration - 0.2) {
        adPlayer.muted = true;
        adPlayer.playbackRate = 16.0;
        adPlayer.currentTime = Math.max(0, adPlayer.duration - 0.1);
        if (Date.now() - lastVideoSkipTs > 2500) {
          lastVideoSkipTs = Date.now();
          chrome.runtime.sendMessage({
            type: "REPORT_VIDEO_AD_MITIGATED",
            site: CURRENT_HOST,
            method: "Pre-Roll Fast-Forward"
          }).catch(() => {});
        }
      }
    }
  }

  // ============================================================================
  // 2. Heuristic Evasion Sensor (Finds Unblocked 3rd-Party & Cloaked 1st-Party Ads)
  // ============================================================================
  const inspectedLeakNodes = new WeakSet();
  let breakageReportsSent = 0;
  let antiAdblockWallReported = false;

  function evaluateResourceHeuristics(urlStr, initiatorType) {
    if (!urlStr || inspectedResourceUrls.has(urlStr)) return null;
    if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) return null;
    inspectedResourceUrls.add(urlStr);

    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (_) {
      return null;
    }

    const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
    const thirdParty = isThirdPartyHost(host);
    const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();

    // First-party resources are only flagged if they hit unmistakable ad-cloaking / auction endpoints
    if (!thirdParty) {
      const hasCloakedAdPath =
        /\/(openrtb2?|prebid|hb_bidder|vast\.xml|vpaid|pagead\/|adserver\/|adframe|ad_delivery\/|bidrequest)\b/i.test(
          pathAndQuery
        );
      const hasCloakedAdQuery = /(gdpr_consent=|us_privacy=|gpp_sid=|ad_unit=|adslot=|bidid=)/i.test(
        parsed.search
      );
      if (hasCloakedAdPath && (hasCloakedAdQuery || host !== CURRENT_HOST)) {
        return {
          candidateHost: host,
          baseDomain: extractBaseDomain(host),
          sampleUrl: urlStr.slice(0, 260),
          initiatorSite: CURRENT_HOST,
          resourceType: initiatorType || "xmlhttprequest",
          confidence: 82,
          category: "First-Party Cloaked Ad / RTB",
          signals: ["FIRST_PARTY_CLOAKED_AD", "URL_ADTECH_ENDPOINT"]
        };
      }
      return null;
    }

    let score = 0;
    const signals = [];

    // Signal 1: Subdomain naming conventions used by ad/telemetry servers
    if (/^(ads?|adserv(er|ice)?|banners?|bid(der)?|pop(s|under)?|sponsor|vast|ima)\./i.test(host)) {
      score += 42;
      signals.push("AD_SUBDOMAIN_PREFIX");
    } else if (/^(trk|track(er|ing)?|telemetry|pixel|beacon|metrics|collect|analytics|stat(s)?|log(s|ger)?)\./i.test(host)) {
      score += 36;
      signals.push("TRACKER_SUBDOMAIN_PREFIX");
    }

    // Signal 2: Hostname lexical tokens
    if (/(adsystem|adserver|adnetwork|adexchange|doubleclick|bidswitch|pubmatic|rubicon|criteo|taboola|outbrain|adnxs|popads|exoclick)/i.test(host)) {
      score += 40;
      signals.push("KNOWN_ADTECH_LEXEME");
    }

    // Signal 3: High-signal URL path tokens for ad delivery / header bidding / VAST
    if (/\/(adserver|pagead|prebid|hb_bidder|openrtb|bidrequest|vast|vpaid|adframe|adbanner|popunder|ad_data|sponsored|adunit)\b/i.test(pathAndQuery)) {
      score += 38;
      signals.push("URL_ADTECH_ENDPOINT");
    }

    // Signal 4: High-signal URL path tokens for tracking pixels, ID syncing & fingerprinting
    if (/\/(pixel(\.gif|\.png)?|beacon|telemetry|fingerprint|id-sync|usersync|cookie_sync|collect|event_track|click_track)\b/i.test(pathAndQuery)) {
      score += 32;
      signals.push("URL_TRACKER_ENDPOINT");
    }

    // Signal 5: Ad-tech & consent/privacy query string fingerprints
    if (/(gdpr_consent=|us_privacy=|gpp_sid=|ad_unit=|adslot=|bidid=|imp_id=|clickid=|fbclid=|gclid=)/i.test(parsed.search)) {
      score += 28;
      signals.push("ADTECH_QUERY_PARAMS");
    }

    // Signal 6: Beacon / Ping initiator or 1x1 pixel query signature
    if (initiatorType === "beacon" || initiatorType === "ping") {
      score += 24;
      signals.push(`INITIATOR_${initiatorType.toUpperCase()}`);
    }

    // Signal 7: High query parameter count (common in tracking beacons & bid requests)
    const paramCount = Array.from(parsed.searchParams.keys()).length;
    if (paramCount >= 8) {
      score += 14;
      signals.push(`HIGH_PARAM_DENSITY(${paramCount})`);
    }

    if (score < 45) return null;

    const category = signals.some((s) => s.includes("AD"))
      ? "Suspect Ad Server"
      : "Suspect Tracker / Beacon";

    return {
      candidateHost: host,
      baseDomain: extractBaseDomain(host),
      sampleUrl: urlStr.slice(0, 260),
      initiatorSite: CURRENT_HOST,
      resourceType: initiatorType || "other",
      confidence: Math.min(99, score),
      category,
      signals
    };
  }

  function scanVisualAdLeaksAndAntiAdblock() {
    if (isSitePaused || !document.body) return;

    // 1. Check for visible uncollapsed ad containers that slipped past cosmetic CSS
    const leakSelectors = [
      'ins.adsbygoogle[data-ad-status="filled"]',
      '[data-ad-rendered="true"]',
      '[data-testid*="sponsored-ad" i]',
      '[aria-label="SponsoredAd"]'
    ];
    for (const sel of leakSelectors) {
      const nodes = document.querySelectorAll(sel);
      for (const node of nodes) {
        if (inspectedLeakNodes.has(node) || node.hasAttribute("data-aegis-hidden")) continue;
        const rect = node.getBoundingClientRect();
        if (rect.width >= 120 && rect.height >= 45) {
          inspectedLeakNodes.add(node);
          node.setAttribute("data-aegis-hidden", "true");
          node.style.setProperty("display", "none", "important");
          chrome.runtime.sendMessage({
            type: "REPORT_VISUAL_AD_LEAK",
            site: CURRENT_HOST,
            selector: sel,
            dimensions: `${Math.round(rect.width)}x${Math.round(rect.height)}`
          }).catch(() => {});
        }
      }
    }

    // 2. Detect & Actively Strip Anti-Adblock Walls (Admiral "Powered by Admiral", Funding Choices, etc.) + Unlock Scroll
    neutralizeAntiAdblockWallsAndUnlockScroll();
  }

  function unlockPageScroll() {
    for (const rootEl of [document.documentElement, document.body]) {
      if (!rootEl) continue;
      rootEl.setAttribute("data-aegis-scroll-unlocked", "true");
      rootEl.style.setProperty("overflow", "auto", "important");
      rootEl.style.setProperty("overflow-y", "auto", "important");
      rootEl.style.setProperty("position", "static", "important");
      rootEl.style.setProperty("pointer-events", "auto", "important");
      rootEl.classList.remove("fc-ab-root", "modal-open", "no-scroll", "noscroll", "overflow-hidden");
    }
  }

  function findTopModalBackdrop(node) {
    let curr = node;
    let bestCandidate = node;
    while (curr && curr !== document.body && curr !== document.documentElement) {
      const tag = (curr.tagName || "").toLowerCase();
      if (tag === "overlay-base" || curr.classList?.contains("fc-ab-root") || curr.classList?.contains("fc-whitelist-root")) {
        return curr;
      }
      try {
        const st = window.getComputedStyle(curr);
        const z = parseInt(st.zIndex, 10);
        if (st.position === "fixed" || (Number.isFinite(z) && z >= 999)) {
          bestCandidate = curr;
        }
      } catch (_) {}
      if (curr.parentElement === document.body) {
        try {
          const st = window.getComputedStyle(curr);
          if (st.position === "fixed" || st.position === "absolute" || parseInt(st.zIndex, 10) >= 100) {
            bestCandidate = curr;
          }
        } catch (_) {}
        break;
      }
      curr = curr.parentElement;
    }
    return bestCandidate;
  }

  function neutralizeAntiAdblockWallsAndUnlockScroll() {
    if (isSitePaused || !document.body) return;

    // A. Fast selector match for known Admiral / Funding Choices / anti-adblock containers
    const knownWallNodes = document.querySelectorAll(
      '.fc-ab-root, .fc-whitelist-root, .fc-dialog-overlay, [class^="admiral-"], [id^="admiral-"], [class*="fEy1Z2XT"], a[href*="getadmiral.com"], img[src*="getadmiral.com"]'
    );
    let wallNeutralized = false;
    let wallDetail = "";

    for (const node of knownWallNodes) {
      const modalRoot = findTopModalBackdrop(node);
      if (modalRoot && modalRoot !== document.body && modalRoot !== document.documentElement) {
        wallDetail = synthesizeCssSelector(modalRoot) || "admiral-or-fc-modal";
        modalRoot.setAttribute("data-aegis-hidden", "true");
        modalRoot.style.setProperty("display", "none", "important");
        try {
          modalRoot.remove();
        } catch (_) {}
        wallNeutralized = true;
      }
    }

    // B. Text & Fixed-Overlay heuristic scan for dynamically obfuscated Admiral / anti-adblock modals
    const candidateModals = document.querySelectorAll(
      '[id*="adblock" i], [class*="adblock" i], [role="dialog"], [aria-modal="true"], body > div, overlay-base'
    );
    for (const el of candidateModals) {
      if (!el || el === zapperHost || el.hasAttribute("data-aegis-hidden")) continue;
      const txt = (el.textContent || "").slice(0, 900);
      if (!txt) continue;

      const isAdmiralOrWallText =
        /powered by admiral|getadmiral\.com|disable your ad\s*blocker|ad\s*blocker detected|whitelist (this site|us)|turn off your ad\s*blocker|allow ads on|continue without disabling/i.test(
          txt
        );
      if (!isAdmiralOrWallText) continue;

      const rect = el.getBoundingClientRect();
      let isOverlay = rect.width >= 200 && rect.height >= 80;
      try {
        const st = window.getComputedStyle(el);
        if (st.position === "fixed" || parseInt(st.zIndex, 10) >= 100) {
          isOverlay = true;
        }
      } catch (_) {}

      if (isOverlay) {
        const modalRoot = findTopModalBackdrop(el);
        wallDetail = synthesizeCssSelector(modalRoot) || "anti-adblock-modal";
        modalRoot.setAttribute("data-aegis-hidden", "true");
        modalRoot.style.setProperty("display", "none", "important");
        try {
          modalRoot.remove();
        } catch (_) {}
        wallNeutralized = true;
      }
    }

    if (wallNeutralized) {
      unlockPageScroll();
      if (!antiAdblockWallReported) {
        antiAdblockWallReported = true;
        chrome.runtime.sendMessage({
          type: "REPORT_BREAKAGE_DIAGNOSTIC",
          site: CURRENT_HOST,
          reason: "ANTI_ADBLOCK_WALL_NEUTRALIZED",
          detail: wallDetail
        }).catch(() => {});
      }
    }
  }

  function initBreakageDiagnosticListener() {
    window.addEventListener(
      "error",
      (evt) => {
        if (isSitePaused || breakageReportsSent >= 3) return;

        // Case A: Blocked <script src="..."> element load failure on page
        const target = evt && evt.target;
        if (target && target.tagName === "SCRIPT" && target.src) {
          try {
            const parsed = new URL(target.src, location.href);
            const failedHost = parsed.hostname.toLowerCase().replace(/^www\./, "");
            if (failedHost && isThirdPartyHost(failedHost)) {
              breakageReportsSent += 1;
              chrome.runtime.sendMessage({
                type: "REPORT_BREAKAGE_DIAGNOSTIC",
                site: CURRENT_HOST,
                reason: "SCRIPT_LOAD_BLOCKED",
                failedHost,
                detail: parsed.href.slice(0, 180)
              }).catch(() => {});
            }
          } catch (_) {}
          return;
        }

        // Case B: Unhandled ReferenceError referencing missing SDK globals
        const msg = String((evt && evt.message) || "");
        const sdkMatch = msg.match(
          /\b(googletag|google|fbq|_fbq|ga|gtag|Intercom|hbspt|Sentry|optimizely)\b is not defined/i
        );
        if (sdkMatch) {
          breakageReportsSent += 1;
          chrome.runtime.sendMessage({
            type: "REPORT_BREAKAGE_DIAGNOSTIC",
            site: CURRENT_HOST,
            reason: `MISSING_SDK_GLOBAL(${sdkMatch[1]})`,
            detail: msg.slice(0, 160)
          }).catch(() => {});
        }
      },
      true
    );
  }

  function scanThirdPartyIframes() {
    if (isSitePaused || !document.body) return;
    const iframes = document.querySelectorAll("iframe[src]");
    for (const frame of iframes) {
      if (inspectedIframes.has(frame)) continue;
      inspectedIframes.add(frame);

      const src = frame.getAttribute("src") || "";
      let parsed;
      try {
        parsed = new URL(src, location.href);
      } catch (_) {
        continue;
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") continue;
      const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
      if (!isThirdPartyHost(host)) continue;

      const rect = frame.getBoundingClientRect();
      const w = Math.round(rect.width || parseInt(frame.getAttribute("width") || "0", 10));
      const h = Math.round(rect.height || parseInt(frame.getAttribute("height") || "0", 10));
      const dimKey = `${w}x${h}`;

      const signals = [];
      let score = 0;

      if (IAB_AD_SIZES.has(dimKey)) {
        score += 52;
        signals.push(`IAB_AD_IFRAME_${dimKey}`);
      }
      if (/^(ads?|adserv|banner|bid|pop|trc)\./i.test(host) || /(ad|banner|sponsor|promo|dfp|gpt)/i.test(frame.id + " " + frame.className)) {
        score += 30;
        signals.push("AD_IFRAME_ATTR_MATCH");
      }

      if (score >= 48) {
        chrome.runtime.sendMessage({
          type: "REPORT_HEURISTIC_SUSPECT",
          suspect: {
            candidateHost: host,
            baseDomain: extractBaseDomain(host),
            sampleUrl: parsed.href.slice(0, 260),
            initiatorSite: CURRENT_HOST,
            resourceType: "sub_frame",
            confidence: Math.min(99, score),
            category: "Suspect Ad Iframe",
            signals
          }
        }).catch(() => {});
      }
    }
  }

  function initResourceHeuristicObserver() {
    if (typeof PerformanceObserver === "undefined") return;
    try {
      const processEntries = (entries) => {
        if (isSitePaused) return;
        for (const entry of entries) {
          const suspect = evaluateResourceHeuristics(entry.name, entry.initiatorType || "other");
          if (suspect) {
            chrome.runtime.sendMessage({
              type: "REPORT_HEURISTIC_SUSPECT",
              suspect
            }).catch(() => {});
          }
        }
      };

      const existing = performance.getEntriesByType("resource") || [];
      processEntries(existing);

      const perfObs = new PerformanceObserver((list) => {
        processEntries(list.getEntries());
      });
      perfObs.observe({ type: "resource", buffered: true });
    } catch (_) {
      // Ignore if restricted by page policy
    }
  }

  // ============================================================================
  // 3. Interactive Shadow-DOM Element Zapper (Alt+Shift+Z or Popup Trigger)
  // ============================================================================
  let zapperActive = false;
  let zapperHost = null;
  let zapperBox = null;
  let zapperLabel = null;
  let hoveredTarget = null;

  function synthesizeCssSelector(el) {
    if (!el || el === document.body || el === document.documentElement) return null;
    if (el.id && /^[a-zA-Z][\w-]{1,64}$/.test(el.id)) {
      return `#${CSS.escape(el.id)}`;
    }
    for (const attr of ["data-ad-slot", "data-ad-unit", "data-ad-client", "data-testid", "aria-label"]) {
      const val = el.getAttribute(attr);
      if (val && val.length < 60) {
        return `${el.tagName.toLowerCase()}[${attr}="${CSS.escape(val)}"]`;
      }
    }
    const classes = Array.from(el.classList || [])
      .filter((c) => c && c.length < 42 && !/^(active|open|show|hidden|flex|grid|block|relative|absolute)$/.test(c))
      .slice(0, 3);
    if (classes.length > 0) {
      return `${el.tagName.toLowerCase()}.${classes.map((c) => CSS.escape(c)).join(".")}`;
    }
    // Fallback to parent + nth-of-type
    const parent = el.parentElement;
    if (parent && parent !== document.body) {
      const siblings = Array.from(parent.children).filter((c) => c.tagName === el.tagName);
      const idx = siblings.indexOf(el) + 1;
      const parentSel = synthesizeCssSelector(parent);
      if (parentSel) {
        return `${parentSel} > ${el.tagName.toLowerCase()}:nth-of-type(${idx})`;
      }
    }
    return el.tagName.toLowerCase();
  }

  function startElementZapper() {
    if (zapperActive) {
      stopElementZapper();
      return;
    }
    zapperActive = true;

    zapperHost = document.createElement("div");
    zapperHost.id = "aegisblock-zapper-host";
    zapperHost.style.cssText = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
    const shadow = zapperHost.attachShadow({ mode: "closed" });

    const wrapper = document.createElement("div");
    wrapper.innerHTML = `
      <style>
        .hud {
          position: fixed;
          top: 16px;
          left: 50%;
          transform: translateX(-50%);
          background: rgba(9, 13, 22, 0.94);
          border: 1px solid #38bdf8;
          color: #f8fafc;
          font-family: system-ui, -apple-system, sans-serif;
          font-size: 13px;
          padding: 10px 16px;
          border-radius: 10px;
          box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55);
          display: flex;
          align-items: center;
          gap: 12px;
          pointer-events: auto;
        }
        .badge {
          background: #10b981;
          color: #052e16;
          font-weight: 700;
          font-size: 11px;
          padding: 2px 8px;
          border-radius: 999px;
          text-transform: uppercase;
        }
        .selector-pill {
          font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
          font-size: 12px;
          color: #38bdf8;
          background: rgba(56, 189, 248, 0.12);
          padding: 3px 8px;
          border-radius: 6px;
          max-width: 340px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .btn-cancel {
          background: rgba(239, 68, 68, 0.18);
          color: #fca5a5;
          border: 1px solid rgba(239, 68, 68, 0.45);
          border-radius: 6px;
          padding: 4px 10px;
          font-size: 12px;
          cursor: pointer;
        }
        .highlight-box {
          position: fixed;
          border: 2px solid #10b981;
          background: rgba(16, 185, 129, 0.18);
          border-radius: 4px;
          pointer-events: none;
          transition: all 0.05s ease-out;
          display: none;
        }
      </style>
      <div class="hud">
        <span class="badge">Element Zapper</span>
        <span>Hover an ad or annoyance &amp; <b>Click</b> to block permanently</span>
        <span class="selector-pill" id="zapper-sel">Move cursor...</span>
        <button class="btn-cancel" id="zapper-close">Esc / Cancel</button>
      </div>
      <div class="highlight-box" id="zapper-box"></div>
    `;
    shadow.appendChild(wrapper);
    document.documentElement.appendChild(zapperHost);

    zapperBox = shadow.getElementById("zapper-box");
    zapperLabel = shadow.getElementById("zapper-sel");
    shadow.getElementById("zapper-close").addEventListener("click", (e) => {
      e.stopPropagation();
      stopElementZapper();
    });

    window.addEventListener("mousemove", onZapperMouseMove, true);
    window.addEventListener("click", onZapperClick, true);
    window.addEventListener("keydown", onZapperKeyDown, true);
  }

  function stopElementZapper() {
    zapperActive = false;
    hoveredTarget = null;
    window.removeEventListener("mousemove", onZapperMouseMove, true);
    window.removeEventListener("click", onZapperClick, true);
    window.removeEventListener("keydown", onZapperKeyDown, true);
    if (zapperHost) {
      zapperHost.remove();
      zapperHost = null;
    }
  }

  function onZapperMouseMove(e) {
    if (!zapperActive) return;
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (!el || el === zapperHost || el === document.body || el === document.documentElement) {
      if (zapperBox) zapperBox.style.display = "none";
      hoveredTarget = null;
      return;
    }
    hoveredTarget = el;
    const rect = el.getBoundingClientRect();
    const sel = synthesizeCssSelector(el) || el.tagName.toLowerCase();
    if (zapperLabel) zapperLabel.textContent = sel;
    if (zapperBox) {
      zapperBox.style.display = "block";
      zapperBox.style.top = `${rect.top}px`;
      zapperBox.style.left = `${rect.left}px`;
      zapperBox.style.width = `${rect.width}px`;
      zapperBox.style.height = `${rect.height}px`;
    }
  }

  function onZapperClick(e) {
    if (!zapperActive || !hoveredTarget) return;
    e.preventDefault();
    e.stopPropagation();
    const sel = synthesizeCssSelector(hoveredTarget);
    if (sel) {
      hoveredTarget.setAttribute("data-aegis-hidden", "true");
      if (!customSelectors.includes(sel)) {
        customSelectors.push(sel);
        applyCustomSelectors(customSelectors);
      }
      chrome.runtime.sendMessage({
        type: "SAVE_CUSTOM_SELECTOR",
        site: CURRENT_HOST,
        selector: sel
      }).catch(() => {});
    }
    stopElementZapper();
  }

  function onZapperKeyDown(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      stopElementZapper();
    }
  }

  // ============================================================================
  // 4. Lifecycle Bootstrap & Runtime Messaging
  // ============================================================================
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || typeof msg !== "object") return false;
    if (msg.type === "START_ELEMENT_ZAPPER") {
      startElementZapper();
      sendResponse({ ok: true });
      return false;
    }
    if (msg.type === "SITE_CONFIG_UPDATED") {
      applyPauseState(msg.isPaused);
      applyCustomSelectors(msg.customSelectors || []);
      if (!msg.isPaused) {
        scanCosmeticElements();
      }
      sendResponse({ ok: true });
      return false;
    }
    return false;
  });

  function bootstrap() {
    chrome.runtime.sendMessage({ type: "GET_SITE_CONFIG", site: CURRENT_HOST }, (resp) => {
      if (chrome.runtime.lastError || !resp) return;
      applyPauseState(resp.isPaused);
      applyCustomSelectors(resp.customSelectors || []);
      if (!resp.isPaused) {
        scanCosmeticElements();
        guardVideoAds();
        scanThirdPartyIframes();
        scanVisualAdLeaksAndAntiAdblock();
      }
    });

    initResourceHeuristicObserver();
    initBreakageDiagnosticListener();

    let rafPending = false;
    const observer = new MutationObserver(() => {
      if (isSitePaused || rafPending) return;
      rafPending = true;
      requestAnimationFrame(() => {
        rafPending = false;
        scanCosmeticElements();
        guardVideoAds();
        scanThirdPartyIframes();
        scanVisualAdLeaksAndAntiAdblock();
      });
    });

    const startObserving = () => {
      if (document.documentElement) {
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true
        });
      }
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        scanCosmeticElements();
        guardVideoAds();
        scanThirdPartyIframes();
        scanVisualAdLeaksAndAntiAdblock();
        startObserving();
      }, { once: true });
    } else {
      scanCosmeticElements();
      guardVideoAds();
      scanThirdPartyIframes();
      scanVisualAdLeaksAndAntiAdblock();
      startObserving();
    }
  }

  bootstrap();
})();
