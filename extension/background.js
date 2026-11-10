/**
 * AegisBlock — Manifest V3 Background Service Worker
 * - Zero-Leak Local Telemetry & Rule Analytics Engine
 * - Real-time DNR Match Collector (onRuleMatchedDebug)
 * - Self-Learning Heuristic Evasion Evaluator & Dynamic DNR Rule Synthesizer
 * - Per-Site Allowlist (allowAllRequests) & Custom Cosmetic Selector Manager
 */

const STORAGE_KEY = "aegisblock_state_v1";
const ALLOWLIST_RULE_ID_BASE = 50000;
const SITE_EXCEPTION_RULE_ID_BASE = 60000;
const DYNAMIC_BLOCK_RULE_ID_BASE = 10000;
const MAX_RECENT_EVENTS = 250;

// Estimated average payload bytes saved per blocked resource type
const BYTES_SAVED_BY_TYPE = {
  script: 48000,
  sub_frame: 65000,
  image: 32000,
  media: 240000,
  xmlhttprequest: 14000,
  stylesheet: 18000,
  font: 42000,
  ping: 1200,
  csp_report: 1500,
  websocket: 8000,
  other: 12000
};

let ruleCatalog = { rules: {}, coveredDomains: [] };
let coveredDomainSet = new Set();
let stateCache = null;
let saveTimer = null;
const tabStats = new Map(); // tabId -> { host, blocked, sanitized, cosmetic, suspects: [] }

function createDefaultState() {
  return {
    version: "1.0.0",
    createdAt: Date.now(),
    globalEnabled: true,
    autoLearnEnabled: false,
    autoLearnThreshold: 85,
    allowlistedSites: [],
    customSelectorsBySite: {}, // { "example.com": ["#promo-box"] }
    dynamicBlockRules: [],     // [{ id, domain, category, source, createdAt, confidence, signals }]
    siteDomainExceptions: [],  // [{ id, site, domain, createdAt }]
    ignoredSuspects: [],       // ["cdn.safe-example.com"]
    metrics: {
      totalNetworkBlocked: 0,
      adsBlocked: 0,
      trackersBlocked: 0,
      annoyancesBlocked: 0,
      dynamicRulesMatched: 0,
      surrogatesServed: 0,
      queryStripped: 0,
      headersModified: 0,
      cosmeticHidden: 0,
      videoAdsSkipped: 0,
      visualLeaksCaught: 0,
      falsePositivesFlagged: 0,
      estimatedBytesSaved: 0
    },
    ruleHits: {},              // ruleId -> { id, count, ruleset, vendor, category, patternSummary, lastSeen }
    domainStats: {},           // blockedHost -> { host, count, category, vendor, resourceTypes: {}, initiatorSites: [], lastSeen }
    siteStats: {},             // initiatorHost -> { site, blocked, sanitized, cosmetic, video, thirdPartyTrackers: [], lastSeen }
    suspectCandidates: {},     // candidateHost -> { candidateHost, baseDomain, count, confidence, category, signals: [], initiatorSites: [], resourceTypes: [], sampleUrl, firstSeen, lastSeen, promotedRuleId }
    falsePositiveReports: {},  // key(site::domain) -> { key, site, blockedDomain, ruleId, reason, detail, count, lastSeen, mitigated }
    recentEvents: []           // [{ id, ts, kind, action, initiatorSite, targetHost, resourceType, ruleId, ruleset, vendor, category, url }]
  };
}

async function loadRuleCatalog() {
  try {
    const url = chrome.runtime.getURL("rules/rule_catalog.json");
    const res = await fetch(url);
    if (res.ok) {
      ruleCatalog = await res.json();
      coveredDomainSet = new Set(ruleCatalog.coveredDomains || []);
    }
  } catch (err) {
    console.warn("[AegisBlock] Failed to load rule_catalog.json:", err);
  }
}

async function ensureState() {
  if (stateCache) return stateCache;
  if (Object.keys(ruleCatalog.rules || {}).length === 0) {
    await loadRuleCatalog();
  }
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  if (stored && stored[STORAGE_KEY]) {
    const def = createDefaultState();
    stateCache = {
      ...def,
      ...stored[STORAGE_KEY],
      metrics: { ...def.metrics, ...(stored[STORAGE_KEY].metrics || {}) }
    };
  } else {
    stateCache = createDefaultState();
    await chrome.storage.local.set({ [STORAGE_KEY]: stateCache });
  }
  return stateCache;
}

function scheduleSaveState() {
  if (saveTimer) return;
  saveTimer = setTimeout(async () => {
    saveTimer = null;
    if (stateCache) {
      await chrome.storage.local.set({ [STORAGE_KEY]: stateCache });
    }
  }, 600);
}

function normalizeHost(rawUrlOrHost) {
  if (!rawUrlOrHost) return "";
  if (!rawUrlOrHost.includes("://")) {
    return rawUrlOrHost.toLowerCase().replace(/^www\./, "").trim();
  }
  try {
    return new URL(rawUrlOrHost).hostname.toLowerCase().replace(/^www\./, "");
  } catch (_) {
    return "";
  }
}

function extractBaseDomain(hostname) {
  const clean = normalizeHost(hostname);
  const parts = clean.split(".");
  if (parts.length <= 2) return clean;
  const twoPartTlds = new Set(["co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in"]);
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

function isDomainAlreadyBlocked(host, state) {
  const clean = normalizeHost(host);
  const base = extractBaseDomain(clean);
  if (coveredDomainSet.has(clean) || coveredDomainSet.has(base)) return true;
  return (state.dynamicBlockRules || []).some(
    (r) => r.domain === clean || r.domain === base || clean.endsWith(`.${r.domain}`)
  );
}

function getTabTracker(tabId, initiatorHost = "") {
  if (!tabStats.has(tabId)) {
    tabStats.set(tabId, {
      host: initiatorHost || "",
      blocked: 0,
      sanitized: 0,
      cosmetic: 0,
      video: 0,
      recentDomains: [],
      recentRuleIds: [],
      suspects: [],
      reloadTimestamps: []
    });
  }
  const entry = tabStats.get(tabId);
  if (initiatorHost && !entry.host) {
    entry.host = initiatorHost;
  }
  return entry;
}

async function updateActionBadge(tabId) {
  if (typeof tabId !== "number" || tabId < 0) return;
  const state = await ensureState();
  const tracker = tabStats.get(tabId);
  const host = tracker ? tracker.host : "";
  const isPaused = !state.globalEnabled || (host && state.allowlistedSites.includes(host));

  try {
    if (isPaused) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
      await chrome.action.setBadgeText({ tabId, text: "OFF" });
      return;
    }
    const total = tracker ? tracker.blocked + tracker.cosmetic : 0;
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
    await chrome.action.setBadgeText({
      tabId,
      text: total > 0 ? (total > 999 ? "999+" : String(total)) : ""
    });
  } catch (_) {
    // Tab may have closed
  }
}

function pushRecentEvent(state, evt) {
  state.recentEvents.unshift({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    ts: Date.now(),
    ...evt
  });
  if (state.recentEvents.length > MAX_RECENT_EVENTS) {
    state.recentEvents.length = MAX_RECENT_EVENTS;
  }
}

function ensureSiteStat(state, site) {
  const clean = normalizeHost(site) || "direct-or-background";
  if (!state.siteStats[clean]) {
    state.siteStats[clean] = {
      site: clean,
      blocked: 0,
      sanitized: 0,
      cosmetic: 0,
      video: 0,
      thirdPartyTrackers: [],
      lastSeen: Date.now()
    };
  }
  state.siteStats[clean].lastSeen = Date.now();
  return state.siteStats[clean];
}

// ============================================================================
// 1. Real-Time DeclarativeNetRequest Telemetry Collector
// ============================================================================
async function handleDnrRuleMatched(info) {
  if (!info || !info.request || !info.rule) return;
  const state = await ensureState();

  const req = info.request;
  const rule = info.rule;
  const ruleId = String(rule.ruleId);
  const rulesetId = rule.rulesetId || "_dynamic";
  const targetHost = normalizeHost(req.url);
  const initiatorSite = normalizeHost(req.initiator || req.documentUrl || "") || targetHost || "browser";
  const resourceType = req.type || "other";
  const tabId = typeof req.tabId === "number" ? req.tabId : -1;

  // Ignore allowlist & surgical exception rules (IDs >= ALLOWLIST_RULE_ID_BASE)
  if (rule.ruleId >= ALLOWLIST_RULE_ID_BASE) return;

  // Lookup rule metadata
  let meta = ruleCatalog.rules[ruleId];
  if (!meta) {
    const dyn = (state.dynamicBlockRules || []).find((r) => String(r.id) === ruleId);
    if (dyn) {
      meta = {
        id: dyn.id,
        ruleset: "dynamic_custom",
        vendor: `Learned / Custom Rule (${dyn.domain})`,
        category: dyn.category || "Learned Block Rule",
        patternSummary: `||${dyn.domain}^`
      };
    } else {
      meta = {
        id: rule.ruleId,
        ruleset: rulesetId,
        vendor: `DNR Rule #${ruleId}`,
        category: rulesetId === "url_privacy_clean" ? "Privacy Sanitizer" : "Network Block",
        patternSummary: `Rule #${ruleId}`
      };
    }
  }

  const isSanitizer = rulesetId === "url_privacy_clean";
  const isHeaderMod = ruleId === "3002";
  const isSurrogate = Boolean(meta && meta.surrogate);

  if (isSanitizer) {
    if (isHeaderMod) {
      state.metrics.headersModified += 1;
    } else {
      state.metrics.queryStripped += 1;
    }
  } else {
    state.metrics.totalNetworkBlocked += 1;
    state.metrics.estimatedBytesSaved += BYTES_SAVED_BY_TYPE[resourceType] || 15000;
    if (isSurrogate) {
      state.metrics.surrogatesServed = (state.metrics.surrogatesServed || 0) + 1;
    }

    if (rulesetId === "ads_core") {
      state.metrics.adsBlocked += 1;
    } else if (rulesetId === "trackers_privacy") {
      state.metrics.trackersBlocked += 1;
    } else if (rulesetId === "annoyances_social") {
      state.metrics.annoyancesBlocked += 1;
    } else {
      state.metrics.dynamicRulesMatched += 1;
    }
  }

  // Record per-rule hit matrix
  if (!state.ruleHits[ruleId]) {
    state.ruleHits[ruleId] = {
      id: Number(ruleId),
      count: 0,
      ruleset: meta.ruleset,
      vendor: meta.vendor,
      category: meta.category,
      patternSummary: meta.patternSummary,
      lastSeen: Date.now()
    };
  }
  state.ruleHits[ruleId].count += 1;
  state.ruleHits[ruleId].lastSeen = Date.now();

  // Record blocked/target domain leaderboard
  if (targetHost && !isSanitizer) {
    const baseHost = extractBaseDomain(targetHost) || targetHost;
    if (!state.domainStats[baseHost]) {
      state.domainStats[baseHost] = {
        host: baseHost,
        count: 0,
        category: meta.category,
        vendor: meta.vendor,
        resourceTypes: {},
        initiatorSites: [],
        lastSeen: Date.now()
      };
    }
    const dStat = state.domainStats[baseHost];
    dStat.count += 1;
    dStat.lastSeen = Date.now();
    dStat.resourceTypes[resourceType] = (dStat.resourceTypes[resourceType] || 0) + 1;
    if (initiatorSite && !dStat.initiatorSites.includes(initiatorSite) && dStat.initiatorSites.length < 40) {
      dStat.initiatorSites.push(initiatorSite);
    }
  }

  // Record first-party initiator site stats
  if (initiatorSite) {
    const sStat = ensureSiteStat(state, initiatorSite);
    if (isSanitizer) {
      sStat.sanitized += 1;
    } else {
      sStat.blocked += 1;
      const baseTarget = extractBaseDomain(targetHost);
      if (baseTarget && !sStat.thirdPartyTrackers.includes(baseTarget) && sStat.thirdPartyTrackers.length < 50) {
        sStat.thirdPartyTrackers.push(baseTarget);
      }
    }
  }

  // Update per-tab tracker & badge
  if (tabId >= 0) {
    const tTracker = getTabTracker(tabId, initiatorSite);
    if (isSanitizer) {
      tTracker.sanitized += 1;
    } else {
      tTracker.blocked += 1;
      if (targetHost && !tTracker.recentDomains.includes(targetHost)) {
        tTracker.recentDomains.unshift(targetHost);
        if (tTracker.recentDomains.length > 15) tTracker.recentDomains.pop();
      }
      if (!tTracker.recentRuleIds) tTracker.recentRuleIds = [];
      if (!tTracker.recentRuleIds.includes(Number(ruleId))) {
        tTracker.recentRuleIds.unshift(Number(ruleId));
        if (tTracker.recentRuleIds.length > 15) tTracker.recentRuleIds.pop();
      }
    }
    updateActionBadge(tabId);
  }

  // Push to recent live events ring buffer (skip noisy header-mod repeats if identical)
  if (!isHeaderMod || state.metrics.headersModified % 5 === 1) {
    pushRecentEvent(state, {
      kind: isSanitizer ? "SANITIZED" : "BLOCKED",
      action: isHeaderMod ? "modifyHeaders" : isSanitizer ? "stripQueryParams" : isSurrogate ? "redirectSurrogate" : "block",
      initiatorSite,
      targetHost: targetHost || initiatorSite,
      resourceType,
      ruleId: Number(ruleId),
      ruleset: meta.ruleset,
      vendor: meta.vendor,
      category: meta.category,
      url: (req.url || "").slice(0, 220)
    });
  }

  scheduleSaveState();
}

if (
  chrome.declarativeNetRequest &&
  chrome.declarativeNetRequest.onRuleMatchedDebug
) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(handleDnrRuleMatched);
}

// ============================================================================
// 2. Dynamic DNR Rules Sync (Allowlist + Custom/Learned Block Rules)
// ============================================================================
async function syncDynamicDnrRules() {
  const state = await ensureState();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);

  const addRules = [];

  if (!state.globalEnabled) {
    // Global pause rule: allow all requests at highest priority
    addRules.push({
      id: ALLOWLIST_RULE_ID_BASE,
      priority: 10000,
      action: { type: "allowAllRequests" },
      condition: {
        resourceTypes: ["main_frame", "sub_frame"]
      }
    });
  } else {
    // Per-site allowlist rules
    state.allowlistedSites.forEach((site, idx) => {
      const cleanSite = normalizeHost(site);
      if (!cleanSite) return;
      addRules.push({
        id: ALLOWLIST_RULE_ID_BASE + 1 + idx * 2,
        priority: 5000,
        action: { type: "allowAllRequests" },
        condition: {
          requestDomains: [cleanSite],
          resourceTypes: ["main_frame", "sub_frame"]
        }
      });
      addRules.push({
        id: ALLOWLIST_RULE_ID_BASE + 2 + idx * 2,
        priority: 5000,
        action: { type: "allow" },
        condition: {
          initiatorDomains: [cleanSite]
        }
      });
    });

    // Surgical Per-Site Domain Exceptions (fixes false positives without pausing whole site)
    (state.siteDomainExceptions || []).forEach((exc, idx) => {
      const cleanSite = normalizeHost(exc.site);
      const cleanDom = normalizeHost(exc.domain);
      if (!cleanSite || !cleanDom) return;
      addRules.push({
        id: SITE_EXCEPTION_RULE_ID_BASE + 1 + idx,
        priority: 6000,
        action: { type: "allow" },
        condition: {
          initiatorDomains: [cleanSite],
          requestDomains: [cleanDom],
          resourceTypes: [
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "csp_report",
            "media",
            "websocket",
            "other"
          ]
        }
      });
    });

    // User custom & heuristic-promoted dynamic block rules
    for (const dyn of state.dynamicBlockRules) {
      if (!dyn.domain || !dyn.id) continue;
      addRules.push({
        id: Number(dyn.id),
        priority: 25,
        action: { type: "block" },
        condition: {
          requestDomains: [dyn.domain],
          domainType: "thirdParty",
          resourceTypes: [
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "csp_report",
            "media",
            "websocket",
            "other"
          ]
        }
      });
    }
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules
  });
}

async function promoteDomainToDynamicRule(domain, options = {}) {
  const state = await ensureState();
  const cleanDomain = extractBaseDomain(domain) || normalizeHost(domain);
  if (!cleanDomain) return null;

  const existing = state.dynamicBlockRules.find((r) => r.domain === cleanDomain);
  if (existing) return existing;

  const maxId = state.dynamicBlockRules.reduce(
    (max, r) => Math.max(max, Number(r.id) || DYNAMIC_BLOCK_RULE_ID_BASE),
    DYNAMIC_BLOCK_RULE_ID_BASE
  );
  const newRule = {
    id: maxId + 1,
    domain: cleanDomain,
    category: options.category || "Learned Ad/Tracker Host",
    source: options.source || "Heuristic Research Lab",
    confidence: options.confidence || 100,
    signals: options.signals || ["USER_PROMOTED"],
    createdAt: Date.now()
  };

  state.dynamicBlockRules.push(newRule);

  if (state.suspectCandidates[cleanDomain]) {
    state.suspectCandidates[cleanDomain].promotedRuleId = newRule.id;
  }
  for (const key of Object.keys(state.suspectCandidates)) {
    if (state.suspectCandidates[key].baseDomain === cleanDomain) {
      state.suspectCandidates[key].promotedRuleId = newRule.id;
    }
  }

  await syncDynamicDnrRules();
  scheduleSaveState();
  return newRule;
}

// ============================================================================
// 3. Heuristic Suspect Ingestion & Cross-Site Prevalence Scoring
// ============================================================================
async function ingestHeuristicSuspect(suspect, senderTabId = -1) {
  if (!suspect || !suspect.candidateHost) return;
  const state = await ensureState();

  const host = normalizeHost(suspect.candidateHost);
  const baseDomain = extractBaseDomain(host) || host;

  if (state.ignoredSuspects.includes(host) || state.ignoredSuspects.includes(baseDomain)) {
    return;
  }
  if (isDomainAlreadyBlocked(host, state)) {
    return;
  }

  if (!state.suspectCandidates[host]) {
    state.suspectCandidates[host] = {
      candidateHost: host,
      baseDomain,
      count: 0,
      confidence: suspect.confidence || 50,
      category: suspect.category || "Suspect Third-Party Resource",
      signals: [],
      initiatorSites: [],
      resourceTypes: [],
      sampleUrl: suspect.sampleUrl || `https://${host}/`,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      promotedRuleId: null
    };
  }

  const entry = state.suspectCandidates[host];
  entry.count += 1;
  entry.lastSeen = Date.now();

  for (const sig of suspect.signals || []) {
    if (!entry.signals.includes(sig)) {
      entry.signals.push(sig);
    }
  }
  if (suspect.initiatorSite && !entry.initiatorSites.includes(suspect.initiatorSite)) {
    entry.initiatorSites.push(suspect.initiatorSite);
  }
  if (suspect.resourceType && !entry.resourceTypes.includes(suspect.resourceType)) {
    entry.resourceTypes.push(suspect.resourceType);
  }

  // Boost confidence when observed across multiple independent first-party sites (Cross-Site Prevalence)
  const crossSiteBonus = Math.min(28, (entry.initiatorSites.length - 1) * 12);
  if (entry.initiatorSites.length >= 2 && !entry.signals.includes("CROSS_SITE_PREVALENCE")) {
    entry.signals.push("CROSS_SITE_PREVALENCE");
  }
  entry.confidence = Math.min(99, Math.max(entry.confidence, (suspect.confidence || 50) + crossSiteBonus));

  if (senderTabId >= 0) {
    const tTracker = getTabTracker(senderTabId, suspect.initiatorSite);
    if (!tTracker.suspects.some((s) => s.candidateHost === host)) {
      tTracker.suspects.push({
        candidateHost: host,
        baseDomain,
        confidence: entry.confidence,
        category: entry.category,
        signals: entry.signals
      });
    }
  }

  pushRecentEvent(state, {
    kind: "SUSPECT",
    action: "heuristicFlag",
    initiatorSite: suspect.initiatorSite || "page",
    targetHost: host,
    resourceType: suspect.resourceType || "script",
    ruleId: 0,
    ruleset: "heuristic_sensor",
    vendor: `Unblocked Candidate (${entry.confidence}% confidence)`,
    category: entry.category,
    url: suspect.sampleUrl || `https://${host}/`
  });

  // Auto-Learn Promotion if enabled and confidence meets threshold
  if (state.autoLearnEnabled && entry.confidence >= (state.autoLearnThreshold || 85) && !entry.promotedRuleId) {
    await promoteDomainToDynamicRule(baseDomain, {
      category: entry.category,
      source: "Auto-Learn Heuristic Engine",
      confidence: entry.confidence,
      signals: entry.signals
    });
  }

  scheduleSaveState();
}

// ============================================================================
// 4. Representative Research Benchmark Seeder (For Instant Lab Exploration)
// ============================================================================
async function seedSampleResearchTelemetry() {
  const state = await ensureState();
  const now = Date.now();

  const sampleMatches = [
    { ruleId: "1001", host: "pagead2.googlesyndication.com", site: "news-daily.com", type: "script", count: 42 },
    { ruleId: "1001", host: "securepubads.g.doubleclick.net", site: "sports-stream.tv", type: "sub_frame", count: 36 },
    { ruleId: "1004", host: "fastlane.rubiconproject.com", site: "news-daily.com", type: "xmlhttprequest", count: 29 },
    { ruleId: "1004", host: "hbopenbid.pubmatic.com", site: "tech-review.io", type: "xmlhttprequest", count: 24 },
    { ruleId: "1005", host: "bidder.criteo.com", site: "shop-deals.com", type: "script", count: 19 },
    { ruleId: "2001", host: "www.googletagmanager.com", site: "tech-review.io", type: "script", count: 31 },
    { ruleId: "2002", host: "connect.facebook.net", site: "shop-deals.com", type: "script", count: 18 },
    { ruleId: "2004", host: "script.hotjar.com", site: "saas-portal.app", type: "script", count: 14 },
    { ruleId: "2006", host: "sb.scorecardresearch.com", site: "news-daily.com", type: "ping", count: 27 },
    { ruleId: "3001", host: "shop-deals.com", site: "shop-deals.com", type: "main_frame", count: 15 },
    { ruleId: "3002", host: "doubleclick.net", site: "news-daily.com", type: "xmlhttprequest", count: 22 },
    { ruleId: "4001", host: "cdn.taboola.com", site: "news-daily.com", type: "script", count: 16 },
    { ruleId: "4001", host: "widgets.outbrain.com", site: "finance-watch.org", type: "sub_frame", count: 12 }
  ];

  for (const item of sampleMatches) {
    for (let i = 0; i < item.count; i++) {
      await handleDnrRuleMatched({
        request: {
          url: `https://${item.host}/v2/ad_delivery?cb=${1000 + i}`,
          initiator: `https://${item.site}`,
          type: item.type,
          tabId: -1
        },
        rule: {
          ruleId: Number(item.ruleId),
          rulesetId:
            item.ruleId.startsWith("1")
              ? "ads_core"
              : item.ruleId.startsWith("2")
              ? "trackers_privacy"
              : item.ruleId.startsWith("3")
              ? "url_privacy_clean"
              : "annoyances_social"
        }
      });
    }
  }

  // Add cosmetic & video skip samples
  state.metrics.cosmeticHidden += 38;
  state.metrics.videoAdsSkipped += 6;
  ensureSiteStat(state, "news-daily.com").cosmetic += 19;
  ensureSiteStat(state, "sports-stream.tv").video += 6;
  ensureSiteStat(state, "tech-review.io").cosmetic += 11;

  // Add realistic unblocked Heuristic Evasion Candidates for the user to inspect & promote
  const sampleSuspects = [
    {
      candidateHost: "ads-telemetry.rtb-edge-delivery.net",
      baseDomain: "rtb-edge-delivery.net",
      sampleUrl: "https://ads-telemetry.rtb-edge-delivery.net/openrtb2/auction?ad_unit=top_728x90&gdpr_consent=1",
      initiatorSite: "news-daily.com",
      resourceType: "xmlhttprequest",
      confidence: 92,
      category: "Suspect Ad Server",
      signals: ["AD_SUBDOMAIN_PREFIX", "URL_ADTECH_ENDPOINT", "ADTECH_QUERY_PARAMS", "CROSS_SITE_PREVALENCE"]
    },
    {
      candidateHost: "pixel-sync.audience-graph-cdn.io",
      baseDomain: "audience-graph-cdn.io",
      sampleUrl: "https://pixel-sync.audience-graph-cdn.io/usersync/pixel.gif?uid=99182&us_privacy=1YNN",
      initiatorSite: "shop-deals.com",
      resourceType: "ping",
      confidence: 88,
      category: "Suspect Tracker / Beacon",
      signals: ["TRACKER_SUBDOMAIN_PREFIX", "URL_TRACKER_ENDPOINT", "ADTECH_QUERY_PARAMS", "INITIATOR_PING"]
    },
    {
      candidateHost: "banner.native-Yield-exchange.com",
      baseDomain: "native-yield-exchange.com",
      sampleUrl: "https://banner.native-yield-exchange.com/adframe.html?slot=sidebar_300x250",
      initiatorSite: "sports-stream.tv",
      resourceType: "sub_frame",
      confidence: 84,
      category: "Suspect Ad Iframe",
      signals: ["IAB_AD_IFRAME_300x250", "AD_SUBDOMAIN_PREFIX", "URL_ADTECH_ENDPOINT"]
    },
    {
      candidateHost: "metrics.firstparty-cloaked-analytics.org",
      baseDomain: "firstparty-cloaked-analytics.org",
      sampleUrl: "https://metrics.firstparty-cloaked-analytics.org/collect?v=2&tid=G-99812&cid=10291",
      initiatorSite: "finance-watch.org",
      resourceType: "beacon",
      confidence: 76,
      category: "Suspect Tracker / Beacon",
      signals: ["TRACKER_SUBDOMAIN_PREFIX", "URL_TRACKER_ENDPOINT", "INITIATOR_BEACON"]
    }
  ];

  for (const s of sampleSuspects) {
    await ingestHeuristicSuspect(s, -1);
    // Simulate second site observation for top candidates
    if (s.confidence >= 85) {
      await ingestHeuristicSuspect({ ...s, initiatorSite: "tech-review.io" }, -1);
    }
  }

  // Seed representative False-Positive / Breakage correlation entry
  recordFalsePositiveDiagnostic(state, {
    site: "saas-portal.app",
    blockedDomain: "script.hotjar.com",
    ruleId: 2004,
    reason: "SCRIPT_LOAD_BLOCKED",
    detail: "Blocked third-party script on saas-portal.app (Rule #2004)"
  });

  await chrome.storage.local.set({ [STORAGE_KEY]: state });
  return state;
}

function recordFalsePositiveDiagnostic(state, { site, blockedDomain, ruleId = 0, reason = "USER_PAUSED_SITE", detail = "" }) {
  const cleanSite = normalizeHost(site);
  const cleanDom = normalizeHost(blockedDomain) || cleanSite;
  if (!cleanSite || !cleanDom) return null;

  if (!state.falsePositiveReports) state.falsePositiveReports = {};
  const key = `${cleanSite}::${cleanDom}`;
  const isNew = !state.falsePositiveReports[key];

  if (isNew) {
    state.metrics.falsePositivesFlagged = (state.metrics.falsePositivesFlagged || 0) + 1;
    state.falsePositiveReports[key] = {
      key,
      site: cleanSite,
      blockedDomain: cleanDom,
      baseDomain: extractBaseDomain(cleanDom) || cleanDom,
      ruleId: Number(ruleId) || 0,
      reason,
      detail: detail || `${reason} on ${cleanSite}`,
      count: 1,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      mitigated: false
    };
  } else {
    state.falsePositiveReports[key].count += 1;
    state.falsePositiveReports[key].lastSeen = Date.now();
    state.falsePositiveReports[key].reason = reason;
    if (ruleId) state.falsePositiveReports[key].ruleId = Number(ruleId);
  }

  pushRecentEvent(state, {
    kind: "FALSE_POSITIVE",
    action: reason,
    initiatorSite: cleanSite,
    targetHost: cleanDom,
    resourceType: "diagnostic",
    ruleId: Number(ruleId) || 0,
    ruleset: "breakage_sensor",
    vendor: `Breakage / False-Positive Sensor (${reason})`,
    category: "False-Positive Candidate",
    url: detail || `${cleanSite} -> ${cleanDom}`
  });

  return state.falsePositiveReports[key];
}

// ============================================================================
// 5. Tab Navigation & Keyboard Shortcut Listeners
// ============================================================================
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab && tab.url && tab.url.startsWith("http")) {
    const host = normalizeHost(tab.url);
    const prev = tabStats.get(tabId);
    const now = Date.now();
    let reloadTimestamps = [];

    if (prev && prev.host === host) {
      reloadTimestamps = (prev.reloadTimestamps || []).filter((ts) => now - ts < 15000);
      reloadTimestamps.push(now);
      // Rapid reload heuristic: 3+ reloads within 15s while resources were blocked on this tab
      if (reloadTimestamps.length >= 3 && prev.blocked > 0 && prev.recentDomains && prev.recentDomains.length > 0) {
        const state = await ensureState();
        recordFalsePositiveDiagnostic(state, {
          site: host,
          blockedDomain: prev.recentDomains[0],
          ruleId: (prev.recentRuleIds && prev.recentRuleIds[0]) || 0,
          reason: "RAPID_TAB_RELOAD",
          detail: `User reloaded ${host} ${reloadTimestamps.length}x in 15s after blocking ${prev.recentDomains[0]}`
        });
        scheduleSaveState();
      }
    } else {
      reloadTimestamps = [now];
    }

    tabStats.set(tabId, {
      host,
      blocked: 0,
      sanitized: 0,
      cosmetic: 0,
      video: 0,
      recentDomains: prev && prev.host === host ? (prev.recentDomains || []).slice(0, 5) : [],
      recentRuleIds: prev && prev.host === host ? (prev.recentRuleIds || []).slice(0, 5) : [],
      suspects: [],
      reloadTimestamps
    });
    updateActionBadge(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStats.delete(tabId);
});

chrome.commands.onCommand.addListener(async (command) => {
  if (command === "toggle-element-zapper") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, { type: "START_ELEMENT_ZAPPER" }).catch(() => {});
    }
  }
});

chrome.runtime.onInstalled.addListener(async () => {
  await loadRuleCatalog();
  await ensureState();
  await syncDynamicDnrRules();
});

// ============================================================================
// 6. Message Router for Content Scripts, Popup, and Research Studio Dashboard
// ============================================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const state = await ensureState();
    const senderTabId = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : -1;

    switch (msg.type) {
      case "GET_SITE_CONFIG": {
        const site = normalizeHost(msg.site);
        const isPaused = !state.globalEnabled || state.allowlistedSites.includes(site);
        const customSelectors = state.customSelectorsBySite[site] || [];
        sendResponse({
          ok: true,
          isPaused,
          globalEnabled: state.globalEnabled,
          customSelectors
        });
        return;
      }

      case "REPORT_COSMETIC_TELEMETRY": {
        const site = normalizeHost(msg.site);
        const count = Number(msg.count) || 1;
        state.metrics.cosmeticHidden += count;
        const sStat = ensureSiteStat(state, site);
        sStat.cosmetic += count;

        if (senderTabId >= 0) {
          const tTracker = getTabTracker(senderTabId, site);
          tTracker.cosmetic += count;
          updateActionBadge(senderTabId);
        }

        const firstSample = (msg.samples && msg.samples[0]) || { selector: ".ad-slot" };
        pushRecentEvent(state, {
          kind: "COSMETIC",
          action: "hideElement",
          initiatorSite: site,
          targetHost: firstSample.selector,
          resourceType: "dom",
          ruleId: 0,
          ruleset: "cosmetic_css",
          vendor: `Cosmetic Hide (${count} element${count > 1 ? "s" : ""})`,
          category: "Cosmetic DOM Filter",
          url: `${site} -> ${firstSample.selector}`
        });
        scheduleSaveState();
        sendResponse({ ok: true });
        return;
      }

      case "REPORT_VIDEO_AD_MITIGATED": {
        const site = normalizeHost(msg.site);
        state.metrics.videoAdsSkipped += 1;
        state.metrics.estimatedBytesSaved += 450000;
        const sStat = ensureSiteStat(state, site);
        sStat.video += 1;

        if (senderTabId >= 0) {
          const tTracker = getTabTracker(senderTabId, site);
          tTracker.video += 1;
        }

        pushRecentEvent(state, {
          kind: "VIDEO_SKIP",
          action: "skipVideoAd",
          initiatorSite: site,
          targetHost: msg.method || "Video Pre-Roll Skip",
          resourceType: "media",
          ruleId: 0,
          ruleset: "video_ad_guard",
          vendor: "Video Ad Stream Guard",
          category: "Video Ad Skipper",
          url: `${site} (${msg.method || "Auto-Skip"})`
        });
        scheduleSaveState();
        sendResponse({ ok: true });
        return;
      }

      case "REPORT_HEURISTIC_SUSPECT": {
        await ingestHeuristicSuspect(msg.suspect, senderTabId);
        sendResponse({ ok: true });
        return;
      }

      case "REPORT_VISUAL_AD_LEAK": {
        const site = normalizeHost(msg.site);
        state.metrics.visualLeaksCaught = (state.metrics.visualLeaksCaught || 0) + 1;
        state.metrics.cosmeticHidden += 1;
        const sStat = ensureSiteStat(state, site);
        sStat.cosmetic += 1;

        pushRecentEvent(state, {
          kind: "SUSPECT",
          action: "visualAdLeak",
          initiatorSite: site,
          targetHost: msg.selector || "filled-ad-slot",
          resourceType: "dom-leak",
          ruleId: 0,
          ruleset: "visual_leak_sensor",
          vendor: `Visual Ad Leak Auto-Collapsed (${msg.dimensions || "IAB"})`,
          category: "Visual Ad Leak",
          url: `${site} ## ${msg.selector}`
        });
        scheduleSaveState();
        sendResponse({ ok: true });
        return;
      }

      case "REPORT_BREAKAGE_DIAGNOSTIC": {
        const site = normalizeHost(msg.site);
        const tTracker = senderTabId >= 0 ? getTabTracker(senderTabId, site) : null;
        const failedHost = normalizeHost(msg.failedHost);
        const recentBlocked = (tTracker && tTracker.recentDomains) || [];
        const recentRules = (tTracker && tTracker.recentRuleIds) || [];

        // Only flag if the failed script or page error correlates with a domain blocked by AegisBlock
        let correlatedDomain = "";
        let correlatedRuleId = recentRules[0] || 0;
        if (failedHost && (isDomainAlreadyBlocked(failedHost, state) || recentBlocked.includes(failedHost))) {
          correlatedDomain = failedHost;
        } else if (recentBlocked.length > 0) {
          correlatedDomain = recentBlocked[0];
        }

        if (correlatedDomain) {
          recordFalsePositiveDiagnostic(state, {
            site,
            blockedDomain: correlatedDomain,
            ruleId: correlatedRuleId,
            reason: msg.reason || "PAGE_BREAKAGE_SIGNAL",
            detail: msg.detail || ""
          });
          scheduleSaveState();
        }
        sendResponse({ ok: true, correlatedDomain });
        return;
      }

      case "ALLOW_DOMAIN_ON_SITE": {
        const site = normalizeHost(msg.site);
        const domain = extractBaseDomain(msg.domain) || normalizeHost(msg.domain);
        if (!site || !domain) {
          sendResponse({ ok: false });
          return;
        }
        if (!state.siteDomainExceptions) state.siteDomainExceptions = [];
        const exists = state.siteDomainExceptions.find((e) => e.site === site && e.domain === domain);
        if (!exists) {
          state.siteDomainExceptions.push({
            id: SITE_EXCEPTION_RULE_ID_BASE + state.siteDomainExceptions.length + 1,
            site,
            domain,
            createdAt: Date.now()
          });
        }
        for (const fp of Object.values(state.falsePositiveReports || {})) {
          if (fp.site === site && (fp.blockedDomain === domain || fp.baseDomain === domain)) {
            fp.mitigated = true;
          }
        }
        await syncDynamicDnrRules();
        scheduleSaveState();
        sendResponse({ ok: true, siteDomainExceptions: state.siteDomainExceptions });
        return;
      }

      case "REMOVE_SITE_DOMAIN_EXCEPTION": {
        const site = normalizeHost(msg.site);
        const domain = normalizeHost(msg.domain);
        state.siteDomainExceptions = (state.siteDomainExceptions || []).filter(
          (e) => !(e.site === site && e.domain === domain)
        );
        await syncDynamicDnrRules();
        scheduleSaveState();
        sendResponse({ ok: true, siteDomainExceptions: state.siteDomainExceptions });
        return;
      }

      case "SAVE_CUSTOM_SELECTOR": {
        const site = normalizeHost(msg.site);
        const selector = (msg.selector || "").trim();
        if (site && selector) {
          if (!state.customSelectorsBySite[site]) {
            state.customSelectorsBySite[site] = [];
          }
          if (!state.customSelectorsBySite[site].includes(selector)) {
            state.customSelectorsBySite[site].push(selector);
          }
          pushRecentEvent(state, {
            kind: "ZAPPER",
            action: "saveCustomSelector",
            initiatorSite: site,
            targetHost: selector,
            resourceType: "dom",
            ruleId: 0,
            ruleset: "element_zapper",
            vendor: "User Element Zapper",
            category: "Custom Cosmetic Rule",
            url: `${site} ## ${selector}`
          });
          scheduleSaveState();
        }
        sendResponse({ ok: true, selectors: state.customSelectorsBySite[site] || [] });
        return;
      }

      case "REMOVE_CUSTOM_SELECTOR": {
        const site = normalizeHost(msg.site);
        const selector = (msg.selector || "").trim();
        if (site && state.customSelectorsBySite[site]) {
          state.customSelectorsBySite[site] = state.customSelectorsBySite[site].filter(
            (s) => s !== selector
          );
          if (state.customSelectorsBySite[site].length === 0) {
            delete state.customSelectorsBySite[site];
          }
          scheduleSaveState();
        }
        sendResponse({ ok: true });
        return;
      }

      case "GET_POPUP_DATA": {
        const tabId = typeof msg.tabId === "number" ? msg.tabId : -1;
        const site = normalizeHost(msg.site);
        const isSitePaused = !state.globalEnabled || (site && state.allowlistedSites.includes(site));
        const tTracker = tabId >= 0 ? getTabTracker(tabId, site) : null;
        const siteStat = site && state.siteStats[site] ? state.siteStats[site] : { blocked: 0, sanitized: 0, cosmetic: 0, video: 0, thirdPartyTrackers: [] };
        const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets();

        // Find unpromoted suspects for this site or globally
        const siteSuspects = Object.values(state.suspectCandidates)
          .filter((s) => !s.promotedRuleId && (!site || s.initiatorSites.includes(site)))
          .sort((a, b) => b.confidence - a.confidence)
          .slice(0, 5);

        // Find unmitigated false-positive diagnostics for this site
        const siteFalsePositives = Object.values(state.falsePositiveReports || {})
          .filter((fp) => !fp.mitigated && (!site || fp.site === site))
          .sort((a, b) => b.lastSeen - a.lastSeen)
          .slice(0, 3);

        sendResponse({
          ok: true,
          globalEnabled: state.globalEnabled,
          autoLearnEnabled: state.autoLearnEnabled,
          autoLearnThreshold: state.autoLearnThreshold,
          site,
          isSitePaused,
          tabStats: tTracker || { blocked: 0, sanitized: 0, cosmetic: 0, video: 0, recentDomains: [], suspects: [] },
          siteStat,
          metrics: state.metrics,
          enabledRulesets,
          dynamicRuleCount: state.dynamicBlockRules.length,
          staticRuleSummary: ruleCatalog.summary || {},
          siteSuspects,
          siteFalsePositives,
          totalSuspectCount: Object.values(state.suspectCandidates).filter((s) => !s.promotedRuleId).length,
          totalFalsePositiveCount: Object.values(state.falsePositiveReports || {}).filter((fp) => !fp.mitigated).length
        });
        return;
      }

      case "TOGGLE_SITE_PAUSE": {
        const site = normalizeHost(msg.site);
        if (!site) {
          sendResponse({ ok: false });
          return;
        }
        const idx = state.allowlistedSites.indexOf(site);
        let isPaused = false;
        if (idx >= 0) {
          state.allowlistedSites.splice(idx, 1);
          isPaused = false;
        } else {
          state.allowlistedSites.push(site);
          isPaused = true;
          // If the user paused a site where domains were recently blocked, log a false-positive candidate
          const tTracker = typeof msg.tabId === "number" && msg.tabId >= 0 ? tabStats.get(msg.tabId) : null;
          if (tTracker && tTracker.recentDomains && tTracker.recentDomains.length > 0) {
            recordFalsePositiveDiagnostic(state, {
              site,
              blockedDomain: tTracker.recentDomains[0],
              ruleId: (tTracker.recentRuleIds && tTracker.recentRuleIds[0]) || 0,
              reason: "USER_PAUSED_SITE",
              detail: `User paused shield on ${site} after blocking ${tTracker.recentDomains[0]}`
            });
          }
        }
        await syncDynamicDnrRules();
        scheduleSaveState();

        if (typeof msg.tabId === "number" && msg.tabId >= 0) {
          updateActionBadge(msg.tabId);
          chrome.tabs.sendMessage(msg.tabId, {
            type: "SITE_CONFIG_UPDATED",
            isPaused: !state.globalEnabled || isPaused,
            customSelectors: state.customSelectorsBySite[site] || []
          }).catch(() => {});
        }
        sendResponse({ ok: true, isPaused: !state.globalEnabled || isPaused, allowlistedSites: state.allowlistedSites });
        return;
      }

      case "TOGGLE_GLOBAL_ENABLED": {
        state.globalEnabled = Boolean(msg.enabled);
        await syncDynamicDnrRules();
        scheduleSaveState();
        const tabs = await chrome.tabs.query({});
        for (const t of tabs) {
          if (typeof t.id === "number") updateActionBadge(t.id);
        }
        sendResponse({ ok: true, globalEnabled: state.globalEnabled });
        return;
      }

      case "TOGGLE_AUTO_LEARN": {
        state.autoLearnEnabled = Boolean(msg.enabled);
        if (typeof msg.threshold === "number") {
          state.autoLearnThreshold = Math.max(50, Math.min(99, msg.threshold));
        }
        scheduleSaveState();
        sendResponse({
          ok: true,
          autoLearnEnabled: state.autoLearnEnabled,
          autoLearnThreshold: state.autoLearnThreshold
        });
        return;
      }

      case "PROMOTE_SUSPECT_TO_RULE": {
        const rule = await promoteDomainToDynamicRule(msg.domain, {
          category: msg.category || "Learned Ad/Tracker Host",
          source: msg.source || "Research Lab Promotion",
          confidence: msg.confidence || 95,
          signals: msg.signals || ["RESEARCH_LAB_PROMOTED"]
        });
        sendResponse({ ok: Boolean(rule), rule, dynamicBlockRules: state.dynamicBlockRules });
        return;
      }

      case "BULK_PROMOTE_SUSPECTS": {
        const minConfidence = Number(msg.minConfidence) || 80;
        const promoted = [];
        for (const cand of Object.values(state.suspectCandidates)) {
          if (!cand.promotedRuleId && cand.confidence >= minConfidence) {
            const rule = await promoteDomainToDynamicRule(cand.baseDomain || cand.candidateHost, {
              category: cand.category,
              source: `Bulk Promote (>=${minConfidence}%)`,
              confidence: cand.confidence,
              signals: cand.signals
            });
            if (rule) promoted.push(rule);
          }
        }
        sendResponse({ ok: true, promotedCount: promoted.length, promoted });
        return;
      }

      case "IGNORE_SUSPECT": {
        const host = normalizeHost(msg.host);
        if (host && !state.ignoredSuspects.includes(host)) {
          state.ignoredSuspects.push(host);
          delete state.suspectCandidates[host];
          scheduleSaveState();
        }
        sendResponse({ ok: true });
        return;
      }

      case "REMOVE_DYNAMIC_RULE": {
        const id = Number(msg.ruleId);
        state.dynamicBlockRules = state.dynamicBlockRules.filter((r) => Number(r.id) !== id);
        for (const cand of Object.values(state.suspectCandidates)) {
          if (Number(cand.promotedRuleId) === id) {
            cand.promotedRuleId = null;
          }
        }
        await syncDynamicDnrRules();
        scheduleSaveState();
        sendResponse({ ok: true, dynamicBlockRules: state.dynamicBlockRules });
        return;
      }

      case "TOGGLE_STATIC_RULESET": {
        const rulesetId = msg.rulesetId;
        const enable = Boolean(msg.enable);
        await chrome.declarativeNetRequest.updateEnabledRulesets({
          enableRulesetIds: enable ? [rulesetId] : [],
          disableRulesetIds: enable ? [] : [rulesetId]
        });
        const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
        sendResponse({ ok: true, enabledRulesets });
        return;
      }

      case "GET_DASHBOARD_STATE": {
        const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
        sendResponse({
          ok: true,
          state,
          ruleCatalog,
          enabledRulesets
        });
        return;
      }

      case "SEED_DEMO_TELEMETRY": {
        const updated = await seedSampleResearchTelemetry();
        sendResponse({ ok: true, state: updated });
        return;
      }

      case "RESET_TELEMETRY": {
        const fresh = createDefaultState();
        fresh.allowlistedSites = state.allowlistedSites;
        fresh.customSelectorsBySite = state.customSelectorsBySite;
        fresh.dynamicBlockRules = state.dynamicBlockRules;
        fresh.globalEnabled = state.globalEnabled;
        fresh.autoLearnEnabled = state.autoLearnEnabled;
        stateCache = fresh;
        await chrome.storage.local.set({ [STORAGE_KEY]: fresh });
        sendResponse({ ok: true, state: fresh });
        return;
      }

      default:
        sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` });
    }
  })();
  return true;
});
