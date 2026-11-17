/**
 * NulKast-Block — Blocker Research & Analytics Studio Controller
 */

let currentState = null;
let ruleCatalog = { rules: {}, summary: {} };
let enabledRulesets = [];
let activeStreamKind = "ALL";
let streamSearchQuery = "";
let ruleAuditorQuery = "";

const STATIC_RULESET_META = [
  {
    id: "ads_core",
    title: "Core Ad Networks & RTB Exchanges",
    desc: "Blocks Google Ads/DoubleClick, Amazon AAX, AppNexus, Rubicon, PubMatic, Criteo, popunders & VAST video ads."
  },
  {
    id: "trackers_privacy",
    title: "Cross-Site Trackers & Fingerprinting",
    desc: "Blocks Google Analytics, Meta/TikTok pixels, Hotjar/Clarity session replay, DMP graphs & <a ping> beacons."
  },
  {
    id: "url_privacy_clean",
    title: "URL Tracking Parameter & Header Sanitizer",
    desc: "Strips 48+ click-IDs (utm_*, fbclid, gclid, msclkid, twclid) & removes Browsing-Topics / NEL headers."
  },
  {
    id: "annoyances_social",
    title: "Sponsored Chumboxes & Push Nags",
    desc: "Blocks Taboola, Outbrain, Revcontent, MGID native widgets and OneSignal/OptinMonster marketing popups."
  }
];

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatTime(ts) {
  if (!ts) return "—";
  return new Date(ts).toLocaleTimeString([], { hour12: false });
}

function showToast(msg) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    el.style.display = "none";
  }, 2400);
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === tabId);
  });
}

function renderBarList(containerId, items) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";
  const maxVal = Math.max(1, ...items.map((i) => i.value));

  for (const item of items) {
    const pct = Math.round((item.value / maxVal) * 100);
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-meta">
        <span>${item.label}</span>
        <span>${item.value.toLocaleString()}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${pct}%; background: ${item.color};"></div>
      </div>
    `;
    container.appendChild(row);
  }
}

function buildSynthesizedDnrJson(state) {
  const rules = [];
  let nextId = 9001;

  // Include promoted dynamic block rules + unpromoted high-confidence (>=75%) candidates
  const domains = new Set();
  for (const r of state.dynamicBlockRules || []) {
    if (r.domain) domains.add(r.domain);
  }
  for (const c of Object.values(state.suspectCandidates || {})) {
    if ((c.confidence || 0) >= 75) {
      domains.add(c.baseDomain || c.candidateHost);
    }
  }

  const sortedDomains = Array.from(domains).sort();
  if (sortedDomains.length > 0) {
    rules.push({
      id: nextId++,
      priority: 20,
      action: { type: "block" },
      condition: {
        requestDomains: sortedDomains,
        domainType: "thirdParty",
        resourceTypes: [
          "sub_frame",
          "stylesheet",
          "script",
          "image",
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
  return rules;
}

function renderDashboard() {
  if (!currentState) return;
  const m = currentState.metrics || {};
  const suspects = Object.values(currentState.suspectCandidates || {});
  const unpromotedSuspects = suspects.filter((s) => !s.promotedRuleId);
  const staticTotal = (ruleCatalog.summary && ruleCatalog.summary.totalStaticRules) || 48;
  const staticDomains = (ruleCatalog.summary && ruleCatalog.summary.totalCoveredDomains) || 396;
  const dynCount = (currentState.dynamicBlockRules || []).length;

  // Pills
  document.getElementById("pill-suspects").textContent = String(unpromotedSuspects.length);
  document.getElementById("pill-rules").textContent = String(staticTotal + dynCount);
  document.getElementById("pill-events").textContent = String((currentState.recentEvents || []).length);

  // KPIs
  document.getElementById("kpi-network-blocked").textContent = (m.totalNetworkBlocked || 0).toLocaleString();
  document.getElementById("kpi-sanitized").textContent = (
    (m.queryStripped || 0) + (m.headersModified || 0)
  ).toLocaleString();
  document.getElementById("kpi-cosmetic").textContent = (
    (m.cosmeticHidden || 0) + (m.videoAdsSkipped || 0)
  ).toLocaleString();
  document.getElementById("kpi-suspects").textContent = suspects.length.toLocaleString();
  document.getElementById("kpi-active-rules").textContent = `${staticTotal} + ${dynCount}`;
  document.getElementById("kpi-covered-domains").textContent = `${staticDomains + dynCount} domains in static + learned sets`;
  document.getElementById("kpi-bytes-saved").textContent = formatBytes(m.estimatedBytesSaved || 0);

  // Chart 1: Protection Layer Bars
  renderBarList("chart-layer-bars", [
    { label: "Core Ad Networks (ads_core)", value: m.adsBlocked || 0, color: "#10b981" },
    { label: "Cross-Site Trackers (trackers_privacy)", value: m.trackersBlocked || 0, color: "#38bdf8" },
    { label: "URL & Header Privacy Sanitizer", value: (m.queryStripped || 0) + (m.headersModified || 0), color: "#6366f1" },
    { label: "Cosmetic DOM & Video Ad Guard", value: (m.cosmeticHidden || 0) + (m.videoAdsSkipped || 0), color: "#a855f7" },
    { label: "Sponsored Chumboxes & Annoyances", value: m.annoyancesBlocked || 0, color: "#f59e0b" },
    { label: "Learned / Custom Dynamic Rules", value: m.dynamicRulesMatched || 0, color: "#ec4899" }
  ]);

  // Chart 2: Resource Type Aggregation
  const resCounts = {
    script: 0,
    xmlhttprequest: 0,
    sub_frame: 0,
    ping: 0,
    image: 0,
    media: 0
  };
  for (const d of Object.values(currentState.domainStats || {})) {
    for (const [rType, cnt] of Object.entries(d.resourceTypes || {})) {
      if (resCounts[rType] !== undefined) {
        resCounts[rType] += cnt;
      } else {
        resCounts.script += 0;
      }
    }
  }
  renderBarList("chart-resource-bars", [
    { label: "JavaScript Bundles (script)", value: resCounts.script, color: "#38bdf8" },
    { label: "XHR / Fetch Auction & Beacons", value: resCounts.xmlhttprequest, color: "#10b981" },
    { label: "Ad Iframes (sub_frame)", value: resCounts.sub_frame, color: "#f59e0b" },
    { label: "HTML5 Pings & CSP Reports (ping)", value: resCounts.ping, color: "#ef4444" },
    { label: "Tracking Pixels & Banners (image)", value: resCounts.image, color: "#a855f7" },
    { label: "Video VAST / Pre-Roll Streams", value: resCounts.media + (m.videoAdsSkipped || 0), color: "#6366f1" }
  ]);

  // Table: Top Blocked Domains
  const topDomainsBody = document.getElementById("tbody-top-domains");
  topDomainsBody.innerHTML = "";
  const sortedDomains = Object.values(currentState.domainStats || {}).sort((a, b) => b.count - a.count);
  if (sortedDomains.length === 0) {
    topDomainsBody.innerHTML = `<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 18px;">No blocked domain telemetry yet. Browse the web or click <b>"🧪 Load Sample Research Dataset"</b> above.</td></tr>`;
  } else {
    for (const d of sortedDomains.slice(0, 12)) {
      const siteCount = (d.initiatorSites || []).length;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono" style="color: var(--accent-blue); font-weight: 600;">${d.host}</td>
        <td>
          <div>${d.vendor || d.category}</div>
          <span class="tag">${d.category || "Blocked"}</span>
        </td>
        <td style="font-weight: 800;">${d.count.toLocaleString()}</td>
        <td><span class="tag emerald">${siteCount} site${siteCount === 1 ? "" : "s"}</span></td>
      `;
      topDomainsBody.appendChild(tr);
    }
  }

  // Table: Top Tracker-Heavy Websites
  const topSitesBody = document.getElementById("tbody-top-sites");
  topSitesBody.innerHTML = "";
  const sortedSites = Object.values(currentState.siteStats || {}).sort(
    (a, b) => b.blocked + b.cosmetic - (a.blocked + a.cosmetic)
  );
  if (sortedSites.length === 0) {
    topSitesBody.innerHTML = `<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 18px;">No website telemetry recorded yet.</td></tr>`;
  } else {
    for (const s of sortedSites.slice(0, 12)) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono" style="font-weight: 700;">${s.site}</td>
        <td style="color: var(--accent-emerald); font-weight: 700;">${(s.blocked || 0).toLocaleString()}</td>
        <td style="color: var(--accent-blue);">${((s.cosmetic || 0) + (s.video || 0)).toLocaleString()}</td>
        <td><span class="tag amber">${(s.thirdPartyTrackers || []).length} trackers</span></td>
      `;
      topSitesBody.appendChild(tr);
    }
  }

  // ==========================================================================
  // TAB 2: HEURISTIC DISCOVERY & RULE LAB
  // ==========================================================================
  document.getElementById("dash-chk-autolearn").checked = Boolean(currentState.autoLearnEnabled);

  const suspectsBody = document.getElementById("tbody-suspects");
  suspectsBody.innerHTML = "";
  const sortedSuspects = suspects.sort((a, b) => b.confidence - a.confidence);
  if (sortedSuspects.length === 0) {
    suspectsBody.innerHTML = `<tr><td colspan="6" style="color: var(--text-muted); text-align: center; padding: 20px;">No unblocked heuristic suspects flagged yet. Click <b>"🧪 Load Sample Research Dataset"</b> to test the Rule Synthesizer.</td></tr>`;
  } else {
    for (const s of sortedSuspects) {
      const tr = document.createElement("tr");
      const signalTags = (s.signals || [])
        .map((sig) => `<span class="tag blue">${sig}</span>`)
        .join("");
      const siteList = (s.initiatorSites || []).join(", ") || "—";

      const tdHost = document.createElement("td");
      tdHost.innerHTML = `
        <div class="mono" style="font-weight: 700; color: var(--text-primary);">${s.candidateHost}</div>
        <div class="mono" style="font-size: 11px; color: var(--text-muted); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${s.sampleUrl || ""}">${s.sampleUrl || ""}</div>
      `;

      const tdConf = document.createElement("td");
      tdConf.innerHTML = `<span class="tag ${s.confidence >= 85 ? "amber" : "blue"}" style="font-size: 12px;">${s.confidence}%</span>`;

      const tdCat = document.createElement("td");
      tdCat.textContent = s.category || "Suspect Resource";

      const tdSigs = document.createElement("td");
      tdSigs.innerHTML = signalTags;

      const tdSites = document.createElement("td");
      tdSites.className = "mono";
      tdSites.textContent = siteList;

      const tdAct = document.createElement("td");
      if (s.promotedRuleId) {
        tdAct.innerHTML = `<span class="tag emerald">✓ Blocked (Rule #${s.promotedRuleId})</span>`;
      } else {
        const btnPromote = document.createElement("button");
        btnPromote.className = "btn emerald";
        btnPromote.style.cssText = "padding: 4px 10px; font-size: 11.5px; min-height: 28px; margin-right: 6px;";
        btnPromote.textContent = "+ Promote to DNR Rule";
        btnPromote.addEventListener("click", () => {
          chrome.runtime.sendMessage(
            {
              type: "PROMOTE_SUSPECT_TO_RULE",
              domain: s.baseDomain || s.candidateHost,
              category: s.category,
              confidence: s.confidence,
              signals: s.signals,
              source: "Research Studio Promotion"
            },
            () => {
              showToast(`Promoted ${s.baseDomain || s.candidateHost} to active DNR rule!`);
              fetchDashboardState();
            }
          );
        });

        const btnIgnore = document.createElement("button");
        btnIgnore.className = "btn";
        btnIgnore.style.cssText = "padding: 4px 8px; font-size: 11px; min-height: 28px;";
        btnIgnore.textContent = "Ignore";
        btnIgnore.addEventListener("click", () => {
          chrome.runtime.sendMessage({ type: "IGNORE_SUSPECT", host: s.candidateHost }, () => {
            showToast(`Ignored ${s.candidateHost}`);
            fetchDashboardState();
          });
        });

        tdAct.appendChild(btnPromote);
        tdAct.appendChild(btnIgnore);
      }

      tr.appendChild(tdHost);
      tr.appendChild(tdConf);
      tr.appendChild(tdCat);
      tr.appendChild(tdSigs);
      tr.appendChild(tdSites);
      tr.appendChild(tdAct);
      suspectsBody.appendChild(tr);
    }
  }

  // Synthesized DNR JSON Preview
  const synthRules = buildSynthesizedDnrJson(currentState);
  document.getElementById("synthesized-json-preview").textContent = JSON.stringify(synthRules, null, 2);

  // False-Positive & Page Breakage Diagnostics Table
  const fpBody = document.getElementById("tbody-false-positives");
  if (fpBody) {
    fpBody.innerHTML = "";
    const fpList = Object.values(currentState.falsePositiveReports || {}).sort((a, b) => b.lastSeen - a.lastSeen);
    if (fpList.length === 0) {
      fpBody.innerHTML = `<tr><td colspan="5" style="color: var(--text-muted); text-align: center; padding: 18px;">No false-positive or page breakage signals detected.</td></tr>`;
    } else {
      for (const fp of fpList) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono" style="font-weight: 700;">${fp.site}</td>
          <td class="mono" style="color: var(--accent-amber);">${fp.blockedDomain}</td>
          <td>
            <span class="tag amber">${fp.reason}</span>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${fp.detail || ""}</div>
          </td>
          <td class="mono">${fp.ruleId ? `#${fp.ruleId}` : "—"}</td>
          <td></td>
        `;
        const tdFix = tr.lastElementChild;
        if (fp.mitigated) {
          tdFix.innerHTML = `<span class="tag emerald">✓ Allowed on ${fp.site}</span>`;
        } else {
          const btnAllow = document.createElement("button");
          btnAllow.className = "btn amber";
          btnAllow.style.cssText = "padding: 4px 10px; font-size: 11.5px; min-height: 28px;";
          btnAllow.textContent = `Allow ${fp.baseDomain || fp.blockedDomain} on ${fp.site}`;
          btnAllow.addEventListener("click", () => {
            chrome.runtime.sendMessage(
              {
                type: "ALLOW_DOMAIN_ON_SITE",
                site: fp.site,
                domain: fp.baseDomain || fp.blockedDomain
              },
              () => {
                showToast(`Created surgical allow rule for ${fp.baseDomain || fp.blockedDomain} on ${fp.site}`);
                fetchDashboardState();
              }
            );
          });
          tdFix.appendChild(btnAllow);
        }
        fpBody.appendChild(tr);
      }
    }
  }

  // ==========================================================================
  // TAB 3: RULESETS, DYNAMIC RULES, ALLOWLIST & AUDITOR
  // ==========================================================================
  const rulesetCards = document.getElementById("ruleset-cards");
  rulesetCards.innerHTML = "";
  for (const rs of STATIC_RULESET_META) {
    const isEnabled = enabledRulesets.includes(rs.id);
    const ruleCount = (ruleCatalog.summary && ruleCatalog.summary.rulesets && ruleCatalog.summary.rulesets[rs.id]) || 0;
    const card = document.createElement("div");
    card.className = "ruleset-card";
    card.innerHTML = `
      <div>
        <div style="font-weight: 700; font-size: 13.5px; color: var(--text-primary);">${rs.title}</div>
        <div style="font-size: 11.5px; color: var(--text-secondary); margin-top: 3px;">${rs.desc}</div>
        <div style="margin-top: 6px;"><span class="tag blue">${ruleCount} compiled DNR rules</span></div>
      </div>
    `;
    const chk = document.createElement("input");
    chk.type = "checkbox";
    chk.checked = isEnabled;
    chk.style.cssText = "width: 18px; height: 18px; cursor: pointer; accent-color: #10b981;";
    chk.addEventListener("change", () => {
      chrome.runtime.sendMessage(
        {
          type: "TOGGLE_STATIC_RULESET",
          rulesetId: rs.id,
          enable: chk.checked
        },
        () => {
          showToast(`${rs.id} ${chk.checked ? "enabled" : "disabled"}`);
          fetchDashboardState();
        }
      );
    });
    card.appendChild(chk);
    rulesetCards.appendChild(card);
  }

  // Dynamic Block Rules Table
  const dynBody = document.getElementById("tbody-dynamic-rules");
  dynBody.innerHTML = "";
  const dynRules = currentState.dynamicBlockRules || [];
  if (dynRules.length === 0) {
    dynBody.innerHTML = `<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 14px;">No custom or promoted dynamic rules yet.</td></tr>`;
  } else {
    for (const r of dynRules) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">#${r.id}</td>
        <td class="mono" style="color: var(--accent-emerald); font-weight: 700;">||${r.domain}^</td>
        <td><span class="tag">${r.source || "Custom"}</span></td>
        <td></td>
      `;
      const btnDel = document.createElement("button");
      btnDel.className = "btn danger";
      btnDel.style.cssText = "padding: 3px 8px; font-size: 11px; min-height: 26px;";
      btnDel.textContent = "Remove";
      btnDel.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "REMOVE_DYNAMIC_RULE", ruleId: r.id }, () => {
          showToast(`Removed dynamic rule #${r.id}`);
          fetchDashboardState();
        });
      });
      tr.lastElementChild.appendChild(btnDel);
      dynBody.appendChild(tr);
    }
  }

  // Allowlist & Zapped Selectors Table
  const allowBody = document.getElementById("tbody-allowlist-and-zapper");
  allowBody.innerHTML = "";
  const allowSites = currentState.allowlistedSites || [];
  const zappedMap = currentState.customSelectorsBySite || {};
  let hasAllowOrZap = false;

  for (const site of allowSites) {
    hasAllowOrZap = true;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono" style="font-weight: 700;">${site}</td>
      <td><span class="tag amber">Allowlisted (Shield Paused)</span></td>
      <td></td>
    `;
    const btnRemove = document.createElement("button");
    btnRemove.className = "btn";
    btnRemove.style.cssText = "padding: 3px 8px; font-size: 11px; min-height: 26px;";
    btnRemove.textContent = "Re-Enable Shield";
    btnRemove.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "TOGGLE_SITE_PAUSE", site, tabId: -1 }, () => {
        showToast(`Protection re-enabled on ${site}`);
        fetchDashboardState();
      });
    });
    tr.lastElementChild.appendChild(btnRemove);
    allowBody.appendChild(tr);
  }

  for (const [site, selectors] of Object.entries(zappedMap)) {
    for (const sel of selectors) {
      hasAllowOrZap = true;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${site}</td>
        <td class="mono" style="color: var(--accent-blue);">${sel}</td>
        <td></td>
      `;
      const btnDel = document.createElement("button");
      btnDel.className = "btn danger";
      btnDel.style.cssText = "padding: 3px 8px; font-size: 11px; min-height: 26px;";
      btnDel.textContent = "Delete";
      btnDel.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "REMOVE_CUSTOM_SELECTOR", site, selector: sel }, () => {
          showToast(`Removed selector ${sel}`);
          fetchDashboardState();
        });
      });
      tr.lastElementChild.appendChild(btnDel);
      allowBody.appendChild(tr);
    }
  }

  for (const exc of currentState.siteDomainExceptions || []) {
    hasAllowOrZap = true;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${exc.site}</td>
      <td><span class="tag emerald">Surgical Allow: ${exc.domain}</span></td>
      <td></td>
    `;
    const btnDel = document.createElement("button");
    btnDel.className = "btn danger";
    btnDel.style.cssText = "padding: 3px 8px; font-size: 11px; min-height: 26px;";
    btnDel.textContent = "Remove";
    btnDel.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "REMOVE_SITE_DOMAIN_EXCEPTION", site: exc.site, domain: exc.domain }, () => {
        showToast(`Removed surgical exception for ${exc.domain} on ${exc.site}`);
        fetchDashboardState();
      });
    });
    tr.lastElementChild.appendChild(btnDel);
    allowBody.appendChild(tr);
  }

  if (!hasAllowOrZap) {
    allowBody.innerHTML = `<tr><td colspan="3" style="color: var(--text-muted); text-align: center; padding: 14px;">No allowlisted sites or zapped selectors yet.</td></tr>`;
  }

  // Rule Effectiveness Auditor Table
  renderRuleAuditorTable();

  // ==========================================================================
  // TAB 4: LIVE TELEMETRY STREAM
  // ==========================================================================
  renderLiveStreamTable();
}

function renderRuleAuditorTable() {
  if (!currentState) return;
  const tbody = document.getElementById("tbody-rule-auditor");
  tbody.innerHTML = "";

  const hitsMap = currentState.ruleHits || {};
  const allCatalogRules = Object.values(ruleCatalog.rules || {});
  const merged = allCatalogRules.map((r) => ({
    ...r,
    count: (hitsMap[String(r.id)] && hitsMap[String(r.id)].count) || 0
  }));

  for (const dyn of currentState.dynamicBlockRules || []) {
    merged.push({
      id: dyn.id,
      ruleset: "dynamic_custom",
      vendor: `Learned / Custom (${dyn.domain})`,
      category: dyn.category || "Learned Block",
      patternSummary: `||${dyn.domain}^`,
      count: (hitsMap[String(dyn.id)] && hitsMap[String(dyn.id)].count) || 0
    });
  }

  const q = ruleAuditorQuery.toLowerCase().trim();
  const filtered = merged
    .filter((r) => {
      if (!q) return true;
      return (
        String(r.id).includes(q) ||
        (r.vendor || "").toLowerCase().includes(q) ||
        (r.category || "").toLowerCase().includes(q) ||
        (r.patternSummary || "").toLowerCase().includes(q) ||
        (r.ruleset || "").toLowerCase().includes(q)
      );
    })
    .sort((a, b) => b.count - a.count || a.id - b.id);

  for (const r of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${r.id}</td>
      <td><span class="tag blue">${r.ruleset}</span></td>
      <td style="font-weight: 600;">${r.vendor}</td>
      <td>${r.category}</td>
      <td class="mono" style="color: var(--text-secondary);">${r.patternSummary}</td>
      <td style="font-weight: 800; color: ${r.count > 0 ? "var(--accent-emerald)" : "var(--text-muted)"};">
        ${r.count.toLocaleString()}
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function renderLiveStreamTable() {
  if (!currentState) return;
  const tbody = document.getElementById("tbody-live-stream");
  tbody.innerHTML = "";

  const q = streamSearchQuery.toLowerCase().trim();
  const events = (currentState.recentEvents || []).filter((evt) => {
    if (activeStreamKind !== "ALL") {
      if (activeStreamKind === "COSMETIC") {
        if (evt.kind !== "COSMETIC" && evt.kind !== "VIDEO_SKIP" && evt.kind !== "ZAPPER") return false;
      } else if (evt.kind !== activeStreamKind) {
        return false;
      }
    }
    if (!q) return true;
    return (
      (evt.initiatorSite || "").toLowerCase().includes(q) ||
      (evt.targetHost || "").toLowerCase().includes(q) ||
      (evt.vendor || "").toLowerCase().includes(q) ||
      (evt.url || "").toLowerCase().includes(q)
    );
  });

  if (events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="color: var(--text-muted); text-align: center; padding: 20px;">No matching telemetry events in buffer.</td></tr>`;
    return;
  }

  for (const evt of events.slice(0, 120)) {
    const tr = document.createElement("tr");
    const badgeClass =
      evt.kind === "BLOCKED"
        ? "emerald"
        : evt.kind === "SUSPECT"
        ? "amber"
        : "blue";

    tr.innerHTML = `
      <td class="mono" style="color: var(--text-muted);">${formatTime(evt.ts)}</td>
      <td><span class="tag ${badgeClass}">${evt.kind}</span></td>
      <td class="mono">${evt.initiatorSite || "—"}</td>
      <td class="mono" style="font-weight: 600; color: var(--text-primary);">${evt.targetHost || "—"}</td>
      <td class="mono">${evt.resourceType || "—"}</td>
      <td>
        <div>${evt.vendor || ""}</div>
        <div class="mono" style="font-size: 11px; color: var(--text-muted);">${evt.ruleId ? `Rule #${evt.ruleId} (${evt.ruleset})` : evt.ruleset}</div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function fetchDashboardState() {
  chrome.runtime.sendMessage({ type: "GET_DASHBOARD_STATE" }, (resp) => {
    if (resp && resp.ok) {
      currentState = resp.state;
      ruleCatalog = resp.ruleCatalog || { rules: {}, summary: {} };
      enabledRulesets = resp.enabledRulesets || [];
      renderDashboard();
    }
  });
}

function downloadJsonFile(filename, dataObj) {
  const blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ============================================================================
// Universal Command Palette (Cmd+K / Ctrl+K)
// ============================================================================
const COMMAND_ITEMS = [
  {
    title: "📊 Jump to Overview & Blocker Analytics",
    hint: "Tab 1",
    run: () => switchTab("tab-overview")
  },
  {
    title: "🔬 Jump to Heuristic Discovery & Rule Lab",
    hint: "Tab 2",
    run: () => switchTab("tab-heuristics")
  },
  {
    title: "🛡️ Jump to DNR Ruleset Auditor & Allowlist",
    hint: "Tab 3",
    run: () => switchTab("tab-rules")
  },
  {
    title: "⚡ Jump to Live Telemetry Stream",
    hint: "Tab 4",
    run: () => switchTab("tab-stream")
  },
  {
    title: "🧪 Load Sample Multi-Site Research Dataset",
    hint: "Benchmark",
    run: () => document.getElementById("btn-seed-demo").click()
  },
  {
    title: "⚡ Bulk Promote All ≥80% Confidence Heuristic Suspects",
    hint: "Auto-Synthesize",
    run: () => document.getElementById("btn-bulk-promote").click()
  },
  {
    title: "📥 Export Full Telemetry & Synthesized DNR JSON",
    hint: "JSON Snapshot",
    run: () => document.getElementById("btn-export-telemetry").click()
  },
  {
    title: "🗑️ Reset Telemetry Counters & Event Logs",
    hint: "Clear Stats",
    run: () => document.getElementById("btn-reset-telemetry").click()
  }
];

function renderCommandPalette(filterText = "") {
  const listEl = document.getElementById("cmd-list");
  listEl.innerHTML = "";
  const q = filterText.toLowerCase().trim();
  const matches = COMMAND_ITEMS.filter(
    (c) => !q || c.title.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q)
  );
  for (const item of matches) {
    const btn = document.createElement("button");
    btn.className = "cmd-item";
    btn.innerHTML = `<span>${item.title}</span><span class="kbd-hint">${item.hint}</span>`;
    btn.addEventListener("click", () => {
      document.getElementById("cmd-palette").close();
      item.run();
    });
    listEl.appendChild(btn);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  fetchDashboardState();

  // Auto-refresh when chrome.storage.local updates
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.nulkast_block_state_v1) {
      currentState = changes.nulkast_block_state_v1.newValue;
      renderDashboard();
    }
  });

  // Tab switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Load Sample Research Dataset
  document.getElementById("btn-seed-demo").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "SEED_DEMO_TELEMETRY" }, (resp) => {
      if (resp && resp.ok) {
        showToast("Loaded sample multi-site blocker & evasion research dataset!");
        fetchDashboardState();
      }
    });
  });

  // Export Research JSON
  document.getElementById("btn-export-telemetry").addEventListener("click", () => {
    if (!currentState) return;
    const payload = {
      exportedAt: new Date().toISOString(),
      extension: "NulKast-Block MV3",
      state: currentState,
      synthesizedDnrRules: buildSynthesizedDnrJson(currentState)
    };
    downloadJsonFile(`nulkast-block-telemetry-${Date.now()}.json`, payload);
    showToast("Exported research telemetry JSON!");
  });

  // Reset Telemetry
  document.getElementById("btn-reset-telemetry").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "RESET_TELEMETRY" }, () => {
      showToast("Telemetry stats reset.");
      fetchDashboardState();
    });
  });

  // Heuristic Lab controls
  document.getElementById("dash-chk-autolearn").addEventListener("change", (e) => {
    chrome.runtime.sendMessage(
      {
        type: "TOGGLE_AUTO_LEARN",
        enabled: e.target.checked
      },
      () => {
        showToast(e.target.checked ? "Auto-Learn Enabled (≥85%)" : "Auto-Learn Disabled");
        fetchDashboardState();
      }
    );
  });

  document.getElementById("btn-bulk-promote").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "BULK_PROMOTE_SUSPECTS", minConfidence: 80 }, (resp) => {
      const cnt = (resp && resp.promotedCount) || 0;
      showToast(cnt > 0 ? `Promoted ${cnt} high-confidence suspect(s) to DNR rules!` : "No unpromoted suspects ≥80% found.");
      fetchDashboardState();
    });
  });

  document.getElementById("btn-copy-synthesized").addEventListener("click", async () => {
    const text = document.getElementById("synthesized-json-preview").textContent;
    await navigator.clipboard.writeText(text);
    showToast("Copied synthesized DNR ruleset JSON to clipboard!");
  });

  document.getElementById("btn-download-synthesized").addEventListener("click", () => {
    if (!currentState) return;
    const rules = buildSynthesizedDnrJson(currentState);
    downloadJsonFile("synthesized_learned_rules.json", rules);
    showToast("Downloaded synthesized_learned_rules.json!");
  });

  // Add Custom Domain Rule
  document.getElementById("btn-add-custom-domain").addEventListener("click", () => {
    const input = document.getElementById("input-custom-domain");
    const domain = (input.value || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!domain) return;
    chrome.runtime.sendMessage(
      {
        type: "PROMOTE_SUSPECT_TO_RULE",
        domain,
        category: "Manual Custom Block",
        confidence: 100,
        signals: ["MANUAL_USER_RULE"],
        source: "Manual Custom Entry"
      },
      () => {
        input.value = "";
        showToast(`Blocked ||${domain}^ in dynamic DNR table`);
        fetchDashboardState();
      }
    );
  });

  // Add Allowlist Site
  document.getElementById("btn-add-allowlist").addEventListener("click", () => {
    const input = document.getElementById("input-allowlist-site");
    const site = (input.value || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!site) return;
    chrome.runtime.sendMessage({ type: "TOGGLE_SITE_PAUSE", site, tabId: -1 }, () => {
      input.value = "";
      showToast(`Allowlisted ${site}`);
      fetchDashboardState();
    });
  });

  // Rule Auditor Search
  document.getElementById("input-rule-search").addEventListener("input", (e) => {
    ruleAuditorQuery = e.target.value;
    renderRuleAuditorTable();
  });

  // Live Stream Filters & Search
  document.querySelectorAll("#stream-filter-pills .filter-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#stream-filter-pills .filter-pill").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeStreamKind = btn.dataset.kind;
      renderLiveStreamTable();
    });
  });

  document.getElementById("input-stream-search").addEventListener("input", (e) => {
    streamSearchQuery = e.target.value;
    renderLiveStreamTable();
  });

  // Command Palette (Ctrl+K / Cmd+K) and "/" shortcut
  const cmdDialog = document.getElementById("cmd-palette");
  const cmdInput = document.getElementById("cmd-input");

  document.getElementById("btn-cmd-palette").addEventListener("click", () => {
    renderCommandPalette("");
    cmdInput.value = "";
    cmdDialog.showModal();
    cmdInput.focus();
  });

  cmdInput.addEventListener("input", () => {
    renderCommandPalette(cmdInput.value);
  });

  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (cmdDialog.open) {
        cmdDialog.close();
      } else {
        renderCommandPalette("");
        cmdInput.value = "";
        cmdDialog.showModal();
        cmdInput.focus();
      }
      return;
    }

    const activeTag = (document.activeElement && document.activeElement.tagName) || "";
    if (e.key === "/" && activeTag !== "INPUT" && activeTag !== "TEXTAREA") {
      e.preventDefault();
      const ruleSearch = document.getElementById("input-rule-search");
      const streamSearch = document.getElementById("input-stream-search");
      if (document.getElementById("tab-stream").classList.contains("active")) {
        streamSearch.focus();
      } else {
        switchTab("tab-rules");
        ruleSearch.focus();
      }
    }
  });
});
