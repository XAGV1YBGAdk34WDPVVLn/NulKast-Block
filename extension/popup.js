/**
 * NulKast-Block — Popup Controller
 */

let currentTabId = -1;
let currentSite = "";
let isSitePaused = false;

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function showToast(text) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = text;
  el.style.display = "block";
  setTimeout(() => {
    el.style.display = "none";
  }, 1800);
}

function sendMsg(payload, cb) {
  try {
    chrome.runtime.sendMessage(payload, (resp) => {
      if (chrome.runtime.lastError) return;
      if (typeof cb === "function") cb(resp);
    });
  } catch (_) {}
}

function renderPopup(data) {
  const shieldCard = document.getElementById("shield-card");
  const statusText = document.getElementById("status-text");
  const siteHostname = document.getElementById("site-hostname");
  const siteHint = document.getElementById("site-hint");
  const btnToggleSite = document.getElementById("btn-toggle-site");

  isSitePaused = Boolean(data.isSitePaused);

  if (!currentSite) {
    siteHostname.textContent = "Browser Internal Page";
    statusText.textContent = "System Page";
    siteHint.textContent = "Network DNR Shield active globally";
    btnToggleSite.disabled = true;
    btnToggleSite.style.opacity = "0.5";
  } else {
    siteHostname.textContent = currentSite;
    btnToggleSite.disabled = false;
    btnToggleSite.style.opacity = "1";
    if (isSitePaused) {
      shieldCard.classList.add("paused");
      statusText.textContent = "Paused on this site";
      siteHint.textContent = "Ads & trackers are currently allowed here";
      btnToggleSite.textContent = "Enable Shield";
    } else {
      shieldCard.classList.remove("paused");
      statusText.textContent = "Protection Active";
      siteHint.textContent = "Blocking ads, trackers & URL click-IDs";
      btnToggleSite.textContent = "Pause Site";
    }
  }

  const tStats = data.tabStats || { blocked: 0, cosmetic: 0, sanitized: 0 };
  const sStats = data.siteStat || { blocked: 0, cosmetic: 0, sanitized: 0 };

  document.getElementById("page-blocked").textContent = String(
    Math.max(tStats.blocked || 0, sStats.blocked || 0)
  );
  document.getElementById("page-cosmetic").textContent = String(
    Math.max(tStats.cosmetic || 0, sStats.cosmetic || 0)
  );
  document.getElementById("page-sanitized").textContent = String(
    Math.max(tStats.sanitized || 0, sStats.sanitized || 0)
  );

  const m = data.metrics || {};
  const totalBlocked = (m.totalNetworkBlocked || 0) + (m.cosmeticHidden || 0);
  document.getElementById("total-blocked").textContent = totalBlocked.toLocaleString();
  document.getElementById("total-saved").textContent = formatBytes(m.estimatedBytesSaved || 0);

  const staticCount = (data.staticRuleSummary && data.staticRuleSummary.totalStaticRules) || 48;
  const dynCount = data.dynamicRuleCount || 0;
  document.getElementById("total-rules").textContent = `${staticCount} + ${dynCount} learned`;

  document.getElementById("chk-autolearn").checked = Boolean(data.autoLearnEnabled);

  const chkCaptcha = document.getElementById("chk-allow-captcha");
  const captchaSub = document.getElementById("captcha-toggle-sub");
  if (chkCaptcha) {
    if (data.allowCaptchaGlobally) {
      chkCaptcha.checked = true;
      chkCaptcha.disabled = true;
      if (captchaSub) captchaSub.textContent = "Allowed globally (manage in Analytics Lab)";
    } else if (!currentSite) {
      chkCaptcha.checked = false;
      chkCaptcha.disabled = true;
      if (captchaSub) captchaSub.textContent = "Open a website to allow CAPTCHAs per-site";
    } else {
      chkCaptcha.disabled = false;
      chkCaptcha.checked = Boolean(data.siteCaptchaExplicit);
      if (captchaSub) {
        captchaSub.textContent = data.siteCaptchaExplicit
          ? "CAPTCHAs & bot checks allowed on this site"
          : "Allow reCAPTCHA, Turnstile, hCaptcha & bot checks";
      }
    }
  }

  // Render Heuristic Suspects
  const suspects = data.siteSuspects || [];
  const totalSuspects = data.totalSuspectCount || suspects.length;
  document.getElementById("suspect-badge-count").textContent = `${totalSuspects} candidate${totalSuspects === 1 ? "" : "s"}`;

  const listEl = document.getElementById("suspect-list");
  listEl.innerHTML = "";

  if (suspects.length === 0) {
    const empty = document.createElement("div");
    empty.style.cssText = "font-size: 11px; color: var(--text-muted); padding: 4px 0;";
    empty.textContent =
      totalSuspects > 0
        ? `${totalSuspects} suspect domain(s) waiting in Analytics Lab.`
        : "No unblocked ad/tracker evasions detected on this page.";
    listEl.appendChild(empty);
  } else {
    for (const s of suspects.slice(0, 3)) {
      const row = document.createElement("div");
      row.className = "suspect-item";

      const hostSpan = document.createElement("span");
      hostSpan.className = "suspect-host";
      hostSpan.title = `${s.candidateHost} (${(s.signals || []).join(", ")})`;
      hostSpan.textContent = s.baseDomain || s.candidateHost;

      const scoreSpan = document.createElement("span");
      scoreSpan.className = "suspect-score";
      scoreSpan.textContent = `${s.confidence}%`;

      const blockBtn = document.createElement("button");
      blockBtn.className = "btn-mini-block";
      blockBtn.textContent = "+ Block";
      blockBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage(
          {
            type: "PROMOTE_SUSPECT_TO_RULE",
            domain: s.baseDomain || s.candidateHost,
            category: s.category,
            confidence: s.confidence,
            signals: s.signals,
            source: "Popup 1-Click Block"
          },
          () => {
            showToast(`Blocked ${s.baseDomain || s.candidateHost}`);
            refreshPopup();
          }
        );
      });

      row.appendChild(hostSpan);
      row.appendChild(scoreSpan);
      row.appendChild(blockBtn);
      listEl.appendChild(row);
    }
  }

  // Render False-Positive / Breakage Diagnostics if any exist for this site
  const fpCard = document.getElementById("fp-card");
  const fpList = document.getElementById("fp-list");
  const fps = data.siteFalsePositives || [];
  if (fpCard && fpList) {
    if (fps.length === 0) {
      fpCard.style.display = "none";
      fpList.innerHTML = "";
    } else {
      fpCard.style.display = "block";
      document.getElementById("fp-badge-count").textContent = `${fps.length} breakage signal${fps.length === 1 ? "" : "s"}`;
      fpList.innerHTML = "";
      for (const fp of fps.slice(0, 2)) {
        const row = document.createElement("div");
        row.className = "suspect-item";

        const hostSpan = document.createElement("span");
        hostSpan.className = "suspect-host";
        hostSpan.title = `${fp.reason}: ${fp.detail || fp.blockedDomain}`;
        hostSpan.textContent = `${fp.baseDomain || fp.blockedDomain} (${fp.reason})`;

        const allowBtn = document.createElement("button");
        allowBtn.className = "btn-mini-block";
        allowBtn.textContent = "Allow Here";
        allowBtn.addEventListener("click", () => {
          chrome.runtime.sendMessage(
            {
              type: "ALLOW_DOMAIN_ON_SITE",
              site: fp.site || currentSite,
              domain: fp.baseDomain || fp.blockedDomain
            },
            () => {
              showToast(`Allowed ${fp.baseDomain || fp.blockedDomain} on ${fp.site || currentSite}`);
              refreshPopup();
            }
          );
        });

        row.appendChild(hostSpan);
        row.appendChild(allowBtn);
        fpList.appendChild(row);
      }
    }
  }
}

async function refreshPopup() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    currentTabId = typeof tab.id === "number" ? tab.id : -1;
    if (tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
      try {
        currentSite = new URL(tab.url).hostname.toLowerCase().replace(/^www\./, "");
      } catch (_) {
        currentSite = "";
      }
    } else {
      currentSite = "";
    }
  }

  sendMsg(
    {
      type: "GET_POPUP_DATA",
      tabId: currentTabId,
      site: currentSite
    },
    (resp) => {
      if (resp && resp.ok) {
        renderPopup(resp);
      }
    }
  );
}

document.addEventListener("DOMContentLoaded", () => {
  refreshPopup();

  document.getElementById("btn-toggle-site").addEventListener("click", () => {
    if (!currentSite) return;
    chrome.runtime.sendMessage(
      {
        type: "TOGGLE_SITE_PAUSE",
        site: currentSite,
        tabId: currentTabId
      },
      (resp) => {
        if (resp && resp.ok) {
          refreshPopup();
        }
      }
    );
  });

  document.getElementById("chk-allow-captcha").addEventListener("change", (e) => {
    if (!currentSite) return;
    const enabled = e.target.checked;
    chrome.runtime.sendMessage(
      {
        type: "TOGGLE_SITE_CAPTCHA",
        site: currentSite,
        enabled
      },
      () => {
        showToast(
          enabled
            ? `CAPTCHAs allowed on ${currentSite} — reload if needed`
            : `CAPTCHA allowance removed for ${currentSite}`
        );
        refreshPopup();
      }
    );
  });

  document.getElementById("chk-autolearn").addEventListener("change", (e) => {
    chrome.runtime.sendMessage(
      {
        type: "TOGGLE_AUTO_LEARN",
        enabled: e.target.checked
      },
      () => {
        showToast(e.target.checked ? "Auto-Learn Enabled (≥85%)" : "Auto-Learn Paused");
        refreshPopup();
      }
    );
  });

  document.getElementById("btn-zapper").addEventListener("click", async () => {
    if (currentTabId >= 0) {
      chrome.tabs.sendMessage(currentTabId, { type: "START_ELEMENT_ZAPPER" }).catch(() => {});
      window.close();
    }
  });

  document.getElementById("btn-open-lab").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
});
