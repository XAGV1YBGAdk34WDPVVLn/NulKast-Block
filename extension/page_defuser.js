/**
 * NulKast-Block — MAIN World Pre-Execution Anti-Adblock & Scroll-Lock Defuser
 * Runs at `document_start` in the page's MAIN JS world to disarm Admiral ("Powered by Admiral"),
 * Google Funding Choices, and BlockAdBlock before inline or tag-manager scripts can initialize them.
 */
(() => {
  const isPaused = () =>
    document.documentElement &&
    document.documentElement.getAttribute("data-nulkast-block-paused") === "true";

  if (isPaused()) return;

  const noop = () => {};

  // 1. Disarm Admiral (`window.admiral`) command queue & event hooks
  const inertQueue = [];
  inertQueue.push = function () {
    return 0;
  };

  const admiralStub = function (cmd, eventName, callback) {
    if (isPaused()) return;
    // Never fire "measure.detected" or "arget.detected" callbacks; if a script listens for non-blocked state, satisfy it
    if (cmd === "after" && typeof callback === "function" && /detected/i.test(String(eventName))) {
      return;
    }
  };
  admiralStub.q = inertQueue;
  admiralStub.v = 2;
  admiralStub.s = "1";

  try {
    Object.defineProperty(window, "admiral", {
      get() {
        return admiralStub;
      },
      set() {},
      configurable: false,
      enumerable: true
    });
  } catch (_) {
    window.admiral = admiralStub;
  }

  // 2. Satisfy common global bait flags checked by publisher anti-adblock scripts
  try {
    Object.defineProperty(window, "canRunAds", {
      get: () => true,
      set: noop,
      configurable: true
    });
    Object.defineProperty(window, "isAdBlockActive", {
      get: () => false,
      set: noop,
      configurable: true
    });
  } catch (_) {
    window.canRunAds = true;
    window.isAdBlockActive = false;
  }

  // 3. Neutralize BlockAdBlock / FuckAdBlock constructors & instances
  const InertDetector = function () {};
  InertDetector.prototype.on = function (detected, fn) {
    if (!detected && typeof fn === "function") {
      try { fn(); } catch (_) {}
    }
    return this;
  };
  InertDetector.prototype.onDetected = function () { return this; };
  InertDetector.prototype.onNotDetected = function (fn) {
    if (typeof fn === "function") {
      try { fn(); } catch (_) {}
    }
    return this;
  };
  InertDetector.prototype.check = () => true;
  InertDetector.prototype.setOption = function () { return this; };

  try {
    const detectorInstance = new InertDetector();
    for (const prop of ["BlockAdBlock", "FuckAdBlock"]) {
      Object.defineProperty(window, prop, {
        get: () => InertDetector,
        set: noop,
        configurable: true
      });
    }
    for (const prop of ["blockAdBlock", "fuckAdBlock"]) {
      Object.defineProperty(window, prop, {
        get: () => detectorInstance,
        set: noop,
        configurable: true
      });
    }
  } catch (_) {}

  // 4. Intercept dynamic <script> injection for known Admiral / anti-adblock bootstrapper URLs
  const BLOCKED_SCRIPT_PATTERNS =
    /(getadmiral\.com|chalkdream\.com|succeedscene\.com|RCe0c7c73598674c2288fae1d365c8dd9d|fundingchoicesmessages\.google\.com|blockadblock|fuckadblock)/i;

  function isBlockedAntiAdblockScript(node) {
    if (isPaused() || !node || node.nodeType !== 1 || node.tagName !== "SCRIPT") return false;
    const src = String(node.src || node.getAttribute("src") || "");
    if (src && BLOCKED_SCRIPT_PATTERNS.test(src)) {
      return true;
    }
    const text = String(node.textContent || "");
    if (
      text &&
      (text.includes("window,\"admiral\"") ||
        text.includes("window,'admiral'") ||
        text.includes("chalkdream.com") ||
        text.includes("getadmiral.com"))
    ) {
      return true;
    }
    return false;
  }

  const origInsertBefore = Node.prototype.insertBefore;
  Node.prototype.insertBefore = function (newNode, refNode) {
    if (isBlockedAntiAdblockScript(newNode)) {
      const dummy = document.createElement("script");
      dummy.type = "text/plain";
      dummy.setAttribute("data-nulkast-stripped", "admiral-script");
      return origInsertBefore.call(this, dummy, refNode);
    }
    return origInsertBefore.call(this, newNode, refNode);
  };

  const origAppendChild = Node.prototype.appendChild;
  Node.prototype.appendChild = function (newNode) {
    if (isBlockedAntiAdblockScript(newNode)) {
      const dummy = document.createElement("script");
      dummy.type = "text/plain";
      dummy.setAttribute("data-nulkast-stripped", "admiral-script");
      return origAppendChild.call(this, dummy);
    }
    return origAppendChild.call(this, newNode);
  };
})();
