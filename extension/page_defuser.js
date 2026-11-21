/**
 * NulKast-Block — MAIN World Pre-Execution Anti-Adblock & Scroll-Lock Defuser
 * Runs at `document_start` in the page's MAIN JS world to disarm Admiral ("Powered by Admiral"),
 * Google Funding Choices, and BlockAdBlock before inline or tag-manager scripts can initialize them.
 */
(() => {
  if (window.__nulkastPageDefuserLoaded) return;
  window.__nulkastPageDefuserLoaded = true;

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
    // Never fire "measure.detected" or "target.detected" callbacks
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
      configurable: true,
      enumerable: true
    });
  } catch (_) {
    try {
      window.admiral = admiralStub;
    } catch (_) {}
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
    try {
      window.canRunAds = true;
      window.isAdBlockActive = false;
    } catch (_) {}
  }

  // 3. Neutralize BlockAdBlock / FuckAdBlock constructors & instances
  let fuckYourAdLogged = false;
  const triggerFuckYourAd = () => {
    try {
      window.fuckYourAd = true;
    } catch (_) {}
    if (!fuckYourAdLogged) {
      fuckYourAdLogged = true;
      try {
        console.info("[NulKast-Block] fuckAdBlock intercepted -> fuckYourAd");
      } catch (_) {}
    }
  };

  const InertDetector = function () {};
  InertDetector.prototype.reply = "fuckYourAd";
  InertDetector.prototype.on = function (detected, fn) {
    if (detected) {
      triggerFuckYourAd();
    } else if (typeof fn === "function") {
      try { fn(); } catch (_) {}
    }
    return this;
  };
  InertDetector.prototype.onDetected = function () {
    triggerFuckYourAd();
    return this;
  };
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

  // 4. Intercept dynamic <script> src assignment for known Admiral / anti-adblock bootstrapper URLs
  // (Targets HTMLScriptElement.prototype.src instead of Node.prototype.appendChild/insertBefore
  // so unrelated website DOMExceptions never appear in the extension error console.)
  const BLOCKED_SCRIPT_PATTERNS =
    /(getadmiral\.com|chalkdream\.com|succeedscene\.com|RCe0c7c73598674c2288fae1d365c8dd9d|fundingchoicesmessages\.google\.com|blockadblock|fuckadblock)/i;

  try {
    const srcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");
    if (srcDesc && typeof srcDesc.set === "function" && typeof srcDesc.get === "function") {
      Object.defineProperty(HTMLScriptElement.prototype, "src", {
        configurable: true,
        enumerable: true,
        get() {
          return srcDesc.get.call(this);
        },
        set(val) {
          if (!isPaused() && val && BLOCKED_SCRIPT_PATTERNS.test(String(val))) {
            try {
              this.type = "text/plain";
              this.setAttribute("data-nulkast-stripped", "admiral-script");
            } catch (_) {}
            return;
          }
          return srcDesc.set.call(this, val);
        }
      });
    }
  } catch (_) {}
})();
