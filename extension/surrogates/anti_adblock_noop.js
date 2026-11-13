/**
 * AegisBlock Surrogate — Anti-Adblock & Visitor Recovery Neutralizer (Admiral, Funding Choices, BlockAdBlock)
 * Satisfies anti-adblock scripts expecting window.admiral / window.googlefc / window.BlockAdBlock without triggering modals.
 */
(() => {
  const noop = () => {};
  const noopTrue = () => true;
  const noopFalse = () => false;

  const admiralFn = function () {};
  admiralFn.q = [];
  admiralFn.v = 2;
  admiralFn.s = "1";

  try {
    Object.defineProperty(window, "admiral", {
      get: () => admiralFn,
      set: noop,
      configurable: false
    });
  } catch (_) {
    window.admiral = admiralFn;
  }

  try {
    window.canRunAds = true;
    window.isAdBlockActive = false;
    window.googlefc = window.googlefc || {
      ccpa: { getInitialCcpaStatus: noop, overrideDnsLink: false },
       callbackQueue: []
    };
  } catch (_) {}

  const FakeAdBlockDetector = function () {};
  FakeAdBlockDetector.prototype.on = function (detected, fn) {
    if (!detected && typeof fn === "function") {
      try { fn(); } catch (_) {}
    }
    return this;
  };
  FakeAdBlockDetector.prototype.onDetected = function () { return this; };
  FakeAdBlockDetector.prototype.onNotDetected = function (fn) {
    if (typeof fn === "function") {
      try { fn(); } catch (_) {}
    }
    return this;
  };
  FakeAdBlockDetector.prototype.check = noopTrue;
  FakeAdBlockDetector.prototype.emitEvent = function () { return this; };
  FakeAdBlockDetector.prototype.clearEvent = noop;
  FakeAdBlockDetector.prototype.setOption = function () { return this; };

  try {
    window.BlockAdBlock = FakeAdBlockDetector;
    window.FuckAdBlock = FakeAdBlockDetector;
    window.blockAdBlock = new FakeAdBlockDetector();
    window.fuckAdBlock = new FakeAdBlockDetector();
  } catch (_) {}
})();
