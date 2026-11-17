/**
 * NulKast-Block Surrogate — Google Analytics & GTag (analytics.js / gtag/js)
 * Preserves outbound link navigation by invoking hitCallback / event_callback immediately.
 */
(() => {
  const noop = () => {};
  const gaName = window.GoogleAnalyticsObject || "ga";

  function gaStub(...args) {
    const last = args[args.length - 1];
    if (last && typeof last === "object" && typeof last.hitCallback === "function") {
      setTimeout(() => {
        try {
          last.hitCallback();
        } catch (_) {}
      }, 1);
    } else if (typeof last === "function") {
      setTimeout(() => {
        try {
          last({
            get: () => "",
            set: noop,
            send: noop
          });
        } catch (_) {}
      }, 1);
    }
  }

  gaStub.q = (window[gaName] && window[gaName].q) || [];
  gaStub.l = Date.now();
  gaStub.loaded = true;
  gaStub.create = () => ({ get: () => "", set: noop, send: noop });
  gaStub.getByName = () => null;
  gaStub.getAll = () => [];
  gaStub.remove = noop;

  window.GoogleAnalyticsObject = gaName;
  window[gaName] = gaStub;

  window.dataLayer = window.dataLayer || [];
  const origPush = window.dataLayer.push.bind(window.dataLayer);
  window.dataLayer.push = function (...items) {
    for (const item of items) {
      const cfg = item && typeof item === "object" ? item[2] || item : null;
      if (cfg && typeof cfg.event_callback === "function") {
        setTimeout(() => {
          try {
            cfg.event_callback();
          } catch (_) {}
        }, 1);
      }
    }
    return origPush(...items);
  };

  window.gtag =
    window.gtag ||
    function () {
      window.dataLayer.push(arguments);
    };
})();
