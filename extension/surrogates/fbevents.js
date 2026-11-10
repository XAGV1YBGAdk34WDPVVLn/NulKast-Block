/**
 * AegisBlock Surrogate — Meta / Facebook Pixel (fbevents.js)
 * Prevents ReferenceError when e-commerce checkout buttons call fbq('track', ...).
 */
(() => {
  if (typeof window.fbq === "function" && window.fbq.loaded) return;
  const noop = () => {};
  const fbq = function () {};
  fbq.callMethod = noop;
  fbq.push = noop;
  fbq.loaded = true;
  fbq.version = "2.0";
  fbq.queue = [];
  fbq.getState = () => ({ pixelInitializationTime: Date.now(), pixels: [] });
  window.fbq = fbq;
  window._fbq = fbq;
})();
