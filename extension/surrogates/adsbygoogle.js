/**
 * AegisBlock Surrogate — Google AdSense (adsbygoogle.js)
 * Satisfies publisher scripts checking window.adsbygoogle.loaded without network calls.
 */
(() => {
  const adsbygoogle = window.adsbygoogle || [];
  adsbygoogle.loaded = true;
  adsbygoogle.push = function () {
    return 0;
  };
  window.adsbygoogle = adsbygoogle;

  const markDone = () => {
    const nodes = document.querySelectorAll("ins.adsbygoogle");
    for (const el of nodes) {
      el.setAttribute("data-adsbygoogle-status", "done");
      el.setAttribute("data-ad-status", "unfilled");
    }
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", markDone, { once: true });
  } else {
    markDone();
  }
})();
