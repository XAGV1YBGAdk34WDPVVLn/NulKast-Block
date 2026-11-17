/**
 * NulKast-Block Surrogate — Google Publisher Tags (gpt.js / pubads_impl.js)
 * Neutralizes GPT ad requests while satisfying publisher page scripts expecting window.googletag.
 */
(() => {
  const noop = () => {};
  const noopThis = function () { return this; };
  const noopNull = () => null;
  const noopArray = () => [];
  const noopStr = () => "";
  const noopBool = () => false;

  const gt = window.googletag || {};
  const existingCmd = Array.isArray(gt.cmd) ? gt.cmd.slice() : [];

  function createSlotMock(adUnitPath, size, optDiv) {
    const targeting = {};
    const slot = {
      addService: noopThis,
      clearCategoryExclusions: noopThis,
      clearTargeting: function (k) {
        if (k) delete targeting[k];
        else Object.keys(targeting).forEach((key) => delete targeting[key]);
        return this;
      },
      defineSizeMapping: noopThis,
      get: noopNull,
      getAdUnitPath: () => adUnitPath || "",
      getAttributeKeys: noopArray,
      getCategoryExclusions: noopArray,
      getDomId: () => optDiv || "",
      getName: () => adUnitPath || "",
      getResponseInformation: noopNull,
      getServices: noopArray,
      getSizes: () => (Array.isArray(size) ? size : []),
      getSlotElementId: () => optDiv || "",
      getSlotId: () => ({
        getAdUnitPath: () => adUnitPath || "",
        getDomId: () => optDiv || "",
        getId: () => optDiv || "slot_0",
        getName: () => adUnitPath || "",
        toString: () => optDiv || "slot_0"
      }),
      getTargeting: (k) => (k && targeting[k] ? targeting[k] : []),
      getTargetingKeys: () => Object.keys(targeting),
      set: noopThis,
      setCategoryExclusion: noopThis,
      setClickUrl: noopThis,
      setCollapseEmptyDiv: noopThis,
      setForceSafeFrame: noopThis,
      setSafeFrameConfig: noopThis,
      setTargeting: function (k, v) {
        if (k) targeting[k] = Array.isArray(v) ? v : [String(v)];
        return this;
      },
      updateTargetingFromMap: noopThis
    };
    return slot;
  }

  const slots = [];
  const listeners = {};
  const pubadsService = {
    addEventListener: function (type, fn) {
      if (!listeners[type]) listeners[type] = [];
      if (typeof fn === "function") {
        listeners[type].push(fn);
        if (type === "slotRenderEnded" || type === "slotOnload") {
          setTimeout(() => {
            try {
              const mockSlot = slots[0] || createSlotMock("/nulkast/slot", [[728, 90]], "div-gpt-ad-0");
              fn({
                isEmpty: false,
                size: [728, 90],
                slot: mockSlot,
                serviceName: "publisher_ads"
              });
            } catch (_) {}
          }, 0);
        }
      }
      return this;
    },
    clear: noopBool,
    clearCategoryExclusions: noopThis,
    clearTagForChildDirectedTreatment: noopThis,
    clearTargeting: noopThis,
    collapseEmptyDivs: noopBool,
    defineOutOfPagePassback: () => createSlotMock(),
    definePassback: () => createSlotMock(),
    disableInitialLoad: noop,
    display: noop,
    enableAsyncRendering: noopBool,
    enableLazyLoad: noop,
    enableSingleRequest: noopBool,
    enableSyncRendering: noopBool,
    enableVideoAds: noop,
    get: noopNull,
    getAttributeKeys: noopArray,
    getCorrelator: noopStr,
    getSlots: () => slots.slice(),
    getSlotIdMap: () => ({}),
    getTargeting: noopArray,
    getTargetingKeys: noopArray,
    isInitialLoadDisabled: noopBool,
    refresh: noop,
    removeEventListener: noopBool,
    set: noopThis,
    setCategoryExclusion: noopThis,
    setCentering: noop,
    setCookieOptions: noopThis,
    setForceSafeFrame: noopThis,
    setLocation: noopThis,
    setPrivacySettings: noopThis,
    setPublisherProvidedId: noopThis,
    setRequestNonPersonalizedAds: noopThis,
    setSafeFrameConfig: noopThis,
    setTagForChildDirectedTreatment: noopThis,
    setTagForUnderAgeOfConsent: noopThis,
    setTargeting: noopThis,
    setVideoContent: noop,
    updateCorrelator: noopThis
  };

  const companionAdsService = {
    addEventListener: noopThis,
    enableSyncLoading: noop,
    setRefreshUnfilledSlots: noop,
    getSlots: noopArray
  };

  const contentService = {
    addEventListener: noopThis,
    setContent: noop
  };

  gt.apiReady = true;
  gt.pubadsReady = true;
  gt.version = "2026110101";
  gt.companionAds = () => companionAdsService;
  gt.content = () => contentService;
  gt. pubads = () => pubadsService;
  gt.defineSlot = (adUnitPath, size, optDiv) => {
    const s = createSlotMock(adUnitPath, size, optDiv);
    slots.push(s);
    return s;
  };
  gt.defineOutOfPageSlot = (adUnitPath, optDiv) => {
    const s = createSlotMock(adUnitPath, [], optDiv);
    slots.push(s);
    return s;
  };
  gt.defineUnit = gt.defineSlot;
  gt.destroySlots = () => {
    slots.length = 0;
    return true;
  };
  gt.disablePublisherConsole = noop;
  gt.display = noop;
  gt.enableServices = noop;
  gt.getVersion = () => gt.version;
  gt.openConsole = noop;
  gt.setAdIframeTitle = noop;
  gt.sizeMapping = () => ({
    addSize: noopThis,
    build: noopArray
  });

  const cmdQueue = [];
  cmdQueue.push = function (...fns) {
    for (const fn of fns) {
      if (typeof fn === "function") {
        try {
          fn();
        } catch (_) {}
      }
    }
    return cmdQueue.length;
  };
  gt.cmd = cmdQueue;
  window.googletag = gt;

  for (const fn of existingCmd) {
    cmdQueue.push(fn);
  }
})();
