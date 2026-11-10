/**
 * AegisBlock Surrogate — Google IMA3 Video Ad SDK (ima3.js)
 * Prevents HTML5/Video.js/Brightcove/JWPlayer video players from hanging on a black
 * spinner when pre-roll ad requests are blocked by immediately signaling completion.
 */
(() => {
  const noop = () => {};
  window.google = window.google || {};
  const ima = window.google.ima || {};

  const AdEventType = {
    AD_BREAK_READY: "adBreakReady",
    AD_BUFFERING: "adBuffering",
    AD_CAN_PLAY: "adCanPlay",
    AD_METADATA: "adMetadata",
    AD_PROGRESS: "adProgress",
    ALL_ADS_COMPLETED: "allAdsCompleted",
    CLICK: "click",
    COMPLETE: "complete",
    CONTENT_PAUSE_REQUESTED: "contentPauseRequested",
    CONTENT_RESUME_REQUESTED: "contentResumeRequested",
    DURATION_CHANGE: "durationChange",
    FIRST_QUARTILE: "firstQuartile",
    IMPRESSION: "impression",
    INTERACTION: "interaction",
    LINEAR_CHANGED: "linearChanged",
    LOADED: "loaded",
    LOG: "log",
    MIDPOINT: "midpoint",
    PAUSED: "paused",
    RESUMED: "resumed",
    SKIPPABLE_STATE_CHANGED: "skippableStateChanged",
    SKIPPED: "skipped",
    STARTED: "started",
    THIRD_QUARTILE: "thirdQuartile",
    USER_CLOSE: "userClose",
    VIDEO_CLICKED: "videoClicked",
    VIDEO_ICON_CLICKED: "videoIconClicked",
    VOLUME_CHANGED: "volumeChanged",
    VOLUME_MUTED: "volumeMuted"
  };

  const AdErrorEventType = { AD_ERROR: "adError" };
  const AdsManagerLoadedEventType = { ADS_MANAGER_LOADED: "adsManagerLoaded" };

  class EventTargetStub {
    constructor() {
      this._listeners = {};
    }
    addEventListener(type, fn) {
      if (!this._listeners[type]) this._listeners[type] = [];
      if (typeof fn === "function") this._listeners[type].push(fn);
    }
    removeEventListener(type, fn) {
      if (!this._listeners[type]) return;
      this._listeners[type] = this._listeners[type].filter((f) => f !== fn);
    }
    _emit(type, payload) {
      const list = this._listeners[type] || [];
      for (const fn of list) {
        try {
          fn(payload);
        } catch (_) {}
      }
    }
  }

  class AdsManagerStub extends EventTargetStub {
    collapse() {}
    configureAdsManager() {}
    destroy() {}
    discardAdBreak() {}
    expand() {}
    focus() {}
    getAdSkippableState() { return true; }
    getCuePoints() { return []; }
    getCurrentAd() { return null; }
    getCurrentAdCuePoints() { return []; }
    getRemainingTime() { return 0; }
    getVolume() { return 0; }
    init() {}
    isCustomClickTrackingUsed() { return false; }
    isCustomPlaybackUsed() { return false; }
    pause() {}
     focus() {}
    resize() {}
    resume() {}
    setVolume() {}
    skip() {}
    start() {
      setTimeout(() => {
        this._emit(AdEventType.CONTENT_RESUME_REQUESTED, { type: AdEventType.CONTENT_RESUME_REQUESTED });
        this._emit(AdEventType.ALL_ADS_COMPLETED, { type: AdEventType.ALL_ADS_COMPLETED });
      }, 1);
    }
    stop() {}
    updateAdsRenderingSettings() {}
  }

  class AdsLoaderStub extends EventTargetStub {
    constructor() {
      super();
      this._settings = new ImaSdkSettingsStub();
    }
    contentComplete() {}
    destroy() {}
    getSettings() { return this._settings; }
     getVersion() { return "3.600.0"; }
    requestAds() {
      const manager = new AdsManagerStub();
      setTimeout(() => {
        this._emit(AdsManagerLoadedEventType.ADS_MANAGER_LOADED, {
          type: AdsManagerLoadedEventType.ADS_MANAGER_LOADED,
          getAdsManager: () => manager,
          getUserRequestContext: () => ({})
        });
        this._emit(AdErrorEventType.AD_ERROR, {
          type: AdErrorEventType.AD_ERROR,
          getError: () => new AdErrorStub(),
          getUserRequestContext: () => ({})
        });
      }, 1);
    }
  }

  class AdDisplayContainerStub {
    initialize() {}
    destroy() {}
  }

  class AdsRequestStub {
    setAdWillAutoPlay() {}
    setAdWillPlayMuted() {}
    setContinuousPlayback() {}
  }

  class AdsRenderingSettingsStub {}
  class CompanionAdSelectionSettingsStub {}
  class ImaSdkSettingsStub {
    getCompanionBackfill() { return ""; }
    getDisableCustomPlaybackForIOS10Plus() { return false; }
    getFeatureFlags() { return {}; }
    getLocale() { return "en"; }
    getNumRedirects() { return 0; }
    getPlayerType() { return ""; }
    getPlayerVersion() { return ""; }
    getPpid() { return ""; }
    isCookiesEnabled() { return false; }
    setAutoPlayAdBreaks() {}
    setCompanionBackfill() {}
    setCookiesEnabled() {}
    setDisableCustomPlaybackForIOS10Plus() {}
    setFeatureFlags() {}
    setLocale() {}
    setNumRedirects() {}
    setPageCorrelator() {}
    setPlayerType() {}
    setPlayerVersion() {}
    setPpid() {}
    setSessionId() {}
    setStreamCorrelator() {}
    setVpaidAllowed() {}
    setVpaidMode() {}
  }

  class AdErrorStub {
    getErrorCode() { return 1009; }
    getInnerError() { return null; }
    getMessage() { return "The VAST response document is empty."; }
    getType() { return "adPlayError"; }
    getVastErrorCode() { return 303; }
    toString() { return "AdError 1009: The VAST response document is empty."; }
  }

  ima.AdDisplayContainer = AdDisplayContainerStub;
  ima.AdsLoader = AdsLoaderStub;
  ima.AdsManager = AdsManagerStub;
  ima.AdsManagerLoadedEvent = { Type: AdsManagerLoadedEventType };
  ima.AdsRenderingSettings = AdsRenderingSettingsStub;
  ima.AdsRequest = AdsRequestStub;
  ima.AdError = AdErrorStub;
  ima.AdErrorEvent = { Type: AdErrorEventType };
  ima.AdEvent = { Type: AdEventType };
  ima.CompanionAdSelectionSettings = CompanionAdSelectionSettingsStub;
  ima.CustomContentLoadedEvent = { Type: { CUSTOM_CONTENT_LOADED: "customContentLoaded" } };
  ima.ImaSdkSettings = ImaSdkSettingsStub;
  ima.OmidAccessMode = { DOMAIN: "domain", FULL: "full", LIMITED: "limited" };
  ima.UiElements = { AD_ATTRIBUTION: "adAttribution", COUNTDOWN: "countdown" };
  ima.ViewMode = { FULLSCREEN: "fullscreen", NORMAL: "normal" };
  ima.VERSION = "3.600.0";
  ima.settings = new ImaSdkSettingsStub();
  ima.init = noop;

  window.google.ima = ima;
})();
