#!/usr/bin/env python3
"""
AegisBlock MV3 Static DeclarativeNetRequest (DNR) Ruleset & Icon Compiler.
Generates validated Chromium/Edge Manifest V3 static rulesets, a human-readable
rule catalog for the Research & Analytics Studio, and crisp PNG toolbar icons.
"""

import json
import math
import struct
import zlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EXT_DIR = ROOT_DIR / "extension"
RULES_DIR = EXT_DIR / "rules"
ICONS_DIR = EXT_DIR / "icons"

ALL_RESOURCE_TYPES_EXCEPT_MAIN = [
    "sub_frame",
    "stylesheet",
    "script",
    "image",
    "font",
    "object",
    "xmlhttprequest",
    "ping",
    "csp_report",
    "media",
    "websocket",
    "webtransport",
    "webbundle",
    "other",
]


def build_ads_core_rules():
    """
    Ruleset 1: ads_core (IDs 1001 - 1999)
    High-performance requestDomains clusters + surgical urlFilter rules.
    """
    rules = []
    catalog = {}
    rule_id = 1001

    vendor_clusters = [
        (
            "Google Ads & DoubleClick RTB",
            "Ad Network / RTB",
            [
                "doubleclick.net",
                "googlesyndication.com",
                "googleadservices.com",
                "adservice.google.com",
                "pagead2.googlesyndication.com",
                "tpc.googlesyndication.com",
                "ade.googlesyndication.com",
                "afs.googlesyndication.com",
                "imasdk.googleapis.com",
                "2mdn.net",
                "admeld.com",
                "invitemedia.com",
            ],
        ),
        (
            "Amazon Advertising & AAX",
            "Ad Network / RTB",
            [
                "amazon-adsystem.com",
                "aax.amazon-adsystem.com",
                "c.amazon-adsystem.com",
                "s.amazon-adsystem.com",
                "fls-na.amazon-adsystem.com",
                "aan.amazon.com",
                "assoc-amazon.com",
                "serving-sys.com",
                "sizmek.com",
            ],
        ),
        (
            "Microsoft / Xandr / AppNexus Ad Exchange",
            "Ad Network / RTB",
            [
                "adnxs.com",
                "ib.adnxs.com",
                "secure.adnxs.com",
                "acdn.adnxs.com",
                "adnxs-simple.com",
                "ads.msn.com",
                "adnexus.net",
                "bat.bing.com",
                "r.bing.com",
            ],
        ),
        (
            "Programmatic Header Bidding & SSP Exchanges",
            "Programmatic SSP",
            [
                "rubiconproject.com",
                "fastlane.rubiconproject.com",
                "pubmatic.com",
                "ads.pubmatic.com",
                "hbopenbid.pubmatic.com",
                "openx.net",
                "us-u.openx.net",
                "indexww.com",
                "casalemedia.com",
                "htlb.casalemedia.com",
                "smartadserver.com",
                "cedato.com",
                "sovrn.com",
                "lijit.com",
                "33across.com",
                "3lift.com",
                "triplelift.com",
                "tlx.3lift.com",
                "contextweb.com",
                "bidswitch.net",
                "gumgum.com",
                "kargo.com",
                "sharethrough.com",
                "sonobi.com",
                "spotxchange.com",
                "spotx.tv",
                "teads.tv",
                "a.teads.tv",
                "yieldmo.com",
                "media.net",
                " contextual.media.net",
                "adform.net",
                "adition.com",
                "improvedigital.com",
                "onetag-sys.com",
                "richaudience.com",
                "rhythmone.com",
                "synacor.com",
                "undertone.com",
                "mps.vsnt.net",
                "app.mps.vsnt.net",
                "mps.nbcuni.com",
            ],
        ),
        (
            "Criteo, RTB House & Retargeting Networks",
            "Retargeting Ads",
            [
                "criteo.com",
                "criteo.net",
                "bidder.criteo.com",
                "gum.criteo.com",
                "static.criteo.net",
                "rtbhouse.com",
                "creativecdn.com",
                "adsrvr.org",
                "match.adsrvr.org",
                "js.adsrvr.org",
                "insight.adsrvr.org",
                "adroll.com",
                "d.adroll.com",
                "s.adroll.com",
                "steelhousemedia.com",
                " TellApart.com",
                "nextroll.com",
            ],
        ),
        (
            "Mobile, In-App & Banner Ad Networks",
            "Display / Banner Ads",
            [
                "admob.com",
                "inmobi.com",
                "unityads.unity3d.com",
                "applovin.com",
                "applvn.com",
                "vungle.com",
                "chartboost.com",
                "ironsrc.com",
                "fyber.com",
                "smaato.net",
                "mopub.com",
                "adcolony.com",
                "tapjoy.com",
                "startappservice.com",
                "flurry.com",
                "conversantmedia.com",
                "fastclick.net",
                "valueclick.com",
                "zedo.com",
                "tribalfusion.com",
                "exponential.com",
                "adtech.de",
                "adtechus.com",
                "advertising.com",
                "bidvertiser.com",
                "chitika.net",
                "kontera.com",
                "vibrantmedia.com",
                "intellitxt.com",
                "buysellads.com",
                "carbonads.com",
                "carbonads.net",
                "ethicalads.io",
            ],
        ),
        (
            "Popunders, Adware & Aggressive Click Networks",
            "Popunder / High-Risk Ads",
            [
                "popads.net",
                "popcash.net",
                "propellerads.com",
                "propellerclick.com",
                "adcash.com",
                "adsterra.com",
                "adsterratech.com",
                "exoclick.com",
                "exosrv.com",
                "juicyads.com",
                "trafficjunky.net",
                "trafficstars.com",
                "clickadu.com",
                "hilltopads.net",
                "hilltopads.com",
                "ero-advertising.com",
                "plugrush.com",
                "popmyads.com",
                "popunder.net",
                "admaven.com",
                "ad-maven.com",
                "bidpush.com",
                "pushame.com",
                "pushengage.com",
                "richpush.co",
                "evadav.com",
                "galaksion.com",
                "zeroredirect1.com",
                "parkingcrew.net",
                "sedoparking.com",
                "bodis.com",
            ],
        ),
        (
            "Video VAST / VPAID & CTV Ad Servers",
            "Video Ads",
            [
                "fwmrm.net",
                "freewheel.tv",
                "innovid.com",
                "springserve.com",
                "vid.springserve.com",
                "aniview.com",
                "connatix.com",
                "primis.tech",
                "playwire.com",
                "vidoomy.com",
                "vi.ai",
                "brid.tv",
                "jwpltx.com",
                "b.jw-cdn.com",
                "unrulymedia.com",
                "tremorhub.com",
                "telaria.com",
                "beachfront.com",
                "lkqd.net",
                "brightroll.com",
            ],
        ),
        (
            "Ad Verification & Viewability Beacons",
            "Ad Verification",
            [
                "moatads.com",
                "z.moatads.com",
                "px.moatads.com",
                "adsafeprotected.com",
                "pixel.adsafeprotected.com",
                "fw.adsafeprotected.com",
                "doubleverify.com",
                "cdn.doubleverify.com",
                "tps.doubleverify.com",
                "integralads.com",
                "iasds01.com",
                "whiteops.com",
                "humansecurity.com",
                "confiant-integrations.net",
                "geoedge.be",
            ],
        ),
    ]

    for vendor, category, domains in vendor_clusters:
        clean_domains = sorted({d.strip().lower() for d in domains if d.strip()})
        rules.append(
            {
                "id": rule_id,
                "priority": 10,
                "action": {"type": "block"},
                "condition": {
                    "requestDomains": clean_domains,
                    "resourceTypes": ALL_RESOURCE_TYPES_EXCEPT_MAIN,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "ads_core",
            "vendor": vendor,
            "category": category,
            "description": f"Blocks {len(clean_domains)} domains in {vendor}",
            "patternSummary": f"{clean_domains[0]} (+{len(clean_domains) - 1} more)",
        }
        rule_id += 1

    # High-signal URL pattern rules for third-party ad delivery & Prebid/VAST endpoints
    # Note: Chromium's C++ url_pattern_index forbids `||*` (subdomain anchor followed by wildcard).
    # Substring path matching `/...` with `domainType: "thirdParty"` is the valid Chromium MV3 pattern.
    # SDKs that cause anti-adblock walls or player hangs when hard-blocked use priority-30 local surrogate redirects.
    url_patterns = [
        ("/pagead/js/adsbygoogle.js", "Google AdSense Script (Surrogate Stub)", "Ad Script Surrogate", ["script"], "/surrogates/adsbygoogle.js"),
        ("/pagead/lvz?", "Google PageAd Beacon", "Ad Beacon", ALL_RESOURCE_TYPES_EXCEPT_MAIN, None),
        ("/gpt/pubads_impl", "Google Publisher Tags (GPT Surrogate)", "Ad Script Surrogate", ["script"], "/surrogates/googletag_gpt.js"),
        ("/tag/js/gpt.js", "Google Publisher Tags Bootstrap (Surrogate)", "Ad Script Surrogate", ["script"], "/surrogates/googletag_gpt.js"),
        ("/prebid*.js", "Prebid.js Header Bidding Engine", "Programmatic SSP", ["script"], None),
        ("/hb_bidder*.js", "Header Bidder Bundle", "Programmatic SSP", ["script"], None),
        ("/adserver/*", "Generic Third-Party AdServer Path", "Ad Server", ["script", "sub_frame", "xmlhttprequest", "image"], None),
        ("/adframe.", "Third-Party Ad Iframe", "Ad Iframe", ["sub_frame", "script"], None),
        ("/adbanner/", "Third-Party Ad Banner Asset", "Display / Banner Ads", ["image", "sub_frame", "script"], None),
        ("/vast.xml", "VAST Video Ad Manifest", "Video Ads", ["xmlhttprequest", "other", "media"], None),
        ("/vpaid*.js", "VPAID Video Ad Script", "Video Ads", ["script", "xmlhttprequest"], None),
        ("/ima3.js", "Interactive Media Ads (IMA3 Surrogate)", "Video Ad Surrogate", ["script"], "/surrogates/google_ima3.js"),
        ("/popunder*.js", "Third-Party Popunder Script", "Popunder / High-Risk Ads", ["script"], None),
        ("/ad-delivery/", "Third-Party Ad Delivery Endpoint", "Ad Server", ["script", "xmlhttprequest", "sub_frame"], None),
        ("/sponsored-links", "Third-Party Sponsored Links Widget", "Sponsored Content", ["script", "sub_frame", "xmlhttprequest"], None),
        ("/openrtb2/auction", "OpenRTB 2.x Programmatic Auction Endpoint", "Programmatic SSP", ["xmlhttprequest", "ping"], None),
        ("/bidrequest?", "RTB Bid Request Endpoint", "Programmatic SSP", ["xmlhttprequest", "ping"], None),
    ]

    for url_filter, vendor, category, res_types, surrogate_path in url_patterns:
        action = (
            {"type": "redirect", "redirect": {"extensionPath": surrogate_path}}
            if surrogate_path
            else {"type": "block"}
        )
        rules.append(
            {
                "id": rule_id,
                "priority": 30 if surrogate_path else 10,
                "action": action,
                "condition": {
                    "urlFilter": url_filter,
                    "domainType": "thirdParty",
                    "resourceTypes": res_types,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "ads_core",
            "vendor": vendor,
            "category": category,
            "surrogate": surrogate_path,
            "description": (
                f"Redirects third-party {vendor} ({url_filter}) to inert local surrogate {surrogate_path}"
                if surrogate_path
                else f"Blocks third-party {vendor} ({url_filter})"
            ),
            "patternSummary": f"{url_filter} -> {surrogate_path}" if surrogate_path else url_filter,
        }
        rule_id += 1

    return rules, catalog


def build_trackers_privacy_rules():
    """
    Ruleset 2: trackers_privacy (IDs 2001 - 2999)
    Blocks behavioral analytics, session replay, fingerprinting, pixel beacons, and ping/csp_report telemetry.
    """
    rules = []
    catalog = {}
    rule_id = 2001

    tracker_clusters = [
        (
            "Google Analytics, Tag Manager & Measurement",
            "Analytics & Telemetry",
            [
                "google-analytics.com",
                "ssl.google-analytics.com",
                "www.google-analytics.com",
                "googletagmanager.com",
                "www.googletagmanager.com",
                "googletagservices.com",
                "analytics.google.com",
                "firebaseinstallations.googleapis.com",
                "firebaselogging-pa.googleapis.com",
                "crashlytics.com",
                "app-measurement.com",
            ],
        ),
        (
            "Meta / Facebook Pixel & Cross-Site Graph Trackers",
            "Social & Pixel Tracker",
            [
                "connect.facebook.net",
                "pixel.facebook.com",
                "an.facebook.com",
                "atdmt.com",
                "liverail.com",
            ],
        ),
        (
            "TikTok, X/Twitter, LinkedIn, Pinterest & Snap Pixels",
            "Social & Pixel Tracker",
            [
                "analytics.tiktok.com",
                "business-api.tiktok.com",
                "ads-twitter.com",
                "static.ads-twitter.com",
                "analytics.twitter.com",
                "px.ads.linkedin.com",
                "snap.licdn.com",
                "dc.ads.linkedin.com",
                "ct.pinterest.com",
                "trk.pinterest.com",
                "tr.snapchat.com",
                "alb.reddit.com",
                "events.redditmedia.com",
            ],
        ),
        (
            "Session Replay & Keystroke/Mouse Heatmap Recording",
            "Session Replay / Invasive",
            [
                "hotjar.com",
                "static.hotjar.com",
                "vars.hotjar.com",
                "script.hotjar.com",
                "hotjar.io",
                "fullstory.com",
                "rs.fullstory.com",
                "edge.fullstory.com",
                "clarity.ms",
                "www.clarity.ms",
                "c.clarity.ms",
                "mouseflow.com",
                "cdn.mouseflow.com",
                "crazyegg.com",
                "script.crazyegg.com",
                "luckyorange.com",
                "luckyorange.net",
                "smartlook.com",
                "rec.smartlook.com",
                "inspectlet.com",
                "hn.inspectlet.com",
                "logrocket.com",
                "cdn.logrocket.io",
                "logrocket.io",
                "contentsquare.net",
                "decibelinsight.net",
                "glassboxdigital.io",
                "quantummetric.com",
                "heap.io",
                "heapanalytics.com",
                "cdn.heapanalytics.com",
            ],
        ),
        (
            "Product Analytics, CDP & Event Funnels",
            "Analytics & CDP",
            [
                "mixpanel.com",
                "api.mixpanel.com",
                "cdn.mxpnl.com",
                "segment.io",
                "segment.com",
                "api.segment.io",
                "cdn.segment.com",
                "amplitude.com",
                "api.amplitude.com",
                "cdn.amplitude.com",
                "rudderstack.com",
                "posthog.com",
                "app.posthog.com",
                "kissmetrics.com",
                "pardot.com",
                "pi.pardot.com",
                "marketo.net",
                "munchkin.marketo.net",
                "marketo.com",
                "hs-analytics.net",
                "hs-scripts.com",
                "hsadspixel.net",
                "track.hubspot.com",
                "braze.com",
                "sdk.iad-01.braze.com",
                "appboy.com",
                "clevertap.com",
                "wzrkt.com",
                "optimizely.com",
                "cdn.optimizely.com",
                "logx.optimizely.com",
                "vwo.com",
                "dev.visualwebsiteoptimizer.com",
                "abtasty.com",
                "kameleoon.eu",
            ],
        ),
        (
            "Cross-Site Identity Graphs, DMPs & Audience Trackers",
            "Identity Graph / DMP",
            [
                "scorecardresearch.com",
                "sb.scorecardresearch.com",
                "b.scorecardresearch.com",
                "voicefive.com",
                "quantserve.com",
                "pixel.quantserve.com",
                "secure.quantserve.com",
                "quantcount.com",
                "bluekai.com",
                "tags.bluekai.com",
                "krxd.net",
                "cdn.krxd.net",
                "beacon.krxd.net",
                "demdex.net",
                "dpm.demdex.net",
                "omtrdc.net",
                "2o7.net",
                "adobedtm.com",
                "assets.adobedtm.com",
                "everesttech.net",
                "rlcdn.com",
                "idsync.rlcdn.com",
                "pippio.com",
                "liveintent.com",
                "liadm.com",
                "tapad.com",
                "pixel.tapad.com",
                "lotame.com",
                "crwdcntrl.net",
                "bcp.crwdcntrl.net",
                "exelator.com",
                "agkn.com",
                "neustar.biz",
                "addthis.com",
                "s7.addthis.com",
                "addtoany.com",
                "sharethis.com",
                "w.sharethis.com",
                "id5-sync.com",
                "uidapi.com",
                "intentiq.com",
                "permutive.com",
                "cdn.permutive.com",
                "chartbeat.com",
                "static.chartbeat.com",
                "ping.chartbeat.net",
                "parsely.com",
                "srv.pixel.parsely.com",
                "newrelic.com",
                "nr-data.net",
                "bam.nr-data.net",
                "js-agent.newrelic.com",
                "bugsnag.com",
                "notify.bugsnag.com",
                "datadoghq-browser-agent.com",
                "browser-intake-datadoghq.com",
            ],
        ),
        (
            "Device Fingerprinting & Bot/Fraud Profiling Scripts",
            "Device Fingerprinting",
            [
                "fpjs.io",
                "fpnpmcdn.net",
                "fingerprintjs.com",
                "api.fpjs.io",
                "iovation.com",
                "mpsnare.iesnare.com",
                "threatmetrix.com",
                "h.online-metrix.net",
                "sift.com",
                "cdn.sift.com",
                "siftscience.com",
                "forther.com",
                "perimeterx.net",
                " socure.com",
                "maxmind.com",
            ],
        ),
    ]

    for vendor, category, domains in tracker_clusters:
        clean_domains = sorted({d.strip().lower() for d in domains if d.strip() and "/" not in d})
        rules.append(
            {
                "id": rule_id,
                "priority": 10,
                "action": {"type": "block"},
                "condition": {
                    "requestDomains": clean_domains,
                    "domainType": "thirdParty",
                    "resourceTypes": ALL_RESOURCE_TYPES_EXCEPT_MAIN,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "trackers_privacy",
            "vendor": vendor,
            "category": category,
            "description": f"Blocks {len(clean_domains)} third-party tracking domains in {vendor}",
            "patternSummary": f"{clean_domains[0]} (+{len(clean_domains) - 1} more)",
        }
        rule_id += 1

    # Block all third-party HTML5 <a ping="..."> hyperlink auditing & CSP report telemetry beacons
    rules.append(
        {
            "id": rule_id,
            "priority": 15,
            "action": {"type": "block"},
            "condition": {
                "domainType": "thirdParty",
                "resourceTypes": ["ping", "csp_report"],
            },
        }
    )
    catalog[str(rule_id)] = {
        "id": rule_id,
        "ruleset": "trackers_privacy",
        "vendor": "Browser <a ping> & CSP Beacon Guard",
        "category": "Beacon / Ping Blocker",
        "description": "Blocks all third-party HTML5 hyperlink auditing pings and CSP telemetry beacons",
        "patternSummary": "resourceTypes: [ping, csp_report] (thirdParty)",
    }
    rule_id += 1

    # High-signal URL pattern rules for tracking pixels & telemetry endpoints
    # Note: Chromium's C++ url_pattern_index forbids `||*` (subdomain anchor followed by wildcard).
    # Analytics & Pixel SDKs use priority-30 local surrogate redirects so hitCallback/fbq calls never break page navigation.
    tracker_patterns = [
        ("/analytics.js", "Generic Third-Party analytics.js (Surrogate)", "Tracker Script Surrogate", ["script"], "/surrogates/google_analytics.js"),
        ("/gtag/js?", "Google Global Site Tag (gtag.js Surrogate)", "Tracker Script Surrogate", ["script"], "/surrogates/google_analytics.js"),
        ("/collect?v=1", "Universal Analytics Measurement Collect", "Analytics & Telemetry", ["image", "xmlhttprequest", "ping"], None),
        ("/g/collect?v=2", "GA4 Measurement Collect Endpoint", "Analytics & Telemetry", ["xmlhttprequest", "ping", "image"], None),
        ("/fbevents.js", "Meta Facebook Pixel (fbevents.js Surrogate)", "Tracker Script Surrogate", ["script"], "/surrogates/fbevents.js"),
        ("/scevent.min.js", "Snapchat Pixel Script (sc-static.net)", "Social & Pixel Tracker", ["script"], None),
        ("/pixel.gif", "Third-Party 1x1 Tracking Pixel GIF", "Social & Pixel Tracker", ["image", "ping"], None),
        ("/beacon.js", "Third-Party Telemetry Beacon Script", "Beacon / Ping Blocker", ["script"], None),
        ("/fingerprint*.js", "Third-Party Browser Fingerprinting Script", "Device Fingerprinting", ["script"], None),
        ("/id-sync", "Cross-Domain Cookie ID Sync Endpoint", "Identity Graph / DMP", ["image", "sub_frame", "xmlhttprequest", "script"], None),
        ("/usersync", "Programmatic User-Sync Pixel", "Identity Graph / DMP", ["image", "sub_frame", "xmlhttprequest"], None),
        ("/api/*/envelope/?sentry_key=", "Sentry Third-Party Telemetry Envelope", "Analytics & Telemetry", ["xmlhttprequest", "ping", "other"], None),
    ]

    for url_filter, vendor, category, res_types, surrogate_path in tracker_patterns:
        clean_filter = url_filter.replace(" ", "")
        action = (
            {"type": "redirect", "redirect": {"extensionPath": surrogate_path}}
            if surrogate_path
            else {"type": "block"}
        )
        rules.append(
            {
                "id": rule_id,
                "priority": 30 if surrogate_path else 10,
                "action": action,
                "condition": {
                    "urlFilter": clean_filter,
                    "domainType": "thirdParty",
                    "resourceTypes": res_types,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "trackers_privacy",
            "vendor": vendor,
            "category": category,
            "surrogate": surrogate_path,
            "description": (
                f"Redirects third-party {vendor} ({clean_filter}) to inert local surrogate {surrogate_path}"
                if surrogate_path
                else f"Blocks third-party {vendor} ({clean_filter})"
            ),
            "patternSummary": f"{clean_filter} -> {surrogate_path}" if surrogate_path else clean_filter,
        }
        rule_id += 1

    return rules, catalog


def build_url_privacy_clean_rules():
    """
    Ruleset 3: url_privacy_clean (IDs 3001 - 3999)
    Native C++ query parameter sanitization + privacy header stripping.
    """
    rules = []
    catalog = {}
    rule_id = 3001

    tracking_params = [
        # UTM & Google / Analytics / Merchant Center
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "utm_name",
        "utm_reader",
        "utm_viz_id",
        "utm_pubreferrer",
        "utm_swu",
        "_ga",
        "_gl",
        "_gac",
        "gclid",
        "gclsrc",
        "dclid",
        "wbraid",
        "gbraid",
        "srsltid",
        # Meta / Facebook / Instagram
        "fbclid",
        "fb_action_ids",
        "fb_action_types",
        "fb_source",
        "igshid",
        "igs",
        # Microsoft / Bing
        "msclkid",
        # X / Twitter / TikTok / LinkedIn / Pinterest / Reddit / Snapchat / Yahoo / Yandex
        "twclid",
        "ttclid",
        "li_fat_id",
        "epik",
        "rdt_cid",
        "sccid",
        "yclid",
        "ymclid",
        "s_kwcid",
        "wickedid",
        # Affiliate & E-Commerce Attribution (Impact, CJ Affiliate)
        "irclickid",
        "cjevent",
        # Email & Marketing Automation (Mailchimp, HubSpot, Marketo, Vero, Omeda)
        "mc_cid",
        "mc_eid",
        "_hsenc",
        "_hsmi",
        "hsCtaTracking",
        "mkt_tok",
        "vero_id",
        "oly_enc_id",
        "oly_anon_id",
        "rb_clickid",
        "spm",
        "scm",
        "algo_exp_id",
        "algo_pvid",
    ]

    rules.append(
        {
            "id": rule_id,
            "priority": 5,
            "action": {
                "type": "redirect",
                "redirect": {
                    "transform": {
                        "queryTransform": {
                            "removeParams": tracking_params,
                        }
                    }
                },
            },
            "condition": {
                "resourceTypes": ["main_frame", "sub_frame"],
            },
        }
    )
    catalog[str(rule_id)] = {
        "id": rule_id,
        "ruleset": "url_privacy_clean",
        "vendor": "URL Tracking Parameter Sanitizer",
        "category": "URL Query Sanitizer",
        "description": f"Strips {len(tracking_params)} tracking query parameters (utm_*, fbclid, gclid, srsltid, msclkid, twclid, mc_eid, etc.) before navigation",
        "patternSummary": f"removeParams: [utm_*, fbclid, gclid, srsltid, +{len(tracking_params) - 4} more]",
    }
    rule_id += 1

    # Strip Privacy Sandbox / Ad Topics & Chromium experiment fingerprinting request headers
    rules.append(
        {
            "id": rule_id,
            "priority": 5,
            "action": {
                "type": "modifyHeaders",
                "requestHeaders": [
                    {"header": "Sec-Browsing-Topics", "operation": "remove"},
                    {"header": "Sec-Ad-Auction-Fetch", "operation": "remove"},
                    {"header": "X-Client-Data", "operation": "remove"},
                ],
                "responseHeaders": [
                    {"header": "Observe-Browsing-Topics", "operation": "remove"},
                    {"header": "NEL", "operation": "remove"},
                    {"header": "Report-To", "operation": "remove"},
                    {"header": "Reporting-Endpoints", "operation": "remove"},
                ],
            },
            "condition": {
                "domainType": "thirdParty",
                "resourceTypes": ALL_RESOURCE_TYPES_EXCEPT_MAIN,
            },
        }
    )
    catalog[str(rule_id)] = {
        "id": rule_id,
        "ruleset": "url_privacy_clean",
        "vendor": "HTTP Privacy & Anti-Telemetry Header Guard",
        "category": "Header Privacy Guard",
        "description": "Strips Sec-Browsing-Topics, Sec-Ad-Auction-Fetch, X-Client-Data, NEL, and Report-To headers on third-party requests",
        "patternSummary": "modifyHeaders: remove Browsing-Topics, X-Client-Data, NEL, Report-To",
    }
    rule_id += 1

    return rules, catalog


def build_annoyances_social_rules():
    """
    Ruleset 4: annoyances_social (IDs 4001 - 4999)
    Blocks native recommendation chumboxes (Taboola, Outbrain, Revcontent, MGID) and push-notification nags.
    """
    rules = []
    catalog = {}
    rule_id = 4001

    annoyance_clusters = [
        (
            "Native Chumbox & Sponsored Content Widgets (Taboola, Outbrain, Revcontent, MGID)",
            "Sponsored Chumbox",
            [
                "taboola.com",
                "cdn.taboola.com",
                "trc.taboola.com",
                "images.taboola.com",
                "outbrain.com",
                "widgets.outbrain.com",
                "odb.outbrain.com",
                "log.outbrain.com",
                "outbrainimg.com",
                "revcontent.com",
                "trends.revcontent.com",
                "mgid.com",
                "jsc.mgid.com",
                "servicer.mgid.com",
                "zergnet.com",
                "dianomi.com",
                "nativo.com",
                "plista.com",
                "ligatus.com",
                "contentad.net",
                "adblade.com",
                "LockerDome.com",
            ],
        ),
        (
            "Web Push Notification & Marketing Popups",
            "Annoyances / Push Nags",
            [
                "onesignal.com",
                "cdn.onesignal.com",
                "izooto.com",
                "cdn.izooto.com",
                "pushcrew.com",
                "pushwoosh.com",
                "webpushr.com",
                "aimtell.com",
                "gravitec.net",
                "subscribers.com",
                "sumo.com",
                "load.sumo.com",
                "optinmonster.com",
                "a.optmstr.com",
                "privy.com",
                "widget.privy.com",
                "wisepops.com",
                "sleeknote.com",
                "hellobar.com",
            ],
        ),
        (
            "Anti-Adblock & Visitor Recovery Walls (Admiral, Funding Choices, Blockthrough)",
            "Anti-Adblock Wall",
            [
                "getadmiral.com",
                "chalkdream.com",
                "succeedscene.com",
                "fundingchoicesmessages.google.com",
                "blockthrough.com",
                "pagefair.com",
                "pagefair.net",
                "adrecover.com",
                "delivery.adrecover.com",
                "script.ac",
                "antiblock.org",
                "abp.detect.com",
            ],
        ),
    ]

    for vendor, category, domains in annoyance_clusters:
        clean_domains = sorted({d.strip().lower() for d in domains if d.strip()})
        rules.append(
            {
                "id": rule_id,
                "priority": 10,
                "action": {"type": "block"},
                "condition": {
                    "requestDomains": clean_domains,
                    "domainType": "thirdParty",
                    "resourceTypes": ALL_RESOURCE_TYPES_EXCEPT_MAIN,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "annoyances_social",
            "vendor": vendor,
            "category": category,
            "description": f"Blocks {len(clean_domains)} domains in {vendor}",
            "patternSummary": f"{clean_domains[0]} (+{len(clean_domains) - 1} more)",
        }
        rule_id += 1

    # Priority-30 Surrogate Redirects & URL Filter blocks for Admiral / Adobe Launch / Funding Choices anti-adblock scripts
    annoyance_patterns = [
        (
            "RCe0c7c73598674c2288fae1d365c8dd9d",
            "Rotten Tomatoes Adobe DTM Admiral Bootstrapper (Surrogate)",
            "Anti-Adblock Surrogate",
            ["script"],
            "/surrogates/anti_adblock_noop.js",
        ),
        (
            "/admiral*.js",
            "Admiral Visitor Recovery Script (Surrogate)",
            "Anti-Adblock Surrogate",
            ["script"],
            "/surrogates/anti_adblock_noop.js",
        ),
        (
            "/fuckadblock",
            "FuckAdBlock Detector Script (Surrogate)",
            "Anti-Adblock Surrogate",
            ["script"],
            "/surrogates/anti_adblock_noop.js",
        ),
        (
            "/blockadblock",
            "BlockAdBlock Detector Script (Surrogate)",
            "Anti-Adblock Surrogate",
            ["script"],
            "/surrogates/anti_adblock_noop.js",
        ),
        (
            "/load-rottentomatoes-web.js",
            "NBCUniversal / Versant MPS Ad Loader",
            "Ad Server",
            ["script"],
            None,
        ),
    ]

    for url_filter, vendor, category, res_types, surrogate_path in annoyance_patterns:
        action = (
            {"type": "redirect", "redirect": {"extensionPath": surrogate_path}}
            if surrogate_path
            else {"type": "block"}
        )
        rules.append(
            {
                "id": rule_id,
                "priority": 30 if surrogate_path else 15,
                "action": action,
                "condition": {
                    "urlFilter": url_filter,
                    "domainType": "thirdParty",
                    "resourceTypes": res_types,
                },
            }
        )
        catalog[str(rule_id)] = {
            "id": rule_id,
            "ruleset": "annoyances_social",
            "vendor": vendor,
            "category": category,
            "surrogate": surrogate_path,
            "description": (
                f"Redirects {vendor} ({url_filter}) to inert local surrogate {surrogate_path}"
                if surrogate_path
                else f"Blocks {vendor} ({url_filter})"
            ),
            "patternSummary": f"{url_filter} -> {surrogate_path}" if surrogate_path else url_filter,
        }
        rule_id += 1

    return rules, catalog


def create_shield_png(size: int, out_path: Path):
    """
    Generates a crisp anti-aliased RGBA PNG shield icon with an emerald/cyan core
    using only Python's standard library (struct + zlib).
    """
    pixels = bytearray(size * size * 4)
    cx = (size - 1) / 2.0
    cy = (size - 1) / 2.0
    scale = size / 128.0

    for y in range(size):
        for x in range(size):
            # Normalize coordinates to [-1, 1]
            nx = (x - cx) / (size * 0.43)
            ny = (y - cy) / (size * 0.44)

            # Shield parametric contour:
            # Top arch from ny = -0.92 to 0.05, tapering down to a point at ny = 0.96
            in_shield = False
            edge_dist = 1.0
            if -0.92 <= ny <= 0.96:
                if ny < 0.0:
                    half_w = 0.88 - 0.10 * abs(ny + 0.35) ** 1.6
                else:
                    # Taper smoothly to bottom point
                    t = min(1.0, ny / 0.96)
                    half_w = 0.86 * (1.0 - t**1.45)
                # Slight top curve dip
                top_bound = -0.90 + 0.08 * (1.0 - min(1.0, abs(nx) / 0.85))
                if ny >= top_bound and abs(nx) <= half_w:
                    in_shield = True
                    edge_dist = min(half_w - abs(nx), ny - top_bound, 0.96 - ny)

            idx = (y * size + x) * 4
            if not in_shield:
                pixels[idx : idx + 4] = b"\x00\x00\x00\x00"
                continue

            # Anti-aliased outer border
            alpha = int(max(0.0, min(1.0, edge_dist * (size * 0.38))) * 255)

            # Check if inside the inner border ring
            is_border = edge_dist < 0.13
            # Checkmark / Aegis crossbar geometry inside the shield
            # Let's draw a crisp checkmark / shield core
            # Checkmark segments: p1=(-0.32, 0.04) -> p2=(-0.06, 0.30) -> p3=(0.38, -0.26)
            def dist_to_segment(px, py, x1, y1, x2, y2):
                dx, dy = x2 - x1, y2 - y1
                if dx == 0 and dy == 0:
                    return math.hypot(px - x1, py - y1)
                t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
                proj_x = x1 + t * dx
                proj_y = y1 + t * dy
                return math.hypot(px - proj_x, py - proj_y)

            d_check = min(
                dist_to_segment(nx, ny, -0.32, 0.02, -0.06, 0.28),
                dist_to_segment(nx, ny, -0.06, 0.28, 0.36, -0.24),
            )

            if d_check < 0.115:
                # Crisp white/emerald glow checkmark
                r, g, b = (240, 253, 250)
            elif is_border:
                # Metallic cyan-emerald rim
                r = int(16 + (56 - 16) * ((1.0 - (ny + 1) / 2.0)))
                g = int(185 + (189 - 185) * ((1.0 - (ny + 1) / 2.0)))
                b = int(129 + (248 - 129) * ((1.0 - (ny + 1) / 2.0)))
            else:
                # Deep obsidian-navy shield interior with subtle split highlight on left half
                grad = max(0.0, min(1.0, (ny + 0.9) / 1.85))
                split_boost = 14 if nx < 0 else 0
                r = int(11 + 8 * (1 - grad) + split_boost // 2)
                g = int(23 + 32 * (1 - grad) + split_boost)
                b = int(42 + 48 * (1 - grad) + split_boost)

            pixels[idx] = max(0, min(255, r))
            pixels[idx + 1] = max(0, min(255, g))
            pixels[idx + 2] = max(0, min(255, b))
            pixels[idx + 3] = alpha

    # Encode RGBA PNG
    raw_rows = bytearray()
    stride = size * 4
    for y in range(size):
        raw_rows.append(0)  # Filter type 0 (None)
        raw_rows.extend(pixels[y * stride : (y + 1) * stride])

    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(bytes(raw_rows), 9))
        + png_chunk(b"IEND", b"")
    )
    out_path.write_bytes(png_bytes)


VALID_RESOURCE_TYPES = {
    "main_frame",
    "sub_frame",
    "stylesheet",
    "script",
    "image",
    "font",
    "object",
    "xmlhttprequest",
    "ping",
    "csp_report",
    "media",
    "websocket",
    "webtransport",
    "webbundle",
    "other",
}


def validate_chromium_dnr_rule(rule: dict, ruleset_name: str = "ruleset"):
    """
    Implements Chromium's C++ `IndexedRule::CreateVerifiedIndexedRule` &
    `url_pattern_index` validation invariants so any invalid `urlFilter`,
    `requestDomains`, `resourceTypes`, or `action` is caught at build/test time.
    Raises ValueError on any violation.
    """
    rid = rule.get("id")
    if not isinstance(rid, int) or rid < 1:
        raise ValueError(f"{ruleset_name}: Rule ID must be integer >= 1, got {rid!r}")

    priority = rule.get("priority")
    if priority is not None and (not isinstance(priority, int) or priority < 1):
        raise ValueError(f"{ruleset_name} Rule #{rid}: priority must be integer >= 1")

    action = rule.get("action")
    if not isinstance(action, dict) or action.get("type") not in {
        "block",
        "redirect",
        "allow",
        "upgradeScheme",
        "modifyHeaders",
        "allowAllRequests",
    }:
        raise ValueError(f"{ruleset_name} Rule #{rid}: invalid action {action!r}")

    cond = rule.get("condition")
    if not isinstance(cond, dict):
        raise ValueError(f"{ruleset_name} Rule #{rid}: condition must be a dict")

    # 1. Validate urlFilter against Chromium's C++ url_pattern_index parser rules
    if "urlFilter" in cond:
        uf = cond["urlFilter"]
        if not isinstance(uf, str) or not uf:
            raise ValueError(f"{ruleset_name} Rule #{rid}: urlFilter must be a non-empty string")
        if not uf.isascii():
            raise ValueError(f"{ruleset_name} Rule #{rid}: urlFilter contains non-ASCII characters: {uf!r}")
        if "**" in uf:
            raise ValueError(f"{ruleset_name} Rule #{rid}: urlFilter cannot contain consecutive '**': {uf!r}")

        body = uf
        if body.startswith("||"):
            body = body[2:]
            # Chromium C++ check: ANCHOR_TYPE_SUBDOMAIN (`||`) cannot be empty or start with '*', '.', '/', '?', '^', '|'
            if not body or body[0] in {"*", ".", "/", ":", "?", "^", "|"}:
                raise ValueError(
                    f"{ruleset_name} Rule #{rid}: urlFilter with '||' subdomain anchor cannot be followed by {body[:1]!r} ({uf!r})"
                )
        elif body.startswith("|"):
            body = body[1:]
            if not body:
                raise ValueError(f"{ruleset_name} Rule #{rid}: urlFilter '|' anchor cannot be empty")

        if body.endswith("|"):
            body = body[:-1]
            if not body:
                raise ValueError(f"{ruleset_name} Rule #{rid}: urlFilter cannot be only anchors ({uf!r})")

        # Mid-pattern '|' is illegal in Chromium's urlFilter unless regexFilter is used
        if "|" in body:
            raise ValueError(
                f"{ruleset_name} Rule #{rid}: urlFilter cannot contain '|' in the middle of the pattern ({uf!r})"
            )

    # 2. Validate domain lists (requestDomains, excludedRequestDomains, initiatorDomains, excludedInitiatorDomains)
    for dom_key in ("requestDomains", "excludedRequestDomains", "initiatorDomains", "excludedInitiatorDomains"):
        if dom_key in cond:
            dom_list = cond[dom_key]
            if not isinstance(dom_list, list) or len(dom_list) == 0:
                raise ValueError(f"{ruleset_name} Rule #{rid}: {dom_key} must be a non-empty list")
            for d in dom_list:
                if (
                    not isinstance(d, str)
                    or not d
                    or not d.isascii()
                    or " " in d
                    or "/" in d
                    or "*" in d
                    or ":" in d
                    or d.startswith(".")
                    or d.endswith(".")
                ):
                    raise ValueError(f"{ruleset_name} Rule #{rid}: invalid domain {d!r} in {dom_key}")

    # 3. Validate resourceTypes / excludedResourceTypes
    for rt_key in ("resourceTypes", "excludedResourceTypes"):
        if rt_key in cond:
            rt_list = cond[rt_key]
            if not isinstance(rt_list, list) or len(rt_list) == 0:
                raise ValueError(f"{ruleset_name} Rule #{rid}: {rt_key} must be a non-empty list")
            invalid_rt = set(rt_list) - VALID_RESOURCE_TYPES
            if invalid_rt:
                raise ValueError(f"{ruleset_name} Rule #{rid}: invalid {rt_key} {invalid_rt}")

    # 4. Validate allowAllRequests constraint (only main_frame and/or sub_frame allowed)
    if action["type"] == "allowAllRequests":
        rts = set(cond.get("resourceTypes", []))
        if not rts or not rts.issubset({"main_frame", "sub_frame"}):
            raise ValueError(
                f"{ruleset_name} Rule #{rid}: allowAllRequests only supports resourceTypes main_frame/sub_frame"
            )

    # 5. Validate redirect action (extensionPath or transform)
    if action["type"] == "redirect":
        redir = action.get("redirect")
        if not isinstance(redir, dict) or not redir:
            raise ValueError(f"{ruleset_name} Rule #{rid}: redirect action requires a non-empty redirect dict")
        if "extensionPath" in redir:
            ext_p = redir["extensionPath"]
            if not isinstance(ext_p, str) or not ext_p.startswith("/"):
                raise ValueError(
                    f"{ruleset_name} Rule #{rid}: redirect.extensionPath must start with '/', got {ext_p!r}"
                )
            target_file = EXT_DIR / ext_p.lstrip("/")
            if not target_file.exists():
                raise ValueError(
                    f"{ruleset_name} Rule #{rid}: surrogate file missing for extensionPath {ext_p!r}"
                )


def build_all():
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    ICONS_DIR.mkdir(parents=True, exist_ok=True)

    ads_rules, ads_cat = build_ads_core_rules()
    trk_rules, trk_cat = build_trackers_privacy_rules()
    url_rules, url_cat = build_url_privacy_clean_rules()
    ann_rules, ann_cat = build_annoyances_social_rules()

    for rs_name, rs_list in (
        ("ads_core.json", ads_rules),
        ("trackers_privacy.json", trk_rules),
        ("url_privacy_clean.json", url_rules),
        ("annoyances_social.json", ann_rules),
    ):
        for r in rs_list:
            validate_chromium_dnr_rule(r, rs_name)

    (RULES_DIR / "ads_core.json").write_text(json.dumps(ads_rules, indent=2), encoding="utf-8")
    (RULES_DIR / "trackers_privacy.json").write_text(json.dumps(trk_rules, indent=2), encoding="utf-8")
    (RULES_DIR / "url_privacy_clean.json").write_text(json.dumps(url_rules, indent=2), encoding="utf-8")
    (RULES_DIR / "annoyances_social.json").write_text(json.dumps(ann_rules, indent=2), encoding="utf-8")

    # Merge full catalog and compute covered domain count
    full_catalog = {}
    full_catalog.update(ads_cat)
    full_catalog.update(trk_cat)
    full_catalog.update(url_cat)
    full_catalog.update(ann_cat)

    all_rules = ads_rules + trk_rules + url_rules + ann_rules
    covered_domains = set()
    for r in all_rules:
        for d in r.get("condition", {}).get("requestDomains", []):
            covered_domains.add(d)

    catalog_payload = {
        "version": "1.0.0",
        "summary": {
            "totalStaticRules": len(all_rules),
            "totalCoveredDomains": len(covered_domains),
            "rulesets": {
                "ads_core": len(ads_rules),
                "trackers_privacy": len(trk_rules),
                "url_privacy_clean": len(url_rules),
                "annoyances_social": len(ann_rules),
            },
        },
        "rules": full_catalog,
        "coveredDomains": sorted(covered_domains),
    }
    (RULES_DIR / "rule_catalog.json").write_text(json.dumps(catalog_payload, indent=2), encoding="utf-8")

    for sz in (16, 32, 48, 128):
        create_shield_png(sz, ICONS_DIR / f"icon{sz}.png")

    print(
        f"[AegisBlock Compiler] Compiled {len(all_rules)} static DNR rules covering "
        f"{len(covered_domains)} unique ad/tracker domains across 4 rulesets + 4 PNG icons."
    )


if __name__ == "__main__":
    build_all()
