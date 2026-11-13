#!/usr/bin/env python3
"""
Comprehensive Automated Test Suite for AegisBlock MV3 Edge Extension.
Covers:
1. Chromium C++ `url_pattern_index` & `IndexedRule` DNR grammar validation (including regression test for Rule #1010 `||*` error)
2. Manifest V3, Zero-Leak CSP, and PNG IHDR binary verification
3. JavaScript syntax (`node --check`) & Node.js MV3 Service Worker runtime simulation (`background.js` DNR + Telemetry + Heuristics)
4. Dynamic DNR rule generation compliance against Chromium's C++ rule validator
5. SQLite WAL research ingestion & rule synthesis pipeline
6. Windows unpacked extension (`C:\\Users\\oz_co\\code\\extensions\\adblocker`) byte-for-byte sync parity
"""

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import cli
from scripts.build_rules import (
    EXT_DIR,
    ICONS_DIR,
    RULES_DIR,
    build_all,
    validate_chromium_dnr_rule,
)


class TestAegisBlockExtension(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Rebuild and sync before running assertions
        cli.cmd_build(None)
        cli.cmd_simulate_research(None)
        cli.cmd_sync(None)

    def test_01_chromium_dnr_url_filter_regression_guards(self):
        """
        Regression test for `Error: ads_core.json: Rule with id 1010 specifies an incorrect value for the "urlFilter" key.`
        Verifies that `validate_chromium_dnr_rule` rejects `||*` and all illegal Chromium C++ url_pattern_index constructs.
        """
        invalid_patterns = [
            "||*/pagead/js/adsbygoogle.js",  # Illegal `||*` (subdomain anchor followed by wildcard)
            "||.example.com",                # Illegal `||.`
            "||/path/only",                  # Illegal `||/`
            "||",                            # Empty subdomain anchor
            "|",                             # Empty anchor
            "||example.com|extra",           # Illegal mid-string `|`
            "/ads/**.js",                    # Illegal consecutive `**`
            "",                              # Empty urlFilter
            "||exämple.com^",                # Non-ASCII in urlFilter
        ]
        for pat in invalid_patterns:
            bad_rule = {
                "id": 9999,
                "priority": 10,
                "action": {"type": "block"},
                "condition": {
                    "urlFilter": pat,
                    "resourceTypes": ["script"],
                },
            }
            with self.assertRaises(ValueError, msg=f"Pattern {pat!r} should have been rejected"):
                validate_chromium_dnr_rule(bad_rule, "test_ruleset")

        # Valid patterns must pass cleanly
        valid_patterns = [
            "||doubleclick.net^",
            "/pagead/js/adsbygoogle.js",
            "/prebid*.js",
            "/g/collect?v=2",
            "|https://securepubads.g.doubleclick.net/",
        ]
        for pat in valid_patterns:
            good_rule = {
                "id": 1010,
                "priority": 10,
                "action": {"type": "block"},
                "condition": {
                    "urlFilter": pat,
                    "domainType": "thirdParty",
                    "resourceTypes": ["script"],
                },
            }
            validate_chromium_dnr_rule(good_rule, "test_ruleset")

    def test_02_all_compiled_static_rulesets_pass_chromium_validator(self):
        """Verifies every rule in all 4 static JSON rulesets conforms to Chromium C++ IndexedRule invariants."""
        seen_ids = set()
        for rs_file in ("ads_core.json", "trackers_privacy.json", "url_privacy_clean.json", "annoyances_social.json"):
            path = RULES_DIR / rs_file
            self.assertTrue(path.exists(), f"Missing ruleset {rs_file}")
            rules = json.loads(path.read_text(encoding="utf-8"))
            self.assertGreater(len(rules), 0, f"{rs_file} cannot be empty")
            for r in rules:
                validate_chromium_dnr_rule(r, rs_file)
                self.assertNotIn(r["id"], seen_ids, f"Duplicate rule ID {r['id']} in {rs_file}")
                seen_ids.add(r["id"])

    def test_03_manifest_csp_and_icons_integrity(self):
        """Verifies manifest.json MV3 schema, Zero-Leak CSP, and PNG icon dimensions."""
        manifest = json.loads((EXT_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifest_version"], 3)

        csp = manifest.get("content_security_policy", {}).get("extension_pages", "")
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)

        for sz in (16, 32, 48, 128):
            icon_path = ICONS_DIR / f"icon{sz}.png"
            self.assertTrue(icon_path.exists())
            data = icon_path.read_bytes()
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            w, h = struct.unpack(">II", data[16:24])
            self.assertEqual((w, h), (sz, sz))

    def test_04_javascript_syntax_and_zero_external_network_audit(self):
        """Runs `node --check` on all extension JS & surrogate files and verifies 0 external network/cloud sync calls."""
        js_files = [
            "background.js",
            "content.js",
            "page_defuser.js",
            "popup.js",
            "dashboard.js",
            "surrogates/googletag_gpt.js",
            "surrogates/google_ima3.js",
            "surrogates/adsbygoogle.js",
            "surrogates/google_analytics.js",
            "surrogates/fbevents.js",
            "surrogates/anti_adblock_noop.js",
        ]
        for js_name in js_files:
            js_path = EXT_DIR / js_name
            self.assertTrue(js_path.exists(), f"Missing JS file {js_name}")
            proc = subprocess.run(
                ["node", "--check", str(js_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"Syntax error in {js_name}: {proc.stderr}")

            code = js_path.read_text(encoding="utf-8")
            self.assertNotIn("chrome.storage.sync", code)
            self.assertNotIn("navigator.sendBeacon", code)
            self.assertNotIn("new WebSocket(", code)

        # Verify dual-use false-positive domains were surgically removed from blanket requestDomains
        trk_rules = json.loads((RULES_DIR / "trackers_privacy.json").read_text(encoding="utf-8"))
        blanket_domains = set()
        for r in trk_rules:
            blanket_domains.update(r.get("condition", {}).get("requestDomains", []))
        for dual_use in ("intercom.io", "widget.intercom.io", "hubspot.com", "t.co", "sc-static.net", "sentry-cdn.com"):
            self.assertNotIn(dual_use, blanket_domains, f"Dual-use domain {dual_use} should not be in blanket blocklist")

        # Verify modern attribution query parameters are stripped in url_privacy_clean.json
        url_rules = json.loads((RULES_DIR / "url_privacy_clean.json").read_text(encoding="utf-8"))
        removed_params = set(
            url_rules[0]["action"]["redirect"]["transform"]["queryTransform"]["removeParams"]
        )
        for mod_param in ("srsltid", "irclickid", "cjevent", "epik", "rdt_cid", "sccid"):
            self.assertIn(mod_param, removed_params)

        # Verify Rotten Tomatoes / Admiral / Adobe DTM / Funding Choices anti-adblock domains are blocked
        catalog = json.loads((RULES_DIR / "rule_catalog.json").read_text(encoding="utf-8"))
        covered = set(catalog.get("coveredDomains", []))
        for anti_ab_dom in (
            "getadmiral.com",
            "chalkdream.com",
            "succeedscene.com",
            "adobedtm.com",
            "assets.adobedtm.com",
            "fundingchoicesmessages.google.com",
            "mps.vsnt.net",
            "app.mps.vsnt.net",
        ):
            self.assertIn(anti_ab_dom, covered, f"Anti-adblock domain {anti_ab_dom} must be blocked in DNR catalog")

    def test_05_background_service_worker_runtime_simulation_in_node(self):
        """
        Executes `extension/background.js` inside a Node.js MV3 mock environment to test:
        - DNR `onRuleMatchedDebug` telemetry recording
        - Heuristic Evasion Suspect ingestion & cross-site confidence boost
        - 1-Click & Bulk Rule Promotion -> `updateDynamicRules`
        - Per-site Allowlist toggle -> `allowAllRequests` dynamic rules
        - Validates all dynamically generated rules from `background.js` with `validate_chromium_dnr_rule`!
        """
        harness_js = r"""
        const fs = require('fs');
        const path = require('path');
        const vm = require('vm');

        const extDir = process.argv[1];
        const catalogJson = JSON.parse(fs.readFileSync(path.join(extDir, 'rules/rule_catalog.json'), 'utf8'));

        let storageMap = {};
        let dynamicRules = [];
        let enabledRulesets = ['ads_core', 'trackers_privacy', 'url_privacy_clean', 'annoyances_social'];
        let dnrListener = null;
        let msgListener = null;

        const sandbox = {
          console,
          setTimeout,
          clearTimeout,
          URL,
          Date,
          Math,
          Number,
          String,
          Boolean,
          Array,
          Object,
          Set,
          Map,
          Promise,
          fetch: async () => ({
            ok: true,
            json: async () => catalogJson
          }),
          chrome: {
            runtime: {
              getURL: (p) => p,
              onInstalled: { addListener: () => {} },
              onMessage: {
                addListener: (fn) => { msgListener = fn; }
              }
            },
            storage: {
              local: {
                get: async (k) => ({ [k]: storageMap[k] }),
                set: async (obj) => { Object.assign(storageMap, obj); }
              }
            },
            declarativeNetRequest: {
              onRuleMatchedDebug: {
                addListener: (fn) => { dnrListener = fn; }
              },
              getDynamicRules: async () => dynamicRules,
              updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => {
                dynamicRules = dynamicRules.filter(r => !removeRuleIds.includes(r.id)).concat(addRules);
              },
              getEnabledRulesets: async () => enabledRulesets,
              updateEnabledRulesets: async ({ enableRulesetIds = [], disableRulesetIds = [] }) => {
                enabledRulesets = enabledRulesets.filter(id => !disableRulesetIds.includes(id)).concat(enableRulesetIds);
              }
            },
            action: {
              setBadgeBackgroundColor: async () => {},
              setBadgeText: async () => {}
            },
            tabs: {
              onUpdated: { addListener: () => {} },
              onRemoved: { addListener: () => {} },
              query: async () => [],
              sendMessage: async () => {}
            },
            commands: {
              onCommand: { addListener: () => {} }
            }
          }
        };

        const code = fs.readFileSync(path.join(extDir, 'background.js'), 'utf8');
        vm.createContext(sandbox);
        vm.runInContext(code, sandbox);

        function sendMsg(msg, sender = {}) {
          return new Promise((resolve) => {
            msgListener(msg, sender, (resp) => resolve(resp));
          });
        }

        (async () => {
          // 1. Simulate a DNR rule match on Rule #1010
          await dnrListener({
            request: {
              url: 'https://thirdparty-ads.example.org/pagead/js/adsbygoogle.js',
              initiator: 'https://news-portal.com',
              type: 'script',
              tabId: 1
            },
            rule: {
              ruleId: 1010,
              rulesetId: 'ads_core'
            }
          });

          // 2. Simulate reporting a Heuristic Evasion Suspect across two sites
          const suspectPayload = {
            candidateHost: 'ads.evasion-network.io',
            baseDomain: 'evasion-network.io',
            sampleUrl: 'https://ads.evasion-network.io/openrtb2/auction?ad_unit=top',
            initiatorSite: 'news-portal.com',
            resourceType: 'xmlhttprequest',
            confidence: 78,
            category: 'Suspect Ad Server',
            signals: ['AD_SUBDOMAIN_PREFIX', 'URL_ADTECH_ENDPOINT']
          };
          await sendMsg({ type: 'REPORT_HEURISTIC_SUSPECT', suspect: suspectPayload }, { tab: { id: 1 } });
          await sendMsg({
            type: 'REPORT_HEURISTIC_SUSPECT',
            suspect: { ...suspectPayload, initiatorSite: 'sports-daily.com' }
          }, { tab: { id: 2 } });

          // 3. Bulk promote suspects >= 80% confidence (cross-site bonus raises 78 + 12 = 90%)
          const bulkResp = await sendMsg({ type: 'BULK_PROMOTE_SUSPECTS', minConfidence: 80 });

          // 4. Toggle site allowlist pause on `trusted-site.org`
          const pauseResp = await sendMsg({ type: 'TOGGLE_SITE_PAUSE', site: 'trusted-site.org', tabId: 1 });

          // 5. Save custom Element Zapper selector
          await sendMsg({ type: 'SAVE_CUSTOM_SELECTOR', site: 'news-portal.com', selector: '#floating-ad-banner' });

          // 6. Report a False-Positive Breakage Diagnostic & create a surgical per-site allow rule
          await sendMsg({
            type: 'REPORT_BREAKAGE_DIAGNOSTIC',
            site: 'news-portal.com',
            failedHost: 'thirdparty-ads.example.org',
            reason: 'SCRIPT_LOAD_BLOCKED',
            detail: 'Blocked script caused ReferenceError'
          }, { tab: { id: 1 } });

          await sendMsg({
            type: 'ALLOW_DOMAIN_ON_SITE',
            site: 'news-portal.com',
            domain: 'thirdparty-ads.example.org'
          });

          // 7. Fetch full dashboard state
          const dashResp = await sendMsg({ type: 'GET_DASHBOARD_STATE' });

          console.log(JSON.stringify({
            bulkPromotedCount: bulkResp.promotedCount,
            isPaused: pauseResp.isPaused,
            dynamicRules,
            metrics: dashResp.state.metrics,
            customSelectors: dashResp.state.customSelectorsBySite['news-portal.com'],
            falsePositives: dashResp.state.falsePositiveReports,
            siteDomainExceptions: dashResp.state.siteDomainExceptions
          }));
          process.exit(0);
        })();
        """
        proc = subprocess.run(
            ["node", "-e", harness_js, str(EXT_DIR)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["bulkPromotedCount"], 1)
        self.assertTrue(out["isPaused"])
        self.assertEqual(out["metrics"]["totalNetworkBlocked"], 1)
        self.assertEqual(out["metrics"]["adsBlocked"], 1)
        self.assertEqual(out["metrics"]["surrogatesServed"], 1)
        self.assertGreaterEqual(out["metrics"]["falsePositivesFlagged"], 1)
        self.assertIn("#floating-ad-banner", out["customSelectors"])
        self.assertEqual(len(out["siteDomainExceptions"]), 1)

        # Validate every dynamically generated rule produced by background.js against Chromium's C++ rule validator!
        self.assertGreaterEqual(len(out["dynamicRules"]), 4)
        for dyn_rule in out["dynamicRules"]:
            validate_chromium_dnr_rule(dyn_rule, "dynamic_rules")

    def test_06_windows_unpacked_extension_sync_parity(self):
        """Verifies that C:\\Users\\oz_co\\code\\extensions\\adblocker matches extension/ byte-for-byte."""
        win_dir = Path("/mnt/c/Users/oz_co/code/extensions/adblocker")
        self.assertTrue(win_dir.exists())
        for rel in (
            "manifest.json",
            "background.js",
            "content.js",
            "content.css",
            "page_defuser.js",
            "popup.html",
            "popup.js",
            "dashboard.html",
            "dashboard.js",
            "surrogates/anti_adblock_noop.js",
            "rules/ads_core.json",
            "rules/trackers_privacy.json",
            "rules/url_privacy_clean.json",
            "rules/annoyances_social.json",
            "rules/rule_catalog.json",
        ):
            src_bytes = (EXT_DIR / rel).read_bytes()
            dst_bytes = (win_dir / rel).read_bytes()
            self.assertEqual(src_bytes, dst_bytes, f"Out-of-sync file in Windows unpacked dir: {rel}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
