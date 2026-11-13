#!/usr/bin/env python3
"""
AegisBlock — Research, Analytics, DNR Rule Synthesizer & 6-Gate QA CLI.
Backed by SQLite WAL (`data/adblock_research.db`).
"""

import argparse
import json
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from scripts.build_rules import (
    ALL_RESOURCE_TYPES_EXCEPT_MAIN,
    build_all,
    validate_chromium_dnr_rule,
)

ROOT_DIR = Path(__file__).resolve().parent
EXT_DIR = ROOT_DIR / "extension"
RULES_DIR = EXT_DIR / "rules"
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "adblock_research.db"
WINDOWS_EXT_DIR = Path("/mnt/c/Users/oz_co/code/extensions/adblocker")


def get_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS blocked_telemetry (
            domain TEXT PRIMARY KEY,
            vendor TEXT,
            category TEXT,
            hit_count INTEGER DEFAULT 0,
            site_spread INTEGER DEFAULT 0,
            initiator_sites_json TEXT DEFAULT '[]',
            resource_types_json TEXT DEFAULT '{}',
            last_updated INTEGER
        );

        CREATE TABLE IF NOT EXISTS heuristic_candidates (
            candidate_host TEXT PRIMARY KEY,
            base_domain TEXT,
            confidence INTEGER DEFAULT 0,
            category TEXT,
            signals_json TEXT DEFAULT '[]',
            initiator_sites_json TEXT DEFAULT '[]',
            sample_url TEXT,
            promoted INTEGER DEFAULT 0,
            last_updated INTEGER
        );

        CREATE TABLE IF NOT EXISTS learned_rules (
            rule_id INTEGER PRIMARY KEY,
            domain TEXT UNIQUE,
            category TEXT,
            confidence INTEGER DEFAULT 100,
            signals_json TEXT DEFAULT '[]',
            source TEXT,
            created_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS false_positive_reports (
            report_key TEXT PRIMARY KEY,
            site TEXT,
            blocked_domain TEXT,
            rule_id INTEGER DEFAULT 0,
            reason TEXT,
            detail TEXT,
            hit_count INTEGER DEFAULT 1,
            mitigated INTEGER DEFAULT 0,
            last_updated INTEGER
        );

        CREATE TABLE IF NOT EXISTS qa_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            passed INTEGER,
            score INTEGER,
            details_json TEXT
        );
        """
    )
    conn.commit()
    return conn


def compile_learned_rules_into_extension(conn: sqlite3.Connection):
    """Appends SQLite learned_rules into ads_core.json and rule_catalog.json."""
    rows = conn.execute("SELECT * FROM learned_rules ORDER BY rule_id ASC").fetchall()
    if not rows:
        return 0

    ads_path = RULES_DIR / "ads_core.json"
    cat_path = RULES_DIR / "rule_catalog.json"
    ads_rules = json.loads(ads_path.read_text(encoding="utf-8"))
    catalog = json.loads(cat_path.read_text(encoding="utf-8"))

    learned_domains = sorted({r["domain"].strip().lower() for r in rows if r["domain"]})
    if not learned_domains:
        return 0

    # Add or update consolidated learned rule #1900 in ads_core.json
    ads_rules = [r for r in ads_rules if r.get("id") != 1900]
    ads_rules.append(
        {
            "id": 1900,
            "priority": 20,
            "action": {"type": "block"},
            "condition": {
                "requestDomains": learned_domains,
                "domainType": "thirdParty",
                "resourceTypes": ALL_RESOURCE_TYPES_EXCEPT_MAIN,
            },
        }
    )
    ads_path.write_text(json.dumps(ads_rules, indent=2), encoding="utf-8")

    catalog["rules"]["1900"] = {
        "id": 1900,
        "ruleset": "ads_core",
        "vendor": "AegisBlock Self-Learning Research Ruleset",
        "category": "Learned Ad/Tracker Network",
        "description": f"Blocks {len(learned_domains)} domain(s) synthesized by the Heuristic Research Engine",
        "patternSummary": f"{learned_domains[0]} (+{max(0, len(learned_domains) - 1)} more)",
    }
    covered = set(catalog.get("coveredDomains", [])) | set(learned_domains)
    catalog["coveredDomains"] = sorted(covered)
    catalog["summary"]["totalStaticRules"] = (
        len(ads_rules)
        + catalog["summary"]["rulesets"]["trackers_privacy"]
        + catalog["summary"]["rulesets"]["url_privacy_clean"]
        + catalog["summary"]["rulesets"]["annoyances_social"]
    )
    catalog["summary"]["totalCoveredDomains"] = len(covered)
    catalog["summary"]["rulesets"]["ads_core"] = len(ads_rules)
    cat_path.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return len(learned_domains)


def cmd_build(_args):
    conn = get_db()
    build_all()
    learned_cnt = compile_learned_rules_into_extension(conn)
    if learned_cnt:
        print(f"[AegisBlock Compiler] Merged {learned_cnt} learned research domain(s) into static DNR ruleset #1900.")


def cmd_sync(_args):
    WINDOWS_EXT_DIR.mkdir(parents=True, exist_ok=True)
    # Copy extension files cleanly
    for item in EXT_DIR.iterdir():
        dest = WINDOWS_EXT_DIR / item.name
        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
    print(f"[AegisBlock Sync] Synced unpacked extension to {WINDOWS_EXT_DIR}")
    print(r"  -> Load in Microsoft Edge (`edge://extensions`): C:\Users\oz_co\code\extensions\adblocker")


def cmd_ingest(args):
    conn = get_db()
    in_path = Path(args.file).resolve()
    if not in_path.exists():
        print(f"Error: File not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(in_path.read_text(encoding="utf-8"))
    state = payload.get("state", payload)
    now = int(time.time())

    # 1. Ingest blocked domain stats
    domain_stats = state.get("domainStats", {})
    for host, info in domain_stats.items():
        sites = info.get("initiatorSites", [])
        res_types = info.get("resourceTypes", {})
        conn.execute(
            """
            INSERT INTO blocked_telemetry (domain, vendor, category, hit_count, site_spread, initiator_sites_json, resource_types_json, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                hit_count = MAX(blocked_telemetry.hit_count, excluded.hit_count),
                site_spread = MAX(blocked_telemetry.site_spread, excluded.site_spread),
                initiator_sites_json = excluded.initiator_sites_json,
                resource_types_json = excluded.resource_types_json,
                last_updated = excluded.last_updated
            """,
            (
                host,
                info.get("vendor", "Blocked Host"),
                info.get("category", "Network Block"),
                int(info.get("count", 0)),
                len(sites),
                json.dumps(sites),
                json.dumps(res_types),
                now,
            ),
        )

    # 2. Ingest heuristic candidates
    suspects = state.get("suspectCandidates", {})
    promoted_count = 0
    for host, cand in suspects.items():
        base_dom = cand.get("baseDomain") or host
        conf = int(cand.get("confidence", 50))
        promoted = 1 if cand.get("promotedRuleId") else 0
        conn.execute(
            """
            INSERT INTO heuristic_candidates (candidate_host, base_domain, confidence, category, signals_json, initiator_sites_json, sample_url, promoted, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(candidate_host) DO UPDATE SET
                confidence = MAX(heuristic_candidates.confidence, excluded.confidence),
                signals_json = excluded.signals_json,
                initiator_sites_json = excluded.initiator_sites_json,
                promoted = MAX(heuristic_candidates.promoted, excluded.promoted),
                last_updated = excluded.last_updated
            """,
            (
                host,
                base_dom,
                conf,
                cand.get("category", "Suspect Resource"),
                json.dumps(cand.get("signals", [])),
                json.dumps(cand.get("initiatorSites", [])),
                cand.get("sampleUrl", ""),
                promoted,
                now,
            ),
        )
        if args.auto_synthesize and conf >= args.min_confidence:
            conn.execute(
                """
                INSERT OR IGNORE INTO learned_rules (domain, category, confidence, signals_json, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    base_dom,
                    cand.get("category", "Heuristic Synthesized"),
                    conf,
                    json.dumps(cand.get("signals", [])),
                    f"CLI Auto-Synthesize (>={args.min_confidence}%)",
                    now,
                ),
            )
            conn.execute("UPDATE heuristic_candidates SET promoted = 1 WHERE base_domain = ?", (base_dom,))
            promoted_count += 1

    # 3. Ingest user-promoted dynamicBlockRules
    for dyn in state.get("dynamicBlockRules", []):
        dom = dyn.get("domain")
        if not dom:
            continue
        conn.execute(
            """
            INSERT OR IGNORE INTO learned_rules (domain, category, confidence, signals_json, source, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                dom,
                dyn.get("category", "Dynamic Block"),
                int(dyn.get("confidence", 100)),
                json.dumps(dyn.get("signals", ["USER_DYNAMIC"])),
                dyn.get("source", "Extension Dynamic Rule"),
                now,
            ),
        )

    # 4. Ingest False-Positive & Page Breakage Diagnostics
    fp_reports = state.get("falsePositiveReports", {})
    for fp_key, fp in fp_reports.items():
        site = fp.get("site") or ""
        b_dom = fp.get("blockedDomain") or ""
        if not site or not b_dom:
            continue
        conn.execute(
            """
            INSERT INTO false_positive_reports (report_key, site, blocked_domain, rule_id, reason, detail, hit_count, mitigated, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_key) DO UPDATE SET
                hit_count = MAX(false_positive_reports.hit_count, excluded.hit_count),
                reason = excluded.reason,
                detail = excluded.detail,
                mitigated = MAX(false_positive_reports.mitigated, excluded.mitigated),
                last_updated = excluded.last_updated
            """,
            (
                fp_key,
                site,
                b_dom,
                int(fp.get("ruleId", 0)),
                fp.get("reason", "PAGE_BREAKAGE_SIGNAL"),
                fp.get("detail", ""),
                int(fp.get("count", 1)),
                1 if fp.get("mitigated") else 0,
                now,
            ),
        )

    conn.commit()
    merged = compile_learned_rules_into_extension(conn)
    print(
        f"[AegisBlock Research DB] Ingested {len(domain_stats)} blocked domain telemetry records, "
        f"{len(suspects)} heuristic evasion candidates, and {len(fp_reports)} breakage diagnostics."
    )
    if merged:
        print(f"[AegisBlock Synthesizer] Compiled {merged} learned domain(s) into static DNR ruleset #1900.")


def cmd_simulate_research(_args):
    """Seeds representative blocker research telemetry into SQLite and synthesizes rules."""
    sample_payload = {
        "state": {
            "domainStats": {
                "googlesyndication.com": {
                    "vendor": "Google Ads & DoubleClick RTB",
                    "category": "Ad Network / RTB",
                    "count": 148,
                    "initiatorSites": ["news-daily.com", "tech-review.io", "finance-watch.org", "sports-stream.tv"],
                    "resourceTypes": {"script": 92, "sub_frame": 56},
                },
                "doubleclick.net": {
                    "vendor": "Google Ads & DoubleClick RTB",
                    "category": "Ad Network / RTB",
                    "count": 119,
                    "initiatorSites": ["news-daily.com", "sports-stream.tv", "shop-deals.com"],
                    "resourceTypes": {"sub_frame": 74, "xmlhttprequest": 45},
                },
                "rubiconproject.com": {
                    "vendor": "Programmatic Header Bidding & SSP Exchanges",
                    "category": "Programmatic SSP",
                    "count": 84,
                    "initiatorSites": ["news-daily.com", "tech-review.io", "finance-watch.org"],
                    "resourceTypes": {"xmlhttprequest": 68, "script": 16},
                },
                "scorecardresearch.com": {
                    "vendor": "Cross-Site Identity Graphs, DMPs & Audience Trackers",
                    "category": "Identity Graph / DMP",
                    "count": 67,
                    "initiatorSites": ["news-daily.com", "finance-watch.org", "sports-stream.tv"],
                    "resourceTypes": {"ping": 51, "script": 16},
                },
                "hotjar.com": {
                    "vendor": "Session Replay & Keystroke/Mouse Heatmap Recording",
                    "category": "Session Replay / Invasive",
                    "count": 39,
                    "initiatorSites": ["saas-portal.app", "shop-deals.com"],
                    "resourceTypes": {"script": 29, "websocket": 10},
                },
            },
            "suspectCandidates": {
                "ads-telemetry.rtb-edge-delivery.net": {
                    "baseDomain": "rtb-edge-delivery.net",
                    "confidence": 94,
                    "category": "Suspect Ad Server",
                    "signals": ["AD_SUBDOMAIN_PREFIX", "URL_ADTECH_ENDPOINT", "ADTECH_QUERY_PARAMS", "CROSS_SITE_PREVALENCE"],
                    "initiatorSites": ["news-daily.com", "tech-review.io"],
                    "sampleUrl": "https://ads-telemetry.rtb-edge-delivery.net/openrtb2/auction?ad_unit=top_728x90",
                },
                "pixel-sync.audience-graph-cdn.io": {
                    "baseDomain": "audience-graph-cdn.io",
                    "confidence": 89,
                    "category": "Suspect Tracker / Beacon",
                    "signals": ["TRACKER_SUBDOMAIN_PREFIX", "URL_TRACKER_ENDPOINT", "INITIATOR_PING", "CROSS_SITE_PREVALENCE"],
                    "initiatorSites": ["shop-deals.com", "finance-watch.org"],
                    "sampleUrl": "https://pixel-sync.audience-graph-cdn.io/usersync/pixel.gif?uid=99182",
                },
                "banner.native-yield-exchange.com": {
                    "baseDomain": "native-yield-exchange.com",
                    "confidence": 86,
                    "category": "Suspect Ad Iframe",
                    "signals": ["IAB_AD_IFRAME_300x250", "AD_SUBDOMAIN_PREFIX", "URL_ADTECH_ENDPOINT"],
                    "initiatorSites": ["sports-stream.tv"],
                    "sampleUrl": "https://banner.native-yield-exchange.com/adframe.html?slot=sidebar_300x250",
                },
            },
            "falsePositiveReports": {
                "saas-portal.app::script.hotjar.com": {
                    "site": "saas-portal.app",
                    "blockedDomain": "script.hotjar.com",
                    "ruleId": 2004,
                    "reason": "SCRIPT_LOAD_BLOCKED",
                    "detail": "Blocked third-party script on saas-portal.app (Rule #2004)",
                    "count": 1,
                    "mitigated": False,
                }
            },
        }
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    snap_path = DATA_DIR / "sample_telemetry_snapshot.json"
    snap_path.write_text(json.dumps(sample_payload, indent=2), encoding="utf-8")

    ns = argparse.Namespace(file=str(snap_path), auto_synthesize=True, min_confidence=85)
    cmd_ingest(ns)


def cmd_stats(_args):
    conn = get_db()
    cat_path = RULES_DIR / "rule_catalog.json"
    catalog = json.loads(cat_path.read_text(encoding="utf-8")) if cat_path.exists() else {"summary": {}, "rules": {}}
    summary = catalog.get("summary", {})
    surrogate_rules = [r for r in (catalog.get("rules") or {}).values() if r.get("surrogate")]

    print("=" * 74)
    print(" 🛡️  AegisBlock — Blocker Telemetry & Rule Research Summary")
    print("=" * 74)
    print(f"  Static DNR Rules       : {summary.get('totalStaticRules', 0)} ({len(surrogate_rules)} C++ Surrogate Redirects)")
    print(f"  Covered Ad/Trk Domains : {summary.get('totalCoveredDomains', 0)}")
    for rs_id, cnt in (summary.get("rulesets") or {}).items():
        print(f"    - {rs_id:<20}: {cnt} rules")

    top_blocked = conn.execute(
        "SELECT domain, vendor, category, hit_count, site_spread FROM blocked_telemetry ORDER BY hit_count DESC LIMIT 8"
    ).fetchall()
    print("\n 📊 Top Blocked Domains in Research DB:")
    if not top_blocked:
        print("    (No telemetry ingested yet — run `python3 cli.py simulate-research` or `ingest`)")
    for r in top_blocked:
        print(f"    - {r['domain']:<26} | {r['hit_count']:>4} hits | {r['site_spread']} sites | {r['category']}")

    candidates = conn.execute(
        "SELECT candidate_host, base_domain, confidence, category, promoted FROM heuristic_candidates ORDER BY confidence DESC"
    ).fetchall()
    print("\n 🔬 Heuristic Evasion Candidates & Synthesized Rules:")
    if not candidates:
        print("    (No heuristic candidates recorded yet)")
    for c in candidates:
        status = "✓ PROMOTED TO DNR" if c["promoted"] else "PENDING REVIEW"
        print(f"    - {c['base_domain']:<28} | Confidence: {c['confidence']}% | {c['category']:<24} | [{status}]")

    fp_rows = conn.execute(
        "SELECT site, blocked_domain, rule_id, reason, mitigated FROM false_positive_reports ORDER BY last_updated DESC"
    ).fetchall()
    print("\n ⚠️  False-Positive & Page Breakage Diagnostics:")
    if not fp_rows:
        print("    (0 breakage signals recorded)")
    for fp in fp_rows:
        fp_status = "✓ ALLOWED ON SITE" if fp["mitigated"] else "INVESTIGATE / ALLOW"
        print(
            f"    - {fp['site']:<18} -> {fp['blocked_domain']:<22} | Rule #{fp['rule_id']:<4} | {fp['reason']:<20} | [{fp_status}]"
        )
    print("=" * 74)


def cmd_validate(_args):
    """Deterministic 6-Gate Pre-Flight QA Validator for AegisBlock MV3."""
    conn = get_db()
    gates = []

    # Gate 1: Manifest V3 & Permission Minimalism
    manifest_path = EXT_DIR / "manifest.json"
    g1_ok = False
    g1_msg = ""
    if manifest_path.exists():
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        perms = set(m.get("permissions", []))
        required_files = [
            EXT_DIR / "background.js",
            EXT_DIR / "content.js",
            EXT_DIR / "content.css",
            EXT_DIR / "page_defuser.js",
            EXT_DIR / "popup.html",
            EXT_DIR / "popup.js",
            EXT_DIR / "dashboard.html",
            EXT_DIR / "dashboard.js",
            EXT_DIR / "icons" / "icon16.png",
            EXT_DIR / "icons" / "icon128.png",
        ]
        missing = [str(p.name) for p in required_files if not p.exists()]
        if (
            m.get("manifest_version") == 3
            and "declarativeNetRequest" in perms
            and "declarativeNetRequestFeedback" in perms
            and not missing
        ):
            g1_ok = True
            g1_msg = f"MV3 valid, all {len(required_files)} core files & icons present"
        else:
            g1_msg = f"Missing files or perms: {missing}"
    else:
        g1_msg = "manifest.json missing"
    gates.append(("Gate 1: Manifest V3 & Asset Integrity", g1_ok, g1_msg))

    # Gate 2: Zero-Leak CSP & Outbound Network Audit
    g2_ok = False
    g2_msg = ""
    if manifest_path.exists():
        m = json.loads(manifest_path.read_text(encoding="utf-8"))
        csp = m.get("content_security_policy", {}).get("extension_pages", "")
        has_strict_csp = "connect-src 'self'" in csp or "connect-src 'none'" in csp
        external_calls = []
        for js_name in ("background.js", "content.js", "page_defuser.js", "popup.js", "dashboard.js"):
            js_path = EXT_DIR / js_name
            if js_path.exists():
                code = js_path.read_text(encoding="utf-8")
                if re.search(r"\bfetch\s*\(\s*['\"]https?://", code) or "navigator.sendBeacon" in code or "new WebSocket(" in code:
                    external_calls.append(js_name)
                if "chrome.storage.sync" in code:
                    external_calls.append(f"{js_name}(storage.sync)")
        if has_strict_csp and not external_calls:
            g2_ok = True
            g2_msg = "CSP enforces `connect-src 'self'` and 0 outbound HTTP/WebSocket/storage.sync leaks found"
        else:
            g2_msg = f"CSP={csp}, external_calls={external_calls}"
    gates.append(("Gate 2: Zero-Leak CSP & Outbound Network Audit", g2_ok, g2_msg))

    # Gate 3: DNR Static Ruleset Schema, Chromium C++ url_pattern_index & Quota Validation
    g3_ok = True
    g3_errors = []
    seen_ids = set()
    total_rules = 0
    for rs_name in ("ads_core.json", "trackers_privacy.json", "url_privacy_clean.json", "annoyances_social.json"):
        rs_path = RULES_DIR / rs_name
        if not rs_path.exists():
            g3_ok = False
            g3_errors.append(f"{rs_name} missing")
            continue
        rules = json.loads(rs_path.read_text(encoding="utf-8"))
        for r in rules:
            total_rules += 1
            rid = r.get("id")
            if not isinstance(rid, int) or rid <= 0 or rid in seen_ids:
                g3_ok = False
                g3_errors.append(f"Duplicate/invalid ID {rid}")
            seen_ids.add(rid)
            try:
                validate_chromium_dnr_rule(r, rs_name)
            except ValueError as exc:
                g3_ok = False
                g3_errors.append(str(exc))
    g3_msg = (
        f"Validated {total_rules} static DNR rules against Chromium C++ url_pattern_index parser"
        if g3_ok
        else f"DNR errors: {'; '.join(g3_errors[:3])}"
    )
    gates.append(("Gate 3: DNR Ruleset & Chromium urlFilter Parser", g3_ok, g3_msg))

    # Gate 4: URL Tracking Parameter & Header Privacy Sanitizer
    url_clean_path = RULES_DIR / "url_privacy_clean.json"
    g4_ok = False
    g4_msg = ""
    if url_clean_path.exists():
        u_rules = json.loads(url_clean_path.read_text(encoding="utf-8"))
        remove_params = []
        mod_headers = []
        for r in u_rules:
            act = r.get("action", {})
            if act.get("type") == "redirect":
                remove_params.extend(
                    act.get("redirect", {}).get("transform", {}).get("queryTransform", {}).get("removeParams", [])
                )
            elif act.get("type") == "modifyHeaders":
                mod_headers.extend(act.get("requestHeaders", []) + act.get("responseHeaders", []))
        required_params = {"utm_source", "fbclid", "gclid", "msclkid", "twclid", "mc_eid"}
        if required_params.issubset(set(remove_params)) and len(mod_headers) >= 4:
            g4_ok = True
            g4_msg = f"Stripping {len(remove_params)} tracking query params & {len(mod_headers)} telemetry headers"
        else:
            g4_msg = "Missing required tracking query params or header sanitizers"
    gates.append(("Gate 4: URL Query & Telemetry Header Sanitizer", g4_ok, g4_msg))

    # Gate 5: Cosmetic Pre-Paint Filter, Video Ad Guard & Heuristic Evasion Sensor
    css_code = (EXT_DIR / "content.css").read_text(encoding="utf-8") if (EXT_DIR / "content.css").exists() else ""
    js_code = (EXT_DIR / "content.js").read_text(encoding="utf-8") if (EXT_DIR / "content.js").exists() else ""
    g5_ok = (
        ':root:not([data-aegisblock-paused="true"])' in css_code
        and "REPORT_HEURISTIC_SUSPECT" in js_code
        and "START_ELEMENT_ZAPPER" in js_code
    )
    g5_msg = "Pre-paint CSS disarm selector, Heuristic Evasion Sensor & Shadow-DOM Element Zapper verified"
    gates.append(("Gate 5: Cosmetic Filter & Heuristic Sensor", g5_ok, g5_msg))

    # Gate 6: SQLite Research DB & Windows Unpacked Extension Sync
    win_manifest = WINDOWS_EXT_DIR / "manifest.json"
    g6_ok = DB_PATH.exists() and win_manifest.exists()
    g6_msg = (
        f"SQLite WAL ready ({DB_PATH.name}) & synced to {WINDOWS_EXT_DIR}"
        if g6_ok
        else f"Run `make sync-extension` to sync to {WINDOWS_EXT_DIR}"
    )
    gates.append(("Gate 6: SQLite Research DB & Edge Unpacked Sync", g6_ok, g6_msg))

    passed_all = all(ok for _, ok, _ in gates)
    score = sum(1 for _, ok, _ in gates if ok) * 100 // len(gates)

    conn.execute(
        "INSERT INTO qa_validations (ts, passed, score, details_json) VALUES (?, ?, ?, ?)",
        (int(time.time()), 1 if passed_all else 0, score, json.dumps(gates)),
    )
    conn.commit()

    print("=" * 74)
    print(f" 🛡️  AegisBlock 6-Gate Pre-Flight QA Report (Score: {score}/100)")
    print("=" * 74)
    for title, ok, detail in gates:
        badge = "PASS" if ok else "FAIL"
        print(f"  [{badge}] {title:<48} -> {detail}")
    print("=" * 74)
    if not passed_all:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="AegisBlock MV3 Research & Rule Compiler CLI")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("build", help="Compile static DNR rulesets, icons, and SQLite learned rules")
    sub.add_parser("sync", help="Sync extension to C:\\Users\\oz_co\\code\\extensions\\adblocker")
    sub.add_parser("validate", help="Run 6-Gate Pre-Flight QA Validator")
    sub.add_parser("test", help="Run the automated Python + Node.js MV3 test suite")
    sub.add_parser("stats", help="Display Blocker Research & Telemetry Summary")
    sub.add_parser("simulate-research", help="Seed benchmark multi-site telemetry into SQLite and synthesize rules")

    p_ing = sub.add_parser("ingest", help="Ingest exported telemetry JSON from browser Research Studio")
    p_ing.add_argument("file", help="Path to exported aegisblock-telemetry-*.json")
    p_ing.add_argument("--auto-synthesize", action="store_true", default=True, help="Auto-promote high-confidence suspects")
    p_ing.add_argument("--min-confidence", type=int, default=80, help="Minimum confidence threshold (default: 80)")

    args = parser.parse_args()
    if args.cmd == "build":
        cmd_build(args)
    elif args.cmd == "sync":
        cmd_sync(args)
    elif args.cmd == "validate":
        cmd_validate(args)
    elif args.cmd == "test":
        import unittest
        suite = unittest.defaultTestLoader.discover(str(ROOT_DIR / "tests"), pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        if not res.wasSuccessful():
            sys.exit(1)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "simulate-research":
        cmd_simulate_research(args)
    elif args.cmd == "ingest":
        cmd_ingest(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
