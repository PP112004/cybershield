"""PS1 CLI — GenAI-powered APK threat analyzer.

Thin command-line wrapper over the same modules the FastAPI service uses
(serving/app/apk.py, llm.py, fusion.py), so the CLI and the API cannot
drift apart.

Architecture rule: the risk score and verdict are DETERMINISTIC (weighted
evidence rules over extracted behaviors + IOCs). The LLM — DeepSeek or
Gemini, picked via LLM_PROVIDER / API-key env vars — only writes the analyst
narrative, and falls back to a template offline.

Usage (from the repo root):
    python3 ps1/apk_analyzer.py --demo                 # mock banking trojan
    python3 ps1/apk_analyzer.py --apk path/to/sample.apk
    DEEPSEEK_API_KEY=... python3 ps1/apk_analyzer.py --demo   # LLM narrative
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serving.app import apk, fusion  # noqa: E402

MOCK_APK_METADATA = {
    "package_name": "com.finance.security.update.boi",
    "app_name": "Bank of India Security Update",
    "version_code": "104",
    "version_name": "1.0.4",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ],
    "activities": [
        "com.finance.security.update.boi.MainActivity",
        "com.finance.security.update.boi.OverlayActivity",
    ],
    "receivers": ["com.finance.security.update.boi.SmsReceiver"],
    "services": [
        "com.finance.security.update.boi.AccessibilityMonitoringService",
    ],
    "suspicious_strings": [
        "http://c2-server.mulenet-control.xyz/gate.php",
        "api/v1/log_keys",
        "sms_intercepted",
        "otp_regex: [0-9]{6}",
        "payout_beneficiary: quickcash.refund@ybl",
        "tg_exfil: 8123456789:AAFakeTelegramBotTokenForDemo_12345",
    ],
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GenAI-Powered APK Automated Threat Analyzer")
    parser.add_argument("--apk", help="Path to the APK file to analyze")
    parser.add_argument("--demo", action="store_true",
                        help="Run on mock banking-trojan metadata")
    parser.add_argument("--json", action="store_true",
                        help="Emit the raw JSON report instead of pretty text")
    parser.add_argument("--no-watchlist", action="store_true",
                        help="Do not append extracted IOCs to the watchlist")
    args = parser.parse_args()

    if not args.apk and not args.demo:
        parser.print_help()
        sys.exit(1)

    if args.demo:
        metadata = MOCK_APK_METADATA
    else:
        if not Path(args.apk).exists():
            sys.exit(f"[ERROR] APK file not found: {args.apk}")
        metadata = apk.extract_metadata(args.apk)

    report = apk.risk_engine(metadata)
    if not args.no_watchlist:
        report["watchlist_iocs_added"] = fusion.add_iocs(
            report["iocs"], source=report["package_name"] or "unknown")
    report["analyst_narrative"] = apk.narrative(report)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    print("=" * 60)
    print("      GENAI-POWERED APK AUTOMATED THREAT ANALYZER")
    print("=" * 60)
    print(f"Application Name : {report['app_name']}")
    print(f"Package Name     : {report['package_name']}")
    print(f"Risk Score       : {report['risk_score']}/100 (deterministic)")
    print(f"Threat Severity  : {report['threat_severity']}")
    print(f"Is Malicious     : {report['is_malicious']}")
    print("-" * 60)
    print("FLAGGED BEHAVIORS:")
    for b in report["flagged_behaviors"]:
        print(f"  • [{b['behavior']}] +{b['points']}")
        print(f"    {b['description']}")
    print("-" * 60)
    print("EXTRACTED IOCs:")
    for kind, values in report["iocs"].items():
        for v in values:
            print(f"  {kind:20s} {v}")
    if not args.no_watchlist:
        print(f"  -> {report.get('watchlist_iocs_added', 0)} new IOC(s) "
              f"pushed to the PS2 watchlist")
    print("-" * 60)
    print("ANALYST NARRATIVE:")
    print(report["analyst_narrative"])
    print("=" * 60)


if __name__ == "__main__":
    main()
