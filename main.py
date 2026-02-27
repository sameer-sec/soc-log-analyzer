#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         SOC Log Analyzer & Anomaly Detector                      ║
║         Google Cybersecurity Certificate — Portfolio Project     ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python main.py                          # scan all sample logs
  python main.py --logs logs/samples/     # scan a directory
  python main.py --logs myfile.log        # scan a single file
  python main.py --ai                     # enable Gemini AI analysis
  python main.py --email                  # send email notification
  python main.py --ai --email             # full pipeline
"""

import argparse
import sys
import os
import pandas as pd
from pathlib import Path
from datetime import datetime

# Make sure src/ is importable
sys.path.insert(0, str(Path(__file__).parent))

from src.parsers import load_log
from src.detectors import run_all_detections
from src.database import save_alerts, init_db
from src.reporter02 import generate_html_report, generate_text_report


BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  SOC Log Analyzer & Anomaly Detector                         ║
║     Google Cybersecurity Certificate — Portfolio Project        ║
╚══════════════════════════════════════════════════════════════════╝"""

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[96m",  # cyan
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def cprint(sev, text):
    color = SEVERITY_COLORS.get(sev, "")
    print(f"{color}{text}{RESET}")


def collect_log_files(path_arg: str) -> list[str]:
    p = Path(path_arg)
    if p.is_file():
        return [str(p)]
    elif p.is_dir():
        files = []
        for ext in ["*.log", "*.csv", "*.txt"]:
            files.extend([str(f) for f in p.glob(ext)])
        return files
    else:
        print(f"⚠️  Path not found: {path_arg}")
        return []


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="SOC Log Analyzer")
    parser.add_argument("--logs", default="logs/samples",
                        help="Path to log file or directory (default: logs/samples)")
    parser.add_argument("--ai", action="store_true",
                        help="Enable Gemini AI analysis for CRITICAL/HIGH alerts")
    parser.add_argument("--email", action="store_true",
                        help="Send email notification for CRITICAL/HIGH alerts")
    parser.add_argument("--max-ai", type=int, default=5,
                        help="Max alerts to send to Gemini (default: 5)")
    parser.add_argument("--output", default="reports",
                        help="Output directory for reports (default: reports/)")
    args = parser.parse_args()

    # ── 1. Collect log files ──────────────────────────────────────────────────
    files = collect_log_files(args.logs)
    if not files:
        print("❌  No log files found. Exiting.")
        sys.exit(1)

    print(f"\n📂 Found {len(files)} log file(s):")
    for f in files:
        print(f"   • {f}")

    # ── 2. Parse logs ─────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("📖 Parsing logs...")
    frames = []
    total_lines = 0
    for filepath in files:
        try:
            df = load_log(filepath)
            total_lines += len(df)
            frames.append(df)
            print(f"   ✅ {Path(filepath).name} — {len(df)} records")
        except Exception as e:
            print(f"   ❌ {Path(filepath).name} — {e}")

    if not frames:
        print("❌  No logs could be parsed. Exiting.")
        sys.exit(1)

    # Combine into one DataFrame (columns won't all match; that's fine)
    combined = pd.concat(frames, ignore_index=True, sort=False)
    print(f"\n   Total records loaded: {BOLD}{total_lines}{RESET}")

    # ── 3. Run detection rules ────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("🔍 Running detection rules...")

    all_alerts = []
    for df in frames:
        alerts = run_all_detections(df)
        all_alerts.extend(alerts)

    # Final deduplicate across all frames
    seen = set()
    unique_alerts = []
    for a in all_alerts:
        key = (a.rule_name, a.source_ip, str(a.timestamp)[:16])
        if key not in seen:
            seen.add(key)
            unique_alerts.append(a)

    from src.detectors import SEVERITY_ORDER
    unique_alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 99))

    counts = {s: sum(1 for a in unique_alerts if a.severity == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    print(f"\n   {'─'*50}")
    print(f"   {BOLD}RESULTS: {len(unique_alerts)} alert(s){RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts[sev]
        if c > 0:
            cprint(sev, f"   {sev:8s} : {c}")

    print(f"\n{'─'*60}")
    print("📋 Alert Details:\n")

    for a in unique_alerts:
        cprint(a.severity, f"  [{a.severity}] {a.alert_id} — {a.rule_name}")
        print(f"    MITRE   : {a.mitre_tactic}")
        print(f"    Technique: {a.mitre_technique}")
        print(f"    Detail  : {a.description[:120]}")
        print(f"    Time    : {a.timestamp}")
        if a.source_ip:
            print(f"    IP      : {a.source_ip}")
        print()

    # ── 4. AI Analysis ────────────────────────────────────────────────────────
    if args.ai:
        print(f"{'─'*60}")
        print(f"🤖 Running Gemini AI analysis on top {args.max_ai} alerts...")
        from src.ai_analyzer import analyze_critical_alerts
        analyze_critical_alerts(unique_alerts, max_alerts=args.max_ai)

    # ── 5. Save to SQLite ─────────────────────────────────────────────────────
    print(f"{'─'*60}")
    print("💾 Saving to SQLite database...")
    scan_meta = {
        "files": [Path(f).name for f in files],
        "total_lines": total_lines,
        "alert_count": len(unique_alerts),
        **counts
    }
    init_db()
    save_alerts(unique_alerts, run_meta=scan_meta)
    print("   ✅ Saved to db/alerts.db")

    # ── 6. Generate Reports ───────────────────────────────────────────────────
    print(f"{'─'*60}")
    print("📊 Generating reports...")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = f"{args.output}/report_{ts}.html"
    txt_path  = f"{args.output}/report_{ts}.txt"

    generate_html_report(unique_alerts, scan_meta, html_path)
    generate_text_report(unique_alerts, scan_meta, txt_path)
    print(f"   ✅ HTML report : {html_path}")
    print(f"   ✅ Text report : {txt_path}")

    # ── 7. Email Notification ─────────────────────────────────────────────────
    if args.email:
        print(f"{'─'*60}")
        print("📧 Sending email notification...")
        from src.notifier import send_alert_email
        send_alert_email(unique_alerts, scan_meta)

    # ── 8. Done ───────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"✅  Scan complete.")
    print(f"   Open {html_path} in your browser to view the full report.")
    print(f"{'═'*60}\n")

    return 0 if counts["CRITICAL"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
