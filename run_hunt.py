#!/usr/bin/env python3
"""
LTHT - Linux Threat Hunt Toolkit
==================================
Automated Linux log analyzer with MITRE ATT&CK mapping.
Parses auth.log, syslog, bash_history, and cron logs to detect IOCs,
map findings to ATT&CK techniques, and generate professional reports.

Usage:
    python run_hunt.py --log-dir sample_logs/
    python run_hunt.py --log-dir /var/log/ --output report.html
    python run_hunt.py --log-dir sample_logs/ --json-only
    python run_hunt.py --log-dir sample_logs/ --html-only --quiet

Author: Larry Odeyemi
License: MIT
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_all_logs
from detection_engine import run_all_detections
from mitre_mapper import map_all_findings, get_attack_summary
from report_generator import generate_html_report, generate_json_report


def _print_banner():
    print(r"""
  _   _____ _  _ _____
 | | |_   _| || |_   _|
 | |__ | | | __ | | |
 |____||_| |_||_| |_|

  Linux Threat Hunt Toolkit
  Automated IOC Detection & MITRE ATT&CK Mapping
""")


def _severity_bar(label: str, count: int, total: int, color_code: str):
    bar_len = 20
    pct = (count / total * 100) if total > 0 else 0
    filled = int(pct / 100 * bar_len)
    bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
    print(f"    {label:<12} {bar} {count:>3} ({pct:>5.1f}%)")


def _print_summary(findings: list, attack_summary: dict, parsed_logs: dict):
    total = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")
    total_risk = sum(f.get("risk_score", 0) for f in findings)

    print(f"  Log Entries Analyzed:  {parsed_logs.get('total_entries', 0)}")
    print(f"  Files Parsed:         {', '.join(parsed_logs.get('files_parsed', []))}")
    print()
    print(f"  Total Findings:       {total}")
    print(f"  Aggregate Risk Score: {total_risk}")
    print()

    print("  Severity Breakdown:")
    _severity_bar("CRITICAL", critical, total, "red")
    _severity_bar("HIGH", high, total, "orange")
    _severity_bar("MEDIUM", medium, total, "yellow")
    _severity_bar("LOW", low, total, "green")
    print()

    print(f"  MITRE ATT&CK Coverage:")
    print(f"    Techniques Observed: {attack_summary.get('techniques_observed', 0)}")
    print(f"    Tactics Observed:    {attack_summary.get('tactics_observed', 0)}")
    print()

    tactic_breakdown = attack_summary.get("tactic_breakdown", {})
    if tactic_breakdown:
        print("  Tactic Breakdown:")
        for tactic, count in tactic_breakdown.items():
            print(f"    {tactic:<35} {count} finding(s)")
        print()

    # Top findings
    if findings:
        print("  Top Findings:")
        for f in findings[:5]:
            sev = f.get("severity", "?")
            name = f.get("rule_name", "Unknown")
            risk = f.get("risk_score", 0)
            techs = ", ".join(t["id"] for t in f.get("mitre_techniques", []))
            print(f"    [{sev:>8}] {name:<45} Risk: {risk:>3}  ATT&CK: {techs}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="LTHT - Linux Threat Hunt Toolkit: Automated IOC detection with MITRE ATT&CK mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--log-dir", "-d", required=True, help="Path to directory containing log files")
    parser.add_argument("--output", "-o", default=None, help="Output file path (base name)")
    parser.add_argument("--json-only", action="store_true", help="Generate JSON report only")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console output")

    args = parser.parse_args()

    if not args.quiet:
        _print_banner()

    # Validate input
    if not os.path.isdir(args.log_dir):
        print(f"  Error: Log directory not found: {args.log_dir}")
        sys.exit(1)

    # Phase 1: Parse logs
    if not args.quiet:
        print(f"  Parsing logs in: {args.log_dir}")

    start = time.time()
    parsed_logs = parse_all_logs(args.log_dir)
    parse_time = time.time() - start

    if parsed_logs["total_entries"] == 0:
        print("  Warning: No log entries found. Ensure the directory contains")
        print("  supported files: auth.log, syslog, bash_history, cron.log")
        sys.exit(1)

    if not args.quiet:
        print(f"  Parsed {parsed_logs['total_entries']} entries in {parse_time:.3f}s")

    # Phase 2: Run detections
    if not args.quiet:
        print("  Running detection engine...")

    start = time.time()
    findings = run_all_detections(parsed_logs)
    detect_time = time.time() - start

    if not args.quiet:
        print(f"  Detection completed in {detect_time:.3f}s — {len(findings)} finding(s)")

    # Phase 3: Map to MITRE ATT&CK
    if not args.quiet:
        print("  Mapping to MITRE ATT&CK framework...")

    findings = map_all_findings(findings)
    attack_summary = get_attack_summary(findings)

    # Phase 4: Print summary
    if not args.quiet:
        print()
        _print_summary(findings, attack_summary, parsed_logs)

    # Phase 5: Generate reports
    base_name = args.output or "ltht_report"
    if base_name.endswith(".html") or base_name.endswith(".json"):
        base_name = base_name.rsplit(".", 1)[0]

    if not args.json_only:
        html_path = f"{base_name}.html"
        generate_html_report(findings, attack_summary, parsed_logs, html_path)
        if not args.quiet:
            print(f"  HTML report saved: {html_path}")

    if not args.html_only:
        json_path = f"{base_name}.json"
        generate_json_report(findings, attack_summary, parsed_logs, json_path)
        if not args.quiet:
            print(f"  JSON report saved: {json_path}")

    if not args.quiet:
        print()
        print("  Hunt complete. Open the HTML report in a browser to review findings.")
        print()


if __name__ == "__main__":
    main()
