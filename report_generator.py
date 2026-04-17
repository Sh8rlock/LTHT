#!/usr/bin/env python3
"""
LTHT - Report Generator
========================
Generates professional HTML and JSON threat hunt reports with
executive summary, finding details, MITRE ATT&CK mapping, and timeline.
"""

import json
import html
from datetime import datetime


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
        "INFO": "#2563eb",
    }.get(severity.upper(), "#6b7280")


def _severity_badge(severity: str) -> str:
    color = _severity_color(severity)
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:4px;font-size:0.8rem;font-weight:600;">{severity}</span>'
    )


def _risk_bar(score: int) -> str:
    color = "#dc2626" if score >= 80 else "#ea580c" if score >= 60 else "#ca8a04" if score >= 40 else "#16a34a"
    return (
        f'<div style="background:#e5e7eb;border-radius:4px;width:120px;height:14px;display:inline-block;vertical-align:middle;">'
        f'<div style="background:{color};width:{score}%;height:100%;border-radius:4px;"></div></div>'
        f' <strong>{score}</strong>'
    )


def generate_json_report(findings: list, attack_summary: dict, parsed_logs: dict, output_path: str) -> str:
    """Generate a JSON threat hunt report."""
    report = {
        "report_type": "LTHT Threat Hunt Report",
        "generated_at": datetime.now().isoformat(),
        "tool_version": "1.0.0",
        "summary": {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium_count": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low_count": sum(1 for f in findings if f.get("severity") == "LOW"),
            "total_risk_score": sum(f.get("risk_score", 0) for f in findings),
            "log_entries_analyzed": parsed_logs.get("total_entries", 0),
            "files_parsed": parsed_logs.get("files_parsed", []),
        },
        "mitre_attack_summary": attack_summary,
        "findings": findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return output_path


def generate_html_report(findings: list, attack_summary: dict, parsed_logs: dict, output_path: str) -> str:
    """Generate a professional HTML threat hunt report."""

    total = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")
    total_risk = sum(f.get("risk_score", 0) for f in findings)
    log_count = parsed_logs.get("total_entries", 0)
    files = parsed_logs.get("files_parsed", [])

    # --- Build findings rows ---
    findings_html = ""
    for i, f in enumerate(findings, 1):
        techs = ""
        for t in f.get("mitre_techniques", []):
            techs += (
                f'<a href="{t["url"]}" target="_blank" style="color:#2563eb;text-decoration:none;">'
                f'{t["id"]}</a> — {html.escape(t["name"])}<br>'
            )
        if not techs:
            techs = "—"

        evidence = ""
        for ev in f.get("evidence", [])[:3]:
            evidence += f'<code style="display:block;background:#1e293b;color:#e2e8f0;padding:6px 10px;margin:3px 0;border-radius:4px;font-size:0.78rem;word-break:break-all;">{html.escape(str(ev))}</code>'

        findings_html += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-left:4px solid {_severity_color(f.get('severity','MEDIUM'))};border-radius:8px;padding:20px;margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <div>
                    <span style="color:#6b7280;font-size:0.85rem;">{html.escape(f.get('rule_id',''))}</span>
                    <h3 style="margin:4px 0;font-size:1.1rem;">{html.escape(f.get('rule_name',''))}</h3>
                </div>
                <div style="text-align:right;">
                    {_severity_badge(f.get('severity','MEDIUM'))}
                    <div style="margin-top:6px;">{_risk_bar(f.get('risk_score', 0))}</div>
                </div>
            </div>
            <p style="color:#374151;margin:8px 0;">{html.escape(f.get('description',''))}</p>
            <div style="margin:12px 0;">
                <strong style="font-size:0.85rem;color:#6b7280;">MITRE ATT&CK:</strong><br>
                <div style="margin-top:4px;font-size:0.88rem;">{techs}</div>
            </div>
            <div style="margin:12px 0;">
                <strong style="font-size:0.85rem;color:#6b7280;">Evidence:</strong>
                {evidence}
            </div>
            <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:12px;margin-top:10px;">
                <strong style="color:#166534;font-size:0.85rem;">&#9889; Recommendation:</strong>
                <p style="color:#166534;margin:6px 0 0 0;font-size:0.9rem;">{html.escape(f.get('recommendation',''))}</p>
            </div>
        </div>
        """

    # --- ATT&CK matrix summary ---
    tactic_cards = ""
    for tactic, count in attack_summary.get("tactic_breakdown", {}).items():
        tactic_cards += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center;min-width:140px;">
            <div style="font-size:1.6rem;font-weight:700;color:#1e293b;">{count}</div>
            <div style="font-size:0.82rem;color:#6b7280;margin-top:4px;">{html.escape(tactic)}</div>
        </div>
        """

    technique_rows = ""
    for tid, info in attack_summary.get("technique_details", {}).items():
        tech = info["technique"]
        technique_rows += f"""
        <tr>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;">
                <a href="{tech['url']}" target="_blank" style="color:#2563eb;text-decoration:none;font-weight:600;">{tid}</a>
            </td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{html.escape(tech['name'])}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{html.escape(tech['tactic'])}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;text-align:center;">{info['finding_count']}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;">{_severity_badge(info['max_severity'])}</td>
        </tr>
        """

    # --- Full HTML ---
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LTHT Threat Hunt Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #f1f5f9; padding: 12px; text-align: left; font-size: 0.85rem; color: #475569; border-bottom: 2px solid #e2e8f0; }}
        @media print {{ body {{ background: #fff; }} .container {{ max-width: 100%; }} }}
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:#fff;border-radius:12px;padding:32px;margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <h1 style="color:#fff;font-size:1.8rem;">&#128737; LTHT Threat Hunt Report</h1>
                <p style="color:#94a3b8;margin-top:6px;">Linux Threat Hunt Toolkit — Automated IOC Analysis</p>
            </div>
            <div style="text-align:right;color:#94a3b8;font-size:0.85rem;">
                <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div>Log entries analyzed: {log_count:,}</div>
                <div>Files parsed: {', '.join(files)}</div>
            </div>
        </div>
    </div>

    <!-- Executive Summary -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px;">
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;text-align:center;">
            <div style="font-size:2rem;font-weight:700;">{total}</div>
            <div style="color:#6b7280;font-size:0.88rem;">Total Findings</div>
        </div>
        <div style="background:#fff;border:1px solid #fecaca;border-radius:10px;padding:20px;text-align:center;">
            <div style="font-size:2rem;font-weight:700;color:#dc2626;">{critical}</div>
            <div style="color:#6b7280;font-size:0.88rem;">Critical</div>
        </div>
        <div style="background:#fff;border:1px solid #fed7aa;border-radius:10px;padding:20px;text-align:center;">
            <div style="font-size:2rem;font-weight:700;color:#ea580c;">{high}</div>
            <div style="color:#6b7280;font-size:0.88rem;">High</div>
        </div>
        <div style="background:#fff;border:1px solid #fde68a;border-radius:10px;padding:20px;text-align:center;">
            <div style="font-size:2rem;font-weight:700;color:#ca8a04;">{medium}</div>
            <div style="color:#6b7280;font-size:0.88rem;">Medium</div>
        </div>
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;text-align:center;">
            <div style="font-size:2rem;font-weight:700;color:#1e293b;">{total_risk}</div>
            <div style="color:#6b7280;font-size:0.88rem;">Risk Score</div>
        </div>
    </div>

    <!-- MITRE ATT&CK Summary -->
    <h2 style="margin:28px 0 16px;">&#127919; MITRE ATT&CK Coverage</h2>
    <p style="color:#6b7280;margin-bottom:16px;">
        {attack_summary.get('techniques_observed', 0)} unique techniques observed across
        {attack_summary.get('tactics_observed', 0)} tactics
    </p>

    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;">
        {tactic_cards}
    </div>

    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;margin-bottom:28px;">
        <table>
            <thead>
                <tr>
                    <th>Technique ID</th>
                    <th>Name</th>
                    <th>Tactic(s)</th>
                    <th>Findings</th>
                    <th>Max Severity</th>
                </tr>
            </thead>
            <tbody>
                {technique_rows}
            </tbody>
        </table>
    </div>

    <!-- Detailed Findings -->
    <h2 style="margin:28px 0 16px;">&#128270; Detailed Findings</h2>
    {findings_html}

    <!-- Footer -->
    <div style="text-align:center;color:#94a3b8;font-size:0.8rem;padding:24px 0;border-top:1px solid #e5e7eb;margin-top:32px;">
        Generated by LTHT — Linux Threat Hunt Toolkit v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html_content)

    return output_path
