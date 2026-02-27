"""
Report Generator — HTML + plain text alert reports
"""

import json
from datetime import datetime
from pathlib import Path
from src.detectors import Alert, SEVERITY_ORDER


SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eff6ff",
}


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#6b7280")
    return (f'<span style="background:{color};color:white;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:bold">{sev}</span>')


def generate_html_report(alerts: list[Alert], scan_meta: dict, output_path: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for a in alerts if a.severity == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    # Build alert rows
    rows_html = ""
    for a in alerts:
        bg = SEVERITY_BG.get(a.severity, "#fff")
        ai_section = ""
        if hasattr(a, 'ai_analysis') and a.ai_analysis:
            try:
                ai = json.loads(a.ai_analysis) if isinstance(a.ai_analysis, str) else a.ai_analysis
                actions_html = "".join(f"<li>{x}</li>" for x in ai.get('recommended_actions', []))
                ai_section = f"""
                <div style="margin-top:10px;padding:10px;background:#f0f9ff;border-left:3px solid #0284c7;border-radius:4px">
                  <strong>🤖 AI Analysis (Gemini)</strong><br>
                  <em>{ai.get('explanation','')}</em><br><br>
                  <strong>MITRE:</strong> {ai.get('mitre_tactic','')} | {ai.get('mitre_technique','')}<br>
                  <strong>Recommended Actions:</strong><ul style="margin:4px 0 0 16px">{actions_html}</ul>
                  <strong>False Positive Notes:</strong> {ai.get('false_positive_notes','')}
                </div>"""
            except Exception:
                ai_section = f'<div style="margin-top:8px;color:#666;font-size:12px">{str(a.ai_analysis)[:300]}</div>'

        rows_html += f"""
        <div style="margin-bottom:16px;padding:16px;background:{bg};
                    border-left:4px solid {SEVERITY_COLORS.get(a.severity,'#888')};
                    border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.08)">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
            <span style="font-weight:600;color:#1f2937">{a.alert_id} — {a.rule_name}</span>
            {_severity_badge(a.severity)}
          </div>
          <div style="margin-top:8px;color:#374151;font-size:14px">{a.description}</div>
          <div style="margin-top:8px;font-size:12px;color:#6b7280;display:flex;flex-wrap:wrap;gap:16px">
            <span>📌 <b>MITRE:</b> {a.mitre_tactic} | {a.mitre_technique}</span>
            {'<span>🌐 <b>IP:</b> ' + str(a.source_ip) + '</span>' if a.source_ip else ''}
            {'<span>👤 <b>User:</b> ' + str(a.affected_user) + '</span>' if a.affected_user else ''}
            <span>🕒 {a.timestamp}</span>
            <span>📋 {a.log_type}</span>
          </div>
          <details style="margin-top:8px">
            <summary style="cursor:pointer;font-size:12px;color:#6b7280">Raw Log</summary>
            <code style="font-size:11px;color:#374151;display:block;margin-top:4px;
                         background:#f3f4f6;padding:8px;border-radius:4px;word-break:break-all">
              {a.raw_log[:500]}
            </code>
          </details>
          {ai_section}
        </div>"""

    files_list = ", ".join(scan_meta.get('files', []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Alert Report — {ts}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f8fafc; color:#1f2937; }}
  .container {{ max-width:1000px; margin:0 auto; padding:24px 16px; }}
  .header {{ background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
             color:white; padding:28px 32px; border-radius:10px; margin-bottom:24px }}
  .header h1 {{ font-size:22px; font-weight:700; letter-spacing:0.5px }}
  .header p {{ font-size:13px; color:#94a3b8; margin-top:6px }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
            gap:12px; margin-bottom:24px }}
  .stat-card {{ background:white; border-radius:8px; padding:16px; text-align:center;
                box-shadow:0 1px 4px rgba(0,0,0,.08); border-top:3px solid }}
  .stat-card .num {{ font-size:32px; font-weight:700 }}
  .stat-card .label {{ font-size:12px; color:#6b7280; margin-top:4px }}
  .section-title {{ font-size:15px; font-weight:600; color:#374151;
                    margin:20px 0 12px; padding-bottom:8px;
                    border-bottom:1px solid #e5e7eb }}
  .no-alerts {{ text-align:center; padding:40px; color:#6b7280; background:white;
                border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,.06) }}
  .footer {{ text-align:center; font-size:12px; color:#9ca3af; margin-top:32px; padding-top:16px;
             border-top:1px solid #e5e7eb }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ SOC Log Analyzer — Alert Report</h1>
    <p>Generated: {ts} &nbsp;|&nbsp; Files scanned: {files_list} &nbsp;|&nbsp;
       Total log lines: {scan_meta.get('total_lines','?')}</p>
  </div>

  <div class="stats">
    <div class="stat-card" style="border-color:{SEVERITY_COLORS['CRITICAL']}">
      <div class="num" style="color:{SEVERITY_COLORS['CRITICAL']}">{counts['CRITICAL']}</div>
      <div class="label">CRITICAL</div>
    </div>
    <div class="stat-card" style="border-color:{SEVERITY_COLORS['HIGH']}">
      <div class="num" style="color:{SEVERITY_COLORS['HIGH']}">{counts['HIGH']}</div>
      <div class="label">HIGH</div>
    </div>
    <div class="stat-card" style="border-color:{SEVERITY_COLORS['MEDIUM']}">
      <div class="num" style="color:{SEVERITY_COLORS['MEDIUM']}">{counts['MEDIUM']}</div>
      <div class="label">MEDIUM</div>
    </div>
    <div class="stat-card" style="border-color:{SEVERITY_COLORS['LOW']}">
      <div class="num" style="color:{SEVERITY_COLORS['LOW']}">{counts['LOW']}</div>
      <div class="label">LOW</div>
    </div>
    <div class="stat-card" style="border-color:#6b7280">
      <div class="num" style="color:#374151">{len(alerts)}</div>
      <div class="label">TOTAL ALERTS</div>
    </div>
  </div>

  <div class="section-title">🚨 Alerts (sorted by severity)</div>

  {'<div class="no-alerts">✅ No anomalies detected in the scanned logs.</div>' if not alerts else rows_html}

  <div class="footer">
    Log Analyzer & Anomaly Detector &nbsp;|&nbsp; Google Cybersecurity Certificate Portfolio Project<br>
    MITRE ATT&amp;CK® mappings are for reference only.
  </div>
</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path


def generate_text_report(alerts: list[Alert], scan_meta: dict, output_path: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for a in alerts if a.severity == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    lines = [
        "=" * 72,
        "  SOC LOG ANALYZER — ALERT REPORT",
        f"  Generated : {ts}",
        f"  Files     : {', '.join(scan_meta.get('files', []))}",
        f"  Log lines : {scan_meta.get('total_lines', '?')}",
        "=" * 72,
        "",
        f"  SUMMARY: {len(alerts)} alert(s) found",
        f"  CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}",
        "",
        "-" * 72,
    ]

    for a in alerts:
        lines += [
            f"[{a.severity}] {a.alert_id} — {a.rule_name}",
            f"  Timestamp : {a.timestamp}",
            f"  Log Type  : {a.log_type}",
            f"  Source IP : {a.source_ip or 'N/A'}",
            f"  User      : {a.affected_user or 'N/A'}",
            f"  MITRE     : {a.mitre_tactic} | {a.mitre_technique}",
            f"  Detail    : {a.description}",
            f"  Raw       : {str(a.raw_log)[:120]}...",
        ]
        if hasattr(a, 'ai_analysis') and a.ai_analysis:
            try:
                ai = json.loads(a.ai_analysis) if isinstance(a.ai_analysis, str) else a.ai_analysis
                lines.append(f"  AI Note   : {ai.get('explanation','')[:200]}")
            except Exception:
                pass
        lines.append("-" * 72)

    Path(output_path).parent.mkdir(exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    return output_path
