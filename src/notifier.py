"""
Email Notification Module — smtplib
Sends alert summary emails for CRITICAL/HIGH findings.
Configure via environment variables or config.json.
"""

import smtplib
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from src.detectors import Alert


def load_email_config() -> dict:
    """Load config from environment variables or config.json."""
    # Try environment variables first (recommended for production)
    cfg = {
        "smtp_server":   os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
        "smtp_port":     int(os.environ.get("SMTP_PORT", "587")),
        "smtp_user":     os.environ.get("SMTP_USER", ""),
        "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
        "from_addr":     os.environ.get("ALERT_FROM", ""),
        "to_addr":       os.environ.get("ALERT_TO", ""),
    }

    # Fallback: config.json
    if not cfg["smtp_user"]:
        config_path = "config.json"
        if os.path.exists(config_path):
            with open(config_path) as f:
                file_cfg = json.load(f)
                cfg.update(file_cfg.get("email", {}))

    return cfg


def send_alert_email(alerts: list[Alert], scan_meta: dict = None) -> bool:
    """
    Send an email summary of CRITICAL and HIGH alerts.
    Returns True on success, False on failure.
    """
    cfg = load_email_config()

    if not all([cfg["smtp_user"], cfg["smtp_password"], cfg["from_addr"], cfg["to_addr"]]):
        print("  ⚠️  Email config incomplete — skipping email notification.")
        print("     Set SMTP_USER, SMTP_PASSWORD, ALERT_FROM, ALERT_TO env vars to enable.")
        return False

    critical_high = [a for a in alerts if a.severity in ("CRITICAL", "HIGH")]
    if not critical_high:
        print("  ℹ️  No CRITICAL/HIGH alerts — skipping email notification.")
        return True

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for a in alerts if a.severity == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    # Build HTML body
    rows = ""
    for a in critical_high[:20]:  # cap at 20 in email
        rows += f"""
        <tr>
          <td style="padding:8px;border:1px solid #e5e7eb">{a.alert_id}</td>
          <td style="padding:8px;border:1px solid #e5e7eb;color:{'#dc2626' if a.severity=='CRITICAL' else '#ea580c'};
              font-weight:bold">{a.severity}</td>
          <td style="padding:8px;border:1px solid #e5e7eb">{a.rule_name}</td>
          <td style="padding:8px;border:1px solid #e5e7eb">{a.source_ip or 'N/A'}</td>
          <td style="padding:8px;border:1px solid #e5e7eb">{a.mitre_technique}</td>
          <td style="padding:8px;border:1px solid #e5e7eb">{a.timestamp}</td>
        </tr>"""

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;color:#1f2937">
      <div style="max-width:800px;margin:0 auto">
        <div style="background:#0f172a;color:white;padding:20px;border-radius:8px 8px 0 0">
          <h2 style="margin:0">🛡️ SOC Alert Notification</h2>
          <p style="margin:4px 0 0;color:#94a3b8;font-size:13px">{ts}</p>
        </div>
        <div style="background:#fef2f2;border:1px solid #fecaca;padding:16px;text-align:center">
          <strong style="font-size:18px;color:#dc2626">⚠️ {len(critical_high)} Critical/High Alert(s) Detected</strong>
        </div>
        <div style="background:#f8fafc;padding:16px;display:flex;gap:16px;border-bottom:1px solid #e5e7eb">
          <span>🔴 CRITICAL: <strong>{counts['CRITICAL']}</strong></span>
          <span>🟠 HIGH: <strong>{counts['HIGH']}</strong></span>
          <span>🟡 MEDIUM: <strong>{counts['MEDIUM']}</strong></span>
          <span>🔵 LOW: <strong>{counts['LOW']}</strong></span>
          <span>📋 TOTAL: <strong>{len(alerts)}</strong></span>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:8px">
          <thead><tr style="background:#f3f4f6">
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">ID</th>
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">Severity</th>
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">Rule</th>
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">Source IP</th>
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">MITRE</th>
            <th style="padding:8px;border:1px solid #e5e7eb;text-align:left">Time</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        <p style="font-size:12px;color:#6b7280;margin-top:16px;text-align:center">
          Full report available in the reports/ directory.<br>
          Log Analyzer & Anomaly Detector — Portfolio Project
        </p>
      </div>
    </body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[SOC ALERT] {counts['CRITICAL']} Critical, {counts['HIGH']} High — {ts}"
    msg["From"] = cfg["from_addr"]
    msg["To"] = cfg["to_addr"]
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["smtp_user"], cfg["smtp_password"])
            server.sendmail(cfg["from_addr"], cfg["to_addr"], msg.as_string())
        print(f"  ✅ Alert email sent to {cfg['to_addr']}")
        return True
    except Exception as e:
        print(f"  ❌ Email failed: {e}")
        return False
