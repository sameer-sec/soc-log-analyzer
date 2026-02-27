"""
Detection Engine — SOC Anomaly Rules
Maps findings to MITRE ATT&CK where applicable.
"""

import re
import pandas as pd
from datetime import timedelta
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    alert_id: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    rule_name: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    source_ip: Optional[str]
    affected_user: Optional[str]
    log_type: str
    raw_log: str
    timestamp: str


# ─── Severity colours for reports ────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ─── Suspicious path patterns ────────────────────────────────────────────────
SCAN_PATHS = re.compile(
    r'(?:\.env|config\.php|wp-admin|phpmyadmin|adminer|\.git|backup\.sql'
    r'|\.htaccess|/etc/passwd|/proc/|/\.\.\/)',
    re.IGNORECASE
)

SQL_INJECT = re.compile(
    r'(?:UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|OR\s+1=1'
    r'|--\s*$|;\s*DROP|xp_cmdshell)',
    re.IGNORECASE
)

ENCODED_PS = re.compile(r'powershell.*-en[co]{1,2}[a-z]*\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)

HIGH_RISK_COMMANDS = re.compile(
    r'(?:/etc/shadow|/bin/bash\s+-i|/dev/tcp|nc\s+-[el]|wget\s+http|curl\s+http.*\|\s*bash)',
    re.IGNORECASE
)

DANGEROUS_WIN_EVENTS = {
    4720: ("Account Created",        "MEDIUM", "TA0003", "T1136.001"),
    4732: ("Group Membership Change","MEDIUM", "TA0004", "T1078"),
    7045: ("New Service Installed",  "HIGH",   "TA0003", "T1543.003"),
    4698: ("Scheduled Task Created", "HIGH",   "TA0003", "T1053.005"),
    1102: ("Audit Log Cleared",      "CRITICAL","TA0005","T1070.001"),
    4648: ("Explicit Credential Use","MEDIUM", "TA0008", "T1550.002"),
}


# ─── Detection Functions ──────────────────────────────────────────────────────

def _alert_counter():
    _alert_counter.n = getattr(_alert_counter, 'n', 0)
    _alert_counter.n += 1
    return f"ALERT-{_alert_counter.n:04d}"


def detect_brute_force(df: pd.DataFrame, threshold: int = 5,
                       window_minutes: int = 1) -> list[Alert]:
    """Detect ≥ threshold failed logins from same IP within window."""
    alerts = []
    failed = df[
        df.get('status', pd.Series(dtype=int)).isin([401, 403]) |
        df.get('raw', pd.Series(dtype=str)).str.contains('Failed password|failed to log on', case=False, na=False)
    ].copy()

    if failed.empty or 'timestamp' not in failed.columns:
        return alerts

    failed = failed.dropna(subset=['timestamp']).sort_values('timestamp')

    # Group by IP
    ip_col = 'ip' if 'ip' in failed.columns else None
    if ip_col is None and 'ip' in df.columns:
        ip_col = 'ip'
    
    group_col = ip_col if ip_col else 'log_type'

    for ip, grp in failed.groupby(group_col):
        grp = grp.sort_values('timestamp')
        times = list(grp['timestamp'])
        for i, t in enumerate(times):
            window = [x for x in times if 0 <= (x - t).total_seconds() <= window_minutes * 60]
            if len(window) >= threshold:
                sample_row = grp.iloc[i]
                alerts.append(Alert(
                    alert_id=_alert_counter(),
                    severity="HIGH",
                    rule_name="Brute Force Login Attempt",
                    mitre_tactic="TA0006 - Credential Access",
                    mitre_technique="T1110.001 - Password Guessing",
                    description=f"IP {ip} had {len(window)} failed logins within {window_minutes} minute(s). "
                                f"Classic brute-force indicator.",
                    source_ip=str(ip),
                    affected_user=sample_row.get('user') or sample_row.get('UserName'),
                    log_type=sample_row.get('log_type', 'unknown'),
                    raw_log=str(sample_row.get('raw', '')),
                    timestamp=str(times[i])
                ))
                break  # one alert per IP per window sweep

    return alerts


def detect_recon_scanning(df: pd.DataFrame) -> list[Alert]:
    """Detect path/port scanning (many 404s or sensitive path hits)."""
    alerts = []
    if 'path' not in df.columns:
        return alerts

    # Sensitive path hits
    mask = df['path'].str.contains(SCAN_PATHS, na=False)
    hits = df[mask]

    for ip, grp in hits.groupby('ip'):
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="MEDIUM",
            rule_name="Reconnaissance / Directory Scanning",
            mitre_tactic="TA0043 - Reconnaissance",
            mitre_technique="T1595.003 - Wordlist Scanning",
            description=f"IP {ip} probed {len(grp)} sensitive path(s): "
                        f"{', '.join(grp['path'].tolist()[:5])}",
            source_ip=str(ip),
            affected_user=None,
            log_type="apache",
            raw_log=str(grp.iloc[0].get('raw', '')),
            timestamp=str(grp.iloc[0]['timestamp'])
        ))

    return alerts


def detect_sql_injection(df: pd.DataFrame) -> list[Alert]:
    """Detect SQL injection patterns in URL paths."""
    alerts = []
    if 'path' not in df.columns:
        return alerts

    mask = df['path'].str.contains(SQL_INJECT, na=False)
    hits = df[mask]

    for _, row in hits.iterrows():
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="CRITICAL",
            rule_name="SQL Injection Attempt",
            mitre_tactic="TA0001 - Initial Access",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            description=f"Possible SQL injection in request: {row['path']}",
            source_ip=row.get('ip'),
            affected_user=None,
            log_type="apache",
            raw_log=str(row.get('raw', '')),
            timestamp=str(row['timestamp'])
        ))

    return alerts


def detect_path_traversal(df: pd.DataFrame) -> list[Alert]:
    alerts = []
    if 'path' not in df.columns:
        return alerts

    mask = df['path'].str.contains(r'\.\.[/\\]', na=False)
    for _, row in df[mask].iterrows():
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="HIGH",
            rule_name="Path Traversal Attempt",
            mitre_tactic="TA0001 - Initial Access",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            description=f"Path traversal detected: {row['path']}",
            source_ip=row.get('ip'),
            affected_user=None,
            log_type="apache",
            raw_log=str(row.get('raw', '')),
            timestamp=str(row['timestamp'])
        ))
    return alerts


def detect_suspicious_commands(df: pd.DataFrame) -> list[Alert]:
    """Detect high-risk shell commands in auth/sudo logs."""
    alerts = []
    if 'message' not in df.columns and 'raw' not in df.columns:
        return alerts

    col = 'message' if 'message' in df.columns else 'raw'
    mask = df[col].str.contains(HIGH_RISK_COMMANDS, na=False)

    for _, row in df[mask].iterrows():
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="CRITICAL",
            rule_name="Suspicious Command Execution",
            mitre_tactic="TA0002 - Execution",
            mitre_technique="T1059.004 - Unix Shell",
            description=f"High-risk command detected: {str(row[col])[:200]}",
            source_ip=row.get('ip'),
            affected_user=row.get('user'),
            log_type=row.get('log_type', 'auth'),
            raw_log=str(row.get('raw', '')),
            timestamp=str(row.get('timestamp', ''))
        ))
    return alerts


def detect_new_uid0_user(df: pd.DataFrame) -> list[Alert]:
    """Detect new user created with UID=0 (root-level backdoor)."""
    alerts = []
    col = 'message' if 'message' in df.columns else 'raw'
    if col not in df.columns:
        return alerts

    mask = df[col].str.contains(r'new user.*UID=0|new user.*uid=0', case=False, na=False)
    for _, row in df[mask].iterrows():
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="CRITICAL",
            rule_name="Backdoor Account Created (UID=0)",
            mitre_tactic="TA0003 - Persistence",
            mitre_technique="T1136.001 - Create Local Account",
            description=f"New user with UID=0 (root-equivalent) created: {str(row[col])[:200]}",
            source_ip=row.get('ip'),
            affected_user=row.get('user'),
            log_type=row.get('log_type', 'auth'),
            raw_log=str(row.get('raw', '')),
            timestamp=str(row.get('timestamp', ''))
        ))
    return alerts


def detect_encoded_powershell(df: pd.DataFrame) -> list[Alert]:
    """Detect Base64-encoded PowerShell (obfuscated execution)."""
    alerts = []
    col = 'message' if 'message' in df.columns else 'raw'
    if col not in df.columns:
        return alerts

    mask = df[col].str.contains(ENCODED_PS, na=False)
    for _, row in df[mask].iterrows():
        alerts.append(Alert(
            alert_id=_alert_counter(),
            severity="HIGH",
            rule_name="Encoded PowerShell Execution",
            mitre_tactic="TA0002 - Execution",
            mitre_technique="T1059.001 - PowerShell",
            description=f"Encoded PowerShell command detected — possible obfuscation: {str(row[col])[:200]}",
            source_ip=None,
            affected_user=row.get('user'),
            log_type="windows",
            raw_log=str(row.get('raw', '')),
            timestamp=str(row.get('timestamp', ''))
        ))
    return alerts


def detect_windows_events(df: pd.DataFrame) -> list[Alert]:
    """Map high-risk Windows Event IDs to alerts."""
    alerts = []
    if 'event_id' not in df.columns:
        return alerts

    for _, row in df.iterrows():
        eid = int(row['event_id']) if pd.notna(row['event_id']) else 0
        if eid in DANGEROUS_WIN_EVENTS:
            label, sev, tactic, technique = DANGEROUS_WIN_EVENTS[eid]
            alerts.append(Alert(
                alert_id=_alert_counter(),
                severity=sev,
                rule_name=f"Windows Event {eid}: {label}",
                mitre_tactic=tactic,
                mitre_technique=technique,
                description=f"EventID {eid} on {row.get('computer','?')} by {row.get('user','?')}: {row.get('message','')[:200]}",
                source_ip=None,
                affected_user=str(row.get('user', '')),
                log_type="windows",
                raw_log=str(row.get('raw', '')),
                timestamp=str(row.get('timestamp', ''))
            ))
    return alerts


# ─── Master Runner ────────────────────────────────────────────────────────────

def run_all_detections(df: pd.DataFrame) -> list[Alert]:
    all_alerts = []
    all_alerts += detect_brute_force(df)
    all_alerts += detect_recon_scanning(df)
    all_alerts += detect_sql_injection(df)
    all_alerts += detect_path_traversal(df)
    all_alerts += detect_suspicious_commands(df)
    all_alerts += detect_new_uid0_user(df)
    all_alerts += detect_encoded_powershell(df)
    all_alerts += detect_windows_events(df)

    # Deduplicate: same rule + same IP + same minute
    seen = set()
    unique = []
    for a in all_alerts:
        key = (a.rule_name, a.source_ip, str(a.timestamp)[:16])
        if key not in seen:
            seen.add(key)
            unique.append(a)

    return sorted(unique, key=lambda a: SEVERITY_ORDER.get(a.severity, 99))
