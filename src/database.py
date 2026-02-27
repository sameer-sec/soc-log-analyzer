"""
SQLite Storage Layer — persist alerts and analysis results
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from src.detectors import Alert


DB_PATH = Path("db/alerts.db")


def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    return sqlite3.connect(str(DB_PATH))


def init_db():
    with get_connection() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id     TEXT NOT NULL,
            severity     TEXT NOT NULL,
            rule_name    TEXT NOT NULL,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            description  TEXT,
            source_ip    TEXT,
            affected_user TEXT,
            log_type     TEXT,
            raw_log      TEXT,
            timestamp    TEXT,
            ai_analysis  TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scan_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_at      TEXT DEFAULT (datetime('now')),
            files       TEXT,
            total_lines INTEGER,
            alert_count INTEGER,
            critical    INTEGER,
            high        INTEGER,
            medium      INTEGER,
            low         INTEGER
        );
        """)


def save_alerts(alerts: list[Alert], run_meta: dict = None):
    init_db()
    with get_connection() as con:
        for a in alerts:
            con.execute("""
                INSERT INTO alerts
                (alert_id, severity, rule_name, mitre_tactic, mitre_technique,
                 description, source_ip, affected_user, log_type, raw_log,
                 timestamp, ai_analysis)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                a.alert_id, a.severity, a.rule_name, a.mitre_tactic,
                a.mitre_technique, a.description, a.source_ip,
                a.affected_user, a.log_type, a.raw_log, a.timestamp,
                getattr(a, 'ai_analysis', None)
            ))

        if run_meta:
            con.execute("""
                INSERT INTO scan_runs (files, total_lines, alert_count,
                    critical, high, medium, low)
                VALUES (?,?,?,?,?,?,?)
            """, (
                json.dumps(run_meta.get('files', [])),
                run_meta.get('total_lines', 0),
                run_meta.get('alert_count', 0),
                run_meta.get('CRITICAL', 0),
                run_meta.get('HIGH', 0),
                run_meta.get('MEDIUM', 0),
                run_meta.get('LOW', 0),
            ))


def get_all_alerts() -> list[dict]:
    init_db()
    with get_connection() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def get_scan_history() -> list[dict]:
    init_db()
    with get_connection() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT * FROM scan_runs ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def update_ai_analysis(alert_id: str, analysis: str):
    with get_connection() as con:
        con.execute(
            "UPDATE alerts SET ai_analysis=? WHERE alert_id=?",
            (analysis, alert_id)
        )
