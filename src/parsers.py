"""
Log Parsers for Apache, Auth.log, and Windows Event Logs
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path


# ─── Apache Access Log Parser ─────────────────────────────────────────────────

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)'
)

def parse_apache(filepath: str) -> pd.DataFrame:
    records = []
    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            m = APACHE_PATTERN.match(line.strip())
            if m:
                d = m.groupdict()
                try:
                    dt = datetime.strptime(d['time'], '%d/%b/%Y:%H:%M:%S %z')
                    d['timestamp'] = dt.replace(tzinfo=None)
                except ValueError:
                    d['timestamp'] = pd.NaT
                d['status'] = int(d['status'])
                d['size'] = int(d['size'])
                d['log_type'] = 'apache'
                d['raw'] = line.strip()
                records.append(d)
    return pd.DataFrame(records)


# ─── Auth.log Parser ──────────────────────────────────────────────────────────

AUTH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+(?P<service>\S+):\s+(?P<message>.+)'
)

def parse_auth(filepath: str) -> pd.DataFrame:
    year = datetime.now().year
    records = []
    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            m = AUTH_PATTERN.match(line.strip())
            if m:
                d = m.groupdict()
                try:
                    dt_str = f"{d['month']} {d['day']} {year} {d['time']}"
                    d['timestamp'] = datetime.strptime(dt_str, '%b %d %Y %H:%M:%S')
                except ValueError:
                    d['timestamp'] = pd.NaT

                msg = d['message']
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
                d['ip'] = ip_match.group(1) if ip_match else None

                user_match = re.search(r'(?:for|user[=\s])(\S+)', msg)
                d['user'] = user_match.group(1) if user_match else None

                d['log_type'] = 'auth'
                d['raw'] = line.strip()
                records.append(d)
    return pd.DataFrame(records)


# ─── Windows Event Log Parser ─────────────────────────────────────────────────

WINDOWS_COLUMN_MAP = {
    # Timestamp variants
    'TimeCreated':       'timestamp',
    'Date and Time':     'timestamp',
    'TimeGenerated':     'timestamp',
    'Time Generated':    'timestamp',
    'Time':              'timestamp',

    # Event ID variants
    'EventID':           'event_id',
    'Event ID':          'event_id',
    'Id':                'event_id',
    'EventId':           'event_id',

    # Level / Severity variants
    'Level':             'level',
    'LevelDisplayName':  'level',
    'EntryType':         'level',
    'Keywords':          'level',

    # Source / Provider variants
    'Source':            'source',
    'ProviderName':      'source',
    'LogName':           'source',

    # Message variants
    'Message':           'message',
    'TaskCategory':      'message',
    'Task Category':     'message',

    # Computer / Machine variants
    'Computer':          'computer',
    'MachineName':       'computer',
    'ComputerName':      'computer',

    # User variants
    'UserName':          'user',
    'UserId':            'user',
    'User':              'user',
    'SubjectUserName':   'user',
}


def _detect_separator(filepath: str, encoding: str) -> str:
    """
    Peek at the first line of the file and figure out whether
    it uses commas, tabs, semicolons, or pipes as the separator.
    """
    try:
        with open(filepath, 'r', encoding=encoding, errors='replace') as f:
            first_line = f.readline()
        tab_count   = first_line.count('\t')
        comma_count = first_line.count(',')
        semi_count  = first_line.count(';')
        pipe_count  = first_line.count('|')

        best = max(
            [('\t', tab_count), (',', comma_count),
             (';', semi_count), ('|', pipe_count)],
            key=lambda x: x[1]
        )
        return best[0]   # return the separator that appears most
    except Exception:
        return ','        # safe default


def parse_windows(filepath: str) -> pd.DataFrame:
    df = None
    last_error = None

    # Try encodings one by one
    for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
        try:
            # Auto-detect separator for this encoding
            sep = _detect_separator(filepath, encoding)

            df = pd.read_csv(
                filepath,
                sep=sep,
                encoding=encoding,
                on_bad_lines='skip',
                engine='python',      # python engine handles any separator
            )

            # Strip whitespace from all column names
            df.columns = [c.strip() for c in df.columns]

            # If we only got 1 column, separator detection failed — skip
            if len(df.columns) <= 1:
                df = None
                continue

            break   # success!

        except Exception as e:
            last_error = e
            continue

    if df is None:
        raise ValueError(f"Could not parse CSV after all attempts. Last error: {last_error}")

    print(f"      -> Detected columns: {df.columns.tolist()}")

    # ── Rename columns to standard names ─────────────────────────────────────
    rename_map = {}
    for col in df.columns:
        stripped = col.strip()
        if stripped in WINDOWS_COLUMN_MAP:
            rename_map[col] = WINDOWS_COLUMN_MAP[stripped]
    df = df.rename(columns=rename_map)

    # ── Fill any missing required columns ────────────────────────────────────
    for col in ['timestamp', 'event_id', 'level', 'source', 'message', 'computer', 'user']:
        if col not in df.columns:
            df[col] = 'N/A'
            print(f"      WARNING: Column '{col}' not found - filled with N/A")

    # ── Parse timestamp — try known Windows formats first to avoid warnings ──
    if df['timestamp'].dtype == object:
        formats_to_try = [
            '%m/%d/%Y %H:%M:%S',   # 2/26/2026 23:56:01  <- your format
            '%m/%d/%Y %H:%M',      # 2/26/2026 23:56
            '%Y-%m-%dT%H:%M:%S',   # 2026-02-26T23:56:01 <- PowerShell ISO
            '%Y-%m-%d %H:%M:%S',   # 2026-02-26 23:56:01
            '%d/%m/%Y %H:%M:%S',   # 26/02/2026 23:56:01 <- European
        ]
        import warnings
        parsed_ok = False
        for fmt in formats_to_try:
            try:
                parsed = pd.to_datetime(df['timestamp'], format=fmt, errors='coerce')
                if parsed.notna().mean() > 0.8:   # 80%+ rows parsed = right format
                    df['timestamp'] = parsed
                    parsed_ok = True
                    break
            except Exception:
                continue
        if not parsed_ok:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # ── Ensure event_id is a clean integer ────────────────────────────────────
    df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(0).astype(int)

    # ── Add metadata columns ──────────────────────────────────────────────────
    df['log_type'] = 'windows'
    df['raw'] = df.apply(
        lambda r: (
            f"{r.get('timestamp','?')} | "
            f"EventID:{r.get('event_id','?')} | "
            f"{str(r.get('message',''))[:200]} | "
            f"{r.get('computer','?')} | "
            f"{r.get('user','?')}"
        ),
        axis=1
    )

    # ── Drop completely blank rows ─────────────────────────────────────────────
    df = df.dropna(how='all')

    return df


# ─── Auto-detect & Load ───────────────────────────────────────────────────────

def load_log(filepath: str) -> pd.DataFrame:
    p = Path(filepath)
    name = p.name.lower()
    if 'apache' in name or 'access' in name:
        return parse_apache(filepath)
    elif 'auth' in name:
        return parse_auth(filepath)
    elif 'windows' in name or name.endswith('.csv'):
        return parse_windows(filepath)
    else:
        raise ValueError(f"Cannot determine log type for: {filepath}")
