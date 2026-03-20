import os
import sqlite3
from typing import Optional, List, Dict


# ── Database path ────────────────────────────────────────────────────────────
# Uses %APPDATA%\ArgusShield\argusshield.db for the app's own SQLite database.
# The shared events log is at C:\ProgramData\ArgusShield\events.log.

if hasattr(os, 'getenv'):
    app_data = os.getenv('APPDATA', os.path.expanduser('~'))
    db_dir = os.path.join(app_data, 'ArgusShield')
else:
    db_dir = os.path.dirname(os.path.abspath(__file__))

os.makedirs(db_dir, exist_ok=True)
DB_PATH = os.path.join(db_dir, "argusshield.db")

# Shared events log written by Service + Agent (C++ programs)
EVENTS_LOG_PATH = os.path.join(
    os.environ.get('ProgramData', r'C:\ProgramData'),
    'ArgusShield', 'events.log'
)


# ── Database creation ────────────────────────────────────────────────────────

def create_db() -> None:
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Original detections table
        c.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name TEXT,
            pid INTEGER,
            threat_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Settings table
        c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)

        # NEW: events table — populated from the shared events.log
        c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            component TEXT,
            event_type TEXT,
            pid INTEGER,
            target_pid INTEGER,
            dll_path TEXT,
            technique TEXT,
            severity TEXT,
            action TEXT,
            details TEXT,
            raw_line TEXT UNIQUE
        )
        """)

        # Ensure 'installed' and 'last_event_offset' keys exist
        for key, default in [('installed', '0'), ('last_event_offset', '0')]:
            c.execute("SELECT value FROM settings WHERE key = ?", (key,))
            if c.fetchone() is None:
                c.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    (key, default),
                )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")


# ── Settings helpers ─────────────────────────────────────────────────────────

def get_install_state() -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = ?", ("installed",))
        row = c.fetchone()
        conn.close()
        return row and row[0] == "1"
    except Exception:
        return False


def set_install_state(state: bool) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("installed", "1" if state else "0"),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _get_setting(key: str, default: str = '0') -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


def _set_setting(key: str, value: str) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Import events from shared events.log ─────────────────────────────────────
# Called periodically by the Dashboard to pull new entries from the file
# written by the C++ Service and Agent.

def import_events_from_log() -> int:
    """Read new lines from events.log and insert into the events table.
    Returns the number of newly imported events."""
    if not os.path.exists(EVENTS_LOG_PATH):
        return 0

    # Track file offset so we only read new lines
    offset = int(_get_setting('last_event_offset', '0'))

    try:
        with open(EVENTS_LOG_PATH, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(offset)
            new_lines = f.readlines()
            new_offset = f.tell()
    except Exception:
        return 0

    if not new_lines:
        return 0

    count = 0
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        for line in new_lines:
            line = line.strip()
            if not line:
                continue

            parts = line.split('|')
            if len(parts) < 10:
                continue  # malformed line

            timestamp, component, event_type = parts[0], parts[1], parts[2]
            pid, target_pid = parts[3], parts[4]
            dll_path, technique, severity = parts[5], parts[6], parts[7]
            action, details = parts[8], parts[9]

            try:
                c.execute("""
                    INSERT OR IGNORE INTO events
                    (timestamp, component, event_type, pid, target_pid,
                     dll_path, technique, severity, action, details, raw_line)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, component, event_type,
                    int(pid), int(target_pid),
                    dll_path, technique, severity,
                    action, details, line
                ))
                if c.rowcount > 0:
                    count += 1
            except Exception:
                continue

        conn.commit()
        conn.close()
    except Exception:
        return 0

    _set_setting('last_event_offset', str(new_offset))
    return count


# ── Query helpers for Dashboard + Quarantine pages ───────────────────────────

def get_recent_detections(limit: int = 20) -> List[Dict]:
    """Return the most recent detection/blocking events."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT timestamp, component, event_type, pid, target_pid,
                   dll_path, technique, severity, action, details
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = c.fetchall()
        conn.close()

        return [
            {
                'timestamp': r[0], 'component': r[1], 'event_type': r[2],
                'pid': r[3], 'target_pid': r[4], 'dll_path': r[5],
                'technique': r[6], 'severity': r[7], 'action': r[8],
                'details': r[9],
            }
            for r in rows
        ]
    except Exception:
        return []


def get_detection_stats() -> Dict:
    """Return aggregate stats for the Dashboard stat cards."""
    stats = {
        'total': 0,
        'blocked': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'today': 0,
        'dll_injection': 0,
    }
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM events")
        stats['total'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE action = 'Blocked'")
        stats['blocked'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE severity = 'Critical'")
        stats['critical'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE severity = 'High'")
        stats['high'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE severity = 'Medium'")
        stats['medium'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE severity = 'Low'")
        stats['low'] = c.fetchone()[0]

        import datetime
        c.execute("""
            SELECT COUNT(*) FROM events
            WHERE timestamp LIKE ? 
        """, (f"{datetime.date.today().isoformat()}%",))
        stats['today'] = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM events WHERE technique = 'LoadLibrary'")
        stats['dll_injection'] = c.fetchone()[0]

        conn.close()
    except Exception:
        pass
    return stats


def get_quarantine_entries(limit: int = 50) -> List[Dict]:
    """Return events suitable for the Quarantine table."""
    return get_recent_detections(limit)


if __name__ == "__main__":
    create_db()
    count = import_events_from_log()
    print(f"Imported {count} new events. Stats: {get_detection_stats()}")
