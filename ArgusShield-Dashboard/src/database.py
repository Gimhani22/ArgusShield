import os
import sqlite3
from typing import Optional

# Determine the database path
# Use the application directory or user's AppData if running as executable
if hasattr(os, 'getenv'):
    # For standalone app, use AppData folder
    app_data = os.getenv('APPDATA', os.path.expanduser('~'))
    db_dir = os.path.join(app_data, 'ArgusShield')
else:
    # For development, use the script directory
    db_dir = os.path.dirname(os.path.abspath(__file__))

# Create the directory if it doesn't exist
os.makedirs(db_dir, exist_ok=True)

DB_PATH = os.path.join(db_dir, "argusshield.db")


def create_db() -> None:
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name TEXT,
            pid INTEGER,
            threat_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Simple key/value settings table to persist UI state like install/uninstall
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)

        # Ensure there is an 'installed' key present (default 0)
        cursor.execute("SELECT value FROM settings WHERE key = ?", ("installed",))
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                ("installed", "0"),
            )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")


def get_install_state() -> bool:
    """Return True if installed, False otherwise."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", ("installed",))
        row = cursor.fetchone()
        conn.close()
        return row and row[0] == "1"
    except Exception as e:
        print(f"Error reading installation state: {e}")
        return False


def set_install_state(state: bool) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("installed", "1" if state else "0"),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving installation state: {e}")


if __name__ == "__main__":
    create_db()
