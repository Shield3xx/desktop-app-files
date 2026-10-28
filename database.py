"""
SQLite storage for SafeGuard AV.
Tables:
  quarantine  - every file moved to quarantine (replaces quarantine_log.json)
  scan_history - one row per scan run, with counts and time
"""
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from config import DB_PATH

_lock = threading.Lock()  # scans and the real-time watcher run on other threads

SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantined_path TEXT NOT NULL UNIQUE,
    threat TEXT NOT NULL,
    time INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scanned INTEGER NOT NULL,
    infected INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(SCHEMA)


def add_quarantine(original_path: str, quarantined_path: str, threat: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO quarantine (original_path, quarantined_path, threat, time) "
            "VALUES (?, ?, ?, ?)",
            (original_path, quarantined_path, threat, int(time.time())),
        )


def get_quarantine() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, original_path, quarantined_path, threat, time "
            "FROM quarantine ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def remove_quarantine(entry_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM quarantine WHERE id = ?", (entry_id,))


def add_scan_history(target: str, scanned: int, infected: int,
                     started_at: int, finished_at: int) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scan_history (target, scanned, infected, started_at, finished_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, scanned, infected, started_at, finished_at),
        )


def get_scan_history(limit: int = 50) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
