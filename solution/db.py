"""SQLite persistence for audit runs.

Commands that carry persistent state accept ``--db DB.sqlite``.  Each run is
appended to a ``runs`` table keyed by command and manifest fingerprint, so a
re-audit can tell whether the logical input changed.  Stdout never contains
timestamps or run counters, so output stays identical for identical logical
input even when the database is written.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from .errors import InputError

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_lookup ON runs (command, manifest_id, fingerprint);
"""


def fingerprint(document: object) -> str:
    """Stable content hash of the logical input document."""
    encoded = json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Store:
    def __init__(self, path: str):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
        except sqlite3.Error as exc:
            raise InputError(
                "DB_OPEN_FAILED", "--db", f"cannot open database: {exc}"
            ) from exc
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def record(self, command: str, manifest_id: str, fp: str, payload: dict) -> dict:
        previous = self.conn.execute(
            "SELECT COUNT(*) FROM runs WHERE command=? AND manifest_id=? AND fingerprint=?",
            (command, manifest_id, fp),
        ).fetchone()[0]
        cursor = self.conn.execute(
            "INSERT INTO runs (command, manifest_id, fingerprint, payload) "
            "VALUES (?, ?, ?, ?)",
            (
                command,
                manifest_id,
                fp,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        self.conn.commit()
        total = self.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        return {
            "database": str(Path(self.path)),
            "run_id": cursor.lastrowid,
            "identical_prior_runs": previous,
            "total_runs": total,
            "input_changed_since_prior_run": previous == 0 and total > 1,
        }

    def close(self) -> None:
        self.conn.close()
