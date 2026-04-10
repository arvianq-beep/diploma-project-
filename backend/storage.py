import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(os.environ.get("REPORTS_DB_PATH", Path(__file__).resolve().parent / "reports.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  event_id TEXT,
  label TEXT NOT NULL,
  confidence REAL NOT NULL,
  decision_status TEXT NOT NULL,
  decision_reason TEXT,
  final_status TEXT,
  recommended_action TEXT,
  detector_output TEXT,
  verification_output TEXT,
  final_decision TEXT,
  event_snapshot TEXT,
  traffic_context TEXT,
  raw_input TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
"""

MIGRATIONS = {
    "event_id": "ALTER TABLE reports ADD COLUMN event_id TEXT",
    "final_status": "ALTER TABLE reports ADD COLUMN final_status TEXT",
    "recommended_action": "ALTER TABLE reports ADD COLUMN recommended_action TEXT",
    "detector_output": "ALTER TABLE reports ADD COLUMN detector_output TEXT",
    "verification_output": "ALTER TABLE reports ADD COLUMN verification_output TEXT",
    "final_decision": "ALTER TABLE reports ADD COLUMN final_decision TEXT",
    "event_snapshot": "ALTER TABLE reports ADD COLUMN event_snapshot TEXT",
}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    existing_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(reports)").fetchall()
    }
    for column, statement in MIGRATIONS.items():
        if column not in existing_columns:
            conn.execute(statement)
    conn.commit()
    conn.close()


def insert_report(
    *,
    event_id: str | None,
    label: str,
    confidence: float,
    decision_status: str,
    decision_reason: str | None = None,
    final_status: str | None = None,
    recommended_action: str | None = None,
    detector_output: dict[str, Any] | None = None,
    verification_output: dict[str, Any] | None = None,
    final_decision: dict[str, Any] | None = None,
    event_snapshot: dict[str, Any] | None = None,
    traffic_context: dict[str, Any] | None = None,
    raw_input: dict[str, Any] | None = None,
):
    """Persist Stage 1, Stage 2, and the final backend decision."""

    created_at = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO reports(
            created_at,
            event_id,
            label,
            confidence,
            decision_status,
            decision_reason,
            final_status,
            recommended_action,
            detector_output,
            verification_output,
            final_decision,
            event_snapshot,
            traffic_context,
            raw_input
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            created_at,
            event_id,
            str(label),
            float(confidence),
            str(decision_status),
            str(decision_reason) if decision_reason is not None else None,
            str(final_status) if final_status is not None else None,
            str(recommended_action) if recommended_action is not None else None,
            _json(detector_output),
            _json(verification_output),
            _json(final_decision),
            _json(event_snapshot),
            _json(traffic_context),
            _json(raw_input),
        ),
    )
    conn.commit()
    conn.close()


def _json(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
        return None
    return json.dumps(payload, ensure_ascii=False)
