# backend/storage.py
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import json
from typing import Optional, Dict, Any

DB_PATH = Path(__file__).resolve().parent / "reports.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  label TEXT NOT NULL,
  confidence REAL NOT NULL,
  decision_status TEXT NOT NULL,
  decision_reason TEXT,
  traffic_context TEXT,
  raw_input TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
"""

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()

def insert_report(
    label: str,
    confidence: float,
    decision_status: str,
    decision_reason: Optional[str] = None,
    traffic_context: Optional[Dict[str, Any]] = None,
    raw_input: Optional[Dict[str, Any]] = None,
):
    created_at = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute(
        """INSERT INTO reports(created_at,label,confidence,decision_status,decision_reason,traffic_context,raw_input)
           VALUES(?,?,?,?,?,?,?)""",
        (
            created_at,
            str(label),
            float(confidence),
            str(decision_status),
            str(decision_reason) if decision_reason is not None else None,
            json.dumps(traffic_context, ensure_ascii=False) if traffic_context is not None else None,
            json.dumps(raw_input, ensure_ascii=False) if raw_input is not None else None,
        ),
    )
    conn.commit()
    conn.close()
