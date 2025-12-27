# db.py
import os
import sqlite3
import json
from contextlib import closing
from datetime import datetime
from typing import Optional, Dict, Any, List

DB_PATH = os.environ.get("PQC_SCANNER_DB", "pqc_scanner.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


def _parse_iso_datetime(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.utcfromtimestamp(0)

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue

    return datetime.utcfromtimestamp(0)


def init_db():
    """
    Create the scans table if it doesn't exist.
    """
    with closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                results_json TEXT NOT NULL,
                summary_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan(
    scan_id: str,
    status: str,
    created_at: datetime,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    created_at_str = created_at.isoformat()
    results_json = json.dumps(results)
    summary_json = json.dumps(summary)

    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (id, status, created_at, results_json, summary_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, status, created_at_str, results_json, summary_json),
        )
        conn.commit()


def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, status, created_at, results_json, summary_json
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    id_, status, created_at_str, results_json, summary_json = row
    created_at = _parse_iso_datetime(created_at_str)
    results = json.loads(results_json)
    summary = json.loads(summary_json)

    return {
        "id": id_,
        "status": status,
        "created_at": created_at,
        "results": results,
        "summary": summary,
    }


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, status, created_at, summary_json
            FROM scans
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()

    out: List[Dict[str, Any]] = []
    for id_, status, created_at_str, summary_json in rows:
        try:
            created_at = _parse_iso_datetime(created_at_str)
            summary = json.loads(summary_json)
        except Exception:
            continue

        out.append(
            {
                "id": id_,
                "status": status,
                "created_at": created_at,
                "summary": summary,
            }
        )

    return out
