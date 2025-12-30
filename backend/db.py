from __future__ import annotations

import os
import sqlite3
import json
from contextlib import closing
from datetime import datetime
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("PQC_SCANNER_DB", "pqc_scanner.db")


def get_connection():
    # check_same_thread=False allows background scan threads to write progress
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def _parse_iso_datetime(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.utcfromtimestamp(0)
    try:
        # Python 3.11+ supports fromisoformat with timezone, but we store naive utc
        return datetime.fromisoformat(dt_str)
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(dt_str, fmt)
            except Exception:
                pass
    return datetime.utcfromtimestamp(0)


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """
    Ensure the scans table exists and has the expected columns.
    If you previously created an older schema, we ALTER TABLE to add missing columns.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            progress_json TEXT NOT NULL,
            error_text TEXT NOT NULL,
            results_json TEXT NOT NULL,
            summary_json TEXT NOT NULL
        )
        """
    )

    # Baselines table: map an asset (host:port) to a baseline scan id.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines (
            asset_key TEXT PRIMARY KEY,
            baseline_scan_id TEXT NOT NULL,
            set_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines (baseline_scan_id)")
    cur = conn.execute("PRAGMA table_info(scans)")
    cols = {row[1] for row in cur.fetchall()}

    def add(col: str, ddl: str):
        if col not in cols:
            conn.execute(ddl)

    add("progress_json", "ALTER TABLE scans ADD COLUMN progress_json TEXT NOT NULL DEFAULT '{}'")
    add("error_text", "ALTER TABLE scans ADD COLUMN error_text TEXT NOT NULL DEFAULT ''")
    add("results_json", "ALTER TABLE scans ADD COLUMN results_json TEXT NOT NULL DEFAULT '[]'")
    add("summary_json", "ALTER TABLE scans ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'")

    conn.commit()


def init_db():
    with closing(get_connection()) as conn:
        _ensure_columns(conn)


def save_scan_row(
    scan_id: str,
    status: str,
    created_at: datetime,
    progress: Dict[str, Any],
    error_text: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    created_at_str = created_at.isoformat()
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (id, status, created_at, progress_json, error_text, results_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                status,
                created_at_str,
                json.dumps(progress or {}),
                error_text or "",
                json.dumps(results or []),
                json.dumps(summary or {}),
            ),
        )
        conn.commit()


def update_scan_progress(
    scan_id: str,
    status: str,
    progress: Dict[str, Any],
    error_text: str = "",
) -> None:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            UPDATE scans
            SET status = ?, progress_json = ?, error_text = ?
            WHERE id = ?
            """,
            (status, json.dumps(progress or {}), error_text or "", scan_id),
        )
        conn.commit()


def save_scan_results(
    scan_id: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    status: str = "completed",
) -> None:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            UPDATE scans
            SET status = ?, results_json = ?, summary_json = ?
            WHERE id = ?
            """,
            (status, json.dumps(results or []), json.dumps(summary or {}), scan_id),
        )
        conn.commit()


def load_scan_row(scan_id: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        cur = conn.execute(
            """
            SELECT id, status, created_at, progress_json, error_text, results_json, summary_json
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    id_, status, created_at_str, progress_json, error_text, results_json, summary_json = row
    created_at = _parse_iso_datetime(created_at_str)

    try:
        progress = json.loads(progress_json or "{}")
    except Exception:
        progress = {}

    try:
        results = json.loads(results_json or "[]")
    except Exception:
        results = []

    try:
        summary = json.loads(summary_json or "{}")
    except Exception:
        summary = {}

    return {
        "id": id_,
        "status": status,
        "created_at": created_at,
        "progress": progress,
        "error": error_text or "",
        "results": results,
        "summary": summary,
    }


def list_scan_rows(limit: int = 20) -> List[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        cur = conn.execute(
            """
            SELECT id, status, created_at, progress_json, error_text, summary_json
            FROM scans
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()

    out: List[Dict[str, Any]] = []
    for id_, status, created_at_str, progress_json, error_text, summary_json in rows:
        try:
            created_at = _parse_iso_datetime(created_at_str)
        except Exception:
            created_at = datetime.utcfromtimestamp(0)

        try:
            progress = json.loads(progress_json or "{}")
        except Exception:
            progress = {}

        try:
            summary = json.loads(summary_json or "{}")
        except Exception:
            summary = {}

        out.append(
            {
                "id": id_,
                "status": status,
                "created_at": created_at.isoformat(),
                "progress": progress,
                "error": error_text or "",
                "summary": summary,
            }
        )

    return out


def asset_key(host: str, port: int) -> str:
    return f"{host}:{int(port)}"


def set_baseline(asset_key_str: str, baseline_scan_id: str, set_at: Optional[datetime] = None) -> None:
    set_at = set_at or datetime.utcnow()
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO baselines (asset_key, baseline_scan_id, set_at)
            VALUES (?, ?, ?)
            """,
            (asset_key_str, baseline_scan_id, set_at.isoformat()),
        )
        conn.commit()


def get_baseline(asset_key_str: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        row = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines WHERE asset_key = ?",
            (asset_key_str,),
        ).fetchone()
        if not row:
            return None
        return {"asset_key": row[0], "baseline_scan_id": row[1], "set_at": row[2]}


def list_baselines(limit: int = 500) -> List[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        rows = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines ORDER BY set_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [{"asset_key": r[0], "baseline_scan_id": r[1], "set_at": r[2]} for r in rows]


def set_baselines_from_scan(scan_id: str) -> Dict[str, Any]:
    scan = load_scan_row(scan_id)
    if not scan:
        raise ValueError("scan_id not found")
    results = scan.get("results") or []
    updated = 0
    now = datetime.utcnow()
    for r in results:
        host = r.get("host") or r.get("hostname") or ""
        port = int(r.get("port") or 443)
        if not host:
            continue
        set_baseline(asset_key(host, port), scan_id, set_at=now)
        updated += 1
    return {"scan_id": scan_id, "updated": updated, "set_at": now.isoformat()}
