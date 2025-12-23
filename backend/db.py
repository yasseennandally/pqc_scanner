import os
import sqlite3
import json
from contextlib import closing
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

DB_PATH = os.environ.get("PQC_SCANNER_DB", "pqc_scanner.db")


def get_connection():
    # check_same_thread=False so each thread can open its own connection safely
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _parse_iso_datetime(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.utcfromtimestamp(0)

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(dt_str, fmt)
        except Exception:
            pass
    return datetime.utcfromtimestamp(0)


def _ensure_columns(conn: sqlite3.Connection):
    """
    Add missing columns if table exists from older versions.
    """
    cur = conn.execute("PRAGMA table_info(scans)")
    cols = [r[1] for r in cur.fetchall()]

    def add(col, ddl_type, default_expr=None):
        if col in cols:
            return
        if default_expr is None:
            conn.execute("ALTER TABLE scans ADD COLUMN %s %s" % (col, ddl_type))
        else:
            conn.execute("ALTER TABLE scans ADD COLUMN %s %s DEFAULT %s" % (col, ddl_type, default_expr))

    add("updated_at", "TEXT", "'%s'" % _now_iso())
    add("targets_json", "TEXT", "'[]'")
    add("config_json", "TEXT", "'{}'")
    add("progress_total", "INTEGER", "0")
    add("progress_done", "INTEGER", "0")
    add("error_message", "TEXT", "''")


def init_db():
    with closing(get_connection()) as conn:
        # scans table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                config_json TEXT NOT NULL,
                progress_total INTEGER NOT NULL,
                progress_done INTEGER NOT NULL,
                results_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                error_message TEXT NOT NULL
            )
            """
        )
        _ensure_columns(conn)

        # per-target results table (streaming)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(scan_id, target)
            )
            """
        )

        conn.commit()


# -------------------------
# Scan lifecycle
# -------------------------

def create_scan_row(scan_id: str, created_at: datetime, targets: List[str], config: Dict[str, Any]) -> None:
    created_at_str = created_at.isoformat()
    updated_at_str = _now_iso()

    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
            (id, status, created_at, updated_at, targets_json, config_json,
             progress_total, progress_done, results_json, summary_json, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                "running",
                created_at_str,
                updated_at_str,
                json.dumps(targets),
                json.dumps(config or {}),
                int(len(targets)),
                0,
                "[]",
                "{}",
                "",
            ),
        )
        conn.commit()


def update_scan_progress(scan_id: str, done: int, total: int) -> None:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            UPDATE scans
            SET progress_done = ?, progress_total = ?, updated_at = ?
            WHERE id = ?
            """,
            (int(done), int(total), _now_iso(), scan_id),
        )
        conn.commit()


def mark_scan_completed(scan_id: str, results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            UPDATE scans
            SET status = ?, updated_at = ?, progress_done = ?, progress_total = ?,
                results_json = ?, summary_json = ?, error_message = ?
            WHERE id = ?
            """,
            (
                "completed",
                _now_iso(),
                int(len(results)),
                int(len(results)),
                json.dumps(results),
                json.dumps(summary or {}),
                "",
                scan_id,
            ),
        )
        conn.commit()


def mark_scan_failed(scan_id: str, error_message: str) -> None:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        conn.execute(
            """
            UPDATE scans
            SET status = ?, updated_at = ?, error_message = ?
            WHERE id = ?
            """,
            ("failed", _now_iso(), error_message or "unknown error", scan_id),
        )
        conn.commit()


def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        cur = conn.execute(
            """
            SELECT id, status, created_at, updated_at, targets_json, config_json,
                   progress_total, progress_done, results_json, summary_json, error_message
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    (
        id_, status, created_at_str, updated_at_str, targets_json, config_json,
        progress_total, progress_done, results_json, summary_json, error_message
    ) = row

    return {
        "id": id_,
        "status": status,
        "created_at": _parse_iso_datetime(created_at_str),
        "updated_at": _parse_iso_datetime(updated_at_str),
        "targets": json.loads(targets_json or "[]"),
        "config": json.loads(config_json or "{}"),
        "progress_total": int(progress_total or 0),
        "progress_done": int(progress_done or 0),
        "results": json.loads(results_json or "[]"),
        "summary": json.loads(summary_json or "{}"),
        "error_message": error_message or "",
    }


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        cur = conn.execute(
            """
            SELECT id, status, created_at, summary_json, progress_total, progress_done
            FROM scans
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        rows = cur.fetchall()

    out = []
    for (id_, status, created_at_str, summary_json, progress_total, progress_done) in rows:
        out.append(
            {
                "id": id_,
                "status": status,
                "created_at": _parse_iso_datetime(created_at_str),
                "summary": json.loads(summary_json or "{}"),
                "progress_total": int(progress_total or 0),
                "progress_done": int(progress_done or 0),
            }
        )
    return out


# -------------------------
# Streaming scan results
# -------------------------

def upsert_scan_result(scan_id: str, target: str, result: Dict[str, Any]) -> int:
    """
    Insert/Update one per-target result.
    Returns the row id (best effort).
    """
    host = (result.get("host") or "")
    try:
        port = int(result.get("port") or 0)
    except Exception:
        port = 0

    now = _now_iso()
    payload = json.dumps(result)

    with closing(get_connection()) as conn:
        # ensure row exists
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_results
            (scan_id, target, host, port, result_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, target, host, port, payload, now, now),
        )
        # update row (keeps id stable)
        conn.execute(
            """
            UPDATE scan_results
            SET host = ?, port = ?, result_json = ?, updated_at = ?
            WHERE scan_id = ? AND target = ?
            """,
            (host, port, payload, now, scan_id, target),
        )
        conn.commit()

        cur = conn.execute(
            "SELECT id FROM scan_results WHERE scan_id = ? AND target = ?",
            (scan_id, target),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0


def list_scan_results_since(scan_id: str, after_id: int = 0, limit: int = 200) -> Tuple[List[Dict[str, Any]], int]:
    """
    Return results with scan_results.id > after_id (arrival order).
    Returns: (results_list, next_after_id)
    """
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT id, result_json
            FROM scan_results
            WHERE scan_id = ? AND id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (scan_id, int(after_id), int(limit)),
        )
        rows = cur.fetchall()

    out = []
    next_after = int(after_id)
    for rid, rjson in rows:
        try:
            out.append(json.loads(rjson))
        except Exception:
            out.append({"host": "", "port": 0, "error": "malformed result_json", "risk": "unknown"})
        if rid > next_after:
            next_after = int(rid)

    return out, next_after


def list_all_scan_results(scan_id: str) -> List[Dict[str, Any]]:
    """
    Load all per-target results for finalization (sorted by host/port).
    """
    with closing(get_connection()) as conn:
        cur = conn.execute(
            """
            SELECT result_json
            FROM scan_results
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        rows = cur.fetchall()

    results = []
    for (rjson,) in rows:
        try:
            results.append(json.loads(rjson))
        except Exception:
            continue

    results.sort(key=lambda r: ((r.get("host") or ""), int(r.get("port") or 0)))
    return results


# Backwards-compat helper (old code calling save_scan)
def save_scan(scan_id: str, status: str, created_at: datetime, results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    create_scan_row(scan_id, created_at, [], {})
    mark_scan_completed(scan_id, results, summary)
