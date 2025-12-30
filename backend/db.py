from __future__ import annotations

import os
import sqlite3
import json
from contextlib import closing
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = os.environ.get("PQC_SCANNER_DB", "pqc_scanner.db")


def get_connection() -> sqlite3.Connection:
    # check_same_thread=False allows background scan threads to write progress
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cur.fetchall()]


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """
    Create/upgrade schema. Uses CREATE TABLE IF NOT EXISTS and adds columns if older versions exist.
    """
    # --- scans ---
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

    # --- baselines (Sprint 2) ---
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines (
            asset_key TEXT PRIMARY KEY,
            baseline_scan_id TEXT NOT NULL,
            set_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines(baseline_scan_id)")

    # --- assets (Sprint 3) ---
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            asset_key TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            owner TEXT NOT NULL DEFAULT '',
            team TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT '',
            criticality TEXT NOT NULL DEFAULT '',
            confidentiality_lifetime TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_host_port ON assets(host, port)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_team ON assets(team)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality)")

    # --- asset tags ---
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_tags (
            asset_key TEXT NOT NULL,
            tag TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(asset_key, tag)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags(tag)")

    conn.commit()


def init_db() -> None:
    with closing(get_connection()) as conn:
        _ensure_schema(conn)


def upsert_scan(
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
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (id, status, created_at, progress_json, error_text, results_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                status,
                created_at_str,
                json.dumps(progress, ensure_ascii=False),
                error_text or "",
                json.dumps(results or [], ensure_ascii=False),
                json.dumps(summary or {}, ensure_ascii=False),
            ),
        )
        conn.commit()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT id, status, created_at, progress_json, error_text, results_json, summary_json FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "status": row[1],
            "created_at": row[2],
            "progress": json.loads(row[3] or "{}"),
            "error": row[4] or "",
            "results": json.loads(row[5] or "[]"),
            "summary": json.loads(row[6] or "{}"),
        }


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 50), 500))
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT id, status, created_at, progress_json, error_text, results_json, summary_json FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        out: List[Dict[str, Any]] = []
        for row in cur.fetchall():
            out.append(
                {
                    "id": row[0],
                    "status": row[1],
                    "created_at": row[2],
                    "progress": json.loads(row[3] or "{}"),
                    "error": row[4] or "",
                    "results": json.loads(row[5] or "[]"),
                    "summary": json.loads(row[6] or "{}"),
                }
            )
        return out


# --------------------
# Baselines (Sprint 2)
# --------------------
def set_baseline(asset_key: str, baseline_scan_id: str, set_at: Optional[str] = None) -> None:
    set_at = set_at or datetime.utcnow().isoformat() + "Z"
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO baselines(asset_key, baseline_scan_id, set_at) VALUES (?, ?, ?)",
            (asset_key, baseline_scan_id, set_at),
        )
        conn.commit()


def set_baselines_from_scan(scan_id: str) -> int:
    scan = get_scan(scan_id)
    if not scan:
        return 0
    results = scan.get("results") or []
    n = 0
    for r in results:
        host = r.get("host")
        port = r.get("port")
        if not host or not port:
            continue
        asset_key = f"{host}:{port}"
        set_baseline(asset_key, scan_id)
        n += 1
    return n


def get_baseline(asset_key: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines WHERE asset_key = ?",
            (asset_key,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"asset_key": row[0], "baseline_scan_id": row[1], "set_at": row[2]}


def list_baselines(limit: int = 1000) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 1000), 5000))
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT asset_key, baseline_scan_id, set_at FROM baselines ORDER BY set_at DESC LIMIT ?",
            (limit,),
        )
        return [{"asset_key": r[0], "baseline_scan_id": r[1], "set_at": r[2]} for r in cur.fetchall()]


# --------------------
# Assets (Sprint 3)
# --------------------
def upsert_asset(
    asset_key: str,
    host: str,
    port: int,
    owner: str = "",
    team: str = "",
    environment: str = "",
    criticality: str = "",
    confidentiality_lifetime: str = "",
    notes: str = "",
) -> None:
    now = datetime.utcnow().isoformat() + "Z"
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        # Insert if not exists, otherwise update mutable fields
        conn.execute(
            """
            INSERT INTO assets(asset_key, host, port, created_at, updated_at, owner, team, environment, criticality, confidentiality_lifetime, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_key) DO UPDATE SET
              updated_at=excluded.updated_at,
              owner=excluded.owner,
              team=excluded.team,
              environment=excluded.environment,
              criticality=excluded.criticality,
              confidentiality_lifetime=excluded.confidentiality_lifetime,
              notes=excluded.notes
            """,
            (
                asset_key,
                host,
                int(port),
                now,
                now,
                owner or "",
                team or "",
                environment or "",
                criticality or "",
                confidentiality_lifetime or "",
                notes or "",
            ),
        )
        conn.commit()


def get_asset(asset_key: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            """
            SELECT asset_key, host, port, created_at, updated_at, owner, team, environment, criticality, confidentiality_lifetime, notes
            FROM assets WHERE asset_key = ?
            """,
            (asset_key,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "asset_key": row[0],
            "host": row[1],
            "port": row[2],
            "created_at": row[3],
            "updated_at": row[4],
            "owner": row[5],
            "team": row[6],
            "environment": row[7],
            "criticality": row[8],
            "confidentiality_lifetime": row[9],
            "notes": row[10],
            "tags": list_asset_tags(asset_key),
            "baseline": get_baseline(asset_key),
        }


def list_assets(
    limit: int = 200,
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 200), 2000))
    clauses: List[str] = []
    params: List[Any] = []

    if owner:
        clauses.append("owner = ?")
        params.append(owner)
    if team:
        clauses.append("team = ?")
        params.append(team)
    if environment:
        clauses.append("environment = ?")
        params.append(environment)
    if criticality:
        clauses.append("criticality = ?")
        params.append(criticality)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT asset_key, host, port, created_at, updated_at, owner, team, environment, criticality, confidentiality_lifetime, notes
        FROM assets
        {where}
        ORDER BY updated_at DESC
        LIMIT ?
    """
    params2 = params + [limit]

    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        rows = conn.execute(sql, params2).fetchall()

        out: List[Dict[str, Any]] = []
        for row in rows:
            ak = row[0]
            tags = list_asset_tags(ak)
            if tag and tag not in tags:
                continue
            out.append(
                {
                    "asset_key": ak,
                    "host": row[1],
                    "port": row[2],
                    "created_at": row[3],
                    "updated_at": row[4],
                    "owner": row[5],
                    "team": row[6],
                    "environment": row[7],
                    "criticality": row[8],
                    "confidentiality_lifetime": row[9],
                    "notes": row[10],
                    "tags": tags,
                    "baseline": get_baseline(ak),
                }
            )
        return out


def set_asset_tags(asset_key: str, tags: List[str]) -> None:
    now = datetime.utcnow().isoformat() + "Z"
    cleaned = sorted({t.strip() for t in (tags or []) if t and t.strip()})
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        conn.execute("DELETE FROM asset_tags WHERE asset_key = ?", (asset_key,))
        for t in cleaned:
            conn.execute(
                "INSERT OR IGNORE INTO asset_tags(asset_key, tag, created_at) VALUES (?, ?, ?)",
                (asset_key, t, now),
            )
        conn.commit()


def list_asset_tags(asset_key: str) -> List[str]:
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute("SELECT tag FROM asset_tags WHERE asset_key = ? ORDER BY tag ASC", (asset_key,))
        return [r[0] for r in cur.fetchall()]


def list_tags(limit: int = 500) -> List[str]:
    limit = max(1, min(int(limit or 500), 5000))
    with closing(get_connection()) as conn:
        _ensure_schema(conn)
        cur = conn.execute(
            "SELECT tag, COUNT(*) as c FROM asset_tags GROUP BY tag ORDER BY c DESC, tag ASC LIMIT ?",
            (limit,),
        )
        return [r[0] for r in cur.fetchall()]
