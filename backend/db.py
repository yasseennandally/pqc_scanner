from __future__ import annotations

import os
import sqlite3
import json
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("PQC_SCANNER_DB", "/data/pqc_scanner.db")



def _table_has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r[1] == col for r in rows)
    except Exception:
        return False

def get_connection():
    # check_same_thread=False allows background scan threads / workers to write progress
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    # Always ensure schema exists (API/worker/beat all share the same SQLite file)
    _ensure_columns(conn)
    _ensure_sprint5_tables(conn)
    _ensure_integrations_tables(conn)
    return conn



def _parse_iso_datetime(dt_str: str) -> datetime:
    """Parse an ISO datetime string into a naive UTC datetime.

    Accepts:
      - naive ISO strings (e.g. 2026-01-06T12:34:56.123456)
      - 'Z' suffix (UTC)
      - timezone offsets (e.g. +00:00)
    """
    if not dt_str:
        return datetime.utcfromtimestamp(0)

    s = str(dt_str).strip()
    try:
        # Support 'Z' (UTC) and offset-aware timestamps.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        # Fallback for a few common formats
        s2 = s[:-1] if s.endswith("Z") else s
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s2, fmt)
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
    # Assets inventory table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            asset_key TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            confidentiality_lifetime TEXT NOT NULL,
            notes TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets (owner)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_team ON assets (team)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_env ON assets (environment)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_crit ON assets (criticality)")

    # Tags (many-to-many)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_tags (
            asset_key TEXT NOT NULL,
            tag TEXT NOT NULL,
            PRIMARY KEY(asset_key, tag)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags (tag)")

    cols = {row[1] for row in cur.fetchall()}

    def add(col: str, ddl: str):
        if col not in cols:
            conn.execute(ddl)

    add("progress_json", "ALTER TABLE scans ADD COLUMN progress_json TEXT NOT NULL DEFAULT '{}'")
    add("error_text", "ALTER TABLE scans ADD COLUMN error_text TEXT NOT NULL DEFAULT ''")

    add("job_id", "ALTER TABLE scans ADD COLUMN job_id TEXT NOT NULL DEFAULT ''")
    add("job_state", "ALTER TABLE scans ADD COLUMN job_state TEXT NOT NULL DEFAULT ''")
    add("job_started_at", "ALTER TABLE scans ADD COLUMN job_started_at TEXT NOT NULL DEFAULT ''")
    add("job_finished_at", "ALTER TABLE scans ADD COLUMN job_finished_at TEXT NOT NULL DEFAULT ''")

    add("results_json", "ALTER TABLE scans ADD COLUMN results_json TEXT NOT NULL DEFAULT '[]'")
    add("summary_json", "ALTER TABLE scans ADD COLUMN summary_json TEXT NOT NULL DEFAULT '{}'")

    conn.commit()


def _ensure_sprint5_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 5 tables exist (collections, schedules, scan_results)."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            targets_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        '''
    )

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collection_id INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            interval_minutes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_run_at TEXT NOT NULL,
            next_run_at TEXT NOT NULL,
            last_scan_id TEXT NOT NULL,
            FOREIGN KEY(collection_id) REFERENCES collections(id) ON DELETE CASCADE
        )
        '''
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_collection ON schedules(collection_id)")

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_key TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            quantum_score REAL NOT NULL,
            findings_count INTEGER NOT NULL,
            pqc_relevance TEXT NOT NULL,
            tls_version TEXT NOT NULL,
            key_type TEXT NOT NULL,
            sig_algorithm TEXT NOT NULL,
            owner TEXT NOT NULL,
            team TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL
        )
        '''
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_asset ON scan_results(asset_key, scanned_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)")

def _ensure_integrations_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 8 integrations tables exist (webhooks + delivery log)."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            secret TEXT NOT NULL,
            events_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        '''
    )
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            error_text TEXT NOT NULL,
            FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
            UNIQUE(webhook_id, dedupe_key)
        )
        '''
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook ON webhook_events(webhook_id)")

def _ensure_integrations_tables(conn: sqlite3.Connection) -> None:
    """Ensure Sprint 8 integrations tables exist (webhooks + delivery log)."""
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            secret TEXT NOT NULL,
            events_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        '''
    )

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            error_text TEXT NOT NULL,
            FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
            UNIQUE(webhook_id, dedupe_key)
        )
        '''
    )

    # Backward-compatible migrations if table already existed with fewer columns
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(webhooks)").fetchall()}
        if "events_json" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN events_json TEXT NOT NULL DEFAULT '[]'")
        if "enabled" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        if "created_at" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        if "updated_at" not in cols:
            conn.execute("ALTER TABLE webhooks ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        if "status" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
        if "http_status" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN http_status INTEGER NOT NULL DEFAULT 0")
        if "error_text" not in cols:
            conn.execute("ALTER TABLE webhook_events ADD COLUMN error_text TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass

    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook ON webhook_events(webhook_id)")




def init_db():
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        _ensure_sprint5_tables(conn)
        _ensure_integrations_tables(conn)
        conn.commit()



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
        _ensure_sprint5_tables(conn)
        conn.execute(
            '''
            INSERT OR REPLACE INTO scans (id, status, created_at, progress_json, error_text, results_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
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
    progress: Dict[str, Any],
    status: str = "running",
    error_text: str = "",
) -> None:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        if _table_has_column(conn, "scans", "error_text"):
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, progress_json = ?, error_text = ?
                WHERE id = ?
                ''',
                (status, json.dumps(progress), error_text or "", scan_id),
            )
        else:
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, progress_json = ?
                WHERE id = ?
                ''',
                (status, json.dumps(progress), scan_id),
            )
        conn.commit()

def save_scan_results(
    scan_id: str,
    results: List[Dict[str, Any]],
    summary: Dict[str, Any],
    status: str = "completed",
    error_text: str = "",
) -> None:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        if _table_has_column(conn, "scans", "error_text"):
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, error_text = ?, results_json = ?, summary_json = ?
                WHERE id = ?
                ''',
                (status, error_text or "", json.dumps(results), json.dumps(summary), scan_id),
            )
        else:
            conn.execute(
                '''
                UPDATE scans
                SET status = ?, results_json = ?, summary_json = ?
                WHERE id = ?
                ''',
                (status, json.dumps(results), json.dumps(summary), scan_id),
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


# -----------------------------
# Sprint 3/4: Asset inventory
# -----------------------------

def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def upsert_asset(
    asset_key_str: str,
    owner: str = "",
    team: str = "",
    environment: str = "",
    criticality: str = "",
    confidentiality_lifetime: str = "",
    notes: str = "",
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    tags = tags or []
    owner = owner or ""
    team = team or ""
    environment = environment or ""
    criticality = criticality or ""
    confidentiality_lifetime = confidentiality_lifetime or ""
    notes = notes or ""
    now = _utc_now_iso()

    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO assets (asset_key, owner, team, environment, criticality, confidentiality_lifetime, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_key) DO UPDATE SET
                owner=excluded.owner,
                team=excluded.team,
                environment=excluded.environment,
                criticality=excluded.criticality,
                confidentiality_lifetime=excluded.confidentiality_lifetime,
                notes=excluded.notes,
                updated_at=excluded.updated_at
            """,
            (asset_key_str, owner, team, environment, criticality, confidentiality_lifetime, notes, now),
        )
        # Replace tags
        conn.execute("DELETE FROM asset_tags WHERE asset_key = ?", (asset_key_str,))
        for t in tags:
            t = (t or "").strip()
            if not t:
                continue
            conn.execute("INSERT OR IGNORE INTO asset_tags (asset_key, tag) VALUES (?, ?)", (asset_key_str, t))
        conn.commit()

    return get_asset(asset_key_str) or {
        "asset_key": asset_key_str,
        "owner": owner,
        "team": team,
        "environment": environment,
        "criticality": criticality,
        "confidentiality_lifetime": confidentiality_lifetime,
        "notes": notes,
        "tags": tags,
        "updated_at": now,
    }


def get_asset(asset_key_str: str) -> Optional[Dict[str, Any]]:
    with closing(get_connection()) as conn:
        cur = conn.execute("SELECT asset_key, owner, team, environment, criticality, confidentiality_lifetime, notes, updated_at FROM assets WHERE asset_key = ?", (asset_key_str,))
        row = cur.fetchone()
        if not row:
            return None
        tags_cur = conn.execute("SELECT tag FROM asset_tags WHERE asset_key = ? ORDER BY tag", (asset_key_str,))
        tags = [r[0] for r in tags_cur.fetchall()]
        return {
            "asset_key": row[0],
            "owner": row[1],
            "team": row[2],
            "environment": row[3],
            "criticality": row[4],
            "confidentiality_lifetime": row[5],
            "notes": row[6],
            "updated_at": row[7],
            "tags": tags,
        }


def list_assets(
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 2000,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 2000), 5000))
    sql = "SELECT a.asset_key, a.owner, a.team, a.environment, a.criticality, a.confidentiality_lifetime, a.notes, a.updated_at FROM assets a"
    params: List[Any] = []
    wh: List[str] = []

    if tag:
        sql += " JOIN asset_tags t ON t.asset_key = a.asset_key"
        wh.append("t.tag = ?")
        params.append(tag)

    if owner is not None and owner != "":
        wh.append("a.owner = ?")
        params.append(owner)
    if team is not None and team != "":
        wh.append("a.team = ?")
        params.append(team)
    if environment is not None and environment != "":
        wh.append("a.environment = ?")
        params.append(environment)
    if criticality is not None and criticality != "":
        wh.append("a.criticality = ?")
        params.append(criticality)

    if wh:
        sql += " WHERE " + " AND ".join(wh)
    sql += " ORDER BY a.updated_at DESC LIMIT ?"
    params.append(limit)

    out: List[Dict[str, Any]] = []
    with closing(get_connection()) as conn:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        for row in rows:
            ak = row[0]
            tags_cur = conn.execute("SELECT tag FROM asset_tags WHERE asset_key = ? ORDER BY tag", (ak,))
            tags = [r[0] for r in tags_cur.fetchall()]
            out.append({
                "asset_key": ak,
                "owner": row[1],
                "team": row[2],
                "environment": row[3],
                "criticality": row[4],
                "confidentiality_lifetime": row[5],
                "notes": row[6],
                "updated_at": row[7],
                "tags": tags,
            })
    return out


def list_tags(limit: int = 2000) -> List[str]:
    limit = max(1, min(int(limit or 2000), 5000))
    with closing(get_connection()) as conn:
        cur = conn.execute("SELECT DISTINCT tag FROM asset_tags ORDER BY tag LIMIT ?", (limit,))
        return [r[0] for r in cur.fetchall()]


# -----------------------------
# Sprint 5: collections + scheduling + history
# -----------------------------

def upsert_collection(name: str, targets_text: str) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("collection name is required")
    targets_text = (targets_text or "").strip()
    if not targets_text:
        raise ValueError("targets_text is required")

    now = _utc_now_iso()
    with get_connection() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        row = conn.execute("SELECT id FROM collections WHERE name = ?", (name,)).fetchone()
        if row:
            cid = int(row[0])
            conn.execute("UPDATE collections SET targets_text=?, updated_at=? WHERE id=?", (targets_text, now, cid))
        else:
            cur = conn.execute(
                "INSERT INTO collections (name, targets_text, created_at, updated_at) VALUES (?,?,?,?)",
                (name, targets_text, now, now),
            )
            cid = int(cur.lastrowid)
        conn.commit()
    return get_collection(cid)

def list_collections() -> list[dict]:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, targets_text, created_at, updated_at FROM collections ORDER BY name ASC"
        ).fetchall()
        return [dict(r) for r in rows]

def get_collection(collection_id: int) -> dict:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, targets_text, created_at, updated_at FROM collections WHERE id = ?",
            (int(collection_id),),
        ).fetchone()
        if not row:
            raise KeyError("collection not found")
        return dict(row)

def delete_collection(collection_id: int) -> None:
    with get_connection() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DELETE FROM collections WHERE id = ?", (int(collection_id),))
        conn.commit()

def create_schedule(collection_id: int, interval_minutes: int, enabled: bool = True) -> dict:
    if int(interval_minutes) <= 0:
        raise ValueError("interval_minutes must be > 0")
    now = _utc_now_iso()
    dt = _parse_iso_datetime(now)
    next_dt = dt + timedelta(minutes=int(interval_minutes))
    next_run = next_dt.isoformat() + "Z" if not next_dt.isoformat().endswith("Z") else next_dt.isoformat()

    with get_connection() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        exists = conn.execute("SELECT id FROM collections WHERE id = ?", (int(collection_id),)).fetchone()
        if not exists:
            raise KeyError("collection not found")
        cur = conn.execute(
            """
            INSERT INTO schedules (collection_id, enabled, interval_minutes, created_at, updated_at, last_run_at, next_run_at, last_scan_id)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (int(collection_id), 1 if enabled else 0, int(interval_minutes), now, now, "", next_run, ""),
        )
        conn.commit()
        sid = int(cur.lastrowid)
    return get_schedule(sid)

def list_schedules() -> list[dict]:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT s.id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id
            ORDER BY s.id DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

def get_schedule(schedule_id: int) -> dict:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT s.id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.created_at, s.updated_at, s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id
            WHERE s.id = ?
            """,
            (int(schedule_id),),
        ).fetchone()
        if not row:
            raise KeyError("schedule not found")
        return dict(row)

def update_schedule(schedule_id: int, interval_minutes: int | None = None, enabled: bool | None = None) -> dict:
    now = _utc_now_iso()
    with get_connection() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        row = conn.execute("SELECT interval_minutes, enabled FROM schedules WHERE id=?", (int(schedule_id),)).fetchone()
        if not row:
            raise KeyError("schedule not found")
        cur_interval = int(row[0])
        cur_enabled = int(row[1])

        new_interval = int(interval_minutes) if interval_minutes is not None else cur_interval
        if new_interval <= 0:
            raise ValueError("interval_minutes must be > 0")
        new_enabled = (1 if enabled else 0) if enabled is not None else cur_enabled

        dt = _parse_iso_datetime(now)
        next_dt = dt + timedelta(minutes=int(new_interval))
        next_run = next_dt.isoformat() + "Z" if not next_dt.isoformat().endswith("Z") else next_dt.isoformat()

        conn.execute(
            "UPDATE schedules SET enabled=?, interval_minutes=?, updated_at=?, next_run_at=? WHERE id=?",
            (new_enabled, new_interval, now, next_run, int(schedule_id)),
        )
        conn.commit()
    return get_schedule(int(schedule_id))

def delete_schedule(schedule_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM schedules WHERE id = ?", (int(schedule_id),))
        conn.commit()

def due_schedules(now_iso: str) -> list[dict]:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT s.id, s.collection_id, c.name as collection_name, s.enabled, s.interval_minutes,
                   s.last_run_at, s.next_run_at, s.last_scan_id
            FROM schedules s
            JOIN collections c ON c.id = s.collection_id
            WHERE s.enabled=1 AND s.next_run_at <> '' AND s.next_run_at <= ?
            ORDER BY s.next_run_at ASC
            """,
            (now_iso,),
        ).fetchall()
        return [dict(r) for r in rows]

def mark_schedule_ran(schedule_id: int, run_at_iso: str, interval_minutes: int, last_scan_id: str) -> None:
    run_dt = _parse_iso_datetime(run_at_iso)
    next_dt = run_dt + timedelta(minutes=int(interval_minutes))
    next_run = next_dt.isoformat() + "Z" if not next_dt.isoformat().endswith("Z") else next_dt.isoformat()
    with get_connection() as conn:
        conn.execute(
            "UPDATE schedules SET last_run_at=?, next_run_at=?, last_scan_id=?, updated_at=? WHERE id=?",
            (run_at_iso, next_run, last_scan_id, _utc_now_iso(), int(schedule_id)),
        )
        conn.commit()

def save_scan_asset_summaries(scan_id: str, scanned_at_iso: str, results: list[dict]) -> None:
    scanned_at_iso = scanned_at_iso or _utc_now_iso()
    with get_connection() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        for r in results or []:
            ak = asset_key(r.get("host",""), int(r.get("port",443)))
            findings = r.get("findings") or []
            findings_count = len(findings) if isinstance(findings, list) else 0
            risk_level = str(r.get("risk") or r.get("risk_level") or "unknown")
            quantum_score = float(r.get("quantum_risk_score") or r.get("quantum_score") or r.get("score") or 0.0)
            pqc_rel = str(r.get("pqc_relevance") or "")
            tls_ver = str(r.get("tls_version") or "")
            key_type = str(r.get("key_type") or "")
            sig_alg = str(r.get("sig_algorithm") or "")

            a = get_asset(ak)
            owner = (a.get("owner") or "") if isinstance(a, dict) else ""
            team = (a.get("team") or "") if isinstance(a, dict) else ""
            env = (a.get("environment") or "") if isinstance(a, dict) else ""
            crit = (a.get("criticality") or "") if isinstance(a, dict) else ""

            conn.execute(
                """
                INSERT INTO scan_results (
                    asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                    pqc_relevance, tls_version, key_type, sig_algorithm,
                    owner, team, environment, criticality
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (ak, scan_id, scanned_at_iso, risk_level, quantum_score, findings_count,
                 pqc_rel, tls_ver, key_type, sig_alg,
                 owner, team, env, crit),
            )
        conn.commit()

def get_asset_history(asset_key_str: str, limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit), 200))
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT scanned_at, scan_id, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   owner, team, environment, criticality
            FROM scan_results
            WHERE asset_key = ?
            ORDER BY scanned_at DESC
            LIMIT ?
            """,
            (asset_key_str, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def list_scan_results(scan_id: str, owner: str = "", team: str = "", environment: str = "", criticality: str = "", limit: int = 5000) -> list[dict]:
    """Return scan_results rows for a scan, optionally filtered by inventory snapshot fields."""
    limit = max(1, min(int(limit), 20000))
    owner = (owner or "").strip()
    team = (team or "").strip()
    environment = (environment or "").strip()
    criticality = (criticality or "").strip()

    clauses = ["scan_id = ?"]
    params = [scan_id]

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

    where = " AND ".join(clauses)
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                   pqc_relevance, tls_version, key_type, sig_algorithm,
                   owner, team, environment, criticality
            FROM scan_results
            WHERE {where}
            ORDER BY quantum_score DESC, findings_count DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in rows]

def list_scan_results_since(since_iso: str, limit: int = 200000) -> list[dict]:
    """Return scan_results rows since a timestamp (ISO).
    This is used for trends. If the scan_results table is missing (e.g., DB was created before Sprint 5/6),
    we gracefully return an empty list instead of crashing the API.
    """
    limit = max(1, min(int(limit), 400000))
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                       pqc_relevance, tls_version, key_type, sig_algorithm,
                       owner, team, environment, criticality
                FROM scan_results
                WHERE scanned_at >= ?
                ORDER BY scanned_at ASC
                LIMIT ?
                """,
                (since_iso, limit),
            ).fetchall()
        except sqlite3.OperationalError as e:
            # Typical: "no such table: scan_results"
            if "no such table" in str(e).lower():
                # Ensure tables exist for future calls
                try:
                    _ensure_sprint5_tables(conn)
                    conn.commit()
                except Exception:
                    pass
                return []
            raise
        return [dict(r) for r in rows]


# -----------------------------
# Sprint 8 Integrations: Webhooks + Delivery Log
# -----------------------------

def list_webhooks(limit: int = 200) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, url, secret, events_json, enabled, created_at, updated_at FROM webhooks ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            try:
                ev = json.loads(r["events_json"] or "[]")
            except Exception:
                ev = []
            out.append(
                {
                    "id": r["id"],
                    "name": r["name"],
                    "url": r["url"],
                    "secret": r["secret"],
                    "events": ev,
                    "enabled": bool(r["enabled"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return out


def upsert_webhook(
    name: str,
    url: str,
    secret: str = "",
    events: Optional[List[str]] = None,
    enabled: bool = True,
    webhook_id: Optional[int] = None,
) -> dict:
    name = (name or "").strip()
    url = (url or "").strip()
    secret = secret or ""
    events = events or ["*"]
    if not name:
        raise ValueError("name is required")
    if not url:
        raise ValueError("url is required")

    now = _utc_now_iso()
    ev_json = json.dumps(events)

    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        if webhook_id:
            conn.execute(
                "UPDATE webhooks SET name=?, url=?, secret=?, events_json=?, enabled=?, updated_at=? WHERE id=?",
                (name, url, secret, ev_json, 1 if enabled else 0, now, int(webhook_id)),
            )
        else:
            # Insert or update by name
            conn.execute(
                "INSERT INTO webhooks(name,url,secret,events_json,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET url=excluded.url, secret=excluded.secret, events_json=excluded.events_json, enabled=excluded.enabled, updated_at=excluded.updated_at",
                (name, url, secret, ev_json, 1 if enabled else 0, now, now),
            )
        conn.commit()

        row = conn.execute(
            "SELECT id, name, url, secret, events_json, enabled, created_at, updated_at FROM webhooks WHERE name=?",
            (name,),
        ).fetchone()
        if not row:
            raise RuntimeError("failed to upsert webhook")

        try:
            ev = json.loads(row["events_json"] or "[]")
        except Exception:
            ev = []
        return {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "secret": row["secret"],
            "events": ev,
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


def delete_webhook(webhook_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM webhooks WHERE id = ?", (int(webhook_id),))
        conn.commit()


def record_webhook_event(
    webhook_id: int,
    event_type: str,
    dedupe_key: str,
    payload: dict,
    status: str = "queued",
    http_status: int = 0,
    error_text: str = "",
    max_attempts: int = 5,
) -> Optional[int]:
    """Insert (or re-queue) an outgoing webhook delivery.

    Supports both:
      - New schema (payload_json/status/http_status/attempts/last_attempt_at)
      - Legacy schema where scan_id/asset_key/payload_sha256 are NOT NULL
    """
    import hashlib as _hashlib

    now = _utc_now_iso()
    payload_json = json.dumps(payload or {})
    payload_sha256 = _hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    with get_connection() as conn:
        conn.row_factory = sqlite3.Row

        # Best-effort add of optional columns (never adds NOT NULL without default)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
            if "payload_json" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'")
            if "status" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'")
            if "http_status" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN http_status INTEGER NOT NULL DEFAULT 0")
            if "attempts" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if "last_attempt_at" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        existing = conn.execute(
            "SELECT id, status, attempts FROM webhook_events WHERE webhook_id=? AND dedupe_key=?",
            (int(webhook_id), str(dedupe_key)),
        ).fetchone()

        if existing:
            st = str(existing["status"] or "")
            attempts = int(existing["attempts"] or 0)
            if st == "sent":
                return None
            if attempts >= int(max_attempts):
                return None

            conn.execute(
                "UPDATE webhook_events SET payload_json=?, status=?, http_status=?, error_text=? WHERE id=?",
                (payload_json, str(status), int(http_status), str(error_text or ""), int(existing["id"])),
            )
            conn.commit()
            return int(existing["id"])

        # Schema-adaptive insert
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        data = payload.get("data") if isinstance(payload, dict) else {}
        if not isinstance(data, dict):
            data = {}

        scan_id = str(data.get("scan_id") or "")
        asset_key = str(data.get("asset_key") or "")

        insert_cols = []
        insert_vals = []

        def add(col: str, val):
            if col in cols:
                insert_cols.append(col)
                insert_vals.append(val)

        add("webhook_id", int(webhook_id))
        add("event_type", str(event_type))
        add("dedupe_key", str(dedupe_key))

        # legacy required columns
        add("scan_id", scan_id)
        add("asset_key", asset_key)
        add("payload_sha256", payload_sha256)

        # time + payload
        add("created_at", now)
        add("payload_json", payload_json)

        # status fields
        add("status", str(status))
        add("http_status", int(http_status))
        add("error_text", str(error_text or ""))

        # retry bookkeeping
        add("attempts", 0)
        add("last_attempt_at", "")

        # legacy delivery fields (safe defaults)
        add("ok", 0)
        add("status_code", int(http_status) if http_status else 0)
        add("delivered_at", "")

        sql = f"INSERT INTO webhook_events({','.join(insert_cols)}) VALUES ({','.join(['?']*len(insert_cols))})"
        try:
            cur = conn.execute(sql, tuple(insert_vals))
            conn.commit()
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return None


def bump_webhook_attempt(event_row_id: int) -> None:
    """Increment attempts and set last_attempt_at."""
    now = _utc_now_iso()
    with get_connection() as conn:
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
            if "attempts" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if "last_attempt_at" not in cols:
                conn.execute("ALTER TABLE webhook_events ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        conn.execute(
            "UPDATE webhook_events SET attempts = attempts + 1, last_attempt_at=? WHERE id=?",
            (now, int(event_row_id)),
        )
        conn.commit()


def update_webhook_event(event_row_id: int, status: str, http_status: int = 0, error_text: str = "") -> None:
    """Update delivery status in a schema-adaptive way."""
    now = _utc_now_iso()
    with get_connection() as conn:
        cols = set()
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            pass

        sets = []
        vals = []

        if "status" in cols:
            sets.append("status=?")
            vals.append(str(status))
        if "http_status" in cols:
            sets.append("http_status=?")
            vals.append(int(http_status))
        if "error_text" in cols:
            sets.append("error_text=?")
            vals.append(str(error_text or ""))

        if "ok" in cols and status in ("sent", "failed"):
            sets.append("ok=?")
            vals.append(1 if status == "sent" else 0)
        if "status_code" in cols and http_status:
            sets.append("status_code=?")
            vals.append(int(http_status))
        if "delivered_at" in cols and status in ("sent", "failed"):
            sets.append("delivered_at=?")
            vals.append(now)

        if not sets:
            return

        vals.append(int(event_row_id))
        conn.execute(f"UPDATE webhook_events SET {', '.join(sets)} WHERE id=?", tuple(vals))
        conn.commit()


def list_webhook_events(limit: int = 50):
    """Return recent delivery attempts (powers the UI).

    Schema-adaptive: some installs have legacy webhook_events tables without
    columns like ok/delivered_at/status_code.
    """
    try:
        limit = int(limit or 50)
    except Exception:
        limit = 50
    limit = max(1, min(500, limit))

    with closing(get_connection()) as conn:
        _ensure_integrations_tables(conn)
        conn.row_factory = sqlite3.Row

        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        # Build expressions only using existing columns
        if "status" in cols:
            status_expr = "CASE WHEN status IS NOT NULL AND status != '' THEN status ELSE 'queued' END"
        else:
            status_expr = "'queued'"

        if "ok" in cols and "delivered_at" in cols:
            if "status" in cols:
                status_expr = (
                    "CASE "
                    "WHEN status IS NOT NULL AND status != '' THEN status "
                    "WHEN ok = 1 THEN 'sent' "
                    "WHEN ok = 0 AND delivered_at != '' THEN 'failed' "
                    "ELSE 'queued' END"
                )
            else:
                status_expr = (
                    "CASE "
                    "WHEN ok = 1 THEN 'sent' "
                    "WHEN ok = 0 AND delivered_at != '' THEN 'failed' "
                    "ELSE 'queued' END"
                )

        if "http_status" in cols and "status_code" in cols:
            http_expr = "COALESCE(http_status, status_code, 0)"
        elif "http_status" in cols:
            http_expr = "COALESCE(http_status, 0)"
        elif "status_code" in cols:
            http_expr = "COALESCE(status_code, 0)"
        else:
            http_expr = "0"

        payload_expr = "COALESCE(payload_json, '{}')" if "payload_json" in cols else "'{}'"
        error_expr = "COALESCE(error_text, '')" if "error_text" in cols else "''"
        attempts_expr = "COALESCE(attempts, 0)" if "attempts" in cols else "0"
        last_attempt_expr = "COALESCE(last_attempt_at, '')" if "last_attempt_at" in cols else "''"

        select_cols = [
            "id",
            ("webhook_id" if "webhook_id" in cols else "0 AS webhook_id"),
            ("created_at" if "created_at" in cols else "'' AS created_at"),
            ("event_type" if "event_type" in cols else "'' AS event_type"),
            ("dedupe_key" if "dedupe_key" in cols else "'' AS dedupe_key"),
            f"{status_expr} AS status",
            f"{http_expr} AS http_status",
            f"{error_expr} AS error_text",
            f"{attempts_expr} AS attempts",
            f"{last_attempt_expr} AS last_attempt_at",
            f"{payload_expr} AS payload_json",
        ]

        rows = conn.execute(
            f"""SELECT {', '.join(select_cols)}
                 FROM webhook_events
                 ORDER BY id DESC
                 LIMIT ?""",
            (limit,),
        ).fetchall()

    out = []
    for r in rows:
        d = dict(r)
        pj = d.get("payload_json") or "{}"
        try:
            d["payload"] = json.loads(pj)
        except Exception:
            d["payload"] = pj
        d.pop("payload_json", None)
        out.append(d)
    return out


def list_pending_webhook_events(limit: int = 100, max_attempts: int = 5) -> List[Dict[str, Any]]:
    """Pending deliveries = queued OR failed (or empty status), attempts < max_attempts.

    Schema-adaptive for legacy webhook_events tables.
    """
    try:
        limit = int(limit or 100)
    except Exception:
        limit = 100
    limit = max(1, min(500, limit))

    with closing(get_connection()) as conn:
        _ensure_integrations_tables(conn)
        conn.row_factory = sqlite3.Row

        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(webhook_events)").fetchall()}
        except Exception:
            cols = set()

        status_select = "status" if "status" in cols else "'' AS status"
        http_expr = "COALESCE(http_status, 0)" if "http_status" in cols else ("COALESCE(status_code, 0)" if "status_code" in cols else "0")
        error_expr = "COALESCE(error_text, '')" if "error_text" in cols else "''"
        attempts_expr = "COALESCE(attempts, 0)" if "attempts" in cols else "0"
        last_attempt_expr = "COALESCE(last_attempt_at, '')" if "last_attempt_at" in cols else "''"
        payload_expr = "COALESCE(payload_json, '{}')" if "payload_json" in cols else "'{}'"

        where_clause = "(status='queued' OR status='failed' OR status='' )" if "status" in cols else "1=1"

        rows = conn.execute(
            f"""SELECT
                    id,
                    webhook_id,
                    created_at,
                    event_type,
                    dedupe_key,
                    {status_select},
                    {http_expr} AS http_status,
                    {error_expr} AS error_text,
                    {attempts_expr} AS attempts,
                    {last_attempt_expr} AS last_attempt_at,
                    {payload_expr} AS payload_json
                 FROM webhook_events
                 WHERE {where_clause}
                   AND {attempts_expr} < ?
                 ORDER BY id ASC
                 LIMIT ?""",
            (int(max_attempts), int(limit)),
        ).fetchall()

    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except Exception:
            d["payload"] = d.get("payload_json") or "{}"
        d.pop("payload_json", None)
        out.append(d)
    return out


def update_scan_job(
    scan_id: str,
    job_id: str = "",
    job_state: str = "",
    started_at_iso: str = "",
    finished_at_iso: str = "",
) -> None:
    """Persist Celery job metadata for a scan."""
    with closing(get_connection()) as conn:
        _ensure_columns(conn)
        sets = []
        vals: list[Any] = []
        if job_id != "":
            sets.append("job_id = ?")
            vals.append(job_id)
        if job_state != "":
            sets.append("job_state = ?")
            vals.append(job_state)
        if started_at_iso != "":
            sets.append("job_started_at = ?")
            vals.append(started_at_iso)
        if finished_at_iso != "":
            sets.append("job_finished_at = ?")
            vals.append(finished_at_iso)
        if not sets:
            return
        vals.append(scan_id)
        conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()
