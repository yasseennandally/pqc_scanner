from __future__ import annotations

import os
import time
import uuid
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from scanner import scan_host, parse_target
from policy import summarize_results
from migration import build_tls_migration_plan
from db import init_db, save_scan_row, load_scan_row, list_scan_rows, update_scan_progress, save_scan_results


# -----------------------------
# Pydantic models
# -----------------------------

class ScanRequest(BaseModel):
    targets: List[str]


class ScanProgress(BaseModel):
    total: int
    done: int
    percent: int


class ScanStatus(BaseModel):
    id: str
    status: str
    created_at: datetime
    progress: ScanProgress
    error: str = ""


class ScanWithResults(ScanStatus):
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


# -----------------------------
# In-memory cache (speed)
# -----------------------------

_SCANS: Dict[str, Dict[str, Any]] = {}
_SCANS_LOCK = threading.Lock()


# -----------------------------
# API key + rate limit
# -----------------------------

API_KEY = os.getenv("PQC_API_KEY", "").strip()
PROTECTED_PREFIXES = ("/scan", "/scans", "/code-scan")

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 60
_requests_by_ip = defaultdict(deque)


# -----------------------------
# App
# -----------------------------

app = FastAPI(
    title="PQC Scanner API",
    description="TLS endpoint scanner with PQC-oriented findings, scoring, and migration plans.",
    version="0.6.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    init_db()


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    q = _requests_by_ip[ip]
    while q and (now - q[0]) > RATE_LIMIT_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX_REQUESTS:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please slow down."})
    q.append(now)
    return await call_next(request)


@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if not API_KEY:
        return await call_next(request)

    path = request.url.path

    # health always open
    if path == "/health":
        return await call_next(request)

    # protect docs optionally (demo safety)
    if path in ("/docs", "/openapi.json", "/redoc"):
        provided = request.headers.get("x-api-key", "")
        if provided != API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
        return await call_next(request)

    if any(path == p or path.startswith(p + "/") for p in PROTECTED_PREFIXES):
        provided = request.headers.get("x-api-key", "")
        if provided != API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


# -----------------------------
# Helpers
# -----------------------------

def _progress(total: int, done: int) -> Dict[str, int]:
    pct = int((done * 100) / total) if total else 100
    if pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    return {"total": total, "done": done, "percent": pct}


def _cache_put(scan: Dict[str, Any]) -> None:
    with _SCANS_LOCK:
        _SCANS[scan["id"]] = scan


def _cache_get(scan_id: str) -> Optional[Dict[str, Any]]:
    with _SCANS_LOCK:
        return _SCANS.get(scan_id)


def _cache_update(scan_id: str, **patch) -> None:
    with _SCANS_LOCK:
        if scan_id in _SCANS:
            _SCANS[scan_id].update(patch)


# -----------------------------
# Legacy quick scan (no history)
# -----------------------------

@app.post("/scan")
def scan_legacy(request: ScanRequest):
    results = []
    for t in request.targets:
        host, port = parse_target(t)
        results.append(scan_host(host, port))
    summary = summarize_results(results)
    return {"count": len(results), "results": results, "summary": summary}


# -----------------------------
# Scans with IDs + progress
# -----------------------------

MAX_TARGETS = 200
MAX_TARGET_LEN = 255


def _scan_worker(scan_id: str, targets: List[str]) -> None:
    total = len(targets)
    done = 0
    results: List[Dict[str, Any]] = []

    try:
        # parallel-ish without overwhelming networks
        import concurrent.futures
        max_workers = min(20, max(1, total))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_map = {}
            for t in targets:
                host, port = parse_target(t)
                fut = ex.submit(scan_host, host, port)
                future_map[fut] = (host, port)

            for fut in concurrent.futures.as_completed(future_map):
                res = fut.result()
                results.append(res)

                done += 1
                prog = _progress(total, done)

                _cache_update(scan_id, progress=prog, results=results)
                update_scan_progress(scan_id, status="running", progress=prog, error_text="")
                # keep partial results for reload
                save_scan_results(scan_id, results=results, summary={}, status="running")

        # finalize
        summary = summarize_results(results)
        prog = _progress(total, total)

        final_scan = {
            "id": scan_id,
            "status": "completed",
            "created_at": _cache_get(scan_id)["created_at"],
            "progress": prog,
            "error": "",
            "results": results,
            "summary": summary,
        }
        _cache_put(final_scan)
        save_scan_results(scan_id, results=results, summary=summary, status="completed")
        update_scan_progress(scan_id, status="completed", progress=prog, error_text="")

    except Exception as e:
        prog = _progress(total, done)
        msg = str(e)
        _cache_update(scan_id, status="failed", error=msg, progress=prog)
        update_scan_progress(scan_id, status="failed", progress=prog, error_text=msg)


@app.post("/scans", response_model=ScanStatus)
def create_scan(request: ScanRequest):
    if len(request.targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets. Max is {MAX_TARGETS}.")

    normalized: List[str] = []
    for t in request.targets:
        if not t or len(t) > MAX_TARGET_LEN:
            raise HTTPException(status_code=400, detail="Invalid target.")
        normalized.append(t.strip())

    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    prog = _progress(len(normalized), 0)

    scan = {
        "id": scan_id,
        "status": "running",
        "created_at": created_at,
        "progress": prog,
        "error": "",
        "results": [],
        "summary": {},
    }
    _cache_put(scan)

    save_scan_row(
        scan_id=scan_id,
        status="running",
        created_at=created_at,
        progress=prog,
        error_text="",
        results=[],
        summary={},
    )

    t = threading.Thread(target=_scan_worker, args=(scan_id, normalized), daemon=True)
    t.start()

    return ScanStatus(id=scan_id, status="running", created_at=created_at, progress=ScanProgress(**prog), error="")


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str):
    scan = _cache_get(scan_id)
    if not scan:
        scan = load_scan_row(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        _cache_put(scan)

    return ScanStatus(
        id=scan["id"],
        status=scan["status"],
        created_at=scan["created_at"],
        progress=ScanProgress(**(scan.get("progress") or {"total": 0, "done": 0, "percent": 0})),
        error=scan.get("error", "") or "",
    )


@app.get("/scans/{scan_id}/results", response_model=ScanWithResults)
def get_scan_results(scan_id: str):
    scan = _cache_get(scan_id)
    if not scan:
        scan = load_scan_row(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        _cache_put(scan)

    # If scan is still running, you still get partial results.
    results = scan.get("results") or []
    summary = scan.get("summary") or (summarize_results(results) if results else {})

    return ScanWithResults(
        id=scan["id"],
        status=scan["status"],
        created_at=scan["created_at"],
        progress=ScanProgress(**(scan.get("progress") or {"total": 0, "done": 0, "percent": 0})),
        error=scan.get("error", "") or "",
        results=results,
        summary=summary,
    )


@app.get("/scans")
def list_scans(limit: int = 20):
    limit = max(1, min(100, int(limit)))
    return list_scan_rows(limit=limit)


@app.get("/scans/{scan_id}/migration-plan")
def tls_migration_plan(scan_id: str):
    scan = _cache_get(scan_id)
    if not scan:
        scan = load_scan_row(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    results = scan.get("results") or []
    plan = build_tls_migration_plan(results)
    return {"scan_id": scan_id, "items": plan}
