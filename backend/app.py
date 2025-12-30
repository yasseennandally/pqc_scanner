from __future__ import annotations

import os
import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from scanner import scan_host, parse_target
from policy import summarize_results
from migration import build_tls_migration_plan
from db import (
    init_db,
    save_scan_row,
    update_scan_progress,
    save_scan_results,
    load_scan_row,
    list_scan_rows,
    asset_key,
    set_baseline,
    get_baseline,
    list_baselines,
    set_baselines_from_scan,
)


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

class BaselineRequest(BaseModel):
    host: str
    port: int = 443
    baseline_scan_id: str



def _asset_key_from_result(r: Dict[str, Any]) -> str:
    h = r.get("host") or r.get("hostname") or ""
    p = int(r.get("port") or 443)
    return asset_key(h, p)


def _finding_ids(r: Dict[str, Any]) -> set:
    out = set()
    for f in (r.get("findings") or []):
        fid = f.get("id")
        if fid:
            out.add(str(fid))
    return out


def _compute_asset_diff(current: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cur_ids = _finding_ids(current)
    base_ids = _finding_ids(baseline or {})
    new_ids = sorted(cur_ids - base_ids)
    resolved_ids = sorted(base_ids - cur_ids)
    unchanged_ids = sorted(cur_ids & base_ids)

    def pick(obj: Optional[Dict[str, Any]], keys: List[str], default=None):
        if not obj:
            return default
        for k in keys:
            if k in obj and obj.get(k) is not None:
                return obj.get(k)
        return default

    cur_score = pick(current, ["quantum_risk_score", "risk_score"], None)
    base_score = pick(baseline, ["quantum_risk_score", "risk_score"], None)

    cur_level = pick(current, ["quantum_risk_level", "risk", "risk_level"], "")
    base_level = pick(baseline, ["quantum_risk_level", "risk", "risk_level"], "")

    return {
        "host": current.get("host") or current.get("hostname") or "",
        "port": int(current.get("port") or 443),
        "baseline_present": bool(baseline),
        "current": {"score": cur_score, "level": cur_level},
        "baseline": {"score": base_score, "level": base_level},
        "score_delta": (cur_score - base_score) if (isinstance(cur_score, (int, float)) and isinstance(base_score, (int, float))) else None,
        "new_findings": new_ids,
        "resolved_findings": resolved_ids,
        "unchanged_findings": unchanged_ids,
    }


def _compute_scan_diff(current_scan: Dict[str, Any], baseline_scan: Dict[str, Any]) -> Dict[str, Any]:
    cur_results = current_scan.get("results") or []
    base_results = baseline_scan.get("results") or []

    cur_map = {_asset_key_from_result(r): r for r in cur_results}
    base_map = {_asset_key_from_result(r): r for r in base_results}

    assets = []
    for k, cur in cur_map.items():
        assets.append(_compute_asset_diff(cur, base_map.get(k)))

    total_assets = len(assets)
    total_new = sum(1 for a in assets if a["new_findings"])
    total_resolved = sum(1 for a in assets if a["resolved_findings"])
    total_changed = sum(1 for a in assets if (a["new_findings"] or a["resolved_findings"]))

    regressions = sorted(
        [a for a in assets if (a.get("score_delta") is not None and a["score_delta"] > 0)],
        key=lambda x: x["score_delta"],
        reverse=True,
    )[:25]
    improvements = sorted(
        [a for a in assets if (a.get("score_delta") is not None and a["score_delta"] < 0)],
        key=lambda x: x["score_delta"],
    )[:25]

    return {
        "scan_id": current_scan.get("id"),
        "baseline_scan_id": baseline_scan.get("id"),
        "generated_at": _now_iso(),
        "totals": {
            "assets": total_assets,
            "assets_changed": total_changed,
            "assets_with_new_findings": total_new,
            "assets_with_resolved_findings": total_resolved,
        },
        "top_regressions": regressions,
        "top_improvements": improvements,
        "assets": assets,
    }
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
def _now_iso() -> str:
    """UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()



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



@app.get("/baselines")
def api_list_baselines(limit: int = 500):
    return {"baselines": list_baselines(limit=limit)}


@app.post("/baselines")
def api_set_baseline(req: BaselineRequest):
    k = asset_key(req.host, req.port)
    if not load_scan_row(req.baseline_scan_id):
        raise HTTPException(status_code=404, detail="baseline_scan_id not found")
    set_baseline(k, req.baseline_scan_id)
    return {"asset_key": k, "baseline_scan_id": req.baseline_scan_id}


@app.post("/baselines/from-scan/{scan_id}")
def api_set_baselines_from_scan(scan_id: str):
    try:
        return set_baselines_from_scan(scan_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="scan_id not found")


@app.get("/scans/{scan_id}/diff")
def api_scan_diff(scan_id: str, baseline_scan_id: Optional[str] = None):
    current = load_scan_row(scan_id)
    if not current:
        raise HTTPException(status_code=404, detail="scan_id not found")

    if baseline_scan_id:
        baseline = load_scan_row(baseline_scan_id)
        if not baseline:
            raise HTTPException(status_code=404, detail="baseline_scan_id not found")
        return _compute_scan_diff(current, baseline)

    # Per-asset baselines
    cur_results = current.get("results") or []
    cache: Dict[str, Dict[str, Any]] = {}

    assets = []
    for r in cur_results:
        k = _asset_key_from_result(r)
        b = get_baseline(k)
        bscan_id = b["baseline_scan_id"] if b else None

        baseline_res = None
        if bscan_id:
            if bscan_id not in cache:
                cache[bscan_id] = load_scan_row(bscan_id) or {}
            bscan = cache[bscan_id]
            bmap = {_asset_key_from_result(x): x for x in (bscan.get("results") or [])}
            baseline_res = bmap.get(k)

        ad = _compute_asset_diff(r, baseline_res)
        ad["asset_key"] = k
        ad["baseline_scan_id"] = bscan_id
        assets.append(ad)

    total_assets = len(assets)
    total_new = sum(1 for a in assets if a["new_findings"])
    total_resolved = sum(1 for a in assets if a["resolved_findings"])
    total_changed = sum(1 for a in assets if (a["new_findings"] or a["resolved_findings"]))

    regressions = sorted([a for a in assets if (a.get("score_delta") is not None and a["score_delta"] > 0)], key=lambda x: x["score_delta"], reverse=True)[:25]
    improvements = sorted([a for a in assets if (a.get("score_delta") is not None and a["score_delta"] < 0)], key=lambda x: x["score_delta"])[:25]

    return {
        "scan_id": current.get("id"),
        "baseline_mode": "per_asset",
        "generated_at": _now_iso(),
        "totals": {
            "assets": total_assets,
            "assets_changed": total_changed,
            "assets_with_new_findings": total_new,
            "assets_with_resolved_findings": total_resolved,
        },
        "top_regressions": regressions,
        "top_improvements": improvements,
        "assets": assets,
    }


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
