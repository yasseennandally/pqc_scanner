from __future__ import annotations

import os
import time
import uuid
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from events import deliver_events_for_scan, deliver_test_ping


from scanner import scan_host, parse_target
from policy import summarize_results
from migration import build_tls_migration_plan
from tasks import celery_app, run_scan_task
from db import (
    init_db,
    save_scan_row,
    update_scan_progress,
    save_scan_results, update_scan_job,
    load_scan_row,
    list_scan_rows,
    asset_key,
    set_baseline,
    get_baseline,
    list_baselines,
    set_baselines_from_scan,
    upsert_asset,
    get_asset,
    list_assets,
    list_tags,
    # Sprint 5
    upsert_collection,
    list_collections,
    get_collection,
    delete_collection,
    create_schedule,
    list_schedules,
    get_schedule,
    update_schedule,
    delete_schedule,
    due_schedules,
    mark_schedule_ran,
    save_scan_asset_summaries,
    list_scan_results,
    list_scan_results_since,
    get_asset_history,
    # Sprint 8 integrations
    list_webhooks,
    upsert_webhook,
    delete_webhook,
    list_webhook_events,
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
    job_id: str = ""
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

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PQC_RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("PQC_RATE_LIMIT_MAX_REQUESTS", "240"))
_requests_by_ip = defaultdict(deque)




class AssetUpdate(BaseModel):
    owner: str = ""
    team: str = ""
    environment: str = ""
    criticality: str = ""
    confidentiality_lifetime: str = ""
    tags: List[str] = Field(default_factory=list)
    notes: str = ""


class FixNextItem(BaseModel):
    asset_key: str
    host: str = ""
    port: int = 443
    priority_score: float
    risk_score: float = 0.0
    risk_level: str = ""
    pqc_relevance: str = ""
    pqc_recommendation: str = ""
    owner: str = ""
    team: str = ""
    environment: str = ""
    criticality: str = ""
    confidentiality_lifetime: str = ""
    tags: List[str] = Field(default_factory=list)
    top_findings: List[Dict[str, Any]] = Field(default_factory=list)
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


# Serve frontend UI (put index.html and assets under ./static)
app.mount("/ui", StaticFiles(directory="static", html=True), name="ui")

@app.get("/")
def root():
    return RedirectResponse(url="/ui/")



@app.on_event("startup")
def _startup():
    init_db()


# -----------------------------
# Sprint 5: simple in-process scheduler
# -----------------------------

_SCHED_STOP = threading.Event()
_SCHED_THREAD: Optional[threading.Thread] = None

def _create_scan_and_start(targets: List[str], source: str = "manual", collection_id: Optional[int] = None) -> Dict[str, Any]:
    # normalize and cap
    targets = [t.strip() for t in (targets or []) if t and t.strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided.")
    if len(targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets (max {MAX_TARGETS}).")
    for t in targets:
        if len(t) > MAX_TARGET_LEN:
            raise HTTPException(status_code=400, detail=f"Invalid target: {t[:80]}")

    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    prog = _progress(len(targets), 0)

    scan = {
        "id": scan_id,
        "status": "running",
        "created_at": created_at,
        "progress": prog,
        "error": "",
        "results": [],
        "summary": {},
        "meta": {"source": source, "collection_id": collection_id},
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

    t = threading.Thread(target=_scan_worker, args=(scan_id, targets), daemon=True)
    t.start()

    return {"id": scan_id, "status": "running", "created_at": created_at.isoformat() + "Z"}


def _scheduler_loop():
    # Runs forever, triggers collection scans when due.
    while not _SCHED_STOP.is_set():
        try:
            now = datetime.utcnow().isoformat() + "Z"
            for sch in due_schedules(now):
                # load targets from collection
                col = get_collection(int(sch["collection_id"]))
                targets_text = (col.get("targets_text") or "").strip()
                targets = [ln.strip() for ln in targets_text.splitlines() if ln.strip()]

                created = _create_scan_and_start(targets, source="schedule", collection_id=int(sch["collection_id"]))
                mark_schedule_ran(int(sch["id"]), now, int(sch["interval_minutes"]), created["id"])
        except Exception:
            # swallow errors; scheduler should keep running
            pass

        _SCHED_STOP.wait(10.0)

@app.on_event("startup")
def _start_scheduler():
    global _SCHED_THREAD
    try:
        if _SCHED_THREAD and _SCHED_THREAD.is_alive():
            return
        _SCHED_THREAD = threading.Thread(target=_scheduler_loop, daemon=True)
        _SCHED_THREAD.start()
    except Exception:
        pass

@app.on_event("shutdown")
def _stop_scheduler():
    _SCHED_STOP.set()



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

def _severity_score(sev: str) -> int:
    s = (sev or "").lower()
    if s == "critical":
        return 4
    if s == "high":
        return 3
    if s == "medium":
        return 2
    if s == "low":
        return 1
    return 0


def _criticality_weight(crit: str) -> int:
    c = (crit or "").lower()
    if c == "tier-0":
        return 40
    if c == "tier-1":
        return 30
    if c == "tier-2":
        return 20
    if c == "tier-3":
        return 10
    return 0


def _conf_weight(conf: str) -> int:
    t = (conf or "").lower()
    # very rough parsing; user-entered field
    if "10" in t:
        return 15
    if "5" in t:
        return 10
    if "1" in t:
        return 5
    return 0


def _enrich_result_with_asset(result: Dict[str, Any]) -> Dict[str, Any]:
    """Attach inventory + baseline info to a scan result."""
    host = result.get("host") or ""
    port = result.get("port") if result.get("port") is not None else 443
    ak = f"{host}:{port}"
    result["asset_key"] = ak

    a = get_asset(ak)
    if a:
        result["asset"] = a
        # also flatten common fields for UI convenience
        for k in ["owner","team","environment","criticality","confidentiality_lifetime","notes","tags","updated_at"]:
            result[k] = a.get(k)
    else:
        result["asset"] = None

    b = get_baseline(ak)
    if b:
        result["baseline_scan_id"] = b.get("baseline_scan_id")
        result["baseline_set_at"] = b.get("set_at")
    return result


def _priority_score(result: Dict[str, Any]) -> float:
    # risk score (0-100 expected)
    rs = result.get("risk_score")
    if rs is None:
        rs = result.get("quantum_risk_score")
    try:
        rs_f = float(rs) if rs is not None else 0.0
    except Exception:
        rs_f = 0.0

    findings = result.get("findings") or []
    max_sev = 0
    for f in findings:
        max_sev = max(max_sev, _severity_score((f or {}).get("severity", "")))

    crit = (result.get("criticality") or (result.get("asset") or {}).get("criticality") or "")
    tags = (result.get("tags") or (result.get("asset") or {}).get("tags") or []) or []
    conf = (result.get("confidentiality_lifetime") or (result.get("asset") or {}).get("confidentiality_lifetime") or "")

    score = rs_f * 1.0 + max_sev * 20 + _criticality_weight(crit) + _conf_weight(conf)
    if any((t or "").lower() == "internet-facing" for t in tags):
        score += 15
    if any((t or "").lower() == "pqc" for t in tags):
        score += 5
    return float(round(score, 2))

# -----------------------------

def _progress(total: int, done: int) -> Dict[str, int]:
    pct = int((done * 100) / total) if total else 100
    if pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    return {"total": total, "done": done, "percent": pct}

def _now_iso() -> str:
    """UTC timestamp in ISO 8601 with a trailing 'Z'."""
    return datetime.utcnow().isoformat() + "Z"



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
        # Sprint 5: persist per-asset summaries for history
        try:
            ca = _cache_get(scan_id).get("created_at")
            scanned_at_iso = ca.isoformat() + "Z" if hasattr(ca, "isoformat") else str(ca)
            save_scan_asset_summaries(scan_id, scanned_at_iso=scanned_at_iso, results=results)
        except Exception:
            pass
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

    # Persist scan row immediately (queued)
    save_scan_row(
        scan_id=scan_id,
        status="queued",
        created_at=created_at,
        progress=prog,
        error_text="",
        results=[],
        summary={},
    )

    # Enqueue Celery job
    res = run_scan_task.delay(scan_id, normalized)
    update_scan_job(scan_id, job_id=res.id, job_state="PENDING")

    return ScanStatus(
        job_id=res.id,
        id=scan_id,
        status="queued",
        created_at=created_at,
        progress=ScanProgress(**prog),
        error="",
    )



@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str):
    # IMPORTANT: scans are executed asynchronously by Celery workers which update SQLite.
    # Do NOT rely on in-memory cache for non-terminal states, otherwise UI will never see updates.
    scan = load_scan_row(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Cache only terminal states (optional perf)
    if (scan.get("status") or "").lower() in ("done", "completed", "failed"):
        _cache_put(scan)

    return ScanStatus(
        job_id=scan.get("job_id", "") or "",
        id=scan["id"],
        status=scan["status"],
        created_at=scan["created_at"],
        progress=ScanProgress(**(scan.get("progress") or {"total": 0, "done": 0, "percent": 0})),
        error=scan.get("error", "") or "",
    )



@app.get("/scans/{scan_id}/results", response_model=ScanWithResults)
def get_scan_results(scan_id: str):
    # Reload from SQLite so async worker updates are visible
    scan = load_scan_row(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if (scan.get("status") or "").lower() in ("done", "completed", "failed"):
        _cache_put(scan)

    # If scan is still running, you still get partial results.
    results = scan.get("results") or []
    # Enrich with asset inventory/baseline
    results = [_enrich_result_with_asset(dict(r)) for r in results]
    # Enrich with asset inventory/baseline
    results = [_enrich_result_with_asset(dict(r)) for r in results]
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




# -----------------------------
# Sprint 3: Asset inventory API
# -----------------------------

@app.get("/assets")
def api_list_assets(
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = Query(2000, ge=1, le=5000),
):
    return {"items": list_assets(owner=owner, team=team, environment=environment, criticality=criticality, tag=tag, limit=limit)}


@app.get("/assets/{asset_key_str}")
def api_get_asset(asset_key_str: str):
    a = get_asset(asset_key_str)
    if a:
        return a
    # Create an empty asset record so the UI asset editor can open without a 404.
    return upsert_asset(asset_key_str=asset_key_str)


@app.put("/assets/{asset_key_str}")
def api_put_asset(asset_key_str: str, req: AssetUpdate):
    # Upsert
    return upsert_asset(
        asset_key_str,
        owner=req.owner,
        team=req.team,
        environment=req.environment,
        criticality=req.criticality,
        confidentiality_lifetime=req.confidentiality_lifetime,
        notes=req.notes,
        tags=req.tags,
    )


@app.get("/tags")
def api_list_tags(limit: int = Query(2000, ge=1, le=5000)):
    return {"items": list_tags(limit=limit)}
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


# -----------------------------
# Sprint 4: Fix Next queue
# -----------------------------



# -----------------------------
# Sprint 5: Collections
# -----------------------------

class CollectionUpsertRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    targets_text: str = Field(..., min_length=1, max_length=20000)

@app.get("/collections")
async def api_list_collections():
    return {"items": list_collections()}

@app.post("/collections")
async def api_upsert_collection(req: CollectionUpsertRequest):
    try:
        c = upsert_collection(req.name, req.targets_text)
        return c
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/collections/{collection_id}")
async def api_get_collection(collection_id: int):
    try:
        return get_collection(collection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="collection not found")

@app.delete("/collections/{collection_id}")
async def api_delete_collection(collection_id: int):
    try:
        delete_collection(collection_id)
        return {"ok": True}
    except KeyError:
        raise HTTPException(status_code=404, detail="collection not found")

@app.post("/collections/{collection_id}/scan")
async def api_scan_collection(collection_id: int):
    try:
        col = get_collection(collection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="collection not found")
    targets_text = (col.get("targets_text") or "").strip()
    targets = [ln.strip() for ln in targets_text.splitlines() if ln.strip()]
    created = _create_scan_and_start(targets, source="collection", collection_id=collection_id)
    return created

# -----------------------------
# Sprint 5: Scheduling
# -----------------------------

class ScheduleCreateRequest(BaseModel):
    collection_id: int
    interval_minutes: int = Field(..., ge=1, le=10080)  # up to 7 days
    enabled: bool = True

class ScheduleUpdateRequest(BaseModel):
    interval_minutes: Optional[int] = Field(None, ge=1, le=10080)
    enabled: Optional[bool] = None

@app.get("/schedules")
async def api_list_schedules():
    return {"items": list_schedules()}

@app.post("/schedules")
async def api_create_schedule(req: ScheduleCreateRequest):
    try:
        return create_schedule(req.collection_id, req.interval_minutes, req.enabled)
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/schedules/{schedule_id}")
async def api_get_schedule(schedule_id: int):
    try:
        return get_schedule(schedule_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="schedule not found")

@app.put("/schedules/{schedule_id}")
async def api_update_schedule(schedule_id: int, req: ScheduleUpdateRequest):
    try:
        return update_schedule(schedule_id, req.interval_minutes, req.enabled)
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/schedules/{schedule_id}")
async def api_delete_schedule(schedule_id: int):
    try:
        delete_schedule(schedule_id)
        return {"ok": True}
    except KeyError:
        raise HTTPException(status_code=404, detail="schedule not found")

@app.post("/schedules/{schedule_id}/run-now")
async def api_schedule_run_now(schedule_id: int):
    try:
        sch = get_schedule(schedule_id)
        col = get_collection(int(sch["collection_id"]))
    except KeyError:
        raise HTTPException(status_code=404, detail="schedule/collection not found")
    targets_text = (col.get("targets_text") or "").strip()
    targets = [ln.strip() for ln in targets_text.splitlines() if ln.strip()]
    created = _create_scan_and_start(targets, source="schedule-manual", collection_id=int(sch["collection_id"]))
    # update schedule timestamps immediately
    now = datetime.utcnow().isoformat() + "Z"
    mark_schedule_ran(int(schedule_id), now, int(sch["interval_minutes"]), created["id"])
    return created

# -----------------------------
# Sprint 5: Asset history
# -----------------------------

@app.get("/assets/{asset_key_str}/history")
async def api_asset_history(asset_key_str: str, limit: int = Query(30, ge=1, le=200)):
    try:
        return {"asset_key": asset_key_str, "items": get_asset_history(asset_key_str, limit)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -----------------------------
# Sprint 5: CSV export
# -----------------------------

def _csv_escape(v: Any) -> str:
    s = "" if v is None else str(v)
    if any(ch in s for ch in [",", "\n", "\r", '"']):
        s = '"' + s.replace('"', '""') + '"'
    return s

@app.get("/scans/{scan_id}/export.csv")
async def api_export_scan_csv(scan_id: str):
    scan = load_scan_row(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    rows = scan.get("results") or []
    # minimal fields
    cols = ["asset_key","risk_level","quantum_score","findings_count","tls_version","cipher","key_type","sig_algorithm"]
    lines = [",".join(cols)]
    for r in rows:
        ak = asset_key(r.get("host",""), int(r.get("port",443)))
        findings = r.get("findings") or []
        lines.append(",".join([
            _csv_escape(ak),
            _csv_escape(r.get("risk") or r.get("risk_level")),
            _csv_escape(r.get("quantum_risk_score") or r.get("quantum_score") or r.get("score")),
            _csv_escape(len(findings) if isinstance(findings,list) else 0),
            _csv_escape(r.get("tls_version")),
            _csv_escape(r.get("cipher")),
            _csv_escape(r.get("key_type")),
            _csv_escape(r.get("sig_algorithm")),
        ]))
    csv_body = "\n".join(lines) + "\n"
    return Response(content=csv_body, media_type="text/csv")

@app.get("/fix-next")
def api_fix_next(
    scan_id: Optional[str] = None,
    limit: int = Query(30, ge=1, le=200),
    min_severity: Optional[str] = Query(None, description="critical|high|medium|low|info"),
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
):
    # Choose scan
    sid = scan_id
    if not sid:
        rows = list_scan_rows(limit=1)
        if not rows:
            return {"scan_id": None, "items": []}
        sid = rows[0]["id"]

    scan = load_scan_row(sid)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    results = scan.get("results") or []
    results = [_enrich_result_with_asset(dict(r)) for r in results]

    # Optional filter by inventory fields/tag
    items = []
    min_score = _severity_score(min_severity) if min_severity else None

    for r in results:
        ak = r.get("asset_key") or ""
        # inventory fields may be in flattened fields
        if owner and (r.get("owner") or "") != owner:
            continue
        if team and (r.get("team") or "") != team:
            continue
        if environment and (r.get("environment") or "") != environment:
            continue
        if criticality and (r.get("criticality") or "") != criticality:
            continue
        if tag:
            tags = r.get("tags") or []
            if tag not in tags:
                continue

        findings = r.get("findings") or []
        if min_score is not None:
            # keep only if any finding >= min
            ok = any(_severity_score((f or {}).get("severity", "")) >= min_score for f in findings)
            if not ok:
                continue

        score = _priority_score(r)
        host = r.get("host") or ""
        port = int(r.get("port") or 443)

        # top findings (max 5)
        def f_sort_key(f):
            return (-_severity_score(f.get("severity","")), str(f.get("id","")))
        top = sorted([f for f in findings if isinstance(f, dict)], key=f_sort_key)[:5]
        top_out = []
        for f in top:
            top_out.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "remediation": f.get("remediation"),
                "confidence": f.get("confidence"),
            })

        items.append({
            "asset_key": ak,
            "host": host,
            "port": port,
            "priority_score": score,
            "risk_score": float(r.get("risk_score") or r.get("quantum_risk_score") or 0.0),
            "risk_level": r.get("risk_level") or r.get("risk") or "",
            "pqc_relevance": r.get("pqc_relevance") or "",
            "pqc_recommendation": r.get("pqc_recommendation") or "",
            "owner": r.get("owner") or "",
            "team": r.get("team") or "",
            "environment": r.get("environment") or "",
            "criticality": r.get("criticality") or "",
            "confidentiality_lifetime": r.get("confidentiality_lifetime") or "",
            "tags": r.get("tags") or [],
            "top_findings": top_out,
        })

    items.sort(key=lambda x: (-x["priority_score"], x["asset_key"]))
    return {"scan_id": sid, "items": items[:limit]}


# -----------------------------
# Sprint 6: Dashboards / Metrics
# -----------------------------

def _iso_days_ago(days: int) -> str:
    days = max(1, min(int(days), 3650))
    dt = datetime.utcnow() - timedelta(days=days)
    return dt.replace(microsecond=0).isoformat() + "Z"

@app.get("/metrics/scan/{scan_id}/overview")
def metrics_overview(
    scan_id: str,
    owner: str = Query("", description="Filter by owner snapshot"),
    team: str = Query("", description="Filter by team snapshot"),
    environment: str = Query("", description="Filter by environment snapshot"),
    criticality: str = Query("", description="Filter by criticality snapshot"),
    top_n: int = Query(20, ge=1, le=200),
):
    rows = list_scan_results(
        scan_id=scan_id,
        owner=owner,
        team=team,
        environment=environment,
        criticality=criticality,
        limit=20000,
    )

    counts = {
        "assets_total": len(rows),
        "assets_with_findings": 0,
        "risk_levels": {},
        "pqc_relevance": {},
        "tls_versions": {},
        "key_types": {},
    }

    for r in rows:
        fc = int(r.get("findings_count") or 0)
        if fc > 0:
            counts["assets_with_findings"] += 1
        rl = (r.get("risk_level") or "unknown").lower()
        counts["risk_levels"][rl] = counts["risk_levels"].get(rl, 0) + 1
        pr = (r.get("pqc_relevance") or "unknown").lower()
        counts["pqc_relevance"][pr] = counts["pqc_relevance"].get(pr, 0) + 1
        tv = (r.get("tls_version") or "unknown")
        counts["tls_versions"][tv] = counts["tls_versions"].get(tv, 0) + 1
        kt = (r.get("key_type") or "unknown")
        counts["key_types"][kt] = counts["key_types"].get(kt, 0) + 1

    # top assets: by quantum_score, then findings_count
    top_assets = sorted(
        rows,
        key=lambda x: (float(x.get("quantum_score") or 0.0), int(x.get("findings_count") or 0)),
        reverse=True,
    )[: int(top_n)]

    return {
        "scan_id": scan_id,
        "filters": {
            "owner": owner,
            "team": team,
            "environment": environment,
            "criticality": criticality,
        },
        "counts": counts,
        "top_assets": top_assets,
    }

@app.get("/metrics/trends")
def metrics_trends(
    days: int = Query(30, ge=1, le=3650),
    group_by: str = Query("team", pattern="^(team|environment|owner|criticality)$"),
    metric: str = Query("avg_score", pattern="^(avg_score|avg_findings|assets_with_findings)$"),
    top_groups: int = Query(5, ge=1, le=25),
):

    try:
        since_iso = _iso_days_ago(days)
        rows = list_scan_results_since(since_iso)

        # Bucket by day + group
        buckets = {}  # (day, group) -> accum
        for r in rows:
            scanned_at = str(r.get("scanned_at") or "")
            day = scanned_at[:10] if len(scanned_at) >= 10 else "unknown"
            g = (r.get(group_by) or "(unassigned)") if group_by in ("team","environment","owner","criticality") else "(unassigned)"

            key = (day, g)
            b = buckets.get(key)
            if not b:
                b = {"sum_score": 0.0, "sum_findings": 0, "count": 0, "assets_with_findings": 0}
                buckets[key] = b
            b["sum_score"] += float(r.get("quantum_score") or 0.0)
            fc = int(r.get("findings_count") or 0)
            b["sum_findings"] += fc
            b["count"] += 1
            if fc > 0:
                b["assets_with_findings"] += 1

        # Determine top groups by count across window
        group_totals = {}
        for (day, g), b in buckets.items():
            gt = group_totals.get(g)
            if not gt:
                gt = {"sum_score": 0.0, "sum_findings": 0, "count": 0, "assets_with_findings": 0}
                group_totals[g] = gt
            gt["sum_score"] += b["sum_score"]
            gt["sum_findings"] += b["sum_findings"]
            gt["count"] += b["count"]
            gt["assets_with_findings"] += b["assets_with_findings"]

        # Rank groups
        def _rank_val(gname: str) -> float:
            gt = group_totals.get(gname, {})
            if metric == "avg_findings":
                c = max(1, int(gt.get("count", 0)))
                return float(gt.get("sum_findings", 0)) / c
            if metric == "assets_with_findings":
                return float(gt.get("assets_with_findings", 0))
            c = max(1, int(gt.get("count", 0)))
            return float(gt.get("sum_score", 0.0)) / c

        top = sorted(group_totals.keys(), key=_rank_val, reverse=True)[: int(top_groups)]

        points = []
        for (day, g), b in buckets.items():
            if g not in top:
                continue
            if metric == "avg_findings":
                val = b["sum_findings"] / max(1, b["count"])
            elif metric == "assets_with_findings":
                val = b["assets_with_findings"]
            else:
                val = b["sum_score"] / max(1, b["count"])
            points.append({"day": day, "group": g, "value": val, "n": int(b.get("count") or 0), "assets_with_findings": int(b.get("assets_with_findings") or 0)})

        points.sort(key=lambda x: (x["day"], x["group"]))
        return {
            "since": since_iso,
            "days": days,
            "group_by": group_by,
            "metric": metric,
            "top_groups": top,
            "points": points,
        }
    except Exception as e:
        # Never 500 the UI: return empty points plus an error field for debugging
        return {
            "since": _iso_days_ago(days),
            "days": days,
            "group_by": group_by,
            "metric": metric,
            "top_groups": [],
            "points": [],
            "error": str(e),
        }





# -----------------------------
# Jobs (Celery)
# -----------------------------

@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    try:
        ar = celery_app.AsyncResult(job_id)
        meta = ar.info if isinstance(ar.info, dict) else {}
        return {
            "job_id": job_id,
            "state": ar.state,
            "meta": meta,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -----------------------------
# Sprint 8: Integrations (Webhooks)
# -----------------------------

class WebhookIn(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., min_length=1)
    url: str = Field(..., min_length=1)
    secret: str = ""
    events: List[str] = Field(default_factory=lambda: ["*"])
    enabled: bool = True


@app.post("/integrations/webhooks")
def api_upsert_webhook(body: WebhookIn):
    try:
        w = upsert_webhook(
            name=body.name,
            url=body.url,
            secret=body.secret,
            events=body.events,
            enabled=body.enabled,
            webhook_id=body.id,
        )
        return {"ok": True, "webhook": w}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/integrations/webhooks/{webhook_id}/test")
def api_test_webhook(webhook_id: int):
    try:
        return deliver_test_ping(int(webhook_id))
    except KeyError:
        raise HTTPException(status_code=404, detail="webhook not found")


@app.delete("/integrations/webhooks/{webhook_id}")
def api_delete_webhook(webhook_id: int):
    delete_webhook(webhook_id)
    return {"ok": True}


@app.get("/integrations/webhook-events")
def api_list_webhook_events(limit: int = 50):
    return {"items": list_webhook_events(limit=limit)}

@app.get("/integrations/webhooks")
def api_list_webhooks():
    return list_webhooks()



