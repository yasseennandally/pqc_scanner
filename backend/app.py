from __future__ import annotations

import os
import time
import uuid
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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
    upsert_asset,
    get_asset,
    list_assets,
    list_tags,
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
    if not a:
        raise HTTPException(status_code=404, detail="asset not found")
    return a


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
