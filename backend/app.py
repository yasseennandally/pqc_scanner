# app.py
from __future__ import annotations

import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from threading import Thread
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from scanner import scan_host
from db import init_db, save_scan, load_scan, list_scans
from migration import build_migration_plan_tls


# ---------- Models ----------

class ScanRequest(BaseModel):
    targets: List[str]


class ScanStatus(BaseModel):
    id: str
    status: str
    created_at: datetime
    progress: Dict[str, Any] = {}
    error: str = ""


class ScanWithResults(BaseModel):
    id: str
    status: str
    created_at: datetime
    progress: Dict[str, Any] = {}
    error: str = ""
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


class ScanListItem(BaseModel):
    id: str
    status: str
    created_at: datetime
    summary: Dict[str, Any]


# ---------- App ----------

app = FastAPI(
    title="PQC Scanner API",
    version="1.0.0",
)

# CORS (demo)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- API key middleware ----------

API_KEY = os.getenv("PQC_API_KEY", "").strip()
PROTECTED_PREFIXES = ("/scan", "/scans",)

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    # If not configured, allow all (dev convenience)
    if not API_KEY:
        return await call_next(request)

    path = request.url.path
    if path in ("/health",):
        return await call_next(request)

    if any(path == p or path.startswith(p + "/") for p in PROTECTED_PREFIXES):
        provided = request.headers.get("x-api-key", "")
        if provided != API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)

# ---------- Rate limiting middleware ----------

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 120  # per IP / minute
_requests_by_ip = defaultdict(deque)

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


# ---------- In-memory scans cache (for progress) ----------

SCANS: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health_check():
    return {"status": "ok"}


# ---------- Summary ----------

def build_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results or [])
    high = medium = low = critical = 0
    rsa_count = 0
    errors = 0

    risk_points = 0

    for r in results or []:
        if r.get("error"):
            errors += 1

        risk_level = (r.get("risk_level") or "low").lower()
        if risk_level == "critical":
            critical += 1
            risk_points += 12
        elif risk_level == "high":
            high += 1
            risk_points += 10
        elif risk_level == "medium":
            medium += 1
            risk_points += 5
        else:
            low += 1
            risk_points += 2

        if (r.get("key_type") or "").upper() == "RSA":
            rsa_count += 1
            risk_points += 3

    raw_score = max(0, min(100, 100 - risk_points))
    if raw_score >= 80:
        qlvl = "low"
    elif raw_score >= 50:
        qlvl = "medium"
    else:
        qlvl = "high"

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "errors": errors,
        "rsa_count": rsa_count,
        "quantum_risk_score": raw_score,
        "quantum_risk_level": qlvl,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
    }


# ---------- Background worker ----------

def _scan_worker(scan_id: str, targets: List[str]) -> None:
    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["error"] = ""

    results: List[Dict[str, Any]] = []
    total = len(targets)
    done = 0

    for t in targets:
        try:
            host, port = _parse_target_safe(t)
            results.append(scan_host(host, port))
        except Exception as e:
            results.append({"host": t, "port": None, "error": str(e), "findings": []})

        done += 1
        scan["progress"] = {"total": total, "done": done, "percent": int(done * 100 / max(1, total))}

    scan["results"] = results
    scan["summary"] = build_summary(results)
    scan["status"] = "completed"

    save_scan(scan_id, scan["status"], scan["created_at"], scan["results"], scan["summary"])


def _parse_target_safe(target: str):
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        h, p = t.rsplit(":", 1)
        return h.strip(), int(p.strip())
    return t, 443


# ---------- API endpoints ----------

@app.post("/scan")
def legacy_scan(req: ScanRequest):
    # simple, synchronous
    out = []
    for t in req.targets:
        host, port = _parse_target_safe(t)
        out.append(scan_host(host, port))
    return {"count": len(out), "results": out}


@app.post("/scans", response_model=ScanStatus)
def create_scan(req: ScanRequest):
    MAX_TARGETS = 200
    if len(req.targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets. Max is {MAX_TARGETS}.")
    for t in req.targets:
        if len(t) > 255:
            raise HTTPException(status_code=400, detail="Target too long.")

    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()

    SCANS[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "created_at": created_at,
        "progress": {"total": len(req.targets), "done": 0, "percent": 0},
        "error": "",
        "results": [],
        "summary": {},
    }

    # persist initial row (empty results/summary ok for history)
    save_scan(scan_id, "queued", created_at, [], {"total": 0})

    th = Thread(target=_scan_worker, args=(scan_id, req.targets), daemon=True)
    th.start()

    return ScanStatus(id=scan_id, status="queued", created_at=created_at, progress=SCANS[scan_id]["progress"], error="")


def _get_scan(scan_id: str) -> Dict[str, Any]:
    if scan_id in SCANS:
        return SCANS[scan_id]
    row = load_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    # DB rows do not store progress (demo); mark completed
    row["progress"] = {"total": len(row.get("results", [])), "done": len(row.get("results", [])), "percent": 100}
    row["error"] = ""
    SCANS[scan_id] = row
    return row


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    s = _get_scan(scan_id)
    return ScanStatus(
        id=s["id"],
        status=s["status"],
        created_at=s["created_at"],
        progress=s.get("progress") or {},
        error=s.get("error") or "",
    )


@app.get("/scans/{scan_id}/results", response_model=ScanWithResults)
def get_scan_results(scan_id: str):
    s = _get_scan(scan_id)
    return ScanWithResults(
        id=s["id"],
        status=s["status"],
        created_at=s["created_at"],
        progress=s.get("progress") or {},
        error=s.get("error") or "",
        results=s.get("results") or [],
        summary=s.get("summary") or {},
    )


@app.get("/scans/{scan_id}/migration-plan")
def get_tls_migration_plan(scan_id: str):
    s = _get_scan(scan_id)
    return build_migration_plan_tls(s.get("results") or [])


@app.get("/scans", response_model=List[ScanListItem])
def list_scans_endpoint(limit: int = 20):
    rows = list_scans(limit=limit)
    return [
        ScanListItem(
            id=row["id"],
            status=row["status"],
            created_at=row["created_at"],
            summary=row["summary"],
        )
        for row in rows
    ]
