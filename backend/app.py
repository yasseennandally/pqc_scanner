# app.py
from typing import List, Dict, Any
from datetime import datetime
import uuid
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import run_scan
from db import init_db, save_scan, load_scan, list_scans

from code_scanner import scan_zip_bytes
from migration import build_migration_plan_tls, build_migration_plan_code


# ---------- Pydantic models ----------
class ScanRequest(BaseModel):
    targets: List[str]


class ImportScanRequest(BaseModel):
    results: List[Dict[str, Any]]


class ScanStatus(BaseModel):
    id: str
    status: str
    created_at: datetime


class ScanWithResults(BaseModel):
    id: str
    status: str
    created_at: datetime
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


class ScanListItem(BaseModel):
    id: str
    status: str
    created_at: datetime
    summary: Dict[str, Any]


class CodeFinding(BaseModel):
    file: str
    line: int
    severity: str
    rule_name: str
    line_preview: str
    recommendation: str


class CodeScanResponse(BaseModel):
    count: int
    findings: List[CodeFinding]


# ---------- In-memory store (cache) ----------
SCANS: Dict[str, Dict[str, Any]] = {}


# ---------- Summary helper ----------
def build_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    high = 0
    medium = 0
    low = 0
    errors = 0
    expired = 0
    expiring_soon = 0
    rsa_count = 0

    risk_points = 0

    for r in results:
        risk = (r.get("risk") or "").lower()
        error = r.get("error") or ""

        if error:
            errors += 1

        if "expired" in risk:
            expired += 1
            high += 1
            risk_points += 10
        elif "expiring soon" in risk:
            expiring_soon += 1
            high += 1
            risk_points += 10
        elif risk.startswith("high"):
            high += 1
            risk_points += 10
        elif risk.startswith("medium"):
            medium += 1
            risk_points += 5
        elif risk.startswith("low"):
            low += 1
            risk_points += 2

        if (r.get("key_type") or "") == "RSA":
            rsa_count += 1
            risk_points += 3

    raw_score = 100 - risk_points
    raw_score = max(0, min(100, raw_score))

    if raw_score >= 80:
        quantum_level = "low"
    elif raw_score >= 50:
        quantum_level = "medium"
    else:
        quantum_level = "high"

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "errors": errors,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "rsa_count": rsa_count,
        "quantum_risk_score": raw_score,
        "quantum_risk_level": quantum_level,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


# ---------- FastAPI app ----------
app = FastAPI(
    title="PQC Scanner API",
    description="Scan TLS endpoints + code ZIPs for PQC readiness signals and generate summaries/migration plans.",
    version="1.0.0",
)

# CORS first
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later when hosted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Config ----------
API_KEY = os.getenv("PQC_API_KEY", "").strip()

PROTECTED_PREFIXES = (
    "/scan",
    "/scans",
    "/code-scan",
)

# Rate limiting (demo-safe)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 60
_requests_by_ip = defaultdict(deque)

# Target limits
MAX_TARGETS = 200
MAX_TARGET_LEN = 255


def _validate_targets(targets: List[str]):
    if len(targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets. Max is {MAX_TARGETS}.")
    for t in targets:
        if len(t) > MAX_TARGET_LEN:
            raise HTTPException(status_code=400, detail="Target too long.")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # ✅ allow CORS preflight
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path

    # 1) API key check
    if API_KEY:
        if path == "/health":
            pass
        else:
            if path in ("/docs", "/openapi.json", "/redoc"):
                provided = request.headers.get("x-api-key", "")
                if provided != API_KEY:
                    return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
            elif any(path == p or path.startswith(p + "/") for p in PROTECTED_PREFIXES):
                provided = request.headers.get("x-api-key", "")
                if provided != API_KEY:
                    return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    # 2) Rate limit
    ip = request.client.host if request.client else "unknown"
    now = time.time()

    q = _requests_by_ip[ip]
    while q and (now - q[0]) > RATE_LIMIT_WINDOW_SECONDS:
        q.popleft()

    if len(q) >= RATE_LIMIT_MAX_REQUESTS:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please slow down."})

    q.append(now)
    return await call_next(request)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health_check():
    return {"status": "ok"}


# ---------- Helpers ----------
def _get_scan_from_store(scan_id: str) -> Dict[str, Any]:
    scan = SCANS.get(scan_id)
    if scan:
        return scan

    scan = load_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    SCANS[scan_id] = scan
    return scan


# ---------- TLS legacy endpoint ----------
@app.post("/scan")
def scan_endpoints(request: ScanRequest):
    _validate_targets(request.targets)
    results = run_scan(request.targets)
    return {"count": len(results), "results": results}


# ---------- TLS scans with IDs ----------
@app.post("/scans", response_model=ScanStatus)
def create_scan(request: ScanRequest):
    _validate_targets(request.targets)

    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    status = "completed"

    results = run_scan(request.targets)
    summary = build_summary(results)

    SCANS[scan_id] = {
        "id": scan_id,
        "status": status,
        "created_at": created_at,
        "results": results,
        "summary": summary,
    }

    save_scan(scan_id, status, created_at, results, summary)
    return ScanStatus(id=scan_id, status=status, created_at=created_at)


@app.post("/scans/import", response_model=ScanStatus)
def import_scan(payload: ImportScanRequest):
    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    status = "completed"

    results = payload.results
    summary = build_summary(results)

    SCANS[scan_id] = {
        "id": scan_id,
        "status": status,
        "created_at": created_at,
        "results": results,
        "summary": summary,
    }

    save_scan(scan_id, status, created_at, results, summary)
    return ScanStatus(id=scan_id, status=status, created_at=created_at)


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    scan = _get_scan_from_store(scan_id)
    return ScanStatus(id=scan["id"], status=scan["status"], created_at=scan["created_at"])


@app.get("/scans/{scan_id}/results", response_model=ScanWithResults)
def get_scan_results(scan_id: str):
    scan = _get_scan_from_store(scan_id)
    return ScanWithResults(
        id=scan["id"],
        status=scan["status"],
        created_at=scan["created_at"],
        results=scan["results"],
        summary=scan["summary"],
    )


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


# ✅ THIS IS THE MISSING PIECE: TLS migration plan for a scan ID
@app.get("/scans/{scan_id}/migration-plan")
def tls_migration_plan(scan_id: str):
    scan = _get_scan_from_store(scan_id)
    results = scan.get("results", [])
    return build_migration_plan_tls(results)


# ---------- Code scanning ----------
@app.post("/code-scan", response_model=CodeScanResponse)
async def code_scan(archive: UploadFile = File(...)):
    name = (archive.filename or "").lower()
    if not name.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip file")

    data = await archive.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload")

    findings = scan_zip_bytes(data)
    return {"count": len(findings), "findings": findings}


@app.post("/code-scan/migration-plan")
async def code_migration_plan(archive: UploadFile = File(...)):
    name = (archive.filename or "").lower()
    if not name.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip file")

    data = await archive.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload")

    findings = scan_zip_bytes(data)
    return build_migration_plan_code(findings)
