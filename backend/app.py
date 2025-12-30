from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scanner import scan_host, parse_target
from migration import build_tls_migration_plan

import db


# -----------------------------
# Helpers
# -----------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _asset_key(host: str, port: int) -> str:
    return f"{host}:{int(port)}"


def _finding_id(f: Dict[str, Any]) -> Optional[str]:
    # Supports both styles
    return f.get("id") or f.get("rule_id") or f.get("rid")


def _result_risk_score(r: Dict[str, Any]) -> float:
    v = r.get("risk_score")
    try:
        return float(v)
    except Exception:
        return 0.0


def _scan_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "targets": len(results or []),
        "risk_counts": {},
        "pqc_counts": {},
        "expired": 0,
        "expiring_soon": 0,
    }
    risk_counts: Dict[str, int] = {}
    pqc_counts: Dict[str, int] = {}
    for r in results or []:
        risk = (r.get("risk") or r.get("risk_level") or "unknown").lower()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        pqc = (r.get("pqc_relevance") or "unknown").lower()
        pqc_counts[pqc] = pqc_counts.get(pqc, 0) + 1
        if r.get("days_until_expiry") is not None:
            try:
                d = int(r.get("days_until_expiry"))
                if d < 0:
                    out["expired"] += 1
                elif d <= 30:
                    out["expiring_soon"] += 1
            except Exception:
                pass
    out["risk_counts"] = risk_counts
    out["pqc_counts"] = pqc_counts
    return out


def _enrich_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for r in results or []:
        host = r.get("host")
        port = r.get("port")
        if host and port:
            ak = _asset_key(host, port)
            asset = db.get_asset(ak)
            if asset:
                # Add asset fields in a non-breaking way
                r = dict(r)
                r["asset_key"] = ak
                r["asset_owner"] = asset.get("owner", "")
                r["asset_team"] = asset.get("team", "")
                r["asset_environment"] = asset.get("environment", "")
                r["asset_criticality"] = asset.get("criticality", "")
                r["asset_confidentiality_lifetime"] = asset.get("confidentiality_lifetime", "")
                r["asset_tags"] = asset.get("tags", []) or []
                r["baseline"] = asset.get("baseline")
        enriched.append(r)
    return enriched


# -----------------------------
# API models
# -----------------------------
class ScanCreate(BaseModel):
    targets: List[str] = Field(..., min_length=1)


class ScanProgress(BaseModel):
    total: int = 0
    done: int = 0
    percent: int = 0


class ScanStatus(BaseModel):
    id: str
    status: str
    created_at: str
    progress: ScanProgress
    error: str = ""


class ScanResultsResponse(ScanStatus):
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


class BaselineSetOne(BaseModel):
    asset_key: str
    baseline_scan_id: str


class AssetUpsert(BaseModel):
    owner: Optional[str] = ""
    team: Optional[str] = ""
    environment: Optional[str] = ""
    criticality: Optional[str] = ""
    confidentiality_lifetime: Optional[str] = ""
    notes: Optional[str] = ""
    tags: Optional[List[str]] = None


# -----------------------------
# App
# -----------------------------
app = FastAPI(title="Quantum PQC Scanner", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev-friendly; tighten later
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()

# Track running scan threads so the process doesn't start duplicates
_RUNNING: Set[str] = set()
_LOCK = threading.Lock()


@app.get("/health")
def health():
    return {"ok": True, "ts": _now_iso()}


# -----------------------------
# Scans
# -----------------------------
def _scan_worker(scan_id: str, targets: List[str]) -> None:
    created_at = datetime.now(timezone.utc)
    total = len(targets)
    progress: Dict[str, Any] = {"total": total, "done": 0, "percent": 0}
    results: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {}
    error_text = ""

    # Mark running
    db.upsert_scan(
        scan_id=scan_id,
        status="running",
        created_at=created_at,
        progress=progress,
        error_text="",
        results=results,
        summary=summary,
    )

    for t in targets:
        try:
            host, port = parse_target(t)
            ak = _asset_key(host, port)

            # Ensure asset exists without overwriting existing metadata
            if not db.get_asset(ak):
                db.upsert_asset(asset_key=ak, host=host, port=port)

            r = scan_host(host, port)
            # Normalize host/port presence
            r.setdefault("host", host)
            r.setdefault("port", port)
            results.append(r)
        except Exception as e:
            # record an "error result" for this target so UI can show it
            try:
                host, port = parse_target(t)
            except Exception:
                host, port = (t, 443)
            results.append(
                {
                    "host": host,
                    "port": port,
                    "error": str(e),
                    "findings": [
                        {
                            "id": "SCAN_ERROR",
                            "title": "Scan failed for target",
                            "severity": "high",
                            "remediation": "Check connectivity/DNS and try again.",
                            "confidence": "high",
                            "confidence_reason": "Scanner exception",
                            "evidence": {"exception": str(e), "target": t},
                        }
                    ],
                    "risk": "high",
                    "risk_score": 80,
                    "pqc_relevance": "unknown",
                    "pqc_recommendation": "Investigate scanner error; ensure TLS endpoint reachable.",
                }
            )

        # Update progress + persist
        progress["done"] += 1
        progress["percent"] = int(round((progress["done"] / max(1, total)) * 100))
        summary = _scan_summary(results)

        db.upsert_scan(
            scan_id=scan_id,
            status="running",
            created_at=created_at,
            progress=progress,
            error_text="",
            results=results,
            summary=summary,
        )

    # Completed
    db.upsert_scan(
        scan_id=scan_id,
        status="completed",
        created_at=created_at,
        progress=progress,
        error_text=error_text,
        results=results,
        summary=_scan_summary(results),
    )
    with _LOCK:
        _RUNNING.discard(scan_id)


@app.post("/scans", response_model=ScanStatus)
def create_scan(req: ScanCreate):
    scan_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    targets = [t.strip() for t in (req.targets or []) if t and t.strip()]
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    progress = {"total": len(targets), "done": 0, "percent": 0}
    db.upsert_scan(
        scan_id=scan_id,
        status="starting",
        created_at=created_at,
        progress=progress,
        error_text="",
        results=[],
        summary={},
    )

    th = threading.Thread(target=_scan_worker, args=(scan_id, targets), daemon=True)
    with _LOCK:
        _RUNNING.add(scan_id)
    th.start()

    return ScanStatus(
        id=scan_id,
        status="starting",
        created_at=created_at.isoformat(),
        progress=ScanProgress(**progress),
        error="",
    )


@app.get("/scans", response_model=List[ScanStatus])
def get_scans(limit: int = Query(50, ge=1, le=500)):
    scans = db.list_scans(limit=limit)
    out: List[ScanStatus] = []
    for s in scans:
        prog = s.get("progress") or {}
        out.append(
            ScanStatus(
                id=s["id"],
                status=s["status"],
                created_at=s["created_at"],
                progress=ScanProgress(**{"total": prog.get("total", 0), "done": prog.get("done", 0), "percent": prog.get("percent", 0)}),
                error=s.get("error") or "",
            )
        )
    return out


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    prog = s.get("progress") or {}
    return ScanStatus(
        id=s["id"],
        status=s["status"],
        created_at=s["created_at"],
        progress=ScanProgress(**{"total": prog.get("total", 0), "done": prog.get("done", 0), "percent": prog.get("percent", 0)}),
        error=s.get("error") or "",
    )


@app.get("/scans/{scan_id}/results", response_model=ScanResultsResponse)
def get_scan_results(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    prog = s.get("progress") or {}
    results = _enrich_results(s.get("results") or [])
    summary = s.get("summary") or _scan_summary(results)
    return ScanResultsResponse(
        id=s["id"],
        status=s["status"],
        created_at=s["created_at"],
        progress=ScanProgress(**{"total": prog.get("total", 0), "done": prog.get("done", 0), "percent": prog.get("percent", 0)}),
        error=s.get("error") or "",
        results=results,
        summary=summary,
    )


@app.get("/scans/{scan_id}/migration-plan")
def get_migration_plan(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = s.get("results") or []
    plan = build_tls_migration_plan(results)
    return {"scan_id": scan_id, "generated_at": _now_iso(), "plan": plan}


# -----------------------------
# Baselines (Sprint 2)
# -----------------------------
@app.post("/baselines/from-scan/{scan_id}")
def set_baseline_from_scan(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    n = db.set_baselines_from_scan(scan_id)
    return {"ok": True, "scan_id": scan_id, "baselines_set": n, "set_at": _now_iso()}


@app.get("/baselines")
def get_baselines(limit: int = Query(1000, ge=1, le=5000)):
    return {"items": db.list_baselines(limit=limit)}


@app.post("/baselines")
def set_baseline_one(req: BaselineSetOne):
    if not db.get_scan(req.baseline_scan_id):
        raise HTTPException(status_code=404, detail="baseline_scan_id not found")
    db.set_baseline(req.asset_key, req.baseline_scan_id)
    return {"ok": True, "asset_key": req.asset_key, "baseline_scan_id": req.baseline_scan_id, "set_at": _now_iso()}


@app.get("/scans/{scan_id}/diff")
def scan_diff(scan_id: str, baseline_scan_id: Optional[str] = None):
    current = db.get_scan(scan_id)
    if not current:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_results = current.get("results") or []
    baseline_scan = None
    if baseline_scan_id:
        baseline_scan = db.get_scan(baseline_scan_id)
        if not baseline_scan:
            raise HTTPException(status_code=404, detail="baseline_scan_id not found")

    # Preload baseline results per scan_id if using per-asset baselines
    baseline_cache: Dict[str, List[Dict[str, Any]]] = {}
    out: List[Dict[str, Any]] = []

    for r in current_results:
        host = r.get("host")
        port = r.get("port")
        if not host or not port:
            continue
        ak = _asset_key(host, port)

        # Determine baseline scan for this asset
        b_scan_id = baseline_scan_id
        if not b_scan_id:
            b = db.get_baseline(ak)
            b_scan_id = b.get("baseline_scan_id") if b else None

        if not b_scan_id:
            out.append({"asset_key": ak, "no_baseline": True, "current_scan_id": scan_id})
            continue

        if baseline_scan_id:
            b_results = baseline_scan.get("results") or []
        else:
            if b_scan_id not in baseline_cache:
                b_scan = db.get_scan(b_scan_id)
                baseline_cache[b_scan_id] = (b_scan.get("results") if b_scan else []) or []
            b_results = baseline_cache[b_scan_id]

        # Find matching baseline result for the same asset key
        b_r = None
        for br in b_results:
            if br.get("host") == host and int(br.get("port") or 0) == int(port):
                b_r = br
                break

        if not b_r:
            out.append({"asset_key": ak, "baseline_scan_id": b_scan_id, "no_baseline": True, "current_scan_id": scan_id})
            continue

        cur_findings = {_finding_id(f) for f in (r.get("findings") or []) if _finding_id(f)}
        base_findings = {_finding_id(f) for f in (b_r.get("findings") or []) if _finding_id(f)}

        new_findings = sorted(cur_findings - base_findings)
        resolved_findings = sorted(base_findings - cur_findings)
        unchanged_findings = sorted(cur_findings & base_findings)

        delta = _result_risk_score(r) - _result_risk_score(b_r)

        out.append(
            {
                "asset_key": ak,
                "baseline_scan_id": b_scan_id,
                "current_scan_id": scan_id,
                "new_findings": new_findings,
                "resolved_findings": resolved_findings,
                "unchanged_findings": unchanged_findings,
                "score_delta": delta,
            }
        )

    return {"generated_at": _now_iso(), "assets": out}


# -----------------------------
# Assets (Sprint 3)
# -----------------------------
@app.get("/assets")
def list_assets(
    limit: int = Query(200, ge=1, le=2000),
    owner: Optional[str] = None,
    team: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tag: Optional[str] = None,
):
    items = db.list_assets(limit=limit, owner=owner, team=team, environment=environment, criticality=criticality, tag=tag)
    return {"items": items}


@app.get("/assets/{asset_key}")
def get_asset(asset_key: str):
    a = db.get_asset(asset_key)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    return a


@app.put("/assets/{asset_key}")
def update_asset(asset_key: str, req: AssetUpsert):
    # Ensure it exists
    a = db.get_asset(asset_key)
    if not a:
        # attempt parse
        if ":" in asset_key:
            host, port_s = asset_key.rsplit(":", 1)
            try:
                port = int(port_s)
            except Exception:
                port = 443
        else:
            host, port = asset_key, 443
        db.upsert_asset(asset_key=asset_key, host=host, port=port)
        a = db.get_asset(asset_key) or {}

    # Merge: use provided fields; if None, keep existing
    def pick(name: str) -> str:
        v = getattr(req, name)
        if v is None:
            return a.get(name, "") or ""
        return v or ""

    db.upsert_asset(
        asset_key=asset_key,
        host=a.get("host") or asset_key.split(":")[0],
        port=int(a.get("port") or 443),
        owner=pick("owner"),
        team=pick("team"),
        environment=pick("environment"),
        criticality=pick("criticality"),
        confidentiality_lifetime=pick("confidentiality_lifetime"),
        notes=pick("notes"),
    )
    if req.tags is not None:
        db.set_asset_tags(asset_key, req.tags)

    return {"ok": True, "asset": db.get_asset(asset_key)}


@app.get("/tags")
def list_tags(limit: int = Query(500, ge=1, le=5000)):
    return {"items": db.list_tags(limit=limit)}
