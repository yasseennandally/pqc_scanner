from __future__ import annotations

import os
import uuid
import json
import time
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, List

from urllib import request as _urlrequest
from urllib.error import URLError, HTTPError

import concurrent.futures
from celery import Celery

from scanner import scan_host, parse_target
from policy import summarize_results
from db import (
    save_scan_row,
    update_scan_progress,
    save_scan_results,
    update_scan_job,
    due_schedules,
    get_collection,
    mark_schedule_ran,
    save_scan_asset_summaries,

    # Sprint 8 actions
    get_asset,
    get_baseline,
    get_scan_result_for_asset,
    get_enabled_webhooks_for_event,
    reserve_webhook_event,
    mark_webhook_event_delivered,
)

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

celery_app = Celery("pqc_scanner", broker=BROKER_URL, backend=RESULT_BACKEND)

celery_app.conf.update(
    task_track_started=True,
    worker_send_task_events=True,
    task_send_sent_event=True,
    result_extended=True,
    task_time_limit=int(os.environ.get("TASK_TIME_LIMIT", "900")),       # hard kill (seconds)
    task_soft_time_limit=int(os.environ.get("TASK_SOFT_TIME_LIMIT", "840")),
)

PER_TARGET_TIMEOUT = int(os.environ.get("PER_TARGET_TIMEOUT", "20"))  # seconds per target


def _iso_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _progress(total: int, done: int) -> Dict[str, Any]:
    total = max(1, int(total))
    done = max(0, min(int(done), total))
    pct = int((done / total) * 100)
    return {"total": total, "done": done, "percent": pct}


def scan_target_with_timeout(target: str) -> Dict[str, Any]:
    host, port = parse_target(target)

    # Run the potentially-blocking TLS probe in a separate thread with a timeout.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(scan_host, host, port)
        try:
            return fut.result(timeout=PER_TARGET_TIMEOUT)
        except concurrent.futures.TimeoutError:
            return {
                "target": f"{host}:{port}",
                "host": host,
                "port": port,
                "status": "error",
                "error": f"Scan timed out after {PER_TARGET_TIMEOUT}s",
                "findings": [{
                    "rule_id": "SCAN_TIMEOUT",
                    "title": "Scan timed out",
                    "severity": "medium",
                    "confidence": "high",
                    "reason": f"Target did not complete TLS probe within {PER_TARGET_TIMEOUT}s.",
                    "fix": "Check connectivity/firewall, or increase PER_TARGET_TIMEOUT.",
                    "evidence": {"timeout_seconds": PER_TARGET_TIMEOUT},
                }],
            }


# -----------------------------
# Sprint 8: Webhook actions (integration over export)
# -----------------------------

def _json_bytes(payload: dict) -> bytes:
    # Compact JSON for stable hashing/signing
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hmac_sig(secret: str, ts: str, body: bytes) -> str:
    # Signature base: "<ts>.<body>"
    msg = ts.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _post_json(url: str, body: bytes, headers: dict) -> tuple[bool, int | None, str]:
    req = _urlrequest.Request(url, data=body, method="POST")
    for k, v in (headers or {}).items():
        req.add_header(k, str(v))
    try:
        with _urlrequest.urlopen(req, timeout=10) as resp:
            code = getattr(resp, "status", None)
            return True, int(code) if code is not None else 200, ""
    except HTTPError as e:
        try:
            code = int(getattr(e, "code", 0)) or None
        except Exception:
            code = None
        return False, code, f"HTTPError: {e}"
    except URLError as e:
        return False, None, f"URLError: {e}"
    except Exception as e:
        return False, None, str(e)


def _deliver_webhook_event(event_type: str, scan_id: str, asset_key: str, dedupe_key: str, payload: dict) -> None:
    hooks = get_enabled_webhooks_for_event(event_type)
    if not hooks:
        return

    ts = _iso_now()
    body = _json_bytes(payload)
    payload_sha = hashlib.sha256(body).hexdigest()

    for wh in hooks:
        wh_id = int(wh["id"])
        ev_id = reserve_webhook_event(
            webhook_id=wh_id,
            event_type=event_type,
            scan_id=scan_id,
            asset_key=asset_key,
            dedupe_key=dedupe_key,
            payload_sha256=payload_sha,
        )
        if ev_id is None:
            # Deduped for this webhook
            continue

        sig = _hmac_sig(str(wh["secret"]), ts, body)
        ok, code, err = _post_json(
            str(wh["url"]),
            body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "pqc-migration-tool/1.0",
                "X-PQC-Event": event_type,
                "X-PQC-Timestamp": ts,
                "X-PQC-Signature": sig,
            },
        )
        mark_webhook_event_delivered(ev_id, ok=ok, status_code=code, error_text=err)


def _worst_severity(findings: list[dict]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = "info"
    w = 0
    for f in findings or []:
        sev = str(f.get("severity") or "").lower()
        r = order.get(sev, 0)
        if r > w:
            w = r
            worst = sev
    return worst


def _fire_events_for_scan(scan_id: str, targets: list[str], results: list[dict], summary: dict) -> None:
    # scan.completed
    _deliver_webhook_event(
        event_type="scan.completed",
        scan_id=scan_id,
        asset_key="",
        dedupe_key=f"scan.completed:{scan_id}",
        payload={
            "event_type": "scan.completed",
            "scan_id": scan_id,
            "completed_at": _iso_now(),
            "targets_count": len(targets or []),
            "summary": summary or {},
        },
    )

    # Asset-level events
    for r in results or []:
        host = str(r.get("host") or "")
        port = int(r.get("port") or 443)
        ak = f"{host}:{port}"
        asset = get_asset(ak) or {}
        findings = r.get("findings") or []
        rule_ids = {str(f.get("rule_id") or "") for f in findings if isinstance(f, dict)}
        not_after = str(r.get("not_after") or "")
        days_until_expiry = r.get("days_until_expiry")

        # Expiry signals
        if "CERT_EXPIRED" in rule_ids:
            dedupe = f"cert.expired:{ak}:{not_after}"
            _deliver_webhook_event(
                "cert.expired",
                scan_id,
                ak,
                dedupe,
                payload={
                    "event_type": "cert.expired",
                    "scan_id": scan_id,
                    "asset_key": ak,
                    "host": host,
                    "port": port,
                    "asset": asset,
                    "not_after": not_after,
                    "days_until_expiry": days_until_expiry,
                    "evidence": {"worst_severity": _worst_severity(findings)},
                },
            )
        elif "CERT_EXPIRING_SOON" in rule_ids:
            dedupe = f"cert.expiring_soon:{ak}:{not_after}"
            _deliver_webhook_event(
                "cert.expiring_soon",
                scan_id,
                ak,
                dedupe,
                payload={
                    "event_type": "cert.expiring_soon",
                    "scan_id": scan_id,
                    "asset_key": ak,
                    "host": host,
                    "port": port,
                    "asset": asset,
                    "not_after": not_after,
                    "days_until_expiry": days_until_expiry,
                    "evidence": {"worst_severity": _worst_severity(findings)},
                },
            )

        # Baseline regression (if configured)
        b = get_baseline(ak)
        base_id = (b or {}).get("baseline_scan_id") if isinstance(b, dict) else None
        if base_id:
            base_row = get_scan_result_for_asset(str(base_id), ak)
            if base_row:
                cur_q = float(r.get("quantum_risk_score") or r.get("quantum_score") or 0.0)
                cur_fc = len(findings) if isinstance(findings, list) else 0
                base_q = float(base_row.get("quantum_score") or 0.0)
                base_fc = int(base_row.get("findings_count") or 0)
                regressed = (cur_q > base_q + 0.01) or (cur_fc > base_fc)

                if regressed:
                    state = {
                        "baseline_scan_id": str(base_id),
                        "baseline_quantum_score": round(base_q, 3),
                        "baseline_findings_count": base_fc,
                        "current_quantum_score": round(cur_q, 3),
                        "current_findings_count": cur_fc,
                        "worst_severity": _worst_severity(findings),
                    }
                    state_hash = hashlib.sha256(_json_bytes(state)).hexdigest()[:16]
                    dedupe = f"asset.regressed:{ak}:{base_id}:{state_hash}"
                    _deliver_webhook_event(
                        "asset.regressed",
                        scan_id,
                        ak,
                        dedupe,
                        payload={
                            "event_type": "asset.regressed",
                            "scan_id": scan_id,
                            "asset_key": ak,
                            "host": host,
                            "port": port,
                            "asset": asset,
                            "baseline_scan_id": str(base_id),
                            "baseline": {"quantum_score": base_q, "findings_count": base_fc},
                            "current": {"quantum_score": cur_q, "findings_count": cur_fc},
                            "evidence": state,
                        },
                    )


@celery_app.task(bind=True, name="run_scan_task")
def run_scan_task(self, scan_id: str, targets: List[str]) -> Dict[str, Any]:
    """
    Execute a scan in a Celery worker.
    Persists progress/results to SQLite so the UI can poll /scans/{id}.
    """
    job_id = self.request.id
    update_scan_job(scan_id, job_id=job_id, job_state="STARTED", started_at_iso=_iso_now())

    total = len(targets)
    results: List[Dict[str, Any]] = []
    try:
        prog = _progress(total, 0)
        update_scan_progress(scan_id, status="running", progress=prog, error_text="")
        self.update_state(state="PROGRESS", meta=prog)

        for i, t in enumerate(targets, start=1):
            # Log to worker output so you can see progress in docker logs
            print(f"[run_scan_task] scanning {i}/{total}: {t}", flush=True)

            results.append(scan_target_with_timeout(t))

            prog = _progress(total, i)

            # Persist frequently for good UX
            if i == total or i % 2 == 0:
                summary = summarize_results(results)
                save_scan_results(scan_id, status="running" if i < total else "done", results=results, summary=summary)
                update_scan_progress(scan_id, status="running" if i < total else "done", progress=prog, error_text="")

            self.update_state(state="PROGRESS", meta=prog)

        summary = summarize_results(results)
        save_scan_results(scan_id, status="done", results=results, summary=summary)
        update_scan_progress(scan_id, status="done", progress=_progress(total, total), error_text="")
        update_scan_job(scan_id, job_state="SUCCESS", finished_at_iso=_iso_now())
        # Sprint 5: persist per-asset summaries for history
        try:
            save_scan_asset_summaries(scan_id, _iso_now(), results)
        except Exception as _e:
            print(f"[run_scan_task] save_scan_asset_summaries failed: {_e}", flush=True)
        # Sprint 8: fire webhook events (best-effort; delivery is logged + deduped)
        try:
            _fire_events_for_scan(scan_id, targets, results, summary)
        except Exception as _e:
            print(f"[run_scan_task] webhook actions failed: {_e}", flush=True)

        print(f"[run_scan_task] finished scan_id={scan_id} targets={total}", flush=True)
        return {"scan_id": scan_id, "count": len(results), "job_id": job_id}

    except Exception as e:
        msg = str(e)
        prog = _progress(total, len(results))
        update_scan_progress(scan_id, status="failed", progress=prog, error_text=msg)
        save_scan_results(scan_id, status="failed", results=results, summary=summarize_results(results) if results else {})
        update_scan_job(scan_id, job_state="FAILURE", finished_at_iso=_iso_now())
        print(f"[run_scan_task] FAILED scan_id={scan_id}: {msg}", flush=True)
        raise


@celery_app.task(name="enqueue_due_schedules")
def enqueue_due_schedules() -> Dict[str, Any]:
    """
    Beat-triggered task. Checks due schedules and enqueues scan tasks.
    """
    now_iso = _iso_now()
    due = due_schedules(now_iso)
    enqueued = 0

    for s in due:
        try:
            coll = get_collection(int(s["collection_id"]))
            if not coll or not coll.get("targets_text"):
                continue

            targets = [ln.strip() for ln in coll["targets_text"].splitlines() if ln.strip()]
            if not targets:
                continue

            scan_id = str(uuid.uuid4())
            prog = _progress(len(targets), 0)
            save_scan_row(
                scan_id=scan_id,
                status="queued",
                created_at=datetime.utcnow(),
                progress=prog,
                error_text="",
                results=[],
                summary={},
            )

            res = run_scan_task.delay(scan_id, targets)
            update_scan_job(scan_id, job_id=res.id, job_state="PENDING")
            mark_schedule_ran(int(s["id"]), now_iso, int(s["interval_minutes"]), scan_id)
            enqueued += 1

            print(f"[enqueue_due_schedules] enqueued scan_id={scan_id} job_id={res.id} collection_id={s['collection_id']}", flush=True)

        except Exception as e:
            print(f"[enqueue_due_schedules] error: {e}", flush=True)
            continue

    return {"checked": len(due), "enqueued": enqueued, "now": now_iso}


# Celery Beat schedule: run every 60 seconds
celery_app.conf.beat_schedule = {
    "enqueue-due-schedules-every-60s": {
        "task": "enqueue_due_schedules",
        "schedule": 60.0,
    }
}
