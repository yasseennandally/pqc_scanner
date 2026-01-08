from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any, Dict, List

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
