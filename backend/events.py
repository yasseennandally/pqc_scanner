from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List
from urllib import request, error as urlerror

from db import (
    load_scan_row,
    list_webhooks,
    record_webhook_event,
    bump_webhook_attempt,
    update_webhook_event,
    get_baseline,
    list_pending_webhook_events,
)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def _hmac_sig(secret: str, body: bytes) -> str:
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

def _extract_rule_ids(result: dict) -> List[str]:
    out: List[str] = []
    for f in (result.get("findings") or []):
        rid = (f or {}).get("rule_id")
        if rid:
            out.append(str(rid))
    return out

def build_events_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    scan = load_scan_row(scan_id)
    if not scan:
        return []

    results = scan.get("results") or []
    summary = scan.get("summary") or {}
    status = scan.get("status") or ""

    events: List[Dict[str, Any]] = []

    events.append({
        "event_type": "scan.completed",
        "dedupe_key": _sha256_hex(f"scan.completed:{scan_id}"),
        "payload": {"scan_id": scan_id, "status": status, "summary": summary},
    })

    for r in results:
        host = str(r.get("host") or "")
        port = int(r.get("port") or 443)
        ak = f"{host}:{port}"
        rule_ids = set(_extract_rule_ids(r))
        facts = r.get("facts") or {}

        if "CERT_EXPIRED" in rule_ids:
            fp = str(facts.get("not_after") or "")
            events.append({
                "event_type": "cert.expired",
                "dedupe_key": _sha256_hex(f"cert.expired:{ak}:{fp}"),
                "payload": {"scan_id": scan_id, "asset_key": ak, "facts": facts, "finding_ids": sorted(rule_ids)},
            })

        if "CERT_EXPIRING_SOON" in rule_ids:
            fp = f"{facts.get('not_after','')}:{facts.get('days_until_expiry','')}"
            events.append({
                "event_type": "cert.expiring_soon",
                "dedupe_key": _sha256_hex(f"cert.expiring_soon:{ak}:{fp}"),
                "payload": {"scan_id": scan_id, "asset_key": ak, "facts": facts, "finding_ids": sorted(rule_ids)},
            })

        if "PQC_RSA_ENDPOINT" in rule_ids or "PQC_EC_ENDPOINT" in rule_ids:
            sigs = sorted([x for x in ("PQC_RSA_ENDPOINT","PQC_EC_ENDPOINT") if x in rule_ids])
            fp = ",".join(sigs)
            events.append({
                "event_type": "pqc.not_ready",
                "dedupe_key": _sha256_hex(f"pqc.not_ready:{ak}:{fp}"),
                "payload": {"scan_id": scan_id, "asset_key": ak, "signals": sigs},
            })

        base = get_baseline(ak)
        if base and base.get("baseline_scan_id"):
            base_scan = load_scan_row(str(base["baseline_scan_id"]))
            base_rules: set[str] = set()
            if base_scan:
                for br in (base_scan.get("results") or []):
                    if f"{br.get('host')}:{int(br.get('port') or 443)}" == ak:
                        base_rules = set(_extract_rule_ids(br))
                        break
            new_rules = sorted(rule_ids - base_rules)
            if new_rules:
                fp = ",".join(new_rules)
                events.append({
                    "event_type": "scan.regression",
                    "dedupe_key": _sha256_hex(f"scan.regression:{ak}:{fp}"),
                    "payload": {"scan_id": scan_id, "asset_key": ak, "baseline_scan_id": base["baseline_scan_id"], "new_finding_ids": new_rules},
                })

    return events

def _post_json(url: str, body: bytes, event_type: str, secret: str = "", timeout_s: int = 10) -> int:
    headers = {"Content-Type": "application/json", "X-PQC-Event": event_type}
    if secret:
        headers["X-PQC-Signature"] = _hmac_sig(secret, body)
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout_s) as resp:
        return int(getattr(resp, "status", 200) or 200)

def deliver_events_for_scan(scan_id: str) -> Dict[str, Any]:
    hooks = [h for h in list_webhooks() if h.get("enabled")]
    events = build_events_for_scan(scan_id)

    if not hooks or not events:
        return {"attempted": 0, "sent": 0, "hooks": len(hooks), "events": len(events)}

    attempted = 0
    sent = 0

    for ev in events:
        et = ev["event_type"]
        for wh in hooks:
            allowed = wh.get("events") or ["*"]
            if "*" not in allowed and et not in allowed:
                continue

            payload = {"event_type": et, "ts": int(time.time()), "data": ev.get("payload") or {}}
            dedupe_key = str(ev.get("dedupe_key") or "")

            row_id = record_webhook_event(
                webhook_id=int(wh["id"]),
                event_type=et,
                dedupe_key=dedupe_key,
                payload=payload,
                status="queued",
                max_attempts=5,
            )
            if row_id is None:
                continue

            attempted += 1
            body = json.dumps(payload).encode("utf-8")
            try:
                bump_webhook_attempt(row_id)
                code = _post_json(str(wh.get("url") or ""), body, et, secret=str(wh.get("secret") or ""), timeout_s=10)
                update_webhook_event(row_id, status="sent", http_status=code, error_text="")
                sent += 1
            except urlerror.HTTPError as e:
                code = int(getattr(e, "code", 0) or 0)
                update_webhook_event(row_id, status="failed", http_status=code, error_text=str(e))
            except Exception as e:
                update_webhook_event(row_id, status="failed", http_status=0, error_text=str(e))

    return {"attempted": attempted, "sent": sent, "hooks": len(hooks), "events": len(events)}

def deliver_test_ping(webhook_id: int) -> dict:
    hooks = {int(h["id"]): h for h in list_webhooks()}
    wh = hooks.get(int(webhook_id))
    if not wh:
        raise KeyError("webhook not found")

    nonce = str(uuid.uuid4())
    et = "test.ping"
    payload = {"event_type": et, "ts": int(time.time()), "data": {"message": "pong", "nonce": nonce}}

    dedupe_key = _sha256_hex(f"test.ping:{webhook_id}:{nonce}")

    row_id = record_webhook_event(
        webhook_id=int(webhook_id),
        event_type=et,
        dedupe_key=dedupe_key,
        payload=payload,
        status="queued",
        max_attempts=5,
    )
    if row_id is None:
        return {"ok": False, "reason": "deduped"}

    body = json.dumps(payload).encode("utf-8")
    try:
        bump_webhook_attempt(row_id)
        code = _post_json(str(wh.get("url") or ""), body, et, secret=str(wh.get("secret") or ""), timeout_s=10)
        update_webhook_event(row_id, status="sent", http_status=code, error_text="")
        return {"ok": True, "row_id": row_id, "http_status": code}
    except Exception as e:
        update_webhook_event(row_id, status="failed", http_status=0, error_text=str(e))
        return {"ok": False, "row_id": row_id, "error": str(e)}

def retry_pending_deliveries(limit: int = 50, max_attempts: int = 5) -> Dict[str, Any]:
    hooks = {int(h["id"]): h for h in list_webhooks() if h.get("enabled")}
    pending = list_pending_webhook_events(limit=limit, max_attempts=max_attempts)

    retried = 0
    sent = 0

    for ev in pending:
        wh = hooks.get(int(ev["webhook_id"]))
        if not wh:
            continue

        et = str(ev["event_type"])
        payload = ev.get("payload") or {}
        body = json.dumps(payload).encode("utf-8")

        try:
            bump_webhook_attempt(int(ev["id"]))
            code = _post_json(str(wh.get("url") or ""), body, et, secret=str(wh.get("secret") or ""), timeout_s=10)
            update_webhook_event(int(ev["id"]), status="sent", http_status=code, error_text="")
            sent += 1
        except Exception as e:
            update_webhook_event(int(ev["id"]), status="failed", http_status=0, error_text=str(e))

        retried += 1

    return {"pending": len(pending), "retried": retried, "sent": sent}
