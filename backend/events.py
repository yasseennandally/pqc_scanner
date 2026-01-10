from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional
from urllib import request, error as urlerror

from db import (
    load_scan_row,
    list_webhooks,
    record_webhook_event,
    update_webhook_event,
    get_baseline,
)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _hmac_sig(secret: str, body: bytes) -> str:
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _event_dedupe_key(event_type: str, asset_key: str, fingerprint: str = "") -> str:
    base = f"{event_type}:{asset_key}:{fingerprint}"
    return _sha256_hex(base)


def _extract_finding_ids(result: dict) -> List[str]:
    ids: List[str] = []
    for f in (result.get("findings") or []):
        rid = str((f or {}).get("rule_id") or "")
        if rid:
            ids.append(rid)
    return ids


def build_events_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    scan = load_scan_row(scan_id)
    if not scan:
        return []

    results = scan.get("results") or []
    created_at = scan.get("created_at")
    created_at_str = created_at.isoformat() + "Z" if hasattr(created_at, "isoformat") else str(created_at)

    events: List[Dict[str, Any]] = []
    # scan.completed: always
    events.append(
        {
            "event_type": "scan.completed",
            "scan_id": scan_id,
            "asset_key": "",
            "severity": "info",
            "rule_id": "",
            "dedupe_key": _event_dedupe_key("scan.completed", scan_id, ""),
            "payload": {
                "scan_id": scan_id,
                "status": scan.get("status"),
                "created_at": created_at_str,
                "summary": scan.get("summary") or {},
            },
        }
    )

    # Per-target events
    for r in results:
        host = str(r.get("host") or "")
        port = int(r.get("port") or 443)
        asset_key = f"{host}:{port}"

        finding_ids = _extract_finding_ids(r)
        fid_sorted = sorted(set(finding_ids))

        # Cert expired / expiring soon: based on rule ids already in your findings
        if "CERT_EXPIRED" in fid_sorted:
            not_after = str((r.get("facts") or {}).get("not_after") or "")
            events.append(
                {
                    "event_type": "cert.expired",
                    "scan_id": scan_id,
                    "asset_key": asset_key,
                    "severity": "high",
                    "rule_id": "CERT_EXPIRED",
                    "dedupe_key": _event_dedupe_key("cert.expired", asset_key, not_after),
                    "payload": {"scan_id": scan_id, "asset_key": asset_key, "not_after": not_after, "findings": fid_sorted},
                }
            )

        if "CERT_EXPIRING_SOON" in fid_sorted:
            not_after = str((r.get("facts") or {}).get("not_after") or "")
            days = (r.get("facts") or {}).get("days_until_expiry")
            fp = f"{not_after}:{days}"
            events.append(
                {
                    "event_type": "cert.expiring_soon",
                    "scan_id": scan_id,
                    "asset_key": asset_key,
                    "severity": "medium",
                    "rule_id": "CERT_EXPIRING_SOON",
                    "dedupe_key": _event_dedupe_key("cert.expiring_soon", asset_key, fp),
                    "payload": {"scan_id": scan_id, "asset_key": asset_key, "not_after": not_after, "days_until_expiry": days, "findings": fid_sorted},
                }
            )

        # Regression vs baseline: compare finding ids with baseline scan (if exists)
        bl = get_baseline(asset_key)
        if bl and bl.get("baseline_scan_id"):
            base_scan = load_scan_row(bl["baseline_scan_id"])
            base_results = base_scan.get("results") if base_scan else []
            base_for_asset = None
            for br in base_results or []:
                if str(br.get("host") or "") == host and int(br.get("port") or 443) == port:
                    base_for_asset = br
                    break
            if base_for_asset:
                base_ids = sorted(set(_extract_finding_ids(base_for_asset)))
                new_ids = sorted(set(fid_sorted) - set(base_ids))
                if new_ids:
                    fingerprint = ",".join(new_ids)
                    events.append(
                        {
                            "event_type": "asset.regressed",
                            "scan_id": scan_id,
                            "asset_key": asset_key,
                            "severity": "high",
                            "rule_id": "",
                            "dedupe_key": _event_dedupe_key("asset.regressed", asset_key, fingerprint),
                            "payload": {
                                "scan_id": scan_id,
                                "asset_key": asset_key,
                                "baseline_scan_id": bl["baseline_scan_id"],
                                "new_finding_ids": new_ids,
                            },
                        }
                    )

    return events


def deliver_events_for_scan(scan_id: str) -> Dict[str, Any]:
    hooks = [h for h in list_webhooks() if h.get("enabled")]
    if not hooks:
        return {"delivered": 0, "hooks": 0}

    events = build_events_for_scan(scan_id)
    delivered = 0

    for ev in events:
        et = ev["event_type"]
        for wh in hooks:
            allowed = wh.get("events") or ["*"]
            if "*" not in allowed and et not in allowed:
                continue

            payload = {
                "event_type": et,
                "scan_id": ev.get("scan_id"),
                "asset_key": ev.get("asset_key"),
                "severity": ev.get("severity"),
                "rule_id": ev.get("rule_id"),
                "ts": int(time.time()),
                "data": ev.get("payload") or {},
            }
            body = json.dumps(payload).encode("utf-8")
            sig = _hmac_sig(wh.get("secret") or "", body)

            dedupe_key = str(ev.get("dedupe_key") or "")
            row_id = record_webhook_event(wh["id"], et, dedupe_key, payload, status="queued")
            if row_id is None:
                # deduped
                continue

            try:
                req = request.Request(
                    wh["url"],
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-PQC-Event": et,
                        "X-PQC-Signature": sig,
                    },
                    method="POST",
                )
                with request.urlopen(req, timeout=10) as resp:
                    code = int(getattr(resp, "status", 200))
                update_webhook_event(row_id, status="sent", http_status=code, error_text="")
                delivered += 1
            except urlerror.HTTPError as e:
                update_webhook_event(row_id, status="failed", http_status=int(getattr(e, "code", 0) or 0), error_text=str(e))
            except Exception as e:
                update_webhook_event(row_id, status="failed", http_status=0, error_text=str(e))

    return {"delivered": delivered, "hooks": len(hooks), "events": len(events)}
