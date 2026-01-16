from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib import request, error as urlerror

from db import (
    load_scan_row,
    list_webhooks,
    record_webhook_event,
    bump_webhook_attempt,
    update_webhook_event,
    get_baseline,
    list_pending_webhook_events,
    get_integration_setting,
    list_event_rules,
    get_asset,
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


def _extract_severities(result: dict) -> List[str]:
    out: List[str] = []
    for f in (result.get("findings") or []):
        sev = (f or {}).get("severity")
        if sev:
            out.append(str(sev).lower())
    return out


def _severity_rank(s: str) -> int:
    m = {
        "info": 0,
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return m.get((s or "").strip().lower(), 0)


def _max_severity(sevs: List[str]) -> str:
    best = "info"
    best_r = -1
    for s in sevs:
        r = _severity_rank(s)
        if r > best_r:
            best_r = r
            best = s
    return best


def build_events_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    scan = load_scan_row(scan_id)
    if not scan:
        return []

    results = scan.get("results") or []
    summary = scan.get("summary") or {}
    status = scan.get("status") or ""
    error_text = scan.get("error_text") or ""

    # UI-configurable threshold (default 30) – stored in DB integrations_settings
    try:
        expiring_soon_days = int(get_integration_setting("cert_expiring_soon_days", "30"))
    except Exception:
        expiring_soon_days = 30
    expiring_soon_days = max(1, min(36500, expiring_soon_days))

    events: List[Dict[str, Any]] = []

    # Always emit scan.completed
    events.append(
        {
            "event_type": "scan.completed",
            "dedupe_key": _sha256_hex(f"scan.completed:{scan_id}"),
            "payload": {"scan_id": scan_id, "status": status, "summary": summary},
        }
    )

    # High-value automation event for failures
    if str(status).lower() == "failed":
        events.append(
            {
                "event_type": "scan.failed",
                "dedupe_key": _sha256_hex(f"scan.failed:{scan_id}"),
                "payload": {
                    "scan_id": scan_id,
                    "status": status,
                    "summary": summary,
                    "error_text": error_text,
                },
            }
        )

    for r in results:
        host = str(r.get("host") or "")
        port = int(r.get("port") or 443)
        ak = f"{host}:{port}"

        rule_ids = set(_extract_rule_ids(r))

        # --- FIX (Sprint 8 Step 1): scanner returns a flat dict, not {"facts": {...}} ---
        facts: Dict[str, Any] = {}
        if isinstance(r, dict):
            maybe = r.get("facts")
            if isinstance(maybe, dict) and maybe:
                facts = maybe
            else:
                facts = r

        # Derived helpers for rules
        max_sev = _max_severity(_extract_severities(r))
        quantum_score = r.get("quantum_risk_score", r.get("quantum_score", None))
        risk_level = r.get("risk_level", r.get("risk", ""))

        # Facts helpers
        du = facts.get("days_until_expiry", None)
        try:
            du_int = int(du) if du is not None and str(du) != "" else None
        except Exception:
            du_int = None
        not_after = str(facts.get("not_after") or "")
        verify_reason = str(facts.get("verify_reason") or "")

        # cert.expired
        expired = False
        if du_int is not None and du_int < 0:
            expired = True
        if verify_reason == "expired":
            expired = True
        if "CERT_EXPIRED" in rule_ids or "VERIFY_EXPIRED" in rule_ids:
            expired = True

        if expired:
            fp = f"{not_after}:{du_int if du_int is not None else ''}:{verify_reason}"
            events.append(
                {
                    "event_type": "cert.expired",
                    "dedupe_key": _sha256_hex(f"cert.expired:{ak}:{fp}"),
                    "payload": {
                        "scan_id": scan_id,
                        "asset_key": ak,
                        "days_until_expiry": du_int,
                        "not_after": not_after,
                        "verify_reason": verify_reason,
                        "threshold_days": expiring_soon_days,
                        "facts": facts,
                        "finding_ids": sorted(rule_ids),
                        "max_severity": max_sev,
                        "risk_level": risk_level,
                        "quantum_risk_score": quantum_score,
                    },
                }
            )

        # cert.expiring_soon (facts-based)
        expiring_soon = False
        if du_int is not None and 0 <= du_int <= expiring_soon_days:
            expiring_soon = True
        if "CERT_EXPIRING_SOON" in rule_ids:
            expiring_soon = True

        if expiring_soon:
            fp = f"{not_after}:{du_int if du_int is not None else ''}:{expiring_soon_days}"
            events.append(
                {
                    "event_type": "cert.expiring_soon",
                    "dedupe_key": _sha256_hex(f"cert.expiring_soon:{ak}:{fp}"),
                    "payload": {
                        "scan_id": scan_id,
                        "asset_key": ak,
                        "days_until_expiry": du_int,
                        "not_after": not_after,
                        "threshold_days": expiring_soon_days,
                        "facts": facts,
                        "finding_ids": sorted(rule_ids),
                        "max_severity": max_sev,
                        "risk_level": risk_level,
                        "quantum_risk_score": quantum_score,
                    },
                }
            )

        # pqc.not_ready
        if "PQC_RSA_ENDPOINT" in rule_ids or "PQC_EC_ENDPOINT" in rule_ids:
            sigs = sorted([x for x in ("PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT") if x in rule_ids])
            fp = ",".join(sigs)
            events.append(
                {
                    "event_type": "pqc.not_ready",
                    "dedupe_key": _sha256_hex(f"pqc.not_ready:{ak}:{fp}"),
                    "payload": {
                        "scan_id": scan_id,
                        "asset_key": ak,
                        "signals": sigs,
                        "finding_ids": sorted(rule_ids),
                        "max_severity": max_sev,
                        "risk_level": risk_level,
                        "quantum_risk_score": quantum_score,
                    },
                }
            )

        # scan.regression (baseline comparison)
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
                events.append(
                    {
                        "event_type": "scan.regression",
                        "dedupe_key": _sha256_hex(f"scan.regression:{ak}:{fp}"),
                        "payload": {
                            "scan_id": scan_id,
                            "asset_key": ak,
                            "baseline_scan_id": base["baseline_scan_id"],
                            "new_finding_ids": new_rules,
                            "max_severity": max_sev,
                            "risk_level": risk_level,
                            "quantum_risk_score": quantum_score,
                        },
                    }
                )

    return events


def _post_json(url: str, body: bytes, event_type: str, secret: str = "", timeout_s: int = 10) -> int:
    headers = {"Content-Type": "application/json", "X-PQC-Event": event_type}
    if secret:
        headers["X-PQC-Signature"] = _hmac_sig(secret, body)
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout_s) as resp:
        return int(getattr(resp, "status", 200) or 200)


def _rule_event_types(rule: dict) -> List[str]:
    return [str(x) for x in (rule.get("event_types") or ["*"]) if str(x).strip()]


def _rule_webhook_ids(rule: dict) -> List[int]:
    out: List[int] = []
    for x in (rule.get("webhook_ids") or []):
        try:
            out.append(int(x))
        except Exception:
            continue
    return out


def _event_candidate_rule_ids(payload: dict) -> List[str]:
    cands: List[str] = []
    for k in ("finding_ids", "new_finding_ids", "signals"):
        for x in (payload.get(k) or []):
            if x:
                cands.append(str(x))
    return cands


def _rule_matches(rule: dict, event_type: str, payload: dict) -> bool:
    # event type
    ets = _rule_event_types(rule)
    if "*" not in ets and event_type not in ets:
        return False

    # rule_id filter
    want_rule_ids = [str(x) for x in (rule.get("rule_ids") or []) if str(x).strip()]
    if want_rule_ids:
        cand = set(_event_candidate_rule_ids(payload))
        if not any(rid in cand for rid in want_rule_ids):
            return False

    # severity filter
    min_sev = str(rule.get("min_severity") or "").strip().lower()
    if min_sev:
        got = str(payload.get("max_severity") or payload.get("severity") or "info").lower()
        if _severity_rank(got) < _severity_rank(min_sev):
            return False

    # quantum score filter
    qmin = rule.get("quantum_score_min", None)
    if qmin is not None:
        try:
            qmin_f = float(qmin)
        except Exception:
            qmin_f = -1.0
        if qmin_f >= 0:
            try:
                q = payload.get("quantum_risk_score", None)
                q_f = float(q) if q is not None and str(q) != "" else None
            except Exception:
                q_f = None
            if q_f is None or q_f < qmin_f:
                return False

    # asset metadata filters
    envs = [str(x) for x in (rule.get("environments") or []) if str(x).strip()]
    teams = [str(x) for x in (rule.get("teams") or []) if str(x).strip()]
    crits = [str(x) for x in (rule.get("criticalities") or []) if str(x).strip()]
    tags = [str(x) for x in (rule.get("tags") or []) if str(x).strip()]

    if envs or teams or crits or tags:
        ak = str(payload.get("asset_key") or "")
        if not ak:
            return False
        asset = get_asset(ak)
        if not asset:
            return False

        if envs and str(asset.get("environment") or "") not in envs:
            return False
        if teams and str(asset.get("team") or "") not in teams:
            return False
        if crits and str(asset.get("criticality") or "") not in crits:
            return False
        if tags:
            atags = set([str(t) for t in (asset.get("tags") or [])])
            if not any(t in atags for t in tags):
                return False

    return True


def _routes_for_events(events: List[Dict[str, Any]]) -> List[Tuple[int, Dict[str, Any], str, str]]:
    """Return list of (webhook_id, payload, event_type, dedupe_key) for deliveries.

    If there are enabled rules, routing is determined by rules.
    Otherwise, we fall back to the webhook 'events' allow-list behavior.
    """
    hooks = [h for h in list_webhooks() if h.get("enabled")]
    hooks_by_id = {int(h["id"]): h for h in hooks}

    rules = [r for r in list_event_rules(limit=500) if r.get("enabled")]
    has_rules = len(rules) > 0

    out: List[Tuple[int, Dict[str, Any], str, str]] = []

    for ev in events:
        et = str(ev.get("event_type") or "")
        dedupe_key = str(ev.get("dedupe_key") or "")
        data = ev.get("payload") or {}
        wrapped = {"event_type": et, "ts": int(time.time()), "data": data}

        if has_rules:
            # rules decide destinations
            for rule in rules:
                if not _rule_matches(rule, et, data):
                    continue
                for wid in _rule_webhook_ids(rule):
                    wh = hooks_by_id.get(int(wid))
                    if not wh:
                        continue
                    # include matched rule id(s) for debug/automation
                    payload = dict(wrapped)
                    payload["rule"] = {"id": rule.get("id"), "name": rule.get("name")}
                    out.append((int(wid), payload, et, dedupe_key))
        else:
            # fallback: legacy allow-list on each webhook
            for wh in hooks:
                allowed = wh.get("events") or ["*"]
                if "*" not in allowed and et not in allowed:
                    continue
                out.append((int(wh["id"]), wrapped, et, dedupe_key))

    return out


def deliver_events_for_scan(scan_id: str) -> Dict[str, Any]:
    events = build_events_for_scan(scan_id)
    routes = _routes_for_events(events)

    if not routes:
        return {"attempted": 0, "sent": 0, "routes": 0, "events": len(events)}

    hooks = {int(h["id"]): h for h in list_webhooks() if h.get("enabled")}

    attempted = 0
    sent = 0

    for webhook_id, payload, et, dedupe_key in routes:
        wh = hooks.get(int(webhook_id))
        if not wh:
            continue

        row_id = record_webhook_event(
            webhook_id=int(webhook_id),
            event_type=et,
            dedupe_key=str(dedupe_key),
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
            code = _post_json(
                str(wh.get("url") or ""),
                body,
                et,
                secret=str(wh.get("secret") or ""),
                timeout_s=10,
            )
            update_webhook_event(row_id, status="sent", http_status=code, error_text="")
            sent += 1
        except urlerror.HTTPError as e:
            code = int(getattr(e, "code", 0) or 0)
            update_webhook_event(row_id, status="failed", http_status=code, error_text=str(e))
        except Exception as e:
            update_webhook_event(row_id, status="failed", http_status=0, error_text=str(e))

    return {"attempted": attempted, "sent": sent, "routes": len(routes), "events": len(events)}


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


def test_rules_for_scan(scan_id: str) -> Dict[str, Any]:
    """Dry-run rules engine against a scan, returning per-rule matches."""
    events = build_events_for_scan(scan_id)
    rules = [r for r in list_event_rules(limit=500) if r.get("enabled")]

    out_rules: List[Dict[str, Any]] = []
    for rule in rules:
        matches: List[Dict[str, Any]] = []
        for ev in events:
            et = str(ev.get("event_type") or "")
            data = ev.get("payload") or {}
            if _rule_matches(rule, et, data):
                # Keep it small for UI
                matches.append({"event_type": et, "asset_key": data.get("asset_key", ""), "scan_id": data.get("scan_id", scan_id)})
        out_rules.append({"id": rule.get("id"), "name": rule.get("name"), "matches": matches, "count": len(matches)})

    return {"scan_id": scan_id, "rules": out_rules, "events": len(events)}
