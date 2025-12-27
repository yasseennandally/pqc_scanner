# migration.py
from __future__ import annotations

from typing import Any, Dict, List, Tuple

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def build_migration_plan_tls(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Turn per-endpoint findings into an ordered checklist.
    This is the "enterprise value" view: what to fix first, once, across fleet.
    """
    buckets: Dict[str, Dict[str, Any]] = {}

    for r in results or []:
        host = r.get("host")
        port = r.get("port")
        for f in (r.get("findings") or []):
            rid = f.get("id") or "UNKNOWN"
            sev = (f.get("severity") or "LOW").upper()
            title = f.get("title") or rid
            fix = f.get("fix") or ""
            pqc_note = f.get("pqc_note") or ""

            if rid not in buckets:
                buckets[rid] = {
                    "rule_id": rid,
                    "severity": sev,
                    "title": title,
                    "fix": fix,
                    "pqc_note": pqc_note,
                    "affected": [],
                }
            buckets[rid]["affected"].append({"host": host, "port": port})

    items = list(buckets.values())
    items.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 1), reverse=True)

    return {
        "kind": "tls",
        "items": items,
        "count": len(items),
    }
