from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple

# Ordered by priority (first = most urgent / enables later work)
# Ordered by priority (first = most urgent / enables later work)
# Note: include specific VERIFY_* rules so the plan stays actionable.
RULE_TO_STEP = [
    ("CERT_EXPIRED", ("Renew expired certificates", "Expired certs break security and can block PQC/hybrid rollout.")),
    ("CERT_EXPIRING_SOON", ("Renew soon-to-expire certificates", "Short validity windows complicate migration scheduling.")),

    # Verification failures (specific first; VERIFY_FAILED as catch-all)
    ("VERIFY_REVOKED", ("Fix certificate verification failures", "Revoked certificates must be replaced and revocation causes outages.")),
    ("VERIFY_EXPIRED", ("Fix certificate verification failures", "Expired certificates cause verification failures and outages.")),
    ("VERIFY_HOSTNAME_MISMATCH", ("Fix certificate verification failures", "Hostname/SAN mismatches cause outages and block automation.")),
    ("VERIFY_MISSING_INTERMEDIATE", ("Fix certificate verification failures", "Missing intermediates cause verification failures for many clients.")),
    ("VERIFY_UNTRUSTED_ISSUER", ("Fix certificate verification failures", "Untrusted issuers break validation; fix trust chains/issuance.")),
    ("VERIFY_FAILED", ("Fix certificate verification failures", "Broken trust/hostname/chain causes outages during changes.")),

    ("CHAIN_MISSING_INTERMEDIATE", ("Serve full certificate chain", "Missing intermediates break validation for many clients.")),
    ("CHAIN_SHORT_OR_UNAVAILABLE", ("Ensure intermediates are served", "Incomplete chains complicate automation and audits.")),
    ("CERT_HOST_NOT_IN_SAN", ("Fix SAN/hostname coverage", "Correct SANs avoid production outages when moving TLS termination.")),

    ("LEGACY_TLS_SUPPORTED", ("Disable TLS 1.0/1.1", "Baseline modernization needed before PQC/hybrid adoption.")),
    ("WEAK_CIPHER_ACCEPTED", ("Remove weak TLS 1.2 cipher suites", "Hardening reduces attack surface and increases crypto agility.")),
    ("NO_TLS13", ("Enable TLS 1.3", "Modern TLS stacks are the foundation for future hybrid/PQC support.")),

    ("RSA_KEY_EXCHANGE_ONLY", ("Remove RSA key exchange (use ECDHE)", "PFS is critical to reduce harvest-now-decrypt-later impact.")),
    ("RSA_CERT_PRESENT", ("Plan RSA certificate replacement", "RSA/ECDSA certificates will need migration paths toward PQC/hybrid.")),
    ("ECDSA_CERT_PRESENT", ("Plan ECDSA certificate strategy", "ECDSA may need hybrid/PQC strategy depending on your roadmap.")),
]


RULE_LOOKUP = {rid: (title, why) for rid, (title, why) in RULE_TO_STEP}
PRIORITY = {rid: i for i, (rid, _) in enumerate(RULE_TO_STEP)}


def build_tls_migration_plan(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build an ordered checklist of migration/hardening actions from per-endpoint findings.
    Output schema:
      [
        { "step": "...", "why": "...", "affected": ["host:port", ...], "evidence": {...} },
        ...
      ]
    """
    by_rule: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)

    for r in results or []:
        host = r.get("host")
        port = r.get("port")
        hp = f"{host}:{port}" if host and port else (host or "unknown")
        for f in (r.get("findings") or []):
            rid = f.get("rule_id")
            if not rid:
                continue
            by_rule[rid].append((hp, f.get("evidence") or {}))

    items: List[Dict[str, Any]] = []
    for rid, occurrences in by_rule.items():
        if rid not in RULE_LOOKUP:
            continue

        title, why = RULE_LOOKUP[rid]
        affected = sorted({hp for hp, _ in occurrences})
        # small evidence aggregation
        evidence_samples = [ev for _, ev in occurrences[:3] if ev]
        item = {
            "rule_id": rid,
            "step": title,
            "why": why,
            "affected": affected,
            "evidence_samples": evidence_samples,
        }
        items.append(item)

    items.sort(key=lambda it: PRIORITY.get(it["rule_id"], 10_000))
    return items
