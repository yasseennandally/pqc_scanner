# policy.py
"""
Policy/rules engine: scan facts -> findings.

Phase 2 - OCSP validation Step 1 adds:
- OCSP_STATUS_REVOKED (critical)
- OCSP_STATUS_UNKNOWN (medium)
- OCSP_CHECK_FAILED (low)
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple
from datetime import datetime
from typing import Any, Dict, List


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    fix: str,
    confidence: str,
    confidence_reason: str,
    evidence: Dict[str, Any],
    pqc_note: str = "",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "fix": fix,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
        "evidence": evidence,
        "pqc_note": pqc_note,
    }


def risk_level_from_findings(findings: List[Dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best = 0
    for f in findings:
        best = max(best, order.get((f.get("severity") or "").lower(), 0))
    for k, v in order.items():
        if v == best:
            return k
    return "low"


def pqc_relevance_and_reco(scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> Tuple[str, str]:
    key_type = (scan.get("key_type") or "").upper()
    supported = set(scan.get("tls_supported_versions") or [])

    if "RSA" in key_type:
        return "HIGH", "RSA endpoint: plan hybrid/PQC migration (Kyber KEM + PQ signatures) via crypto-agile termination."
    if "EC" in key_type:
        return "MEDIUM", "ECC endpoint: plan hybrid/PQC migration (Kyber KEM + Dilithium/Falcon) with crypto agility."

    if "TLSv1.2" in supported and "TLSv1.3" not in supported:
        return "MEDIUM", "TLS 1.2-only posture: migrate to TLS 1.3 to enable hybrid/PQC rollout later."
    return "LOW", "Maintain crypto agility and track PQC readiness."


def evaluate_findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Expiry
    days = int(scan.get("days_until_expiry") or 0)
    if days < 0:
        findings.append(
            _finding(
                "CERT_EXPIRED",
                "high",
                "Certificate expired",
                "Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
                "high",
                "Expiry is computed from the presented X.509 certificate.",
                {"days_until_expiry": days, "not_after": scan.get("not_after", "")},
                "Rotation discipline matters for PQC rollouts.",
            )
        )
    elif days <= 14:
        findings.append(
            _finding(
                "CERT_EXPIRING_SOON",
                "medium",
                "Certificate expiring soon",
                "Schedule certificate renewal/rotation soon; ensure renewal automation.",
                "high",
                "Expiry is computed from the presented X.509 certificate.",
                {"days_until_expiry": days, "not_after": scan.get("not_after", "")},
                "Rotation discipline matters for PQC rollouts.",
            )
        )

    # TLS 1.3 support
    supported = scan.get("tls_supported_versions") or []
    if "TLSv1.3" not in supported and supported:
        findings.append(
            _finding(
                "NO_TLS13",
                "high",
                "TLS 1.3 not supported",
                "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
                "high",
                "Derived from active protocol probes.",
                {"tls_supported_versions": supported},
                "TLS 1.3 is typically the baseline for hybrid/PQC TLS rollouts.",
            )
        )

    # Weak TLS 1.2 ciphers accepted
    weak = scan.get("tls12_weak_accepted_ciphers") or []
    if weak:
        findings.append(
            _finding(
                "WEAK_CIPHER_ACCEPTED",
                "critical",
                "Weak TLS 1.2 ciphers accepted by server",
                "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
                "medium",
                "Best-effort probe; depends on client OpenSSL cipher support.",
                {"tls12_weak_accepted_ciphers": weak},
                "Baseline hardening should be done before any PQC/hybrid rollout.",
            )
        )

    # Forward secrecy heuristic
    if not bool(scan.get("forward_secrecy_possible", True)):
        findings.append(
            _finding(
                "NO_FORWARD_SECRECY",
                "medium",
                "Forward secrecy not observed/likely disabled",
                "Prefer ECDHE/DHE cipher suites for TLS 1.2 and migrate to TLS 1.3.",
                "low",
                "Heuristic based on negotiated cipher string; validate server cipher policy for certainty.",
                {"cipher_name": scan.get("cipher_name", ""), "forward_secrecy_possible": False},
                "FS hygiene reduces blast radius during algorithm transitions.",
            )
        )

    # OCSP/CRL URLs (extensions presence)
    ocsp_urls = scan.get("ocsp_urls") or []
    if not ocsp_urls:
        findings.append(
            _finding(
                "CERT_NO_OCSP_AIA",
                "low",
                "No OCSP responder advertised (AIA)",
                "Consider including OCSP AIA in issued certificates, and enable OCSP stapling where appropriate.",
                "high",
                "AIA OCSP URLs are read directly from the X.509 certificate extensions.",
                {"ocsp_urls": []},
                "Revocation posture matters more as certificate strategies evolve for PQC.",
            )
        )

    crl_urls = scan.get("crl_urls") or []
    if not crl_urls:
        findings.append(
            _finding(
                "CERT_NO_CRL_DP",
                "low",
                "No CRL distribution points advertised",
                "Consider adding CRL distribution points to issued certificates if your PKI relies on CRLs.",
                "high",
                "CRL Distribution Points are read directly from the X.509 certificate extensions.",
                {"crl_urls": []},
                "Revocation posture matters more as PKI evolves for PQC.",
            )
        )

    # Stapling presence (advisory)
    if ocsp_urls and not bool(scan.get("ocsp_stapled", False)):
        findings.append(
            _finding(
                "OCSP_STAPLING_MISSING",
                "low",
                "OCSP stapling not observed",
                "Enable OCSP stapling on the TLS terminator (e.g., nginx: ssl_stapling on; ssl_stapling_verify on;).",
                "low",
                "Stapling visibility depends on client/TLS stack support; treat as advisory.",
                {"ocsp_urls": ocsp_urls[:3], "ocsp_stapled": False},
                "Stapling reduces revocation latency; helpful during cert rotations and PQC transition waves.",
            )
        )

    # Phase2 step1: OCSP basic status (active query)
    ocsp_check = scan.get("ocsp_check") or {}
    ocsp_err = (scan.get("ocsp_check_error") or "").strip()

    if ocsp_urls and ocsp_err and not ocsp_check:
        findings.append(
            _finding(
                "OCSP_CHECK_FAILED",
                "low",
                "OCSP status check failed",
                "Verify OCSP responder reachability and ensure the server sends a valid chain or AIA CA Issuers URL is accessible.",
                "low",
                "OCSP check is best-effort; network and PKI constraints can prevent validation.",
                {"ocsp_url": ocsp_urls[0], "error": ocsp_err},
                "OCSP validation improves revocation confidence during PQC transition waves.",
            )
        )
    elif ocsp_check:
        rstat = (ocsp_check.get("response_status") or "").upper()
        cstat = (ocsp_check.get("cert_status") or "").upper()

        if rstat == "SUCCESSFUL" and cstat == "REVOKED":
            findings.append(
                _finding(
                    "OCSP_STATUS_REVOKED",
                    "critical",
                    "OCSP indicates certificate is revoked",
                    "Treat as an incident: replace the certificate and investigate revocation cause immediately.",
                    "medium",
                    "OCSP response parsed successfully; signature validation not yet performed (Phase 2 Step 2).",
                    {"ocsp_check": ocsp_check},
                    "Revocation hygiene is essential before rolling out PQC/hybrid certificates.",
                )
            )
        elif rstat == "SUCCESSFUL" and cstat == "UNKNOWN":
            findings.append(
                _finding(
                    "OCSP_STATUS_UNKNOWN",
                    "medium",
                    "OCSP responder returned UNKNOWN status",
                    "Verify issuance/serial and CA OCSP configuration; consider CRL checks as fallback.",
                    "medium",
                    "OCSP response parsed successfully; signature validation not yet performed (Phase 2 Step 2).",
                    {"ocsp_check": ocsp_check},
                    "Revocation confidence matters during PQC migration.",
                )
            )

    # PQC class
    kt = (scan.get("key_type") or "").upper()
    if "RSA" in kt:
        findings.append(
            _finding(
                "PQC_RSA_ENDPOINT",
                "high",
                "RSA certificate key detected (quantum-vulnerable class)",
                "Inventory RSA usage and plan migration to PQC/hybrid approaches.",
                "high",
                "Public key algorithm extracted from the presented X.509 certificate.",
                {"key_type": "RSA", "key_size": scan.get("key_detail", "")},
                "RSA -> Kyber (KEM) + PQ signatures in a crypto-agile design.",
            )
        )
    elif "EC" in kt:
        findings.append(
            _finding(
                "PQC_EC_ENDPOINT",
                "medium",
                "Elliptic-curve public key detected (quantum-vulnerable class)",
                "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
                "high",
                "Public key algorithm extracted from the presented X.509 certificate.",
                {"key_type": "EC", "curve": scan.get("key_detail", "")},
                "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
            )
        )

    return findings

def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build scan-level summary used by the UI history + executive summary panel.

    Expected per-result shape:
      - result["findings"] is a list of finding dicts with "severity" in {"critical","high","medium","low"}
      - result["error"] may exist for scan failures
      - result["key_type"] may be "RSA" / "EC" etc.

    Returns:
      {
        "total": int,
        "critical": int, "high": int, "medium": int, "low": int,
        "errors": int,
        "rsa_count": int,
        "quantum_risk_score": int (0-100),
        "quantum_risk_level": "low"|"medium"|"high",
        "generated_at": ISO timestamp
      }
    """
    total = len(results)

    critical = high = medium = low = 0
    errors = 0
    rsa_count = 0

    # Simple score model: start from 100 and subtract weighted points
    # (tweak later; it’s deterministic and stable for now)
    points = 0

    for r in results:
        if r.get("error"):
            errors += 1

        kt = (r.get("key_type") or "").upper()
        if "RSA" in kt:
            rsa_count += 1
            points += 2  # RSA gets extra quantum penalty

        for f in (r.get("findings") or []):
            sev = (f.get("severity") or "").lower().strip()
            if sev == "critical":
                critical += 1
                points += 10
            elif sev == "high":
                high += 1
                points += 7
            elif sev == "medium":
                medium += 1
                points += 4
            elif sev == "low":
                low += 1
                points += 1

    score = 100 - points
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score >= 80:
        level = "low"
    elif score >= 50:
        level = "medium"
    else:
        level = "high"

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "errors": errors,
        "rsa_count": rsa_count,
        "quantum_risk_score": score,
        "quantum_risk_level": level,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
    }