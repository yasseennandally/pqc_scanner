# backend/policy.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# -------------------------
# Helpers
# -------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "").lower(), 0)


def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    remediation: str,
    pqc_mapping: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    confidence: str = "medium",
    confidence_reason: str = "",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": (severity or "low").lower(),
        "title": title,
        "fix": remediation,
        "confidence": confidence,
        "confidence_reason": confidence_reason or "",
        "evidence": evidence or {},
        "pqc_note": pqc_mapping or "",
    }


def _get_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def _san_dns(f: Dict[str, Any]) -> List[str]:
    return [str(x).lower() for x in _get_list(f.get("san_dns")) if str(x).strip()]


def _ocsp_urls(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("ocsp_urls")) if str(x).strip()]


def _crl_urls(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("crl_urls")) if str(x).strip()]



def _ocsp_reachability(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [x for x in _get_list(f.get("ocsp_reachability")) if isinstance(x, dict)]


def _crl_reachability(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [x for x in _get_list(f.get("crl_reachability")) if isinstance(x, dict)]


def _any_unreachable(entries: List[Dict[str, Any]]) -> bool:
    for e in entries or []:
        try:
            if not bool(e.get("reachable", False)):
                return True
        except Exception:
            continue
    return False


def _ocsp_stapled_status(f: Dict[str, Any]) -> str:
    return str(f.get("ocsp_stapled_status") or "").strip().lower()


def _tls_versions(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("tls_supported_versions")) if str(x).strip()]


def _weak_tls12(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("tls12_weak_accepted_ciphers")) if str(x).strip()]


def _key_type(f: Dict[str, Any]) -> str:
    return str(f.get("key_type") or "").upper()


def _key_detail(f: Dict[str, Any]) -> str:
    return str(f.get("key_detail") or "")


def _host_in_san(host: str, sans: List[str]) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    for s in sans:
        s = (s or "").lower().strip()
        if not s:
            continue
        if s == h:
            return True
        if s.startswith("*."):
            # wildcard matches one label
            suffix = s[1:]  # ".example.com"
            if h.endswith(suffix) and h.count(".") >= suffix.count(".") + 1:
                return True
    return False


# -------------------------
# Rules
# -------------------------

RULES: List[Dict[str, Any]] = [
    # TLS Protocol
    {
        "id": "NO_TLS13",
        "title": "TLS 1.3 not supported",
        "severity": "high",
        "when": lambda f: ("TLSv1.3" not in _tls_versions(f)) and ("TLSv1.2" in _tls_versions(f)),
        "evidence": lambda f: {"tls_supported_versions": _tls_versions(f)},
        "remediation": "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
        "pqc_mapping": "TLS 1.3 is typically the baseline for hybrid/PQC TLS rollouts.",
        "confidence": "high",
        "confidence_reason": "Derived from active protocol probes.",
    },

    # Weak TLS 1.2
    {
        "id": "WEAK_CIPHER_ACCEPTED",
        "title": "Weak TLS 1.2 ciphers accepted by server",
        "severity": "critical",
        "when": lambda f: len(_weak_tls12(f)) > 0,
        "evidence": lambda f: {"tls12_weak_accepted_ciphers": _weak_tls12(f)[:50]},
        "remediation": "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
        "pqc_mapping": "Baseline hardening should be done before any PQC/hybrid rollout.",
        "confidence": "medium",
        "confidence_reason": "Best-effort probe; depends on client OpenSSL cipher support.",
    },

    # Cert expiry
    {
        "id": "CERT_EXPIRED",
        "title": "Certificate expired",
        "severity": "high",
        "when": lambda f: isinstance(f.get("days_until_expiry"), int) and int(f["days_until_expiry"]) < 0,
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
        "pqc_mapping": "Rotation discipline matters for PQC rollouts.",
        "confidence": "high",
        "confidence_reason": "Expiry is computed from the presented X.509 certificate.",
    },
    {
        "id": "CERT_EXPIRING_SOON",
        "title": "Certificate expiring soon",
        "severity": "medium",
        "when": lambda f: isinstance(f.get("days_until_expiry"), int) and 0 <= int(f["days_until_expiry"]) <= 30,
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Schedule certificate renewal/rotation soon; ensure renewal automation.",
        "pqc_mapping": "Rotation discipline matters for PQC rollouts.",
        "confidence": "high",
        "confidence_reason": "Expiry is computed from the presented X.509 certificate.",
    },

    # Hostname vs SAN
    {
        "id": "CERT_HOST_NOT_IN_SAN",
        "title": "Hostname not covered by certificate SAN (possible mismatch)",
        "severity": "high",
        "when": lambda f: bool(f.get("host")) and (len(_san_dns(f)) > 0) and (not _host_in_san(str(f.get("host") or ""), _san_dns(f))),
        "evidence": lambda f: {"host": str(f.get("host") or ""), "san_dns": _san_dns(f)[:50]},
        "remediation": "Ensure the certificate SAN includes the exact hostname (or correct wildcard) used by clients.",
        "pqc_mapping": "Correct identity binding reduces migration incidents during crypto changes.",
        "confidence": "high",
        "confidence_reason": "Derived from SAN entries present in the X.509 certificate.",
    },

    # Chain & verify
    
    # Verify failure classification
    {
        "id": "VERIFY_HOSTNAME_MISMATCH",
        "title": "Hostname does not match certificate (SAN/CN mismatch)",
        "severity": "high",
        "when": lambda f: str(f.get("verify_reason") or "") == "hostname_mismatch",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "san_dns": _san_dns(f)[:20],
        },
        "remediation": "Issue a certificate that includes the correct DNS name in SAN and ensure the client connects using the expected hostname.",
        "pqc_mapping": "Correct identity binding prevents migration incidents during crypto transitions.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's hostname mismatch error.",
    },
    {
        "id": "VERIFY_EXPIRED",
        "title": "Certificate is expired (verification failed)",
        "severity": "high",
        "when": lambda f: str(f.get("verify_reason") or "") == "expired",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "not_after": _get_str(f.get("not_after")),
            "days_until_expiry": int(f.get("days_until_expiry") or 0),
        },
        "remediation": "Renew and deploy a valid certificate. Ensure automated renewal and monitoring are in place.",
        "pqc_mapping": "Operational certificate health is foundational for safe PQC/hybrid rollout waves.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's expiry error.",
    },
    {
        "id": "VERIFY_REVOKED",
        "title": "Certificate appears revoked (verification failed)",
        "severity": "critical",
        "when": lambda f: str(f.get("verify_reason") or "") == "revoked",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
        },
        "remediation": "Replace the certificate immediately. Investigate the revocation cause and validate key handling/incident response.",
        "pqc_mapping": "Revocation hygiene becomes more important during high-volume cert rotations and transitions.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's revoked indication.",
    },
    {
        "id": "VERIFY_UNTRUSTED_ISSUER",
        "title": "Certificate chain is untrusted (unknown or self-signed issuer)",
        "severity": "medium",
        "when": lambda f: str(f.get("verify_reason") or "") == "untrusted_issuer",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "issuer": _get_str(f.get("issuer")),
            "chain_source": _get_str(f.get("chain_source")),
        },
        "remediation": "Use a certificate issued by a trusted CA for the target environment, or install the proper trust anchor for internal PKI. Ensure intermediates are served.",
        "pqc_mapping": "Trust consistency reduces surprises when updating crypto primitives and PKI components.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from common CA trust failure messages.",
    },
    {
        "id": "VERIFY_MISSING_INTERMEDIATE",
        "title": "Certificate chain may be incomplete (missing intermediate)",
        "severity": "medium",
        "when": lambda f: str(f.get("verify_reason") or "") == "missing_intermediate",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "chain_length": int(f.get("chain_length") or 0),
            "chain_issues": _get_list(f.get("chain_issues"))[:10],
        },
        "remediation": "Configure the TLS terminator to serve the complete certificate chain (include the correct intermediate certificates).",
        "pqc_mapping": "Chain correctness is critical for frictionless certificate strategy changes during migrations.",
        "confidence": "medium",
        "confidence_reason": "verify_reason is derived from verification errors that commonly indicate missing intermediates.",
    },
    {
        "id": "VERIFY_FAILED",
        "title": "Certificate verification failed for default trust store",
        "severity": "medium",
        "when": lambda f: bool(str(f.get("verify_error") or "").strip()) and str(f.get("verify_reason") or "") in ("", "other", None),
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
        },
        "remediation": "Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
        "pqc_mapping": "Clean PKI reduces migration surprises.",
        "confidence": "high",
        "confidence_reason": "Reported directly by the TLS verification stack.",
    },

    {
        "id": "CHAIN_SHORT_OR_UNAVAILABLE",
        "title": "Certificate chain short or unavailable",
        "severity": "medium",
        "when": lambda f: int(f.get("chain_length") or 0) <= 1,
        "evidence": lambda f: {"chain_length": int(f.get("chain_length") or 0), "chain_source": str(f.get("chain_source") or "")},
        "remediation": "Ensure the server sends the full chain (include correct intermediates).",
        "pqc_mapping": "Chain issues complicate PQC rollouts.",
        "confidence": "medium",
        "confidence_reason": "Chain analysis is best-effort.",
    },
    {
        "id": "CHAIN_MISSING_INTERMEDIATE",
        "title": "Server likely missing intermediate certificate (incomplete chain)",
        "severity": "high",
        "when": lambda f: bool(str(f.get("verify_error") or "").strip()) and ("unable to get local issuer certificate" in str(f.get("verify_error") or "").lower()),
        "evidence": lambda f: {
            "chain_length": int(f.get("chain_length") or 0),
            "chain_source": str(f.get("chain_source") or ""),
            "verify_error": str(f.get("verify_error") or ""),
        },
        "remediation": "Serve the full certificate chain (leaf + intermediate). Use your CA’s 'fullchain' bundle and configure the TLS terminator to send intermediates.",
        "pqc_mapping": "Incomplete chains break clients and complicate crypto migrations.",
        "confidence": "medium",
        "confidence_reason": "Verification failed for default trust store; chain collected via unverified handshake. Validate with openssl s_client for critical endpoints.",
    },

    # Revocation endpoints
    {
        "id": "CERT_NO_CRL_DP",
        "title": "No CRL distribution points advertised",
        "severity": "low",
        "when": lambda f: len(_crl_urls(f)) == 0,
        "evidence": lambda f: {"crl_urls": _crl_urls(f)[:10]},
        "remediation": "Consider adding CRL distribution points to issued certificates if your PKI relies on CRLs.",
        "pqc_mapping": "Revocation hygiene is important during crypto transitions.",
        "confidence": "high",
        "confidence_reason": "CRL Distribution Points are read directly from the X.509 certificate extensions.",
    },
    {
        "id": "CERT_NO_OCSP_AIA",
        "title": "No OCSP responder advertised (AIA)",
        "severity": "low",
        "when": lambda f: len(_ocsp_urls(f)) == 0,
        "evidence": lambda f: {"ocsp_urls": _ocsp_urls(f)[:10]},
        "remediation": "Consider including OCSP AIA in issued certificates, and enable OCSP stapling where appropriate.",
        "pqc_mapping": "Revocation posture matters more as certificate strategies evolve for PQC.",
        "confidence": "high",
        "confidence_reason": "AIA OCSP URLs are read directly from the X.509 certificate extensions.",
    },


    {
        "id": "OCSP_ENDPOINT_UNREACHABLE",
        "title": "OCSP responder advertised but unreachable",
        "severity": "medium",
        "when": lambda f: (len(_ocsp_urls(f)) > 0) and (len(_ocsp_reachability(f)) > 0) and _any_unreachable(_ocsp_reachability(f)),
        "evidence": lambda f: {
            "ocsp_urls": _ocsp_urls(f)[:10],
            "ocsp_reachability": _ocsp_reachability(f)[:5],
        },
        "remediation": "Ensure OCSP responder endpoints in AIA are reachable from clients/TLS terminators (DNS, routing, firewalls). If URLs are incorrect, re-issue certificates with correct AIA OCSP URLs.",
        "pqc_mapping": "Revocation reliability matters during cert churn and transition waves (including PQC/hybrid rollouts).",
        "confidence": "medium",
        "confidence_reason": "Reachability is a best-effort HTTP probe; some responders require POST and may not answer HEAD/GET the same way.",
    },
    {
        "id": "CRL_ENDPOINT_UNREACHABLE",
        "title": "CRL distribution point advertised but unreachable",
        "severity": "medium",
        "when": lambda f: (len(_crl_urls(f)) > 0) and (len(_crl_reachability(f)) > 0) and _any_unreachable(_crl_reachability(f)),
        "evidence": lambda f: {
            "crl_urls": _crl_urls(f)[:10],
            "crl_reachability": _crl_reachability(f)[:5],
        },
        "remediation": "Ensure CRL distribution point endpoints are reachable from clients/TLS terminators. If URLs are incorrect, update issuing CA configuration and re-issue certificates.",
        "pqc_mapping": "Revocation hygiene is important during crypto transitions.",
        "confidence": "medium",
        "confidence_reason": "Reachability is a best-effort HTTP probe and may vary by network path.",
    },

    # OCSP stapling (keep it LOW, advisory)
    {
        "id": "OCSP_STAPLING_MISSING",
        "title": "OCSP stapling not observed",
        "severity": "low",
        "when": lambda f: bool(f.get("ocsp_stapling_supported", False)) and (len(_ocsp_urls(f)) > 0) and (not bool(f.get("ocsp_stapled", False))),
        "evidence": lambda f: {
            "ocsp_urls": _ocsp_urls(f)[:10],
            "ocsp_stapled": bool(f.get("ocsp_stapled", False)),
        },
        "remediation": "Enable OCSP stapling on the TLS terminator (e.g., nginx: ssl_stapling on; ssl_stapling_verify on;).",
        "pqc_mapping": "Stapling reduces revocation latency; helpful during cert rotations and PQC transition waves.",
        "confidence": "low",
        "confidence_reason": "Stapling visibility depends on client/TLS stack support; treat as advisory.",
    },


    {
        "id": "OCSP_STATUS_REVOKED",
        "title": "Stapled OCSP indicates certificate is revoked",
        "severity": "critical",
        "when": lambda f: bool(f.get("ocsp_stapled", False)) and (_ocsp_stapled_status(f) == "revoked"),
        "evidence": lambda f: {
            "ocsp_stapled": bool(f.get("ocsp_stapled", False)),
            "ocsp_stapled_status": f.get("ocsp_stapled_status"),
            "ocsp_response_status": f.get("ocsp_response_status"),
            "ocsp_stapled_this_update": f.get("ocsp_stapled_this_update"),
            "ocsp_stapled_next_update": f.get("ocsp_stapled_next_update"),
        },
        "remediation": "Replace the certificate immediately. Investigate CA revocation cause and ensure correct key handling and incident response.",
        "pqc_mapping": "Operational certificate health is foundational for safe crypto transitions.",
        "confidence": "high",
        "confidence_reason": "Status is parsed from the stapled OCSP response (when present).",
    },
    {
        "id": "OCSP_STAPLED_STALE",
        "title": "Stapled OCSP response appears stale/expired",
        "severity": "low",
        "when": lambda f: bool(f.get("ocsp_stapled", False)) and bool(f.get("ocsp_stapled_is_stale", False)),
        "evidence": lambda f: {
            "ocsp_stapled_is_stale": bool(f.get("ocsp_stapled_is_stale", False)),
            "ocsp_stapled_stale_by_days": f.get("ocsp_stapled_stale_by_days"),
            "ocsp_stapled_this_update": f.get("ocsp_stapled_this_update"),
            "ocsp_stapled_next_update": f.get("ocsp_stapled_next_update"),
        },
        "remediation": "Fix OCSP stapling refresh on the TLS terminator and ensure it can reach the OCSP responder. Verify system clock and stapling cache settings.",
        "pqc_mapping": "Stapling reliability helps reduce revocation latency during certificate rotation waves.",
        "confidence": "medium",
        "confidence_reason": "Staleness is derived from the OCSP nextUpdate timestamp, when present.",
    },

    # PQC crypto posture
    {
        "id": "PQC_RSA_ENDPOINT",
        "title": "RSA certificate key detected (quantum-vulnerable class)",
        "severity": "high",
        "when": lambda f: _key_type(f) == "RSA",
        "evidence": lambda f: {"key_type": "RSA", "key_size": _key_detail(f)},
        "remediation": "Inventory RSA usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "RSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
    {
        "id": "PQC_EC_ENDPOINT",
        "title": "Elliptic-curve public key detected (quantum-vulnerable class)",
        "severity": "medium",
        "when": lambda f: _key_type(f) == "EC",
        "evidence": lambda f: {"key_type": "EC", "curve": _key_detail(f)},
        "remediation": "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
]


# -------------------------
# Core evaluation
# -------------------------

def evaluate_tls_findings(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for rule in RULES:
        try:
            if rule["when"](facts):
                findings.append(
                    make_finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        remediation=rule["remediation"],
                        pqc_mapping=rule.get("pqc_mapping", ""),
                        evidence=(rule.get("evidence") or (lambda f: {}))(facts),
                        confidence=rule.get("confidence", "medium"),
                        confidence_reason=rule.get("confidence_reason", ""),
                    )
                )
        except Exception:
            # best-effort rules
            continue

    findings.sort(key=lambda x: _sev_rank(x.get("severity", "")), reverse=True)
    return findings


def risk_level_from_findings(findings: List[Dict[str, Any]]) -> str:
    worst = "low"
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if _sev_rank(sev) > _sev_rank(worst):
            worst = sev
    return worst


def derive_risk_and_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Simple scoring: sum severity points, capped.
    points_map = {"critical": 30, "high": 18, "medium": 8, "low": 2, "info": 1}
    score = 0
    for f in findings:
        score += points_map.get((f.get("severity") or "low").lower(), 0)
    score = max(0, min(100, score))

    risk_level = risk_level_from_findings(findings)
    # Keep UI-friendly labels
    risk_label = risk_level

    # Quantum risk level here is a *separate* label: we keep it conservative.
    # (Your UI already shows quantum_risk_level; you can refine later.)
    if any((f.get("rule_id") == "PQC_RSA_ENDPOINT") for f in findings):
        q_level = "high"
    elif any((f.get("rule_id") == "PQC_EC_ENDPOINT") for f in findings):
        q_level = "medium"
    else:
        q_level = "low"

    return {
        "risk_level": risk_level,
        "risk_label": risk_label,
        "quantum_risk_score": score,
        "quantum_risk_level": q_level,
    }


def derive_pqc_relevance(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    has_rsa = any(f.get("rule_id") == "PQC_RSA_ENDPOINT" for f in findings)
    has_ec = any(f.get("rule_id") == "PQC_EC_ENDPOINT" for f in findings)

    if has_rsa:
        return {
            "pqc_relevance": "HIGH",
            "pqc_recommendation": "RSA endpoint detected. Track hybrid TLS readiness and plan a staged migration (crypto-agile).",
        }
    if has_ec:
        return {
            "pqc_relevance": "MEDIUM",
            "pqc_recommendation": "ECC endpoint detected. Maintain crypto-agility and monitor PQC/hybrid TLS deployments.",
        }
    return {
        "pqc_relevance": "LOW",
        "pqc_recommendation": "Unknown key type. Maintain crypto-agility and track PQC readiness.",
    }


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "errors": 0}
    rsa_count = 0
    worst = "low"
    max_score = 0

    for r in results:
        if (r.get("error") or "").strip():
            counts["errors"] += 1

        findings = r.get("findings") or []
        lvl = risk_level_from_findings(findings)
        if _sev_rank(lvl) > _sev_rank(worst):
            worst = lvl

        score = int(r.get("quantum_risk_score") or 0)
        max_score = max(max_score, score)

        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
            if f.get("rule_id") == "PQC_RSA_ENDPOINT":
                rsa_count += 1

    # quantum_risk_level: based on max_score (simple)
    if max_score >= 70:
        qlvl = "high"
    elif max_score >= 35:
        qlvl = "medium"
    else:
        qlvl = "low"

    return {
        "total": total,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "errors": counts["errors"],
        "rsa_count": rsa_count,
        "quantum_risk_score": max_score,
        "quantum_risk_level": qlvl,
    }


# -------------------------
# Backwards-compat exports
# (so you don't break imports when you revert files)
# -------------------------

def evaluate_policies(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    return evaluate_tls_findings(facts)


def pqc_relevance_and_reco(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    return derive_pqc_relevance(findings)


def risk_level_from_findings_wrapper(findings: List[Dict[str, Any]]) -> str:
    return risk_level_from_findings(findings)


# Keep the exact old names some of your versions imported:
risk_level_from_findings.__name__ = "risk_level_from_findings"
