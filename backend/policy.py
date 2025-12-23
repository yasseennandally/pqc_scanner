from typing import Dict, Any, List, Callable, Optional, Tuple

# policy.py
# Facts (from scanner.py) -> Findings (data-driven rules)
# Python 3.6 compatible.

Severity = str  # "critical" | "high" | "medium" | "low"
Confidence = str  # "high" | "medium" | "low"


def _sev_rank(sev: Severity) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 9)


def _sev_points(sev: Severity) -> int:
    # Used for scoring (bigger = worse)
    return {"critical": 12, "high": 8, "medium": 4, "low": 1}.get(sev, 0)


def _supported_versions(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("tls_supported_versions") or []
    return v if isinstance(v, list) else []


def _support_map(facts: Dict[str, Any]) -> Dict[str, bool]:
    m = facts.get("tls_support_map") or {}
    return m if isinstance(m, dict) else {}


def _probe_errors(facts: Dict[str, Any]) -> Dict[str, str]:
    m = facts.get("tls_probe_errors") or {}
    return m if isinstance(m, dict) else {}


def _weak_accepted(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("tls12_weak_accepted_ciphers") or []
    return v if isinstance(v, list) else []


def _accepted_ciphers(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("tls12_accepted_ciphers") or []
    return v if isinstance(v, list) else []


def _chain_issues(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    v = facts.get("chain_issues") or []
    return v if isinstance(v, list) else []


def _days_until_expiry(facts: Dict[str, Any]) -> Optional[int]:
    d = facts.get("days_until_expiry")
    if d is None:
        d = facts.get("days_to_expiry")
    return d if isinstance(d, int) else None


RuleWhen = Callable[[Dict[str, Any]], bool]
RuleEvidence = Callable[[Dict[str, Any]], Dict[str, Any]]
RuleConfidence = Callable[[Dict[str, Any]], Tuple[Confidence, str]]


def _default_confidence(_: Dict[str, Any]) -> Tuple[Confidence, str]:
    return ("medium", "Heuristic rule; evidence provided in finding.")


def make_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    remediation: str,
    pqc_mapping: str,
    evidence: Optional[Dict[str, Any]] = None,
    confidence: Confidence = "medium",
    confidence_reason: str = "",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "remediation": remediation,
        "pqc_mapping": pqc_mapping,
        "evidence": evidence or {},
        "confidence": confidence,
        "confidence_reason": confidence_reason,
    }


# -------------------------
# Policy Rules (data-driven)
# -------------------------
# Each rule:
# - id, title, severity
# - when(facts) -> bool
# - evidence(facts) -> dict
# - confidence(facts) -> (level, reason)
RULES: List[Dict[str, Any]] = [
    {
        "id": "LEGACY_TLS_SUPPORTED",
        "title": "Legacy TLS versions supported",
        "severity": "critical",
        "when": lambda f: ("TLSv1.0" in _supported_versions(f)) or ("TLSv1.1" in _supported_versions(f)),
        "evidence": lambda f: {
            "supported_versions": _supported_versions(f),
            "probe_errors": _probe_errors(f),
        },
        "confidence": lambda f: ("high", "Observed successful handshake using legacy protocol(s)."),
        "remediation": "Disable TLS 1.0/1.1. Require TLS 1.2+ and prefer TLS 1.3.",
        "pqc_mapping": "Crypto-agility prerequisite for PQC/hybrid TLS rollout.",
    },
    {
        "id": "NO_TLS13",
        "title": "TLS 1.3 not supported",
        "severity": "high",
        "when": lambda f: ("TLSv1.3" not in _supported_versions(f)) and (len(_supported_versions(f)) > 0),
        "evidence": lambda f: {
            "supported_versions": _supported_versions(f),
            "tls13_probe_error": _probe_errors(f).get("TLSv1.3", ""),
        },
        "confidence": lambda f: (
            "medium",
            "TLS 1.3 probe is best-effort (depends on client OpenSSL/Python). Validate at termination layer.",
        ),
        "remediation": "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
        "pqc_mapping": "TLS 1.3 is a practical prerequisite for hybrid/PQC key exchange deployments.",
    },
    {
        "id": "WEAK_CIPHER_ACCEPTED",
        "title": "Weak TLS 1.2 ciphers accepted by server",
        "severity": "critical",
        "when": lambda f: len(_weak_accepted(f)) > 0,
        "evidence": lambda f: {
            "weak_accepted_ciphers": _weak_accepted(f),
            "accepted_ciphers_sample": _accepted_ciphers(f)[:10],
        },
        "confidence": lambda f: ("high", "At least one weak cipher was negotiated during probing."),
        "remediation": "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
        "pqc_mapping": "Baseline hardening should be done before any PQC/hybrid rollout.",
    },
    {
        "id": "NO_FORWARD_SECRECY",
        "title": "Forward secrecy not observed/likely disabled",
        "severity": "medium",
        "when": lambda f: (len(_supported_versions(f)) > 0) and (not bool(f.get("forward_secrecy_possible"))),
        "evidence": lambda f: {
            "forward_secrecy_possible": bool(f.get("forward_secrecy_possible")),
            "accepted_ciphers_sample": _accepted_ciphers(f)[:10],
        },
        "confidence": lambda f: ("medium", "Based on negotiated cipher suite probes; validate full server cipher list if needed."),
        "remediation": "Prefer ECDHE/DHE cipher suites to ensure forward secrecy for TLS 1.2, and migrate to TLS 1.3.",
        "pqc_mapping": "FS hygiene reduces blast radius during algorithm transitions.",
    },
    {
        "id": "CERT_EXPIRED",
        "title": "Certificate expired",
        "severity": "critical",
        "when": lambda f: (_days_until_expiry(f) is not None) and (_days_until_expiry(f) < 0),
        "evidence": lambda f: {"days_until_expiry": _days_until_expiry(f), "not_after": f.get("not_after", "")},
        "confidence": lambda f: ("high", "Derived from X.509 notAfter timestamp."),
        "remediation": "Renew immediately and ensure automated renewal/monitoring.",
        "pqc_mapping": "Expiring cert events are good windows to adopt crypto-agile configurations.",
    },
    {
        "id": "CERT_EXPIRING_SOON",
        "title": "Certificate expiring soon",
        "severity": "high",
        "when": lambda f: (_days_until_expiry(f) is not None) and (_days_until_expiry(f) <= 30) and (_days_until_expiry(f) >= 0),
        "evidence": lambda f: {"days_until_expiry": _days_until_expiry(f), "not_after": f.get("not_after", "")},
        "confidence": lambda f: ("high", "Derived from X.509 notAfter timestamp."),
        "remediation": "Renew/rotate soon. Verify automation for renewals.",
        "pqc_mapping": "Regular rotations reduce risk during crypto migrations.",
    },
    {
        "id": "VERIFY_FAILED",
        "title": "Certificate verification failed for default trust store",
        "severity": "medium",
        "when": lambda f: bool((f.get("verify_error") or "").strip()),
        "evidence": lambda f: {"verify_error": f.get("verify_error", "")},
        "confidence": lambda f: ("high", "TLS verification failed using the local trust store."),
        "remediation": "Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
        "pqc_mapping": "Trust failures block reliable inventory and complicate PQC migration planning.",
    },
    {
        "id": "WEAK_SIGNATURE_IN_CHAIN",
        "title": "Weak signature algorithm detected in certificate chain",
        "severity": "high",
        "when": lambda f: bool(f.get("chain_has_weak_sig")),
        "evidence": lambda f: {"chain_has_weak_sig": True, "chain_length": f.get("chain_length", 0)},
        "confidence": lambda f: ("medium", "Based on parsed certificate chain (may be best-effort on some Python/OpenSSL builds)."),
        "remediation": "Replace/rotate the weakly-signed certificate(s) in the chain (avoid SHA1/MD5).",
        "pqc_mapping": "Modern PKI hygiene is a prerequisite before introducing PQC/hybrid changes.",
    },
    {
        "id": "CHAIN_ISSUES_PRESENT",
        "title": "Certificate chain issues detected",
        "severity": "medium",
        "when": lambda f: len(_chain_issues(f)) > 0,
        "evidence": lambda f: {"chain_issues": _chain_issues(f), "chain_length": f.get("chain_length", 0)},
        "confidence": lambda f: ("medium", "Chain analysis is best-effort; validate with openssl s_client if this endpoint is critical."),
        "remediation": "Fix chain linkage/intermediate CA constraints and ensure proper chain delivery.",
        "pqc_mapping": "Clean PKI chain reduces migration surprises and operational risk.",
    },
    {
        "id": "CERT_NO_OCSP_AIA",
        "title": "No OCSP responder advertised (AIA)",
        "severity": "low",
        "when": lambda f: bool(f.get("cert_no_ocsp_aia")),
        "evidence": lambda f: {"cert_no_ocsp_aia": True},
        "confidence": lambda f: ("medium", "Derived from X.509 AIA extension presence/absence."),
        "remediation": "Consider using OCSP/AIA (and stapling where appropriate) for stronger revocation posture.",
        "pqc_mapping": "Revocation posture matters more as certificate strategies evolve for PQC.",
    },
    {
        "id": "PQC_RSA_ENDPOINT",
        "title": "RSA certificate key detected (PQC priority)",
        "severity": "high",
        "when": lambda f: (f.get("key_type") or "").upper() == "RSA",
        "evidence": lambda f: {"key_type": "RSA", "key_size": f.get("key_detail")},
        "confidence": lambda f: ("high", "Public key algorithm extracted from the presented X.509 certificate."),
        "remediation": "Prioritize for crypto agility. Short-term: consider ECDSA certs. Plan hybrid/PQC when supported.",
        "pqc_mapping": "RSA → PQC/hybrid planning (Kyber KEM; Dilithium signatures when ecosystem is ready).",
    },
    {
        "id": "PQC_EC_ENDPOINT",
        "title": "Elliptic-curve public key detected (quantum-vulnerable class)",
        "severity": "medium",
        "when": lambda f: (f.get("key_type") or "").upper() == "EC",
        "evidence": lambda f: {"key_type": "EC", "curve": f.get("key_detail")},
        "confidence": lambda f: ("high", "Public key algorithm extracted from the presented X.509 certificate."),
        "remediation": "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
    },
]


def evaluate_policies(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert facts -> structured findings (with evidence + confidence).
    """
    findings: List[Dict[str, Any]] = []

    for r in RULES:
        when = r.get("when")
        if when and when(facts):
            ev_fn = r.get("evidence", lambda f: {})
            conf_fn = r.get("confidence", _default_confidence)

            ev = ev_fn(facts) if ev_fn else {}
            conf_level, conf_reason = conf_fn(facts) if conf_fn else _default_confidence(facts)

            findings.append(
                make_finding(
                    rule_id=r.get("id", ""),
                    title=r.get("title", ""),
                    severity=r.get("severity", "low"),
                    remediation=r.get("remediation", ""),
                    pqc_mapping=r.get("pqc_mapping", ""),
                    evidence=ev,
                    confidence=conf_level,
                    confidence_reason=conf_reason,
                )
            )

    # Sort by severity then rule_id
    findings.sort(key=lambda x: (_sev_rank(x.get("severity", "low")), x.get("rule_id", "")))
    return findings


def derive_risk_and_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce:
      - risk_level: high/medium/low
      - risk_label: string (compat for UI)
      - quantum_risk_score: 0..100 (higher is better)
      - quantum_risk_level: high/medium/low (higher is worse)
    """
    if not findings:
        return {
            "risk_level": "low",
            "risk_label": "low",
            "quantum_risk_score": 100,
            "quantum_risk_level": "low",
        }

    # Compute points
    points = 0
    worst_rank = 9
    reasons: List[str] = []

    for f in findings:
        sev = f.get("severity", "low")
        points += _sev_points(sev)
        worst_rank = min(worst_rank, _sev_rank(sev))
        rid = f.get("rule_id", "")
        if rid:
            reasons.append(rid)

    # Map worst_rank -> risk level
    if worst_rank <= 1:
        risk_level = "high"
    elif worst_rank == 2:
        risk_level = "medium"
    else:
        risk_level = "low"

    # 0..100 score (higher = better)
    score = 100 - points
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    # quantum_risk_level is inverse of score
    if score >= 80:
        quantum_level = "low"
    elif score >= 50:
        quantum_level = "medium"
    else:
        quantum_level = "high"

    # Keep compat label as "critical (...)" etc if severe
    if worst_rank == 0:
        label = "critical (%s)" % (", ".join(reasons[:8]) + ("..." if len(reasons) > 8 else ""))
    elif worst_rank == 1:
        label = "high (%s)" % (", ".join(reasons[:8]) + ("..." if len(reasons) > 8 else ""))
    elif worst_rank == 2:
        label = "medium (%s)" % (", ".join(reasons[:8]) + ("..." if len(reasons) > 8 else ""))
    else:
        label = "low (%s)" % (", ".join(reasons[:8]) + ("..." if len(reasons) > 8 else ""))

    return {
        "risk_level": risk_level,
        "risk_label": label,
        "quantum_risk_score": score,
        "quantum_risk_level": quantum_level,
    }


def derive_pqc_relevance(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce per-endpoint PQC relevance and a short recommendation.
    """
    relevance = "low"
    recs: List[str] = []

    for f in findings:
        rid = f.get("rule_id", "")
        if rid == "PQC_RSA_ENDPOINT":
            relevance = "high"
            recs.append("RSA endpoint: prioritize crypto-agility and plan hybrid/PQC rollout.")
        elif rid == "PQC_EC_ENDPOINT" and relevance != "high":
            relevance = "medium"
            recs.append("ECC endpoint: inventory ECC usage and plan PQC/hybrid design as ecosystem matures.")

    if not recs:
        recs.append("No RSA/ECC key detected. Continue inventory and focus on TLS hardening + crypto agility.")

    return {
        "pqc_relevance": relevance,
        "pqc_recommendation": " ".join(recs)[:500],
    }
