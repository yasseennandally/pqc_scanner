from typing import Dict, Any, List, Callable, Optional

Severity = str  # "critical" | "high" | "medium" | "low"

RuleWhen = Callable[[Dict[str, Any]], bool]
RuleEvidence = Callable[[Dict[str, Any]], Dict[str, Any]]


def _sev_rank(sev: Severity) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get((sev or "low").lower(), 9)


def _sev_points(sev: Severity) -> int:
    # scoring: bigger = worse
    return {"critical": 12, "high": 8, "medium": 4, "low": 1}.get((sev or "low").lower(), 0)


def _supported_versions(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("tls_supported_versions") or []
    return v if isinstance(v, list) else []


def _weak_accepted(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("tls12_weak_accepted_ciphers") or []
    return v if isinstance(v, list) else []


def _chain_issues(facts: Dict[str, Any]) -> List[str]:
    v = facts.get("chain_issues") or []
    # scanner stores list[str]
    return v if isinstance(v, list) else []


def make_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    remediation: str,
    pqc_mapping: str,
    confidence: str,
    confidence_reason: str,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": (severity or "low").lower(),
        "remediation": remediation,
        "pqc_mapping": pqc_mapping,
        "confidence": (confidence or "medium").lower(),
        "confidence_reason": confidence_reason or "",
        "evidence": evidence or {},
    }


# -------------------------
# Rules registry (data-driven)
# -------------------------
RULES: List[Dict[str, Any]] = [
    # ---- TLS protocol posture ----
    {
        "id": "LEGACY_TLS_SUPPORTED",
        "title": "Legacy TLS versions supported",
        "severity": "critical",
        "when": lambda f: ("TLSv1.0" in _supported_versions(f)) or ("TLSv1.1" in _supported_versions(f)),
        "evidence": lambda f: {"supported_versions": _supported_versions(f)},
        "remediation": "Disable TLS 1.0/1.1. Require TLS 1.2+ and prefer TLS 1.3.",
        "pqc_mapping": "Crypto-agility prerequisite for PQC/hybrid TLS rollout.",
        "confidence": "high",
        "confidence_reason": "Derived from active protocol negotiation probes.",
    },
    {
        "id": "NO_TLS13",
        "title": "TLS 1.3 not supported",
        "severity": "high",
        "when": lambda f: ("TLSv1.3" not in _supported_versions(f)) and bool(_supported_versions(f)),
        "evidence": lambda f: {"supported_versions": _supported_versions(f)},
        "remediation": "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
        "pqc_mapping": "TLS 1.3 is the typical base for hybrid / PQC-ready deployment paths.",
        "confidence": "high",
        "confidence_reason": "Based on protocol probes; false positives are rare when probes succeed.",
    },

    # ---- Cipher posture ----
    {
        "id": "WEAK_CIPHER_ACCEPTED",
        "title": "Weak TLS 1.2 ciphers accepted by server",
        "severity": "critical",
        "when": lambda f: len(_weak_accepted(f)) > 0,
        "evidence": lambda f: {"weak_accepted_ciphers": _weak_accepted(f)},
        "remediation": "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
        "pqc_mapping": "Baseline hardening should be done before any PQC/hybrid rollout.",
        "confidence": "high",
        "confidence_reason": "Detected by active cipher negotiation attempts against the server.",
    },
    {
        "id": "NO_FORWARD_SECRECY",
        "title": "Forward secrecy not observed/likely disabled",
        "severity": "medium",
        "when": lambda f: (f.get("forward_secrecy_possible") is False),
        "evidence": lambda f: {
            "cipher_name": f.get("cipher_name", ""),
            "tls_version": f.get("tls_version", ""),
            "forward_secrecy_possible": f.get("forward_secrecy_possible"),
        },
        "remediation": "Prefer ECDHE/DHE cipher suites to ensure forward secrecy for TLS 1.2, and migrate to TLS 1.3.",
        "pqc_mapping": "FS hygiene reduces blast radius during algorithm transitions.",
        "confidence": "medium",
        "confidence_reason": "Inference from negotiated cipher; verify with a full cipher sweep if critical.",
    },

    # ---- Certificate and chain posture ----
    {
        "id": "CERT_EXPIRED",
        "title": "Certificate expired",
        "severity": "critical",
        "when": lambda f: bool((f.get("days_until_expiry") is not None) and (f.get("days_until_expiry") < 0)),
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Renew/replace the certificate immediately. Fix automation to avoid recurrence.",
        "pqc_mapping": "Operational hygiene is required before PQC migration planning.",
        "confidence": "high",
        "confidence_reason": "Computed directly from X.509 validity timestamps.",
    },
    {
        "id": "CERT_EXPIRING_SOON",
        "title": "Certificate expiring soon",
        "severity": "high",
        "when": lambda f: bool((f.get("days_until_expiry") is not None) and (0 <= f.get("days_until_expiry") <= 30)),
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Renew/replace the certificate within 30 days. Ensure rotation automation.",
        "pqc_mapping": "Upcoming rotations are a good window to introduce crypto-agility improvements.",
        "confidence": "high",
        "confidence_reason": "Computed directly from X.509 validity timestamps.",
    },
    {
        "id": "CHAIN_ISSUES_PRESENT",
        "title": "Certificate chain issues detected",
        "severity": "medium",
        "when": lambda f: len(_chain_issues(f)) > 0,
        "evidence": lambda f: {"chain_issues": _chain_issues(f), "chain_length": f.get("chain_length")},
        "remediation": "Fix chain linkage/intermediate CA constraints and ensure proper chain delivery.",
        "pqc_mapping": "Clean PKI chain reduces migration surprises and operational risk.",
        "confidence": "medium",
        "confidence_reason": "Chain analysis is best-effort; validate with openssl s_client if critical.",
    },
    {
        "id": "VERIFY_FAILED",
        "title": "TLS verification failed (trust/hostname/chain)",
        "severity": "medium",
        "when": lambda f: bool((f.get("verify_error") or "").strip()),
        "evidence": lambda f: {"verify_error": f.get("verify_error", ""), "verify_mode": f.get("verify_mode", "")},
        "remediation": "Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
        "pqc_mapping": "Trust failures block reliable inventory and complicate PQC migration planning.",
        "confidence": "high",
        "confidence_reason": "Direct error returned by verified TLS handshake attempt.",
    },
    {
        "id": "CERT_HOSTNAME_MISMATCH",
        "title": "Certificate hostname/SAN mismatch",
        "severity": "high",
        "when": lambda f: (f.get("hostname_match") is False),
        "evidence": lambda f: {
            "hostname_match": f.get("hostname_match"),
            "san_dns": f.get("san_dns", []),
            "common_name": f.get("common_name", ""),
        },
        "remediation": "Issue a certificate that matches the exact hostname (SAN) and deploy it on the correct endpoint.",
        "pqc_mapping": "Accurate endpoint identity is required before PQC/hybrid TLS rollout.",
        "confidence": "high",
        "confidence_reason": "Match computed from certificate SAN/CN vs scanned host.",
    },
    {
        "id": "CERT_NO_OCSP_AIA",
        "title": "No OCSP responder advertised (AIA)",
        "severity": "low",
        "when": lambda f: not bool(f.get("ocsp_aia_uris")),
        "evidence": lambda f: {"ocsp_aia_uris": f.get("ocsp_aia_uris", [])},
        "remediation": "Consider using OCSP/AIA (and stapling where appropriate) for stronger revocation posture.",
        "pqc_mapping": "Revocation posture matters more as certificate strategies evolve for PQC.",
        "confidence": "high",
        "confidence_reason": "Extracted from Authority Information Access extension if present.",
    },
    {
        "id": "CERT_NO_CRL_DP",
        "title": "No CRL distribution points advertised",
        "severity": "low",
        "when": lambda f: not bool(f.get("crl_distribution_points")),
        "evidence": lambda f: {"crl_distribution_points": f.get("crl_distribution_points", [])},
        "remediation": "Consider publishing CRL distribution points to improve revocation coverage.",
        "pqc_mapping": "Revocation posture matters more as certificate strategies evolve for PQC.",
        "confidence": "medium",
        "confidence_reason": "Extracted from CRL Distribution Points extension when available; not always required.",
    },

    # ---- PQC relevance ----
    {
        "id": "PQC_RSA_ENDPOINT",
        "title": "RSA public key detected (quantum-vulnerable class)",
        "severity": "high",
        "when": lambda f: (f.get("key_type") == "RSA"),
        "evidence": lambda f: {"key_type": f.get("key_type"), "key_detail": f.get("key_detail")},
        "remediation": "Inventory RSA usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "RSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
    {
        "id": "PQC_EC_ENDPOINT",
        "title": "Elliptic-curve public key detected (quantum-vulnerable class)",
        "severity": "medium",
        "when": lambda f: (f.get("key_type") == "EC"),
        "evidence": lambda f: {"key_type": f.get("key_type"), "curve": f.get("key_detail")},
        "remediation": "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },

    # ---- Optional posture (useful for enterprise reports) ----
    {
        "id": "HSTS_MISSING",
        "title": "HSTS header not observed",
        "severity": "low",
        "when": lambda f: (f.get("hsts_present") is False),
        "evidence": lambda f: {"hsts_present": f.get("hsts_present"), "hsts": f.get("hsts", "")},
        "remediation": "Consider enabling Strict-Transport-Security with an appropriate max-age (and includeSubDomains if safe).",
        "pqc_mapping": "Not directly PQC, but strengthens transport posture and reduces downgrade risk.",
        "confidence": "medium",
        "confidence_reason": "Best-effort HTTP(S) HEAD probe; redirects/CDNs may affect observation.",
    },
    {
        "id": "SNI_REQUIRED",
        "title": "SNI appears required for correct certificate",
        "severity": "low",
        "when": lambda f: bool(f.get("sni_required")),
        "evidence": lambda f: {"sni_required": f.get("sni_required")},
        "remediation": "Ensure scanners/clients provide SNI; document front-door hostname routing.",
        "pqc_mapping": "Scan accuracy depends on correct SNI during inventory and migration planning.",
        "confidence": "medium",
        "confidence_reason": "Observed difference between handshake with SNI vs without SNI.",
    },
]


def evaluate_policies(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for r in RULES:
        when: RuleWhen = r["when"]
        if when(facts):
            ev_fn: RuleEvidence = r.get("evidence", lambda f: {})
            ev = ev_fn(facts)
            findings.append(
                make_finding(
                    rule_id=r["id"],
                    title=r["title"],
                    severity=r["severity"],
                    remediation=r["remediation"],
                    pqc_mapping=r["pqc_mapping"],
                    confidence=r.get("confidence", "medium"),
                    confidence_reason=r.get("confidence_reason", ""),
                    evidence=ev,
                )
            )

    findings.sort(key=lambda x: (_sev_rank(x.get("severity", "low")), x.get("rule_id", "")))
    return findings


def derive_risk_and_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convert findings -> risk label + quantum score.
    """
    if not findings:
        return {
            "risk_level": "low",
            "risk": "low",
            "quantum_risk_score": 95,
            "quantum_risk_level": "low",
        }

    # Worst severity drives risk_level
    worst = min((_sev_rank(f.get("severity", "low")) for f in findings), default=3)
    risk_level = {0: "critical", 1: "high", 2: "medium", 3: "low"}.get(worst, "low")

    # Score: start at 100 and subtract points for each finding
    points = sum(_sev_points(f.get("severity", "low")) for f in findings)
    score = 100 - points
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score >= 80:
        qlvl = "low"
    elif score >= 50:
        qlvl = "medium"
    else:
        qlvl = "high"

    return {
        "risk_level": risk_level,
        "risk": f"{risk_level} ({', '.join([f.get('rule_id','') for f in findings[:6]])}{'...' if len(findings)>6 else ''})",
        "quantum_risk_score": score,
        "quantum_risk_level": qlvl,
    }


def derive_pqc_relevance(facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simple PQC relevance labels based on certificate key algorithm class.
    """
    kt = (facts.get("key_type") or "").upper()
    if kt == "RSA":
        return {"pqc_relevance": "high", "pqc_recommendation": "Prioritize RSA inventory and plan hybrid/PQC migration (Kyber KEM + PQC signatures)."}
    if kt == "EC":
        return {"pqc_relevance": "medium", "pqc_recommendation": "ECC is quantum-vulnerable class; inventory ECDH/ECDSA and plan hybrid/PQC migration."}
    if kt:
        return {"pqc_relevance": "low", "pqc_recommendation": "Key type not classically targeted by Shor; still keep crypto-agility and TLS posture strong."}
    return {"pqc_relevance": "unknown", "pqc_recommendation": "Insufficient certificate info; verify endpoint and re-scan."}
