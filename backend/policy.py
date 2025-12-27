# policy.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

Severity = str  # "critical"|"high"|"medium"|"low"

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    fix: str
    pqc_note: str
    confidence: str  # "high"|"medium"|"low"
    confidence_reason: str
    when: Callable[[Dict[str, Any]], bool]
    evidence: Callable[[Dict[str, Any]], Dict[str, Any]]


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get((sev or "").lower(), 0)


def evaluate_findings(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert facts -> ordered findings list.
    Each finding is stable and UI-friendly:
      - id, severity, title, fix
      - confidence, confidence_reason
      - evidence (machine-readable)
      - pqc_note
    """
    findings: List[Dict[str, Any]] = []
    for rule in RULES:
        try:
            if rule.when(facts):
                findings.append(
                    {
                        "id": rule.id,
                        "severity": rule.severity.upper(),
                        "title": rule.title,
                        "fix": rule.fix,
                        "pqc_note": rule.pqc_note,
                        "confidence": rule.confidence,
                        "confidence_reason": rule.confidence_reason,
                        "evidence": rule.evidence(facts),
                    }
                )
        except Exception:
            # Never let one rule break the scan.
            continue

    findings.sort(key=lambda f: _sev_rank(f.get("severity", "").lower()), reverse=True)
    return findings


def risk_level_from_findings(findings: List[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Returns (risk_label, risk_level) where:
      risk_label is e.g. "critical (RULE1, RULE2)"
      risk_level is one of: "critical"|"high"|"medium"|"low"
    """
    if not findings:
        return ("low", "low")

    top = max((_sev_rank(f["severity"].lower()) for f in findings), default=1)
    level = {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(top, "low")
    ids = [f.get("id", "") for f in findings if f.get("id")]
    label = f"{level} ({', '.join(ids)})" if ids else level
    return (label, level)


def pqc_relevance_and_reco(facts: Dict[str, Any], findings: List[Dict[str, Any]]) -> Tuple[str, str]:
    """
    This is your PQC angle:
      - RSA/EC endpoints => HIGH PQC relevance
      - otherwise MEDIUM/LOW
    """
    key_type = (facts.get("key_type") or "").upper()

    if key_type in ("RSA", "EC"):
        if key_type == "RSA":
            return (
                "HIGH",
                "Endpoint uses RSA. Plan hybrid/PQC migration: Kyber (KEM) + Dilithium/Falcon (signatures) with crypto-agility.",
            )
        return (
            "HIGH",
            "Endpoint uses ECC (ECDSA/ECDH class). Plan hybrid/PQC migration: Kyber (KEM) + Dilithium/Falcon (signatures) with crypto-agility.",
        )

    # If we detect legacy TLS / weak ciphers, still PQC-relevant as “hygiene prerequisite”
    ids = {f.get("id") for f in findings}
    if "LEGACY_TLS_SUPPORTED" in ids or "NO_TLS13" in ids or "WEAK_CIPHER_ACCEPTED" in ids:
        return (
            "MEDIUM",
            "Crypto-agility prerequisite: harden TLS configs and enable TLS 1.3 before PQC/hybrid rollout.",
        )

    return ("LOW", "No direct RSA/ECC certificate key detected. Focus on crypto inventory and readiness.")


# ----------------- Rules -----------------

def _list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


RULES: List[Rule] = [
    Rule(
        id="CERT_EXPIRED",
        title="Certificate expired",
        severity="high",
        fix="Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
        pqc_note="Operational PKI hygiene matters before PQC transitions.",
        confidence="high",
        confidence_reason="Expiry is computed from the presented X.509 certificate.",
        when=lambda f: (f.get("days_until_expiry") is not None) and (f.get("days_until_expiry") < 0),
        evidence=lambda f: {
            "days_until_expiry": f.get("days_until_expiry"),
            "not_after": f.get("not_after"),
        },
    ),
    Rule(
        id="CERT_EXPIRING_SOON",
        title="Certificate expiring soon",
        severity="medium",
        fix="Schedule certificate renewal/rotation soon; ensure renewal automation.",
        pqc_note="Short-lived cert strategies often change during PQC migration.",
        confidence="high",
        confidence_reason="Expiry is computed from the presented X.509 certificate.",
        when=lambda f: (f.get("days_until_expiry") is not None) and (0 <= f.get("days_until_expiry") <= 14),
        evidence=lambda f: {"days_until_expiry": f.get("days_until_expiry")},
    ),
    Rule(
        id="NO_TLS13",
        title="TLS 1.3 not supported",
        severity="high",
        fix="Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
        pqc_note="Hybrid/PQC TLS is typically built on modern TLS stacks; TLS 1.3 readiness is key.",
        confidence="high",
        confidence_reason="Derived from active protocol probes.",
        when=lambda f: "TLSv1.3" not in _list(f.get("tls_supported_versions")),
        evidence=lambda f: {"tls_supported_versions": _list(f.get("tls_supported_versions"))},
    ),
    Rule(
        id="LEGACY_TLS_SUPPORTED",
        title="Legacy TLS versions supported",
        severity="critical",
        fix="Disable TLS 1.0/1.1. Require TLS 1.2+ and prefer TLS 1.3.",
        pqc_note="Baseline hardening should be done before any PQC/hybrid rollout.",
        confidence="high",
        confidence_reason="Derived from active protocol probes.",
        when=lambda f: any(v in ("TLSv1.0", "TLSv1.1") for v in _list(f.get("tls_supported_versions"))),
        evidence=lambda f: {"tls_supported_versions": _list(f.get("tls_supported_versions"))},
    ),
    Rule(
        id="WEAK_CIPHER_ACCEPTED",
        title="Weak TLS 1.2 ciphers accepted by server",
        severity="critical",
        fix="Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
        pqc_note="Baseline hardening should be done before any PQC/hybrid rollout.",
        confidence="medium",
        confidence_reason="Best-effort probe; depends on client OpenSSL cipher support.",
        when=lambda f: len(_list(f.get("tls12_weak_accepted_ciphers"))) > 0,
        evidence=lambda f: {"tls12_weak_accepted_ciphers": _list(f.get("tls12_weak_accepted_ciphers"))},
    ),
    Rule(
        id="VERIFY_FAILED",
        title="Certificate verification failed for default trust store",
        severity="medium",
        fix="Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
        pqc_note="Clean PKI reduces migration surprises and operational risk.",
        confidence="high",
        confidence_reason="Reported directly by the TLS verification stack.",
        when=lambda f: bool(f.get("verify_error")),
        evidence=lambda f: {"verify_error": f.get("verify_error")},
    ),
    Rule(
        id="CHAIN_SHORT_OR_UNAVAILABLE",
        title="Certificate chain short or unavailable",
        severity="medium",
        fix="Ensure the server sends the full chain (include correct intermediates).",
        pqc_note="Clean PKI reduces migration surprises and operational risk.",
        confidence="high",
        confidence_reason="Chain comes from get_verified_chain (client-side verified path).",
        when=lambda f: (f.get("chain_length") is not None) and (f.get("chain_length") <= 1),
        evidence=lambda f: {"chain_length": f.get("chain_length"), "chain_source": f.get("chain_source")},
    ),
    Rule(
        id="CHAIN_MISSING_INTERMEDIATE",
        title="Server likely missing intermediate certificate (incomplete chain)",
        severity="high",
        fix="Serve the full certificate chain (leaf + intermediate). Use your CA’s 'fullchain' bundle and configure the TLS terminator to send intermediates.",
        pqc_note="Chain correctness matters when rotating to PQC/hybrid certificates.",
        confidence="medium",
        confidence_reason="Verification failed for default trust store; chain collected via unverified handshake. Validate with openssl s_client for critical endpoints.",
        when=lambda f: bool(f.get("verify_error")) and (f.get("chain_length") is not None) and (f.get("chain_length") <= 1),
        evidence=lambda f: {"chain_length": f.get("chain_length"), "chain_source": f.get("chain_source"), "verify_error": f.get("verify_error")},
    ),
    Rule(
        id="PQC_RSA_ENDPOINT",
        title="RSA certificate key detected (quantum-vulnerable class)",
        severity="high",
        fix="Inventory RSA usage and plan migration to PQC/hybrid approaches.",
        pqc_note="RSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        confidence="high",
        confidence_reason="Public key algorithm extracted from the presented X.509 certificate.",
        when=lambda f: (f.get("key_type") or "").upper() == "RSA",
        evidence=lambda f: {"key_type": "RSA", "key_size": f.get("key_size")},
    ),
    Rule(
        id="PQC_EC_ENDPOINT",
        title="Elliptic-curve public key detected (quantum-vulnerable class)",
        severity="medium",
        fix="Inventory ECC usage and plan migration to PQC/hybrid approaches.",
        pqc_note="ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        confidence="high",
        confidence_reason="Public key algorithm extracted from the presented X.509 certificate.",
        when=lambda f: (f.get("key_type") or "").upper() == "EC",
        evidence=lambda f: {"key_type": "EC", "curve": f.get("curve")},
    ),
    Rule(
        id="CERT_HOST_NOT_IN_SAN",
        title="Hostname not covered by certificate SAN (possible mismatch)",
        severity="high",
        fix="Ensure the certificate SAN includes the exact hostname (or correct wildcard) used by clients.",
        pqc_note="TLS identity correctness is required before any algorithm migration.",
        confidence="high",
        confidence_reason="Derived from SAN entries present in the X.509 certificate.",
        when=lambda f: bool(f.get("host")) and isinstance(f.get("san_dns"), list) and (f.get("host_match") is False),
        evidence=lambda f: {"host": f.get("host"), "san_dns": _list(f.get("san_dns"))},
    ),
    Rule(
        id="CERT_NO_CRL_DP",
        title="No CRL distribution points advertised",
        severity="low",
        fix="Consider adding CRL distribution points to issued certificates if your PKI relies on CRLs.",
        pqc_note="Revocation posture matters more as certificate strategies evolve for PQC.",
        confidence="high",
        confidence_reason="CRL Distribution Points are read directly from the X.509 certificate extensions.",
        when=lambda f: len(_list(f.get("crl_urls"))) == 0,
        evidence=lambda f: {"crl_urls": _list(f.get("crl_urls"))},
    ),
    Rule(
        id="CERT_NO_OCSP_AIA",
        title="No OCSP responder advertised (AIA)",
        severity="low",
        fix="Consider including OCSP AIA in issued certificates, and enable OCSP stapling where appropriate.",
        pqc_note="Revocation posture matters more as certificate strategies evolve for PQC.",
        confidence="high",
        confidence_reason="AIA OCSP URLs are read directly from the X.509 certificate extensions.",
        when=lambda f: len(_list(f.get("ocsp_urls"))) == 0,
        evidence=lambda f: {"ocsp_urls": _list(f.get("ocsp_urls"))},
    ),
    # Stapling (best-effort; may be unavailable depending on Python/OpenSSL build)
    Rule(
        id="OCSP_STAPLING_MISSING",
        title="OCSP stapling not observed",
        severity="low",
        fix="Enable OCSP stapling on the TLS terminator (e.g., nginx: ssl_stapling on; ssl_stapling_verify on;).",
        pqc_note="Stapling reduces revocation latency; helpful during cert rotations and PQC transition waves.",
        confidence="low",
        confidence_reason="Stapling visibility depends on client/TLS stack support; treat as advisory.",
        when=lambda f: (len(_list(f.get("ocsp_urls"))) > 0) and (f.get("ocsp_stapled") is False),
        evidence=lambda f: {"ocsp_urls": _list(f.get("ocsp_urls")), "ocsp_stapled": f.get("ocsp_stapled")},
    ),
]
