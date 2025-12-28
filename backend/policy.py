from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    fix: str
    confidence: str = "medium"
    confidence_reason: str = ""
    evidence: Dict[str, Any] = None
    pqc_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "fix": self.fix,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "evidence": self.evidence or {},
            "pqc_note": self.pqc_note,
        }


def _add(findings: List[Finding], f: Finding) -> None:
    findings.append(f)


def evaluate_findings(r: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate a scan result dict produced by scanner.scan_host and return
    a list of Finding dicts (stable rule_id, severity, fix, confidence, evidence).
    """
    findings: List[Finding] = []

    # If scan itself failed
    if r.get("error"):
        _add(findings, Finding(
            rule_id="SCAN_FAILED",
            severity="high",
            title="TLS scan failed",
            fix="Verify the target is reachable and supports TLS on this port. Check firewalls, SNI, and DNS.",
            confidence="high",
            confidence_reason="Scan failure reported by the networking/TLS stack.",
            evidence={"error": r.get("error", "")},
            pqc_note="Visibility gaps block PQC planning; fix connectivity first."
        ))
        return [f.to_dict() for f in findings]

    # --- TLS protocol policy ---
    vers = r.get("tls_supported_versions") or []
    if any(v in ("TLSv1", "TLSv1.0", "TLSv1.1") for v in vers):
        _add(findings, Finding(
            rule_id="LEGACY_TLS_SUPPORTED",
            severity="critical",
            title="Legacy TLS versions supported",
            fix="Disable TLS 1.0/1.1. Require TLS 1.2+ and prefer TLS 1.3.",
            confidence="high",
            confidence_reason="Derived from active protocol probes.",
            evidence={"tls_supported_versions": vers},
            pqc_note="Crypto-agility prerequisite for PQC/hybrid TLS rollout."
        ))

    if "TLSv1.3" not in vers and "TLSv1_3" not in vers:
        # Only raise if we have any version data (otherwise unknown)
        if vers:
            _add(findings, Finding(
                rule_id="NO_TLS13",
                severity="high",
                title="TLS 1.3 not supported",
                fix="Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
                confidence="high",
                confidence_reason="Derived from active protocol probes.",
                evidence={"tls_supported_versions": vers},
                pqc_note="Most hybrid/PQC TLS rollouts assume modern TLS stacks."
            ))

    # Weak TLS 1.2 ciphers accepted
    weak = r.get("tls12_weak_accepted_ciphers") or []
    if weak:
        _add(findings, Finding(
            rule_id="WEAK_CIPHER_ACCEPTED",
            severity="critical",
            title="Weak TLS 1.2 ciphers accepted by server",
            fix="Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
            confidence="medium",
            confidence_reason="Best-effort probe; depends on client OpenSSL cipher support.",
            evidence={"tls12_weak_accepted_ciphers": weak},
            pqc_note="Baseline hardening should be done before any PQC/hybrid rollout."
        ))

    # Forward secrecy heuristic
    if r.get("forward_secrecy_possible") is False:
        _add(findings, Finding(
            rule_id="NO_FORWARD_SECRECY",
            severity="medium",
            title="Forward secrecy not observed/likely disabled",
            fix="Prefer ECDHE/DHE cipher suites to ensure forward secrecy for TLS 1.2, and migrate to TLS 1.3.",
            confidence="low",
            confidence_reason="Heuristic based on negotiated cipher string; validate server cipher policy for certainty.",
            evidence={"cipher_name": r.get("cipher_name", ""), "forward_secrecy_possible": False},
            pqc_note="FS hygiene reduces blast radius during algorithm transitions."
        ))

    # --- Certificate lifecycle ---
    days = r.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            _add(findings, Finding(
                rule_id="CERT_EXPIRED",
                severity="high",
                title="Certificate expired",
                fix="Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
                confidence="high",
                confidence_reason="Expiry is computed from the presented X.509 certificate.",
                evidence={"days_until_expiry": days, "not_after": r.get("not_after")},
                pqc_note="Rotation discipline matters for PQC rollouts."
            ))
        elif days <= 14:
            _add(findings, Finding(
                rule_id="CERT_EXPIRING_SOON",
                severity="medium",
                title="Certificate expiring soon",
                fix="Schedule certificate renewal/rotation soon; ensure renewal automation.",
                confidence="high",
                confidence_reason="Expiry is computed from the presented X.509 certificate.",
                evidence={"days_until_expiry": days, "not_after": r.get("not_after")},
                pqc_note="Rotation discipline matters for PQC rollouts."
            ))

    # SAN mismatch
    host = r.get("host") or ""
    san_dns = r.get("san_dns") or []
    if host and san_dns:
        if not _host_in_san(host, san_dns):
            _add(findings, Finding(
                rule_id="CERT_HOST_NOT_IN_SAN",
                severity="high",
                title="Hostname not covered by certificate SAN (possible mismatch)",
                fix="Ensure the certificate SAN includes the exact hostname (or correct wildcard) used by clients.",
                confidence="high",
                confidence_reason="Derived from SAN entries present in the X.509 certificate.",
                evidence={"host": host, "san_dns": san_dns},
                pqc_note="Correct hostname coverage avoids surprises when changing TLS termination."
            ))

    # Verify failures (trust/hostname/chain)
    verify_error = r.get("verify_error") or ""
    if verify_error:
        _add(findings, Finding(
            rule_id="VERIFY_FAILED",
            severity="medium",
            title="Certificate verification failed for default trust store",
            fix="Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
            confidence="high",
            confidence_reason="Reported directly by the TLS verification stack.",
            evidence={"verify_error": verify_error},
            pqc_note="Broken verification complicates migrations and compliance."
        ))

    # Chain issues
    chain_len = r.get("chain_length")
    if isinstance(chain_len, int):
        # Only flag as an issue when we either saw a verify failure, or we obtained the chain from a chain-capable API.
        # When we only have the leaf (chain_source="leaf_only"), treat chain completeness as unknown rather than a finding.
        if chain_len <= 1 and (verify_error or (r.get("chain_source") or "") != "leaf_only"):
            _add(findings, Finding(
                rule_id="CHAIN_SHORT_OR_UNAVAILABLE",
                severity="medium",
                title="Certificate chain short or unavailable",
                fix="Ensure the server sends the full chain (include correct intermediates).",
                confidence="high",
                confidence_reason=_chain_conf_reason(r),
                evidence={"chain_length": chain_len, "chain_source": r.get("chain_source")},
                pqc_note="Chain issues complicate PQC rollouts."
            ))


    # Missing intermediate: only when verify failed AND chain short
    if verify_error and isinstance(chain_len, int) and chain_len <= 1:
        _add(findings, Finding(
            rule_id="CHAIN_MISSING_INTERMEDIATE",
            severity="high",
            title="Server likely missing intermediate certificate (incomplete chain)",
            fix="Serve the full certificate chain (leaf + intermediate). Use your CA’s 'fullchain' bundle and configure the TLS terminator to send intermediates.",
            confidence="medium",
            confidence_reason="Verification failed for default trust store; chain collected via unverified handshake. Validate with openssl s_client for critical endpoints.",
            evidence={"chain_length": chain_len, "chain_source": r.get("chain_source"), "verify_error": verify_error},
            pqc_note="Incomplete chains become more painful during crypto transitions."
        ))

    # OCSP/CRL URLs from cert extensions
    ocsp_urls = r.get("ocsp_urls") or []
    crl_urls = r.get("crl_urls") or []

    if not ocsp_urls:
        _add(findings, Finding(
            rule_id="CERT_NO_OCSP_AIA",
            severity="low",
            title="No OCSP responder advertised (AIA)",
            fix="Consider including OCSP AIA in issued certificates, and enable OCSP stapling where appropriate.",
            confidence="high",
            confidence_reason="AIA OCSP URLs are read directly from the X.509 certificate extensions.",
            evidence={"ocsp_urls": ocsp_urls},
            pqc_note="Revocation posture matters more as certificate strategies evolve for PQC."
        ))
    else:
        # Stapling best-effort
        stapled = r.get("ocsp_stapled")
        if stapled is False:
            _add(findings, Finding(
                rule_id="OCSP_STAPLING_MISSING",
                severity="low",
                title="OCSP stapling not observed",
                fix="Enable OCSP stapling on the TLS terminator (e.g., nginx: ssl_stapling on; ssl_stapling_verify on;).",
                confidence="low",
                confidence_reason="Stapling visibility depends on client/TLS stack support; treat as advisory.",
                evidence={"ocsp_urls": ocsp_urls, "ocsp_stapled": False},
                pqc_note="Stapling reduces revocation latency; helpful during cert rotations and PQC transition waves."
            ))

    if not crl_urls:
        _add(findings, Finding(
            rule_id="CERT_NO_CRL_DP",
            severity="low",
            title="No CRL distribution points advertised",
            fix="Consider adding CRL distribution points to issued certificates if your PKI relies on CRLs.",
            confidence="high",
            confidence_reason="CRL Distribution Points are read directly from the X.509 certificate extensions.",
            evidence={"crl_urls": crl_urls},
            pqc_note="Revocation hygiene reduces surprises during large migrations."
        ))

    # PQC class: RSA / EC
    key_type = (r.get("key_type") or "").upper()
    if key_type == "RSA":
        _add(findings, Finding(
            rule_id="PQC_RSA_ENDPOINT",
            severity="high",
            title="RSA certificate key detected (quantum-vulnerable class)",
            fix="Inventory RSA usage and plan migration to PQC/hybrid approaches.",
            confidence="high",
            confidence_reason="Public key algorithm extracted from the presented X.509 certificate.",
            evidence={"key_type": "RSA", "key_size": r.get("key_detail", "")},
            pqc_note="RSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design."
        ))
    elif key_type == "EC":
        _add(findings, Finding(
            rule_id="PQC_EC_ENDPOINT",
            severity="medium",
            title="Elliptic-curve public key detected (quantum-vulnerable class)",
            fix="Inventory ECC usage and plan migration to PQC/hybrid approaches.",
            confidence="high",
            confidence_reason="Public key algorithm extracted from the presented X.509 certificate.",
            evidence={"key_type": "EC", "curve": r.get("key_detail", "")},
            pqc_note="ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design."
        ))

    # Sort findings by severity (stable)
    findings.sort(key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.rule_id))
    return [f.to_dict() for f in findings]


def _chain_conf_reason(r: Dict[str, Any]) -> str:
    return (r.get("chain_confidence_reason") or "Chain comes from get_verified_chain (client-side verified path).").strip()


def _host_in_san(host: str, san_dns: List[str]) -> bool:
    host = host.lower().strip(".")
    for entry in san_dns:
        e = (entry or "").lower().strip(".")
        if e == host:
            return True
        if e.startswith("*."):
            suffix = e[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") >= suffix.count("."):
                return True
    return False


def risk_level_from_findings(findings: List[Dict[str, Any]]) -> str:
    top = "low"
    top_score = -1
    for f in findings or []:
        s = (f.get("severity") or "").lower()
        sc = SEV_ORDER.get(s, 0)
        if sc > top_score:
            top_score = sc
            top = s
    if top_score < 0:
        return "low"
    return top


def pqc_relevance_and_reco(r: Dict[str, Any]) -> Tuple[str, str]:
    key_type = (r.get("key_type") or "").upper()
    if key_type in ("RSA", "EC"):
        return "HIGH", "Inventory RSA/ECC usage and plan for PQC/hybrid TLS (Kyber KEM + Dilithium/Falcon signatures)."
    return "MEDIUM", "Maintain crypto-agility and track PQC readiness."


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    errors = 0
    rsa_count = 0

    risk_points = 0
    for r in results:
        if r.get("error"):
            errors += 1
            risk_points += 10
            continue

        key_type = (r.get("key_type") or "").upper()
        if key_type == "RSA":
            rsa_count += 1
            risk_points += 3

        findings = r.get("findings") or []
        lvl = risk_level_from_findings(findings)
        if lvl in counts:
            counts[lvl] += 1

        if lvl == "critical":
            risk_points += 10
        elif lvl == "high":
            risk_points += 7
        elif lvl == "medium":
            risk_points += 3
        else:
            risk_points += 1

    raw_score = 100 - risk_points
    raw_score = max(0, min(100, raw_score))
    if raw_score >= 80:
        qlvl = "low"
    elif raw_score >= 50:
        qlvl = "medium"
    else:
        qlvl = "high"

    return {
        "total": total,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "errors": errors,
        "rsa_count": rsa_count,
        "quantum_risk_score": raw_score,
        "quantum_risk_level": qlvl,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat(timespec="seconds"),
    }
