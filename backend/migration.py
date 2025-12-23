# migration.py
from typing import List, Dict, Any


def build_migration_plan_tls(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build actionable TLS migration plan from TLS scan results.

    Works with BOTH:
      - simple fields: risk, key_type, days_until_expiry
      - deep fields: tls_supported_versions, tls12_weak_accepted_ciphers,
                    chain_issues, verify_error, forward_secrecy_possible, findings
    """
    actions: List[Dict[str, Any]] = []

    for r in results:
        host = r.get("host", "")
        port = r.get("port", 443)
        item = f"{host}:{port}"

        risk = (r.get("risk") or "").lower()
        key_type = (r.get("key_type") or "").upper()
        days = r.get("days_until_expiry", r.get("days_to_expiry", None))

        tls_version = (r.get("tls_version") or "").upper()
        tls_supported_versions = r.get("tls_supported_versions") or []
        weak_cipher = bool(r.get("weak_cipher"))
        weak_tls12 = r.get("tls12_weak_accepted_ciphers") or []
        verify_error = r.get("verify_error") or ""
        chain_issues = r.get("chain_issues") or []
        chain_has_weak_sig = bool(r.get("chain_has_weak_sig"))
        forward_secrecy_possible = r.get("forward_secrecy_possible", None)

        # ----- Certificate expiry -----
        if "expired" in risk:
            actions.append({
                "priority": "critical",
                "area": "tls",
                "item": item,
                "problem": "Certificate expired",
                "recommendation": "Rotate certificate immediately. Add monitoring + renewal automation.",
                "pqc_mapping": "During rotation: adopt crypto-agility; plan hybrid/PQC as supported by your TLS stack.",
            })
        elif "expiring soon" in risk or (isinstance(days, int) and days <= 30):
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "Certificate expiring soon",
                "recommendation": "Rotate certificate. Add renewal automation + expiry alerts.",
                "pqc_mapping": "Use this rotation window to prepare for hybrid/PQC capable certificates and stacks.",
            })

        # ----- Trust / chain issues -----
        if verify_error:
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "Certificate verification error",
                "recommendation": "Investigate trust chain, hostname mismatch, or missing intermediates. Fix verification issues.",
                "pqc_mapping": "PQC readiness requires clean trust chains; fix verification first.",
            })

        if chain_issues:
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "Certificate chain issues detected",
                "recommendation": "Repair chain (include intermediates, correct ordering). Ensure clients can validate.",
                "pqc_mapping": "Healthy PKI is required before any PQC/hybrid rollout.",
            })

        if chain_has_weak_sig:
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "Weak signature algorithm in certificate chain",
                "recommendation": "Re-issue/rotate certificates using modern signature algorithms (e.g., SHA-256+).",
                "pqc_mapping": "Modernize now; later transition to PQC/hybrid signature support when available.",
            })

        # ----- TLS protocol version -----
        supports_tls13 = False
        if isinstance(tls_supported_versions, list) and tls_supported_versions:
            supports_tls13 = any("1.3" in str(v) for v in tls_supported_versions)
        else:
            supports_tls13 = ("1.3" in tls_version)

        if not supports_tls13:
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "TLS 1.3 not supported",
                "recommendation": "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
                "pqc_mapping": "Hybrid PQC handshakes are generally TLS 1.3 era features.",
            })

        # ----- Cipher hygiene -----
        if weak_cipher or weak_tls12:
            detail = ""
            if weak_tls12:
                detail = f"Weak TLS1.2 ciphers accepted: {', '.join(weak_tls12[:6])}" + (" ..." if len(weak_tls12) > 6 else "")
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "Weak cipher suites accepted" + (f" ({detail})" if detail else ""),
                "recommendation": "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
                "pqc_mapping": "Baseline hardening should be done before any PQC/hybrid rollout.",
            })

        # ----- Forward secrecy -----
        if forward_secrecy_possible is False:
            actions.append({
                "priority": "medium",
                "area": "tls",
                "item": item,
                "problem": "Forward secrecy not observed/likely disabled",
                "recommendation": "Prefer ECDHE/DHE suites and migrate to TLS 1.3.",
                "pqc_mapping": "FS hygiene reduces blast radius during algorithm transitions.",
            })

        # ----- PQC relevance from key type -----
        if key_type == "RSA":
            actions.append({
                "priority": "high",
                "area": "tls",
                "item": item,
                "problem": "RSA certificate key (quantum-vulnerable long term)",
                "recommendation": "Track RSA endpoints; implement crypto-agility and plan hybrid TLS rollout when supported.",
                "pqc_mapping": "RSA → Kyber (KEM) (hybrid) + Dilithium/Falcon (signatures) when supported.",
            })
        elif key_type == "EC":
            actions.append({
                "priority": "medium",
                "area": "tls",
                "item": item,
                "problem": "ECC certificate key (quantum-vulnerable long term)",
                "recommendation": "Inventory ECC usage; plan hybrid/PQC upgrade path.",
                "pqc_mapping": "ECDSA → Dilithium/Falcon | ECDH/ECDHE → Kyber (KEM) in hybrid modes.",
            })

        # ----- Surface scanner findings if present -----
        findings = r.get("findings")
        if isinstance(findings, list):
            for f in findings[:12]:
                title = (f.get("title") or f.get("message") or "").strip()
                if not title:
                    continue
                sev = (f.get("severity") or "medium").lower()
                actions.append({
                    "priority": "critical" if sev == "critical" else ("high" if sev == "high" else ("medium" if sev == "medium" else "low")),
                    "area": "tls",
                    "item": item,
                    "problem": title,
                    "recommendation": f.get("remediation") or f.get("recommendation") or "Review TLS configuration and remediate.",
                    "pqc_mapping": f.get("pqc_mapping") or "",
                })

    return _finalize(actions, title="TLS Migration Plan")


def build_migration_plan_code(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    actions: List[Dict[str, Any]] = []
    for f in findings:
        rule = (f.get("rule_name") or "").lower()
        file = f.get("file", "")
        line = f.get("line", 1)
        item = f"{file}:{line}"

        if "hardcoded private key" in rule:
            actions.append({
                "priority": "critical",
                "area": "code",
                "item": item,
                "problem": "Hardcoded private key material",
                "recommendation": "Remove immediately, rotate keys, store secrets in a vault (AWS KMS, HashiCorp Vault, etc.).",
                "pqc_mapping": "",
            })
        elif "sha-1" in rule or "sha1" in rule:
            actions.append({
                "priority": "high",
                "area": "code",
                "item": item,
                "problem": "SHA-1 usage",
                "recommendation": "Replace SHA-1 with SHA-256/SHA-3. If used for signatures, replace the whole scheme.",
                "pqc_mapping": "",
            })
        elif "md5" in rule:
            actions.append({
                "priority": "high",
                "area": "code",
                "item": item,
                "problem": "MD5 usage",
                "recommendation": "Replace MD5 with SHA-256/SHA-3.",
                "pqc_mapping": "",
            })
        elif "rsa" in rule:
            actions.append({
                "priority": "high",
                "area": "code",
                "item": item,
                "problem": "RSA usage detected (quantum-vulnerable long term)",
                "recommendation": "Introduce crypto-agility wrapper. Plan migration to Kyber (KEM) + Dilithium/Falcon (signatures) depending on use-case.",
                "pqc_mapping": "RSA → Kyber (KEM) / Dilithium (signatures)",
            })
        elif "ecc" in rule or "ecdsa" in rule or "ecdh" in rule:
            actions.append({
                "priority": "medium",
                "area": "code",
                "item": item,
                "problem": "ECC usage detected (quantum-vulnerable long term)",
                "recommendation": "Inventory ECC usage. Plan migration to Dilithium/Falcon for signatures and Kyber for key exchange.",
                "pqc_mapping": "ECDSA → Dilithium/Falcon | ECDH → Kyber (KEM)",
            })

    return _finalize(actions, title="Code Migration Plan")


def _finalize(actions: List[Dict[str, Any]], title: str) -> Dict[str, Any]:
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions.sort(key=lambda a: priority_rank.get((a.get("priority") or "low").lower(), 9))

    # Deduplicate by (area,item,problem)
    seen = set()
    unique = []
    for a in actions:
        key = (a.get("area"), a.get("item"), a.get("problem"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(a)

    summary = {
        "title": title,
        "total_actions": len(unique),
        "critical": sum(1 for a in unique if (a.get("priority") == "critical")),
        "high": sum(1 for a in unique if (a.get("priority") == "high")),
        "medium": sum(1 for a in unique if (a.get("priority") == "medium")),
        "low": sum(1 for a in unique if (a.get("priority") == "low")),
    }

    top_actions = unique[:10]
    return {"summary": summary, "top_actions": top_actions, "all_actions": unique}
