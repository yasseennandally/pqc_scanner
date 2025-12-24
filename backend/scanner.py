# scanner.py
# TLS + cert scanner with a policy/rules engine producing evidence-based findings.
#
# Python 3.6 compatible (no dataclasses, no re.Pattern typing, no datetime.fromisoformat).
#
# Output fields are kept compatible with your UI/API:
# host, port, subject, issuer, not_before, not_after, days_until_expiry, key_type, key_detail,
# sig_algorithm, risk, pqc_relevance, pqc_recommendation, findings, plus deeper TLS/cert facts.

from __future__ import print_function

import socket
import ssl
import time
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# -------------------------
# Tuning
# -------------------------
DEFAULT_TIMEOUT = 5.0

TLS12_CIPHER_PROBES = [
    # Good / modern
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",

    # Older / weaker (for detection)
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "NULL-SHA",
]

_WEAK_CIPHER_TOKENS = [
    "RC4",
    "3DES",
    "DES-CBC3",
    "NULL",
    "EXPORT",
    "MD5",
    "CBC",   # CBC is not “always broken” but is often considered legacy in strict baselines
]

_SSLCertVerificationError = getattr(ssl, "SSLCertVerificationError", ssl.SSLError)

# -------------------------
# Helpers
# -------------------------
def _utc_iso(dt) -> str:
    if not dt:
        return ""
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return ""

def _parse_target(t: str) -> Tuple[str, int]:
    t = (t or "").strip()
    if not t:
        return "", 443
    if "://" in t:
        # if user pasted https://example.com
        try:
            t = t.split("://", 1)[1]
        except Exception:
            pass
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        host, p = t.rsplit(":", 1)
        host = host.strip()
        try:
            return host, int(p.strip())
        except Exception:
            return host, 443
    return t, 443

def _is_weak_cipher(cipher_name: str) -> bool:
    s = (cipher_name or "").upper()
    if not s:
        return False
    for tok in _WEAK_CIPHER_TOKENS:
        if tok in s:
            return True
    return False

def _make_context_for_protocol(protocol_const, verify: bool, alpn: Optional[List[str]] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(protocol_const)

    # Verification
    if verify:
        try:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_default_certs()
        except Exception:
            # if platform store oddities, fall back
            ctx.verify_mode = ssl.CERT_NONE
            ctx.check_hostname = False
    else:
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False

    # ALPN
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass

    return ctx

def _connect_handshake(
    host: str,
    port: int,
    protocol_const,
    verify: bool,
    alpn: Optional[List[str]] = None,
    cipher: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    sni: bool = True,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "success": False,
        "verify_mode": "default" if verify else "no-verify",
        "verify_error": "",
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "mtls_required": False,   # best-effort guess
        "sni_used": bool(sni),
    }

    ctx = _make_context_for_protocol(protocol_const, verify=verify, alpn=alpn)

    if cipher:
        try:
            ctx.set_ciphers(cipher)
        except Exception as e:
            out["verify_error"] = "set_ciphers failed: %s" % (str(e),)
            return out

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if sni else None) as ssock:
                out["success"] = True
                try:
                    out["tls_version"] = ssock.version() or ""
                except Exception:
                    out["tls_version"] = ""
                try:
                    c = ssock.cipher()
                    if c:
                        out["cipher_name"] = c[0] or ""
                        out["cipher_bits"] = c[2] if len(c) > 2 else None
                except Exception:
                    pass
                try:
                    out["alpn"] = ssock.selected_alpn_protocol() or ""
                except Exception:
                    out["alpn"] = ""
    except _SSLCertVerificationError as e:
        out["verify_error"] = str(e)
    except ssl.SSLError as e:
        # Best-effort detection of “client cert required”
        msg = str(e)
        out["verify_error"] = msg
        if "certificate required" in msg.lower() or "handshake failure" in msg.lower():
            out["mtls_required"] = True
    except Exception as e:
        out["verify_error"] = str(e)

    return out

def _probe_tls_versions(host: str, port: int) -> Dict[str, Any]:
    supported: Dict[str, bool] = {
        "TLSv1.0": False,
        "TLSv1.1": False,
        "TLSv1.2": False,
        "TLSv1.3": False,
    }
    errors: Dict[str, str] = {}

    for label, proto in [
        ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
    ]:
        if proto is None:
            continue
        r = _connect_handshake(host, port, protocol_const=proto, verify=False, alpn=["h2", "http/1.1"])
        if r["success"]:
            supported[label] = True
        else:
            errors[label] = r.get("verify_error", "") or ""

    # TLS 1.3 best-effort: Python 3.6 + OpenSSL 1.0.2 won't negotiate TLS1.3.
    # We still attempt and record results, but "NO_TLS13" should consider this as "unknown" if local stack can't do TLS1.3.
    r = _connect_handshake(host, port, protocol_const=ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
    if r["success"] and (r.get("tls_version") == "TLSv1.3"):
        supported["TLSv1.3"] = True
    elif not r["success"]:
        errors["TLSv1.3"] = r.get("verify_error", "") or ""

    return {
        "tls_supported_versions": [k for k, v in supported.items() if v],
        "tls_support_map": supported,
        "tls_probe_errors": errors,
    }

def _probe_tls12_accepted_ciphers(host: str, port: int) -> Dict[str, Any]:
    accepted: List[str] = []
    weak_accepted: List[str] = []
    any_fs = False

    proto = getattr(ssl, "PROTOCOL_TLSv1_2", None)
    if proto is None:
        return {
            "tls12_accepted_ciphers": [],
            "tls12_weak_accepted_ciphers": [],
            "forward_secrecy_possible": False,
        }

    for c in TLS12_CIPHER_PROBES:
        r = _connect_handshake(
            host, port,
            protocol_const=proto,
            verify=False,
            cipher=c,
            alpn=["h2", "http/1.1"],
        )
        if r["success"]:
            negotiated = r.get("cipher_name") or c
            accepted.append(negotiated)
            if _is_weak_cipher(negotiated):
                weak_accepted.append(negotiated)
            up = (negotiated or "").upper()
            if "ECDHE" in up or "DHE" in up:
                any_fs = True

    def dedupe(xs: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "tls12_accepted_ciphers": dedupe(accepted),
        "tls12_weak_accepted_ciphers": dedupe(weak_accepted),
        "forward_secrecy_possible": any_fs,
    }

def _pk_info(cert: x509.Certificate) -> Tuple[str, str]:
    pk = cert.public_key()
    cls = pk.__class__.__name__.upper()

    if "RSA" in cls:
        try:
            return "RSA", str(getattr(pk, "key_size", ""))
        except Exception:
            return "RSA", ""

    if "EC" in cls or "ELLIPTIC" in cls:
        try:
            curve = getattr(pk, "curve", None)
            return "EC", (getattr(curve, "name", "") if curve else "")
        except Exception:
            return "EC", ""

    return pk.__class__.__name__, ""

def _basic_constraints_is_ca(cert: x509.Certificate) -> Optional[bool]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bool(ext.value.ca)
    except Exception:
        return None

def _get_cert_chain_der(ssock) -> List[bytes]:
    chain: List[bytes] = []
    try:
        leaf = ssock.getpeercert(binary_form=True)
        if leaf:
            chain.append(leaf)
    except Exception:
        pass

    # Not all Python/openssl builds expose these:
    for meth_name in ("getpeercertchain", "get_verified_chain", "get_unverified_chain"):
        meth = getattr(ssock, meth_name, None)
        if meth:
            try:
                lst = meth()
                for item in lst:
                    if isinstance(item, (bytes, bytearray)):
                        chain.append(bytes(item))
                    else:
                        pb = getattr(item, "public_bytes", None)
                        if pb:
                            try:
                                chain.append(pb())
                            except Exception:
                                pass
                break
            except Exception:
                continue

    out: List[bytes] = []
    seen = set()
    for b in chain:
        if not b:
            continue
        h = hash(b)
        if h in seen:
            continue
        seen.add(h)
        out.append(b)
    return out

def _analyze_cert_chain(chain_der: List[bytes]) -> Dict[str, Any]:
    parsed: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    chain_has_weak_sig = False

    certs: List[x509.Certificate] = []
    for der in chain_der:
        try:
            certs.append(x509.load_der_x509_certificate(der, default_backend()))
        except Exception:
            continue

    for idx, cert in enumerate(certs):
        try:
            subj = cert.subject.rfc4514_string()
        except Exception:
            subj = ""
        try:
            iss = cert.issuer.rfc4514_string()
        except Exception:
            iss = ""
        try:
            sig = cert.signature_algorithm_oid._name
        except Exception:
            sig = ""

        if sig:
            up = sig.lower()
            if "sha1" in up or "md5" in up:
                chain_has_weak_sig = True

        parsed.append({
            "index": idx,
            "subject": subj,
            "issuer": iss,
            "not_before": _utc_iso(getattr(cert, "not_valid_before", None)),
            "not_after": _utc_iso(getattr(cert, "not_valid_after", None)),
            "sig_algorithm": sig,
            "is_ca": _basic_constraints_is_ca(cert),
        })

    # Very small, best-effort checks:
    if len(parsed) <= 1:
        issues.append({
            "type": "chain_short_or_unavailable",
            "severity": "medium",
            "detail": "Only leaf certificate observed (full chain not provided or not retrievable).",
        })
    else:
        # check issuer/subject linkage (non-cryptographic best-effort)
        for i in range(len(parsed) - 1):
            if parsed[i].get("issuer") and parsed[i+1].get("subject"):
                if parsed[i]["issuer"] != parsed[i+1]["subject"]:
                    issues.append({
                        "type": "chain_link_mismatch",
                        "severity": "medium",
                        "detail": "Issuer of cert[%d] does not match subject of cert[%d]." % (i, i+1),
                    })
                    break

    if chain_has_weak_sig:
        issues.append({
            "type": "weak_signature_in_chain",
            "severity": "high",
            "detail": "At least one certificate in the served chain uses a weak signature algorithm (SHA1/MD5).",
        })

    return {
        "cert_chain": parsed,
        "chain_length": len(parsed),
        "chain_issues": issues,
        "chain_has_weak_sig": chain_has_weak_sig,
    }

def _extract_cert_extensions(cert: x509.Certificate, host: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "cert_san": [],
        "cert_san_match": None,  # True/False/None (unknown)
        "cert_key_usage": {},
        "cert_eku": [],
        "cert_ocsp_urls": [],
        "cert_ca_issuers": [],
        "cert_crl_urls": [],
        "cert_serial_number_hex": "",
        "cert_spki_sha256": "",
    }

    # Serial
    try:
        out["cert_serial_number_hex"] = hex(int(cert.serial_number))
    except Exception:
        out["cert_serial_number_hex"] = ""

    # SPKI hash (use public key DER)
    try:
        spki = cert.public_key().public_bytes(
            encoding=getattr(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]), "Encoding").DER,
            format=getattr(__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]), "PublicFormat").SubjectPublicKeyInfo,
        )
        out["cert_spki_sha256"] = hashlib.sha256(spki).hexdigest()
    except Exception:
        out["cert_spki_sha256"] = ""

    # SAN
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = []
        try:
            for name in ext.value.get_values_for_type(x509.DNSName):
                sans.append(name)
        except Exception:
            pass
        out["cert_san"] = sans

        # best-effort hostname match using ssl.match_hostname
        try:
            # match_hostname expects dict like SSL.getpeercert() returns; we approximate with SANs.
            fake = {"subjectAltName": [("DNS", s) for s in sans]}
            ssl.match_hostname(fake, host)
            out["cert_san_match"] = True
        except Exception:
            out["cert_san_match"] = False
    except Exception:
        out["cert_san"] = []
        out["cert_san_match"] = None

    # Key Usage
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        out["cert_key_usage"] = {
            "digital_signature": bool(ku.digital_signature),
            "content_commitment": bool(ku.content_commitment),
            "key_encipherment": bool(ku.key_encipherment),
            "data_encipherment": bool(ku.data_encipherment),
            "key_agreement": bool(ku.key_agreement),
            "key_cert_sign": bool(ku.key_cert_sign),
            "crl_sign": bool(ku.crl_sign),
            "encipher_only": bool(getattr(ku, "encipher_only", False)),
            "decipher_only": bool(getattr(ku, "decipher_only", False)),
        }
    except Exception:
        out["cert_key_usage"] = {}

    # EKU
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        eku_oids = []
        for oid in eku:
            try:
                eku_oids.append(oid._name or oid.dotted_string)
            except Exception:
                try:
                    eku_oids.append(oid.dotted_string)
                except Exception:
                    pass
        out["cert_eku"] = eku_oids
    except Exception:
        out["cert_eku"] = []

    # AIA (OCSP + CA Issuers)
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_urls = []
        ca_issuers = []
        for ad in aia:
            try:
                if ad.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(str(ad.access_location.value))
                if ad.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuers.append(str(ad.access_location.value))
            except Exception:
                continue
        out["cert_ocsp_urls"] = ocsp_urls
        out["cert_ca_issuers"] = ca_issuers
    except Exception:
        out["cert_ocsp_urls"] = []
        out["cert_ca_issuers"] = []

    # CRL Distribution Points
    try:
        crl = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls = []
        for dp in crl:
            try:
                fn = dp.full_name
                if fn:
                    for n in fn:
                        try:
                            urls.append(str(n.value))
                        except Exception:
                            pass
            except Exception:
                continue
        out["cert_crl_urls"] = urls
    except Exception:
        out["cert_crl_urls"] = []

    return out

def _probe_hsts_header(host: str, port: int) -> Dict[str, Any]:
    """
    Best-effort: fetch HEAD / over TLS without verification and read Strict-Transport-Security.
    Not all endpoints will respond, and some require HTTP/2; this is a shallow heuristic.
    """
    out = {"hsts_present": False, "hsts_header": ""}

    try:
        ctx = _make_context_for_protocol(ssl.PROTOCOL_TLS, verify=False, alpn=["http/1.1"])
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                req = "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: pqc-scanner\r\nConnection: close\r\n\r\n" % host
                ssock.sendall(req.encode("utf-8"))
                data = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 64 * 1024:
                        break
        text = ""
        try:
            text = data.decode("iso-8859-1", errors="ignore")
        except Exception:
            text = ""
        # naive header parse
        lines = text.split("\r\n")
        for line in lines:
            if line.lower().startswith("strict-transport-security:"):
                out["hsts_present"] = True
                out["hsts_header"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    return out

# -------------------------
# Policy / rules engine
# -------------------------
def make_finding(rule_id, title, severity, remediation, pqc_mapping, confidence, confidence_reason, evidence):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,               # "critical"/"high"/"medium"/"low"
        "remediation": remediation,
        "pqc_mapping": pqc_mapping,
        "confidence": confidence,           # "high"/"medium"/"low"
        "confidence_reason": confidence_reason,
        "evidence": evidence or {},
    }

def _supported_versions(facts):
    v = facts.get("tls_supported_versions")
    if isinstance(v, list):
        return v
    return []

def _days_until_expiry(facts):
    try:
        return facts.get("days_until_expiry")
    except Exception:
        return None

def _chain_issues(facts):
    ci = facts.get("chain_issues") or []
    # chain_issues is list of dicts; return "type" list for evidence readability
    out = []
    try:
        for item in ci:
            t = item.get("type")
            if t:
                out.append(t)
    except Exception:
        pass
    return out

def evaluate_policies(facts):
    findings = []

    # Note about TLS1.3 probing limitations: Python 3.6 + OpenSSL 1.0.2 cannot do TLS1.3
    local_stack_tls13_capable = False
    try:
        # OpenSSL 1.1.1+ exposes TLS 1.3
        if hasattr(ssl, "HAS_TLSv1_3") and ssl.HAS_TLSv1_3:
            local_stack_tls13_capable = True
    except Exception:
        local_stack_tls13_capable = False

    # ----- TLS protocol hygiene -----
    legacy_supported = any(v in _supported_versions(facts) for v in ["TLSv1.0", "TLSv1.1"])
    if legacy_supported:
        findings.append(make_finding(
            "LEGACY_TLS_SUPPORTED",
            "Legacy TLS versions supported",
            "critical",
            "Disable TLS 1.0/1.1. Require TLS 1.2+ and prefer TLS 1.3.",
            "Crypto-agility prerequisite for PQC/hybrid TLS rollout.",
            "high",
            "Supported versions were enumerated via handshake probes.",
            {"supported_versions": _supported_versions(facts)},
        ))

    # TLS 1.3 not supported (only if we can actually test TLS1.3 from local stack)
    if local_stack_tls13_capable:
        if "TLSv1.3" not in _supported_versions(facts):
            findings.append(make_finding(
                "NO_TLS13",
                "TLS 1.3 not supported",
                "high",
                "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
                "Hybrid/PQC TLS work is expected primarily in TLS 1.3 stacks.",
                "medium",
                "TLS 1.3 check depends on local OpenSSL support; verify with external scanner if critical.",
                {"supported_versions": _supported_versions(facts), "local_tls13_capable": local_stack_tls13_capable},
            ))
    else:
        # We don't raise NO_TLS13 on old stacks; we keep it out to avoid false claims.
        pass

    # ----- Cipher hygiene -----
    weak_accept = facts.get("tls12_weak_accepted_ciphers") or []
    if isinstance(weak_accept, list) and len(weak_accept) > 0:
        findings.append(make_finding(
            "WEAK_CIPHER_ACCEPTED",
            "Weak TLS 1.2 ciphers accepted by server",
            "critical",
            "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
            "Baseline hardening should be done before any PQC/hybrid rollout.",
            "medium",
            "Cipher acceptance is probed using a small representative list; run a full cipher scan for completeness.",
            {"tls12_weak_accepted_ciphers": weak_accept[:20]},
        ))

    # Forward secrecy
    fs = facts.get("forward_secrecy_possible")
    if fs is False:
        findings.append(make_finding(
            "NO_FORWARD_SECRECY",
            "Forward secrecy not observed/likely disabled",
            "medium",
            "Prefer ECDHE/DHE cipher suites to ensure forward secrecy for TLS 1.2, and migrate to TLS 1.3.",
            "FS hygiene reduces blast radius during algorithm transitions.",
            "medium",
            "Derived from accepted cipher probes (ECDHE/DHE presence).",
            {"forward_secrecy_possible": False, "tls12_accepted_ciphers": (facts.get("tls12_accepted_ciphers") or [])[:20]},
        ))

    # ----- Cert expiry -----
    d = _days_until_expiry(facts)
    if isinstance(d, int) and d < 0:
        findings.append(make_finding(
            "CERT_EXPIRED",
            "Certificate expired",
            "high",
            "Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
            "Shorter rotation cycles support crypto agility for future PQC certificate strategy.",
            "high",
            "NotAfter and current time were used to compute days_until_expiry.",
            {"days_until_expiry": d, "not_after": facts.get("not_after")},
        ))
    elif isinstance(d, int) and 0 <= d <= 30:
        findings.append(make_finding(
            "CERT_EXPIRING_SOON",
            "Certificate expiring soon",
            "high",
            "Renew/rotate certificates soon. Verify automation for renewals.",
            "Regular rotations reduce risk during crypto migrations.",
            "high",
            "NotAfter and current time were used to compute days_until_expiry.",
            {"days_until_expiry": d, "not_after": facts.get("not_after")},
        ))

    # Verification failed
    ver = (facts.get("verify_error") or "").strip()
    if ver:
        findings.append(make_finding(
            "VERIFY_FAILED",
            "Certificate verification failed for default trust store",
            "medium",
            "Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
            "Trust failures block reliable inventory and complicate PQC migration planning.",
            "medium",
            "This was observed when attempting a verified handshake from this scanner host.",
            {"verify_error": ver},
        ))

    # Chain issues present
    ci = _chain_issues(facts)
    if len(ci) > 0:
        findings.append(make_finding(
            "CHAIN_ISSUES_PRESENT",
            "Certificate chain issues detected",
            "medium",
            "Fix chain linkage/intermediate CA constraints and ensure proper chain delivery.",
            "Clean PKI chain reduces migration surprises and operational risk.",
            "medium",
            "Chain analysis is best-effort; validate with openssl s_client if this endpoint is critical.",
            {"chain_issues": ci, "chain_length": facts.get("chain_length")},
        ))

    # Weak sig in chain
    if bool(facts.get("chain_has_weak_sig")):
        findings.append(make_finding(
            "WEAK_SIGNATURE_IN_CHAIN",
            "Weak signature algorithm detected in certificate chain",
            "high",
            "Replace/rotate the weakly-signed certificate(s) in the chain (avoid SHA1/MD5).",
            "Modern PKI hygiene is a prerequisite before introducing PQC/hybrid changes.",
            "medium",
            "Observed at least one SHA1/MD5 signature in served chain.",
            {"chain_has_weak_sig": True},
        ))

    # OCSP AIA missing
    ocsp = facts.get("cert_ocsp_urls") or []
    if isinstance(ocsp, list) and len(ocsp) == 0:
        findings.append(make_finding(
            "CERT_NO_OCSP_AIA",
            "No OCSP responder advertised (AIA)",
            "low",
            "Consider using OCSP/AIA (and stapling where appropriate) for stronger revocation posture.",
            "Revocation posture matters more as certificate strategies evolve for PQC.",
            "medium",
            "AIA extension not present or contains no OCSP URIs.",
            {"cert_ocsp_urls": ocsp},
        ))

    # SAN match issues (best-effort)
    san_match = facts.get("cert_san_match")
    if san_match is False:
        findings.append(make_finding(
            "CERT_SAN_MISMATCH",
            "Certificate SAN does not appear to match host",
            "high",
            "Issue a certificate whose SAN includes the exact hostname (or correct SNI/host).",
            "Hostname mismatch breaks automation and inventory; fix before PQC migration planning.",
            "low",
            "Hostname matching is best-effort using extracted SANs.",
            {"host": facts.get("host"), "cert_san": (facts.get("cert_san") or [])[:20]},
        ))

    # EKU ServerAuth missing (best-effort)
    eku = facts.get("cert_eku") or []
    if isinstance(eku, list) and len(eku) > 0:
        # If EKU exists but doesn't include serverAuth, that's unusual for a TLS server cert
        has_server_auth = False
        for e in eku:
            if "serverauth" in (str(e).lower()):
                has_server_auth = True
                break
        if not has_server_auth:
            findings.append(make_finding(
                "CERT_EKU_MISSING_SERVERAUTH",
                "Certificate EKU missing Server Authentication",
                "medium",
                "Re-issue certificate with correct EKU for TLS serverAuth if this is a public-facing TLS endpoint.",
                "PKI correctness reduces migration risk and prevents client compatibility issues.",
                "low",
                "EKU parsing depends on extensions being present and correctly decoded.",
                {"cert_eku": eku[:20]},
            ))

    # PQC priority classification by key type
    kt = (facts.get("key_type") or "").upper()
    if kt == "RSA":
        findings.append(make_finding(
            "PQC_RSA_ENDPOINT",
            "RSA certificate key detected (PQC priority)",
            "high",
            "Prioritize for crypto agility. Short-term: consider ECDSA certs. Plan hybrid/PQC when supported.",
            "RSA → PQC/hybrid planning (Kyber KEM; Dilithium signatures when ecosystem is ready).",
            "high",
            "Public key algorithm extracted from the presented X.509 certificate.",
            {"key_type": "RSA", "key_size": facts.get("key_detail")},
        ))
    elif kt == "EC":
        findings.append(make_finding(
            "PQC_EC_ENDPOINT",
            "Elliptic-curve public key detected (quantum-vulnerable class)",
            "medium",
            "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
            "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
            "high",
            "Public key algorithm extracted from the presented X.509 certificate.",
            {"key_type": "EC", "curve": facts.get("key_detail")},
        ))

    # HSTS present/absent is optional; we add only if we successfully checked
    if "hsts_present" in facts:
        if facts.get("hsts_present") is False:
            findings.append(make_finding(
                "NO_HSTS",
                "HSTS not observed (best-effort)",
                "low",
                "Consider enabling Strict-Transport-Security for public HTTPS endpoints to reduce downgrade risk.",
                "TLS posture improvements help maintain stable baselines as PQC/hybrid changes roll out.",
                "low",
                "This is a shallow HEAD / probe; some stacks require HTTP/2 or block HEAD.",
                {"hsts_present": False},
            ))

    # Order by severity
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: rank.get((f.get("severity") or "low").lower(), 9))
    return findings

def derive_risk_and_score(findings):
    """
    Produce:
    - risk_level: critical/high/medium/low
    - risk_label: "critical (RULE1, RULE2, ...)"
    - quantum_risk_score: 0-100 (higher is better)
    - quantum_risk_level: low/medium/high
    """
    if not findings:
        return {"risk_level": "low", "risk_label": "low", "quantum_risk_score": 90, "quantum_risk_level": "low"}

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted(findings, key=lambda f: rank.get((f.get("severity") or "low").lower(), 9))[0]
    risk_level = (top.get("severity") or "low").lower()

    # score: start at 100, subtract by severity
    score = 100
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev == "critical":
            score -= 12
        elif sev == "high":
            score -= 8
        elif sev == "medium":
            score -= 4
        else:
            score -= 2

        # small PQC penalty if endpoint is RSA/EC
        if f.get("rule_id") in ("PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT"):
            score -= 3

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    if score >= 80:
        q_level = "low"
    elif score >= 50:
        q_level = "medium"
    else:
        q_level = "high"

    reasons = [f.get("rule_id") for f in findings if f.get("rule_id")]
    short = ", ".join(reasons[:5]) + ("." if len(reasons) > 5 else "")
    label = "%s (%s)" % (risk_level, short) if short else risk_level

    return {
        "risk_level": risk_level,
        "risk_label": label,
        "quantum_risk_score": score,
        "quantum_risk_level": q_level,
    }

def derive_pqc_relevance(findings):
    relevance = "low"
    rec_lines = []

    has_rsa = any(f.get("rule_id") == "PQC_RSA_ENDPOINT" for f in findings)
    has_ec = any(f.get("rule_id") == "PQC_EC_ENDPOINT" for f in findings)

    if has_rsa:
        relevance = "high"
    elif has_ec:
        relevance = "medium"

    for f in findings:
        rid = f.get("rule_id", "")
        if rid in ("PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT", "NO_TLS13", "LEGACY_TLS_SUPPORTED", "WEAK_CIPHER_ACCEPTED"):
            rec_lines.append("%s: %s" % (f.get("title"), f.get("remediation")))

    if not rec_lines:
        rec_lines = ["Maintain TLS hardening (TLS 1.3, remove weak suites) and plan crypto-agility for future PQC/hybrid TLS."]

    return {"pqc_relevance": relevance, "pqc_recommendation": " ".join(rec_lines[:3])}

# -------------------------
# Main scanner
# -------------------------
def scan_host(host: str, port: int = 443) -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "host": host,
        "port": port,

        # handshake / negotiated
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "verify_mode": "default",
        "verify_error": "",

        # cert basics
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,

        "key_type": "",
        "key_detail": "",
        "sig_algorithm": "",

        # deep probes
        "tls_supported_versions": [],
        "tls_support_map": {},
        "tls_probe_errors": {},

        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        "forward_secrecy_possible": False,

        # chain
        "cert_chain": [],
        "chain_length": 0,
        "chain_issues": [],
        "chain_has_weak_sig": False,

        # extra cert extensions (new)
        "cert_san": [],
        "cert_san_match": None,
        "cert_key_usage": {},
        "cert_eku": [],
        "cert_ocsp_urls": [],
        "cert_ca_issuers": [],
        "cert_crl_urls": [],
        "cert_serial_number_hex": "",
        "cert_spki_sha256": "",

        # HTTP security header probe (optional)
        "hsts_present": None,
        "hsts_header": "",

        # derived
        "weak_cipher": False,
        "error": "",
    }

    if not host:
        facts["error"] = "empty host"
        return facts

    # Main handshake (verified), fallback unverified for capability
    main = _connect_handshake(host, port, protocol_const=ssl.PROTOCOL_TLS, verify=True, alpn=["h2", "http/1.1"])
    if main["success"]:
        facts["tls_version"] = main.get("tls_version", "") or ""
        facts["cipher_name"] = main.get("cipher_name", "") or ""
        facts["cipher_bits"] = main.get("cipher_bits", None)
        facts["alpn"] = main.get("alpn", "") or ""
        facts["verify_mode"] = main.get("verify_mode", "default")
    else:
        facts["verify_error"] = main.get("verify_error", "") or ""
        facts["verify_mode"] = main.get("verify_mode", "default")

        fallback = _connect_handshake(host, port, protocol_const=ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
        if fallback["success"]:
            facts["tls_version"] = fallback.get("tls_version", "") or ""
            facts["cipher_name"] = fallback.get("cipher_name", "") or ""
            facts["cipher_bits"] = fallback.get("cipher_bits", None)
            facts["alpn"] = fallback.get("alpn", "") or ""
        else:
            facts["error"] = fallback.get("verify_error", "") or "handshake failed"
            return facts

    facts["weak_cipher"] = _is_weak_cipher(facts.get("cipher_name", ""))

    # Cert + chain (unverified so it works even if verify fails)
    try:
        ctx = _make_context_for_protocol(ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    facts["subject"] = cert.subject.rfc4514_string()
                    facts["issuer"] = cert.issuer.rfc4514_string()
                    facts["not_before"] = _utc_iso(getattr(cert, "not_valid_before", None))
                    facts["not_after"] = _utc_iso(getattr(cert, "not_valid_after", None))
                    try:
                        facts["sig_algorithm"] = cert.signature_algorithm_oid._name
                    except Exception:
                        facts["sig_algorithm"] = ""

                    kt, kd = _pk_info(cert)
                    facts["key_type"] = kt
                    facts["key_detail"] = kd

                    not_after = getattr(cert, "not_valid_after", None)
                    if not_after:
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        now = datetime.utcnow().replace(tzinfo=timezone.utc)
                        facts["days_until_expiry"] = (not_after - now).days

                    # NEW: parse extensions
                    facts.update(_extract_cert_extensions(cert, host))

                chain_der = _get_cert_chain_der(ssock)
                facts.update(_analyze_cert_chain(chain_der))

    except Exception as e:
        facts["error"] = (facts["error"] + " | " if facts["error"] else "") + "cert/chain: %s" % str(e)

    # Deep probes
    facts.update(_probe_tls_versions(host, port))
    facts.update(_probe_tls12_accepted_ciphers(host, port))

    # Optional: HSTS header
    try:
        h = _probe_hsts_header(host, port)
        facts["hsts_present"] = bool(h.get("hsts_present"))
        facts["hsts_header"] = h.get("hsts_header", "") or ""
    except Exception:
        facts["hsts_present"] = None
        facts["hsts_header"] = ""

    # Policy engine -> findings
    findings = evaluate_policies(facts)
    scoring = derive_risk_and_score(findings)
    pqc = derive_pqc_relevance(findings)

    # Compatibility fields for your existing UI/API:
    facts["findings"] = findings
    facts["risk"] = scoring["risk_label"]
    facts["risk_level"] = scoring["risk_level"]
    facts["quantum_risk_score"] = scoring["quantum_risk_score"]
    facts["quantum_risk_level"] = scoring["quantum_risk_level"]
    facts["pqc_relevance"] = pqc["pqc_relevance"]
    facts["pqc_recommendation"] = pqc["pqc_recommendation"]

    return facts

def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    results = []
    for t in targets:
        host, port = _parse_target(t)
        if not host:
            continue
        results.append(scan_host(host, port))
    return results
