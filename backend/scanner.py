# backend/scanner.py
from __future__ import annotations

import socket
import ssl
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID

from policy import evaluate_tls_findings, derive_risk_and_score, derive_pqc_relevance

DEFAULT_TIMEOUT = 6

# A small probe set: fast + useful signal
TLS12_CIPHER_PROBES = [
    # Modern-ish
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    # Weak (we want to detect acceptance)
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "AES128-SHA",
    "AES256-SHA",
]

_SSLCertVerificationError = getattr(ssl, "SSLCertVerificationError", ssl.SSLError)


def parse_target(target: str) -> Tuple[str, int]:
    """
    Public helper (some app.py versions import it).
    Accepts:
      - example.com
      - example.com:443
      - https://example.com
      - https://example.com:8443/path
    Returns (host, port).
    """
    return _parse_target(target)


def _parse_target(target: str) -> Tuple[str, int]:
    t = (target or "").strip()
    if not t:
        return ("", 0)

    # strip scheme
    if "://" in t:
        t = t.split("://", 1)[1]

    # strip path
    if "/" in t:
        t = t.split("/", 1)[0]

    # host:port
    if ":" in t:
        host, port_s = t.rsplit(":", 1)
        host = host.strip()
        try:
            port = int(port_s.strip())
        except Exception:
            port = 443
        return (host, port)

    return (t, 443)


def _utc_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    return (dt - now).days


def _make_context_for_protocol(protocol_const: int, verify: bool, alpn: Optional[List[str]] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(protocol_const)

    # reasonable defaults
    ctx.check_hostname = bool(verify)
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE

    if verify:
        ctx.load_default_certs()

    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass

    # Do not force min/max here; let protocol_const drive it.
    return ctx


def _connect_handshake(
    host: str,
    port: int,
    protocol_const: int,
    verify: bool = False,
    cipher: Optional[str] = None,
    alpn: Optional[List[str]] = None,
    sni: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "success": False,
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "verify_error": "",
    }

    ctx = _make_context_for_protocol(protocol_const, verify=verify, alpn=alpn)

    if cipher:
        try:
            ctx.set_ciphers(cipher)
        except Exception as e:
            out["verify_error"] = f"set_ciphers failed: {e}"
            return out

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if sni else None) as ssock:
                out["success"] = True
                out["tls_version"] = ssock.version() or ""
                c = ssock.cipher()
                if c:
                    out["cipher_name"] = c[0] or ""
                    out["cipher_bits"] = c[2] if len(c) > 2 else None
                try:
                    out["alpn"] = ssock.selected_alpn_protocol() or ""
                except Exception:
                    out["alpn"] = ""
    except _SSLCertVerificationError as e:
        out["verify_error"] = str(e)
    except ssl.SSLError as e:
        out["verify_error"] = str(e)
    except Exception as e:
        out["verify_error"] = str(e)

    return out


def _probe_tls_versions(host: str, port: int) -> Dict[str, Any]:
    supported: Dict[str, bool] = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}
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

    # TLS 1.3 best-effort
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


def _is_weak_cipher(name: str) -> bool:
    n = (name or "").upper()
    # This is intentionally conservative for "baseline hardening"
    if "NULL" in n or "EXPORT" in n or "RC4" in n or "3DES" in n or "MD5" in n:
        return True
    if n.endswith("-SHA") and ("GCM" not in n) and ("CHACHA20" not in n):
        return True
    return False


def _probe_tls12_accepted_ciphers(host: str, port: int) -> Dict[str, Any]:
    accepted: List[str] = []
    weak_accepted: List[str] = []
    any_fs = False

    proto = getattr(ssl, "PROTOCOL_TLSv1_2", None)
    if proto is None:
        return {"tls12_accepted_ciphers": [], "tls12_weak_accepted_ciphers": [], "forward_secrecy_possible": False}

    for c in TLS12_CIPHER_PROBES:
        r = _connect_handshake(host, port, protocol_const=proto, verify=False, cipher=c, alpn=["h2", "http/1.1"])
        if r["success"]:
            negotiated = r.get("cipher_name") or c
            accepted.append(negotiated)
            if _is_weak_cipher(negotiated):
                weak_accepted.append(negotiated)
            if "ECDHE" in (negotiated or "").upper() or "DHE" in (negotiated or "").upper():
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
        return ("RSA", str(getattr(pk, "key_size", "") or ""))

    # EC keys in cryptography are usually EllipticCurvePublicKey
    if "ELLIPTIC" in cls or "EC" in cls:
        try:
            curve = getattr(pk, "curve", None)
            return ("EC", (getattr(curve, "name", "") if curve else ""))
        except Exception:
            return ("EC", "")

    return (pk.__class__.__name__, "")


def _extract_leaf_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "san_dns": [],
        "san_ip": [],
        "san_other": [],
        "key_usage": {},
        "eku": [],
        "basic_constraints": {},
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],
    }

    # SAN
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns, ip, other = [], [], []
        for gn in san:
            if isinstance(gn, x509.DNSName):
                dns.append(str(gn.value).lower())
            elif isinstance(gn, x509.IPAddress):
                ip.append(str(gn.value))
            else:
                other.append(str(getattr(gn, "value", gn)))
        out["san_dns"] = dns
        out["san_ip"] = ip
        out["san_other"] = other
    except Exception:
        pass

    # KeyUsage
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        out["key_usage"] = {
            "digital_signature": bool(ku.digital_signature),
            "content_commitment": bool(ku.content_commitment),
            "key_encipherment": bool(ku.key_encipherment),
            "data_encipherment": bool(ku.data_encipherment),
            "key_agreement": bool(ku.key_agreement),
            "key_cert_sign": bool(ku.key_cert_sign),
            "crl_sign": bool(ku.crl_sign),
            "encipher_only": bool(getattr(ku, "encipher_only", False)) if ku.key_agreement else False,
            "decipher_only": bool(getattr(ku, "decipher_only", False)) if ku.key_agreement else False,
        }
    except Exception:
        pass

    # EKU
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ekus: List[str] = []
        for oid in eku:
            name = getattr(oid, "_name", None)
            ekus.append(str(name) if name else str(oid.dotted_string))
        out["eku"] = ekus
    except Exception:
        pass

    # BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        out["basic_constraints"] = {"ca": bool(bc.ca), "path_length": bc.path_length}
    except Exception:
        pass

    # AIA (OCSP + CA Issuers)
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_urls: List[str] = []
        ca_issuers: List[str] = []
        for ad in aia:
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(str(ad.access_location.value))
            elif ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                ca_issuers.append(str(ad.access_location.value))
        out["ocsp_urls"] = ocsp_urls
        out["ca_issuers_urls"] = ca_issuers
    except Exception:
        pass

    # CRL distribution points
    try:
        crldp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls: List[str] = []
        for dp in crldp:
            if not dp.full_name:
                continue
            for n in dp.full_name:
                try:
                    if isinstance(n, x509.UniformResourceIdentifier):
                        urls.append(str(n.value))
                except Exception:
                    continue
        out["crl_urls"] = urls
    except Exception:
        pass

    return out


def _try_get_ocsp_staple(ssock: ssl.SSLSocket) -> Dict[str, Any]:
    """
    Best-effort OCSP stapling detection.
    Some Python/OpenSSL builds expose an ocsp response accessor; others do not.
    """
    out = {
        "ocsp_stapling_supported": False,
        "ocsp_stapled": False,
        "ocsp_stapled_len": 0,
        "ocsp_stapled_sha256": "",
    }

    try:
        attr = getattr(ssock, "ocsp_response", None)

        # Method form
        if callable(attr):
            out["ocsp_stapling_supported"] = True
            resp = attr()
        else:
            # Property form
            resp = attr
            if resp is not None:
                out["ocsp_stapling_supported"] = True

        if isinstance(resp, (bytes, bytearray)) and len(resp) > 0:
            out["ocsp_stapled"] = True
            out["ocsp_stapled_len"] = len(resp)
            out["ocsp_stapled_sha256"] = hashlib.sha256(bytes(resp)).hexdigest()
    except Exception:
        pass

    return out


def _get_cert_chain_der_with_source(ssock: ssl.SSLSocket) -> Tuple[List[bytes], str, str, str]:
    """
    Returns (chain_der_list, chain_source, confidence, confidence_reason)

    We try multiple mechanisms because Python/OpenSSL differs by platform/version.
    """
    # Preferred: verified chain
    for name in ("get_verified_chain", "getpeercertchain"):
        try:
            fn = getattr(ssock, name, None)
            if callable(fn):
                chain = fn()
                if chain:
                    # May already be DER bytes or cert objects; normalize to DER bytes.
                    out: List[bytes] = []
                    for item in chain:
                        if isinstance(item, (bytes, bytearray)):
                            out.append(bytes(item))
                        elif hasattr(item, "public_bytes"):
                            out.append(item.public_bytes())
                    return (out, "get_verified_chain", "high", "Chain comes from get_verified_chain (client-side verified path).")
        except Exception:
            pass

    # Fallback: unverified handshake (we at least have leaf)
    try:
        leaf = ssock.getpeercert(binary_form=True)
        if leaf:
            return ([leaf], "unverified_handshake", "medium", "Chain collected from handshake; may be incomplete.")
    except Exception:
        pass

    return ([], "unverified_handshake", "medium", "No chain details returned.")


def _analyze_cert_chain(chain_der: List[bytes]) -> Dict[str, Any]:
    parsed: List[Dict[str, Any]] = []
    issues: List[str] = []

    for i, der in enumerate(chain_der or []):
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
            kt, kd = _pk_info(cert)
            try:
                sig = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
            except Exception:
                sig = ""
            parsed.append(
                {
                    "index": i,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": _utc_iso(getattr(cert, "not_valid_before", None)),
                    "not_after": _utc_iso(getattr(cert, "not_valid_after", None)),
                    "key": f"{kt} / {kd}".strip(" /"),
                    "sig": sig,
                }
            )
        except Exception:
            continue

    if len(parsed) <= 1:
        issues.append("chain_short_or_unavailable")

    return {
        "cert_chain": parsed,
        "chain_length": len(parsed),
        "chain_issues": issues,
    }


def scan_host(host: str, port: int = 443) -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "host": host,
        "port": port,

        "error": "",
        "verify_mode": "CERT_REQUIRED",
        "verify_error": "",

        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": None,

        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,

        "key_type": "",
        "key_detail": "",
        "sig_algorithm": "",

        "san_dns": [],
        "key_usage": {},
        "eku": [],
        "basic_constraints": {},
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],

        "ocsp_stapling_supported": False,
        "ocsp_stapled": False,
        "ocsp_stapled_len": 0,
        "ocsp_stapled_sha256": "",

        "cert_chain": [],
        "chain_length": 0,
        "chain_issues": [],
        "chain_source": "",
        "chain_confidence": "",
        "chain_confidence_reason": "",

        "tls_supported_versions": [],
        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        "forward_secrecy_possible": False,

        "findings": [],
        "risk_level": "low",
        "risk": "low",
        "quantum_risk_score": 0,
        "quantum_risk_level": "low",
        "pqc_relevance": "LOW",
        "pqc_recommendation": "",
    }

    # Primary handshake (verified)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                facts["tls_version"] = ssock.version() or ""
                c = ssock.cipher()
                if c:
                    facts["cipher_name"] = c[0] or ""
                    facts["cipher_bits"] = c[2] if len(c) > 2 else None
                try:
                    facts["alpn"] = ssock.selected_alpn_protocol()
                except Exception:
                    facts["alpn"] = None

                # OCSP stapling (best-effort)
                facts.update(_try_get_ocsp_staple(ssock))

                # Leaf cert
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    facts["subject"] = cert.subject.rfc4514_string()
                    facts["issuer"] = cert.issuer.rfc4514_string()
                    facts["not_before"] = _utc_iso(getattr(cert, "not_valid_before", None))
                    facts["not_after"] = _utc_iso(getattr(cert, "not_valid_after", None))
                    facts["days_until_expiry"] = _days_until(getattr(cert, "not_valid_after", None))

                    try:
                        facts["sig_algorithm"] = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
                    except Exception:
                        facts["sig_algorithm"] = ""

                    kt, kd = _pk_info(cert)
                    facts["key_type"] = kt
                    facts["key_detail"] = kd

                    facts.update(_extract_leaf_extensions(cert))

                # Chain (best-effort)
                chain_der, chain_source, conf, conf_reason = _get_cert_chain_der_with_source(ssock)
                facts["chain_source"] = chain_source
                facts["chain_confidence"] = conf
                facts["chain_confidence_reason"] = conf_reason
                facts.update(_analyze_cert_chain(chain_der))

    except _SSLCertVerificationError as e:
        facts["verify_error"] = str(e)
    except Exception as e:
        facts["error"] = str(e)

    # Probes (do not require verification)
    try:
        facts.update(_probe_tls_versions(host, port))
    except Exception:
        pass

    try:
        facts.update(_probe_tls12_accepted_ciphers(host, port))
    except Exception:
        pass

    # Findings + scoring
    findings = evaluate_tls_findings(facts)
    scoring = derive_risk_and_score(findings)
    pqc = derive_pqc_relevance(findings)

    facts["findings"] = findings
    facts["risk_level"] = scoring["risk_level"]
    facts["risk"] = scoring["risk_label"]
    facts["quantum_risk_score"] = scoring["quantum_risk_score"]
    facts["quantum_risk_level"] = scoring["quantum_risk_level"]
    facts["pqc_relevance"] = pqc["pqc_relevance"]
    facts["pqc_recommendation"] = pqc["pqc_recommendation"]

    return facts


def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for t in targets:
        host, port = _parse_target(t)
        if not host:
            continue
        results.append(scan_host(host, port))
    return results
