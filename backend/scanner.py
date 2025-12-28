# scanner.py
"""
TLS + certificate scanner.

Phase 2 (OCSP validation) - Step 1:
- Extract OCSP/CA Issuers/CRL URLs from certificate extensions
- Detect stapled OCSP response presence (best-effort)
- Perform *basic* OCSP check (no signature verification yet) against the first OCSP responder
  using issuer certificate from the verified chain or downloaded from CA Issuers AIA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import socket
import ssl
import time
import urllib.request
import urllib.error

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp as x509_ocsp

from policy import evaluate_findings, risk_level_from_findings, pqc_relevance_and_reco


# ---------------------------
# Helpers
# ---------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dt_to_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _get_name_string(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        parts = []
        for attr in name:
            parts.append(f"{getattr(attr.oid, '_name', attr.oid.dotted_string)}={attr.value}")
        return ",".join(parts)


def _parse_host_port(target: str) -> Tuple[str, int]:
    t = target.strip()
    if not t:
        return "", 443
    if "://" in t:
        t = t.split("://", 1)[1]
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        host, port_s = t.rsplit(":", 1)
        return host.strip(), _safe_int(port_s, 443) or 443
    return t, 443

def parse_target(target: str) -> Tuple[str, int]:
    """
    Public wrapper used by app.py.
    Accepts targets like:
      - example.com
      - example.com:443
      - https://example.com
      - https://example.com:8443/path
    Returns (host, port)
    """
    return _parse_host_port(target)


def _socket_connect(host: str, port: int, timeout: float = 6.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _ssl_context_for(version: Optional[int], verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    ctx.load_default_certs()
    if version is not None:
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except Exception:
            pass
    return ctx


def _handshake(
    host: str,
    port: int,
    version: Optional[int] = None,
    verify: bool = True,
    timeout: float = 6.0,
    alpn: Optional[List[str]] = None,
) -> Tuple[ssl.SSLSocket, Dict[str, Any]]:
    raw = _socket_connect(host, port, timeout=timeout)
    ctx = _ssl_context_for(version, verify=verify)
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass

    ssock = ctx.wrap_socket(raw, server_hostname=host)
    ssock.do_handshake()

    info: Dict[str, Any] = {}

    try:
        info["tls_version"] = ssock.version() or ""
    except Exception:
        info["tls_version"] = ""

    try:
        c = ssock.cipher()
        if c:
            info["cipher_name"] = c[0]
            info["cipher_bits"] = c[2]
        else:
            info["cipher_name"] = ""
            info["cipher_bits"] = 0
    except Exception:
        info["cipher_name"] = ""
        info["cipher_bits"] = 0

    try:
        info["alpn"] = ssock.selected_alpn_protocol()
    except Exception:
        info["alpn"] = None

    # Stapled OCSP (best-effort; Python exposes ocsp_response on newer versions)
    ocsp_bytes = None
    try:
        ocsp_bytes = getattr(ssock, "ocsp_response", None)
        if callable(ocsp_bytes):
            ocsp_bytes = ocsp_bytes()
    except Exception:
        ocsp_bytes = None

    info["ocsp_stapled"] = bool(ocsp_bytes)
    info["_ocsp_stapled_bytes_len"] = len(ocsp_bytes) if ocsp_bytes else 0

    return ssock, info


def _supported_versions(host: str, port: int) -> List[str]:
    if not hasattr(ssl, "TLSVersion"):
        return []
    versions = [
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ]
    supported: List[str] = []
    for name, v in versions:
        try:
            s, _ = _handshake(host, port, version=v, verify=False, timeout=4.0, alpn=["h2", "http/1.1"])
            s.close()
            supported.append(name)
        except Exception:
            continue
    return supported


def _pem_or_der_to_x509(data: bytes) -> Optional[x509.Certificate]:
    if not data:
        return None
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except Exception:
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            try:
                return x509.load_der_x509_certificate(data)
            except Exception:
                return None


def _download_bytes(url: str, timeout: float = 6.0) -> Tuple[bytes, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pqc-scanner/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), ""
    except urllib.error.URLError as e:
        return b"", f"{e}"
    except Exception as e:
        return b"", f"{e}"


def _extract_cert_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "san_dns": [],
        "key_usage": {},
        "eku": [],
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],
    }

    # SAN
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns = []
        for gn in san:
            if isinstance(gn, x509.DNSName):
                dns.append(str(gn.value))
        out["san_dns"] = sorted(set(dns))
    except Exception:
        out["san_dns"] = []

    # KeyUsage
    try:
        ku: x509.KeyUsage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        out["key_usage"] = {
            "digital_signature": bool(ku.digital_signature),
            "key_encipherment": bool(ku.key_encipherment),
            "key_agreement": bool(ku.key_agreement),
            "content_commitment": bool(ku.content_commitment),
            "data_encipherment": bool(ku.data_encipherment),
            "key_cert_sign": bool(ku.key_cert_sign),
            "crl_sign": bool(ku.crl_sign),
            "encipher_only": bool(getattr(ku, "encipher_only", False)),
            "decipher_only": bool(getattr(ku, "decipher_only", False)),
        }
    except Exception:
        out["key_usage"] = {}

    # EKU
    try:
        eku: x509.ExtendedKeyUsage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        out["eku"] = [str(oid.dotted_string) for oid in eku]
    except Exception:
        out["eku"] = []

    # AIA (OCSP + CA Issuers)
    try:
        aia: x509.AuthorityInformationAccess = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        ocsp_urls = []
        ca_urls = []
        for desc in aia:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    ocsp_urls.append(str(desc.access_location.value))
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    ca_urls.append(str(desc.access_location.value))
        out["ocsp_urls"] = sorted(set(ocsp_urls))
        out["ca_issuers_urls"] = sorted(set(ca_urls))
    except Exception:
        out["ocsp_urls"] = []
        out["ca_issuers_urls"] = []

    # CRL distribution points
    try:
        dp: x509.CRLDistributionPoints = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        urls: List[str] = []
        for point in dp:
            if point.full_name:
                for gn in point.full_name:
                    if isinstance(gn, x509.UniformResourceIdentifier):
                        urls.append(str(gn.value))
        out["crl_urls"] = sorted(set(urls))
    except Exception:
        out["crl_urls"] = []

    return out


def _key_type_detail(pubkey) -> Tuple[str, str]:
    try:
        name = pubkey.__class__.__name__
        up = name.upper()
        if "RSA" in up:
            size = getattr(pubkey, "key_size", None)
            return "RSA", str(size) if size else ""
        if "EC" in up:
            curve = getattr(pubkey, "curve", None)
            cname = getattr(curve, "name", "") if curve else ""
            return "EC", cname
        if "ED25519" in up:
            return "Ed25519", ""
        if "ED448" in up:
            return "Ed448", ""
        return name, ""
    except Exception:
        return "unknown", ""


# ---------------------------
# OCSP: basic validation (no signature verification)
# ---------------------------

def _pick_issuer_cert(
    leaf: x509.Certificate,
    chain: List[x509.Certificate],
    ca_issuers_urls: List[str],
) -> Tuple[Optional[x509.Certificate], str]:
    # Verified chain typically: [leaf, intermediate, root]
    if chain and len(chain) >= 2:
        return chain[1], "chain"

    # Fallback: download issuer from AIA CA Issuers
    for url in ca_issuers_urls or []:
        data, err = _download_bytes(url, timeout=6.0)
        if err or not data:
            continue
        cert = _pem_or_der_to_x509(data)
        if cert:
            return cert, "aia_ca_issuers"

    return None, "none"


def _ocsp_check_basic(
    ocsp_url: str,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    timeout: float = 6.0,
) -> Tuple[Dict[str, Any], str]:
    """
    Perform a *basic* OCSP request and parse the response.
    Returns (ocsp_info, error). error=="" on success.

    No signature verification in step 1 (we'll add later).
    """
    t0 = time.time()
    try:
        builder = x509_ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1())
        req_bytes = builder.build().public_bytes(serialization.Encoding.DER)

        headers = {
            "Content-Type": "application/ocsp-request",
            "Accept": "application/ocsp-response",
            "User-Agent": "pqc-scanner/0.1",
        }
        req = urllib.request.Request(ocsp_url, data=req_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_bytes = resp.read()
            http_status = getattr(resp, "status", 200)
            resp_headers = dict(resp.headers.items())

        ocsp_resp = x509_ocsp.load_der_ocsp_response(resp_bytes)

        info: Dict[str, Any] = {
            "ocsp_url": ocsp_url,
            "http_status": http_status,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "response_status": getattr(ocsp_resp.response_status, "name", str(ocsp_resp.response_status)),
            "cert_status": "",
            "this_update": "",
            "next_update": "",
            "produced_at": "",
            "revocation_time": "",
            "revocation_reason": "",
            "responder_name": "",
            "http_server": resp_headers.get("Server", ""),
        }

        if ocsp_resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            cs = ocsp_resp.certificate_status
            info["cert_status"] = getattr(cs, "name", str(cs))
            info["this_update"] = _dt_to_iso(getattr(ocsp_resp, "this_update", None))
            info["next_update"] = _dt_to_iso(getattr(ocsp_resp, "next_update", None))
            info["produced_at"] = _dt_to_iso(getattr(ocsp_resp, "produced_at", None))
            info["revocation_time"] = _dt_to_iso(getattr(ocsp_resp, "revocation_time", None))
            rr = getattr(ocsp_resp, "revocation_reason", None)
            info["revocation_reason"] = getattr(rr, "name", str(rr)) if rr is not None else ""
            try:
                rn = ocsp_resp.responder_name
                info["responder_name"] = _get_name_string(rn) if rn else ""
            except Exception:
                info["responder_name"] = ""

        return info, ""
    except Exception as e:
        return {}, f"{e}"


# ---------------------------
# TLS 1.2 cipher probe (best-effort)
# ---------------------------

def _is_weak_tls12_cipher(cipher_name: str) -> bool:
    if not cipher_name:
        return False
    up = cipher_name.upper()
    if "RC4" in up or "3DES" in up or "NULL" in up or "EXPORT" in up or "MD5" in up:
        return True
    # CBC-SHA1 suites often include "-SHA" without "-SHA256/-SHA384"
    if up.endswith("-SHA") and ("-SHA256" not in up) and ("-SHA384" not in up):
        return True
    return False


def _probe_tls12_accepted_ciphers(host: str, port: int, timeout: float = 6.0) -> Dict[str, Any]:
    accepted: List[str] = []
    errors: List[str] = []

    candidates = [
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "AES128-SHA",
        "AES256-SHA",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
    ]

    if not hasattr(ssl, "TLSVersion"):
        return {"accepted": [], "weak_accepted": [], "errors": ["TLSVersion not available in this Python"]}

    for cname in candidates:
        try:
            raw = _socket_connect(host, port, timeout=timeout)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cname)
            ssock = ctx.wrap_socket(raw, server_hostname=host)
            ssock.do_handshake()
            chosen = ssock.cipher()
            ssock.close()
            if chosen and chosen[0] not in accepted:
                accepted.append(chosen[0])
        except Exception as e:
            errors.append(f"{cname}: {e}")

    weak = [c for c in accepted if _is_weak_tls12_cipher(c)]
    return {"accepted": accepted, "weak_accepted": weak, "errors": errors}


# ---------------------------
# Main scan
# ---------------------------

def scan_host(host: str, port: int = 443) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "error": "",
        "verify_mode": "CERT_REQUIRED",
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": 0,
        "alpn": None,
        "ocsp_stapled": False,

        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": 0,
        "key_type": "",
        "key_detail": "",
        "sig_algorithm": "",

        "san_dns": [],
        "key_usage": {},
        "eku": [],
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],

        "cert_chain": [],
        "chain_length": 0,
        "chain_issues": "none",
        "chain_source": "get_verified_chain",
        "chain_confidence_reason": "Chain comes from get_verified_chain (client-side verified path).",

        "tls_supported_versions": [],
        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        "tls_probe_errors": [],
        "forward_secrecy_possible": True,

        # Phase2 step1 outputs
        "ocsp_check": {},
        "ocsp_check_error": "",

        # populated by policy engine
        "findings": [],
        "risk_level": "low",
        "risk": "low",
        "pqc_relevance": "LOW",
        "pqc_recommendation": "",
    }

    ssock: Optional[ssl.SSLSocket] = None
    cert_obj: Optional[x509.Certificate] = None
    chain_certs: List[x509.Certificate] = []

    try:
        ssock, info = _handshake(host, port, verify=True, timeout=7.0, alpn=["h2", "http/1.1"])
        result.update(info)

        der = ssock.getpeercert(binary_form=True)
        cert_obj = x509.load_der_x509_certificate(der)

        result["subject"] = _get_name_string(cert_obj.subject)
        result["issuer"] = _get_name_string(cert_obj.issuer)

        nb = cert_obj.not_valid_before
        na = cert_obj.not_valid_after
        if nb.tzinfo is None:
            nb = nb.replace(tzinfo=timezone.utc)
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        result["not_before"] = _dt_to_iso(nb)
        result["not_after"] = _dt_to_iso(na)
        result["days_until_expiry"] = (na - _utcnow()).days

        pub = cert_obj.public_key()
        kt, kd = _key_type_detail(pub)
        result["key_type"] = kt
        result["key_detail"] = kd
        try:
            result["sig_algorithm"] = cert_obj.signature_algorithm_oid._name or cert_obj.signature_algorithm_oid.dotted_string
        except Exception:
            result["sig_algorithm"] = ""

        result.update(_extract_cert_extensions(cert_obj))

        # Chain (verified) best-effort
        try:
            chain = ssock.get_verified_chain()
            for entry in chain:
                if isinstance(entry, (bytes, bytearray)):
                    chain_certs.append(x509.load_der_x509_certificate(bytes(entry)))
                elif isinstance(entry, x509.Certificate):
                    chain_certs.append(entry)
            if chain_certs and chain_certs[0].fingerprint(hashes.SHA256()) != cert_obj.fingerprint(hashes.SHA256()):
                chain_certs.insert(0, cert_obj)
        except Exception:
            chain_certs = [cert_obj]

        chain_summary = []
        for idx, c in enumerate(chain_certs[:6]):
            try:
                pub2 = c.public_key()
                kt2, kd2 = _key_type_detail(pub2)
                chain_summary.append(
                    {
                        "index": idx,
                        "subject": _get_name_string(c.subject),
                        "issuer": _get_name_string(c.issuer),
                        "not_before": _dt_to_iso(c.not_valid_before.replace(tzinfo=timezone.utc) if c.not_valid_before.tzinfo is None else c.not_valid_before),
                        "not_after": _dt_to_iso(c.not_valid_after.replace(tzinfo=timezone.utc) if c.not_valid_after.tzinfo is None else c.not_valid_after),
                        "key": f"{kt2} / {kd2}".strip(" /"),
                        "sig": getattr(c.signature_algorithm_oid, "_name", "") or c.signature_algorithm_oid.dotted_string,
                        "sha256_fp": c.fingerprint(hashes.SHA256()).hex(),
                    }
                )
            except Exception:
                continue

        result["cert_chain"] = chain_summary
        # for your UI convention: exclude leaf
        result["chain_length"] = max(0, len(chain_certs) - 1)

    except ssl.SSLCertVerificationError as e:
        result["verify_mode"] = "CERT_NONE"
        result["error"] = f"{e}"
        try:
            if ssock:
                ssock.close()
        except Exception:
            pass

        try:
            ssock, info = _handshake(host, port, verify=False, timeout=7.0, alpn=["h2", "http/1.1"])
            result.update(info)
            der = ssock.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(der)

            result["subject"] = _get_name_string(cert_obj.subject)
            result["issuer"] = _get_name_string(cert_obj.issuer)

            nb = cert_obj.not_valid_before
            na = cert_obj.not_valid_after
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=timezone.utc)
            if na.tzinfo is None:
                na = na.replace(tzinfo=timezone.utc)
            result["not_before"] = _dt_to_iso(nb)
            result["not_after"] = _dt_to_iso(na)
            result["days_until_expiry"] = (na - _utcnow()).days

            pub = cert_obj.public_key()
            kt, kd = _key_type_detail(pub)
            result["key_type"] = kt
            result["key_detail"] = kd

            try:
                result["sig_algorithm"] = cert_obj.signature_algorithm_oid._name or cert_obj.signature_algorithm_oid.dotted_string
            except Exception:
                result["sig_algorithm"] = ""

            result.update(_extract_cert_extensions(cert_obj))

            chain_certs = [cert_obj]
            result["chain_source"] = "unverified_handshake"
            result["chain_confidence_reason"] = "Verification failed for default trust store; chain collected via unverified handshake."
            result["chain_length"] = 1
        except Exception as e2:
            result["error"] = result["error"] or str(e2)

    except Exception as e:
        result["error"] = f"{e}"

    finally:
        try:
            if ssock:
                ssock.close()
        except Exception:
            pass

    # TLS version support probe
    try:
        result["tls_supported_versions"] = _supported_versions(host, port)
    except Exception as e:
        result["tls_probe_errors"].append(f"versions: {e}")

    # TLS1.2 cipher probe
    try:
        cprobe = _probe_tls12_accepted_ciphers(host, port, timeout=5.0)
        result["tls12_accepted_ciphers"] = cprobe.get("accepted", [])
        result["tls12_weak_accepted_ciphers"] = cprobe.get("weak_accepted", [])
        errs = cprobe.get("errors", [])[:3]
        if errs:
            result["tls_probe_errors"].extend(errs)
    except Exception as e:
        result["tls_probe_errors"].append(f"ciphers: {e}")

    # Forward secrecy heuristic
    try:
        cn = (result.get("cipher_name") or "").upper()
        if (result.get("tls_version") or "").startswith("TLSv1.3"):
            result["forward_secrecy_possible"] = True
        else:
            result["forward_secrecy_possible"] = ("ECDHE" in cn) or ("DHE" in cn)
    except Exception:
        result["forward_secrecy_possible"] = True

    # Phase2 step1: basic OCSP check if OCSP URLs exist
    try:
        if cert_obj and result.get("ocsp_urls"):
            issuer_cert, src = _pick_issuer_cert(cert_obj, chain_certs, result.get("ca_issuers_urls", []))
            if issuer_cert:
                ocsp_info, err = _ocsp_check_basic(result["ocsp_urls"][0], cert_obj, issuer_cert, timeout=6.0)
                result["ocsp_check"] = ocsp_info
                result["ocsp_check_error"] = err
                result["ocsp_check"]["issuer_source"] = src
            else:
                result["ocsp_check_error"] = "No issuer cert available to build OCSP request (need chain or CA Issuers AIA)."
    except Exception as e:
        result["ocsp_check_error"] = str(e)

    # Build findings + risk + PQC recommendation
    try:
        findings = evaluate_findings(result)
    except Exception as e:
        findings = [{
            "rule_id": "POLICY_ENGINE_ERROR",
            "severity": "low",
            "title": "Policy engine error",
            "fix": "Check server logs and policy rules.",
            "confidence": "low",
            "confidence_reason": "Exception raised while evaluating findings.",
            "evidence": {"error": str(e)},
            "pqc_note": "",
        }]

    result["findings"] = findings
    result["risk_level"] = risk_level_from_findings(findings)
    result["risk"] = result["risk_level"]
    pqc_level, pqc_reco = pqc_relevance_and_reco(result, findings)
    result["pqc_relevance"] = pqc_level
    result["pqc_recommendation"] = pqc_reco

    return result


def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for t in targets:
        host, port = _parse_host_port(t)
        if not host:
            continue
        out.append(scan_host(host, port))
    return out
