# backend/scanner.py
from __future__ import annotations

import socket
import ssl
import hashlib
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509 import ocsp as x509_ocsp

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

def _classify_verify_error(err: Exception) -> Dict[str, Any]:
    # Best-effort classification of TLS certificate verification failures.
    # SSLCertVerificationError often exposes verify_code/verify_message.
    code = getattr(err, "verify_code", None)
    msg = getattr(err, "verify_message", None) or str(err)
    msg_l = (msg or "").lower()

    reason = "other"
    if "hostname" in msg_l or "does not match" in msg_l or "wrong host" in msg_l:
        reason = "hostname_mismatch"
    elif "certificate has expired" in msg_l or "expired" in msg_l:
        reason = "expired"
    elif "revoked" in msg_l:
        reason = "revoked"
    elif "unable to get local issuer" in msg_l or "self signed" in msg_l or "unknown ca" in msg_l:
        reason = "untrusted_issuer"
    elif "unable to get issuer certificate" in msg_l or "unable to verify the first certificate" in msg_l:
        reason = "missing_intermediate"
    elif "certificate chain too long" in msg_l:
        reason = "chain_too_long"

    return {"verify_code": code, "verify_message": msg, "verify_reason": reason}


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
        "verify_code": None,
        "verify_message": "",
        "verify_reason": "",
        "unverified_fallback": False,
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


def _probe_http_endpoint(url: str, timeout: float = 3.0, max_read: int = 4096) -> Dict[str, Any]:
    """Best-effort reachability probe for OCSP/CRL endpoints (NOT a full OCSP request).

    Notes:
      - Many OCSP responders expect POST requests; this probe only checks basic HTTP reachability.
      - Any HTTP response code (including 4xx/5xx) still proves the endpoint is reachable at the network level.
    """
    start = time.time()
    out: Dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "elapsed_ms": None,
        "method": "",
        "error": "",
    }

    def _mark_reachable(method: str, status: Optional[int] = None):
        out["reachable"] = True
        out["method"] = method
        out["status_code"] = status

    try:
        # HEAD first (fast). Some responders reject HEAD (405), which still proves reachability.
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                _mark_reachable("HEAD", getattr(resp, "status", None) or resp.getcode())
        except urllib.error.HTTPError as e:
            _mark_reachable("HEAD", getattr(e, "code", None))
    except Exception as head_err:
        try:
            # Fallback GET with Range to limit bytes.
            req = urllib.request.Request(url, method="GET", headers={"Range": f"bytes=0-{max_read-1}"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    _mark_reachable("GET", getattr(resp, "status", None) or resp.getcode())
                    _ = resp.read(max_read)
            except urllib.error.HTTPError as e:
                _mark_reachable("GET", getattr(e, "code", None))
        except Exception as get_err:
            out["error"] = str(get_err or head_err)
    finally:
        out["elapsed_ms"] = int((time.time() - start) * 1000)

    return out



def _probe_revocation_endpoints(ocsp_urls: List[str], crl_urls: List[str], max_urls: int = 2) -> Dict[str, Any]:
    """Probe advertised OCSP/CRL URLs for basic network/HTTP reachability."""
    ocsp_results: List[Dict[str, Any]] = []
    crl_results: List[Dict[str, Any]] = []

    for u in [x for x in (ocsp_urls or []) if str(x).strip()][:max_urls]:
        try:
            ocsp_results.append(_probe_http_endpoint(str(u)))
        except Exception as e:
            ocsp_results.append({"url": str(u), "reachable": False, "status_code": None, "elapsed_ms": None, "method": "", "error": str(e)})

    for u in [x for x in (crl_urls or []) if str(x).strip()][:max_urls]:
        try:
            crl_results.append(_probe_http_endpoint(str(u)))
        except Exception as e:
            crl_results.append({"url": str(u), "reachable": False, "status_code": None, "elapsed_ms": None, "method": "", "error": str(e)})

    return {"ocsp_reachability": ocsp_results, "crl_reachability": crl_results}


def _parse_stapled_ocsp(der_bytes: bytes) -> Dict[str, Any]:
    """Parse a stapled OCSP response (if present) into status + timestamps."""
    out: Dict[str, Any] = {
        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",
        "ocsp_stapled_is_stale": False,
        "ocsp_stapled_stale_by_days": None,
    }
    try:
        resp = x509_ocsp.load_der_ocsp_response(der_bytes)
        # Cryptography uses OCSPResponseStatus + OCSPCertStatus enums
        out["ocsp_stapled_produced_at"] = _utc_iso(getattr(resp, "produced_at", None))
        if getattr(resp, "response_status", None) is not None:
            out["ocsp_response_status"] = str(resp.response_status).split(".")[-1]
        # Only successful responses have single_response
        single = getattr(resp, "responses", None)
        if single:
            r0 = single[0]
            out["ocsp_stapled_status"] = str(getattr(r0, "cert_status", "")).split(".")[-1].lower()
            out["ocsp_stapled_this_update"] = _utc_iso(getattr(r0, "this_update", None))
            out["ocsp_stapled_next_update"] = _utc_iso(getattr(r0, "next_update", None))
            try:
                nu = getattr(r0, "next_update", None)
                if nu is not None:
                    if nu.tzinfo is None:
                        nu = nu.replace(tzinfo=timezone.utc)
                    now = datetime.utcnow().replace(tzinfo=timezone.utc)
                    out["ocsp_stapled_is_stale"] = nu < now
                    out["ocsp_stapled_stale_by_days"] = int((now - nu).days) if nu < now else 0
            except Exception:
                pass
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

        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",

        "ocsp_reachability": [],
        "crl_reachability": [],
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
        "verify_code": None,
        "verify_message": "",
        "verify_reason": "",
        "unverified_fallback": False,

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

        "ocsp_stapled_status": "",
        "ocsp_stapled_this_update": "",
        "ocsp_stapled_next_update": "",
        "ocsp_stapled_produced_at": "",

        "ocsp_reachability": [],
        "crl_reachability": [],

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

                    # Revocation endpoint reachability (best-effort)
                    try:
                        probes = _probe_revocation_endpoints(
                            facts.get("ocsp_urls", []),
                            facts.get("crl_urls", []),
                            max_urls=2,
                        )
                        facts.update(probes)
                    except Exception:
                        pass

                # Chain (best-effort)
                chain_der, chain_source, conf, conf_reason = _get_cert_chain_der_with_source(ssock)
                facts["chain_source"] = chain_source
                facts["chain_confidence"] = conf
                facts["chain_confidence_reason"] = conf_reason
                facts.update(_analyze_cert_chain(chain_der))

    except _SSLCertVerificationError as e:
        facts["verify_error"] = str(e)
        facts.update(_classify_verify_error(e))
        facts["unverified_fallback"] = True
        # Best-effort fallback: collect cert/chain details without verification so we can still produce actionable findings.
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Populate best-effort facts (do not overwrite verify_error)
                    if not facts.get("tls_version"):
                        facts["tls_version"] = ssock.version() or ""
                    c = ssock.cipher()
                    if c and not facts.get("cipher_name"):
                        facts["cipher_name"] = c[0] or ""
                        facts["cipher_bits"] = c[2] if len(c) > 2 else None
                    try:
                        if facts.get("alpn") is None:
                            facts["alpn"] = ssock.selected_alpn_protocol()
                    except Exception:
                        pass

                    # OCSP stapling (best-effort)
                    facts.update(_try_get_ocsp_staple(ssock))

                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        facts["subject"] = cert.subject.rfc4514_string()
                        facts["issuer"] = cert.issuer.rfc4514_string()
                        facts["not_before"] = _utc_iso(cert.not_valid_before)
                        facts["not_after"] = _utc_iso(cert.not_valid_after)
                        facts["days_until_expiry"] = _days_until(cert.not_valid_after)
                        kt, kd = _extract_key_info(cert)
                        facts["key_type"] = kt
                        facts["key_detail"] = kd
                        facts.update(_extract_leaf_extensions(cert))

                        # Revocation endpoint reachability (best-effort)
                        try:
                            probes = _probe_revocation_endpoints(
                                facts.get("ocsp_urls", []),
                                facts.get("crl_urls", []),
                                max_urls=2,
                            )
                            facts.update(probes)
                        except Exception:
                            pass

                    # Chain (best-effort)
                    chain_der, chain_source, conf, conf_reason = _get_cert_chain_der_with_source(ssock)
                    facts["chain_source"] = chain_source
                    facts["chain_confidence"] = conf
                    facts["chain_confidence_reason"] = conf_reason
                    facts.update(_analyze_cert_chain(chain_der))
        except Exception:
            pass
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
