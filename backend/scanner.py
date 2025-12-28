from __future__ import annotations

import socket
import ssl
import time
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from policy import evaluate_findings, pqc_relevance_and_reco, risk_level_from_findings


DEFAULT_TIMEOUT_SECONDS = 6.0


# ---- Target parsing ----

_TARGET_RE = re.compile(r"^\s*(?:(?:https?|tcp)://)?(?P<host>[^/:]+)(?::(?P<port>\d+))?\s*$")


def parse_target(target: str) -> Tuple[str, int]:
    m = _TARGET_RE.match(target or "")
    if not m:
        return target.strip(), 443
    host = (m.group("host") or "").strip()
    port_s = m.group("port")
    port = int(port_s) if port_s else 443
    return host, port


# ---- Helpers ----

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _safe_iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _pk_info(cert: x509.Certificate) -> Tuple[str, str]:
    """
    Returns (key_type, key_detail)
    key_type is normalized: RSA / EC / UNKNOWN
    key_detail is key_size for RSA or curve for EC
    """
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", str(pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        curve = getattr(pk.curve, "name", "unknown")
        return "EC", str(curve)
    return "UNKNOWN", ""


def _sig_algorithm(cert: x509.Certificate) -> str:
    try:
        # cryptography gives an OID object with a name
        return cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    except Exception:
        try:
            return cert.signature_algorithm_oid.dotted_string
        except Exception:
            return ""


def _parse_san_dns(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return []


def _parse_key_usage(cert: x509.Certificate) -> Dict[str, bool]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        ku: x509.KeyUsage = ext.value
        return {
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
        return {}


def _parse_eku(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku: x509.ExtendedKeyUsage = ext.value
        return [oid.dotted_string for oid in eku]
    except Exception:
        return []


def _parse_aia(cert: x509.Certificate) -> Tuple[List[str], List[str]]:
    ocsp_urls: List[str] = []
    ca_issuers: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for ad in ext.value:
            if ad.access_location and isinstance(ad.access_location, x509.UniformResourceIdentifier):
                uri = ad.access_location.value
                if ad.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(uri)
                elif ad.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuers.append(uri)
    except Exception:
        pass
    return ocsp_urls, ca_issuers


def _parse_crl_dp(cert: x509.Certificate) -> List[str]:
    urls: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for dp in ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
    except Exception:
        pass
    return urls


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - _now_utc()).total_seconds() // 86400)


def _openssl_ocsp_stapling(host: str, port: int, timeout: float = 8.0) -> Tuple[Optional[bool], str]:
    """
    Best-effort OCSP stapling detection using openssl s_client -status.
    Returns (stapled?, debug_text).
    stapled? can be True/False/None (None = couldn't probe).
    """
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "openssl not in PATH"

    cmd = [openssl, "s_client", "-connect", f"{host}:{port}", "-servername", host, "-status"]
    try:
        p = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        out = (p.stdout or b"") + b"\n" + (p.stderr or b"")
        text = out.decode("utf-8", errors="replace")

        # Common outputs:
        # "OCSP response: no OCSP response received"
        # "OCSP Response Status: successful"
        # or OCSP block present
        if re.search(r"OCSP response:\s+no OCSP response received", text, re.IGNORECASE):
            return False, "openssl: no OCSP response received"
        if re.search(r"OCSP Response Status:\s+successful", text, re.IGNORECASE):
            return True, "openssl: OCSP Response Status successful"
        if re.search(r"OCSP Response Status:", text, re.IGNORECASE):
            # status exists but not successful
            return True, "openssl: OCSP Response Status present"
        # Some openssl versions say "no response sent"
        if re.search(r"no response sent", text, re.IGNORECASE):
            return False, "openssl: no response sent"
        return None, "openssl: OCSP status unclear"
    except Exception as e:
        return None, f"openssl probe error: {e}"


def _make_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    # be permissive about ALPN
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> Tuple[ssl.SSLSocket, str]:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        # trigger handshake
        ssock.do_handshake()
        return ssock, ""
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return None, str(e)


def _probe_supported_versions(host: str, port: int, timeout: float) -> List[str]:
    """
    Active probes for TLS versions (best-effort).
    """
    versions = []
    candidates = []
    # Python may not have TLSv1.0/1.1 depending on OpenSSL build
    if hasattr(ssl, "TLSVersion"):
        candidates = [
            ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
            ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
            ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
        ]
    # Filter None
    candidates = [(name, v) for name, v in candidates if v is not None]
    for name, v in candidates:
        try:
            ctx = _make_context(verify=False)
            ctx.minimum_version = v
            ctx.maximum_version = v
            s, err = _handshake(host, port, ctx, timeout)
            if s:
                versions.append(name)
                try:
                    s.close()
                except Exception:
                    pass
        except Exception:
            continue
    # If none, leave empty (unknown)
    return versions


_WEAK_TLS12_CIPHERS = [
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "NULL-MD5",
    "NULL-SHA",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    # also consider CBC ECDHE variants as weaker than GCM/CHACHA
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
]


def _probe_tls12_accepted_ciphers(host: str, port: int, timeout: float) -> Tuple[List[str], List[str]]:
    """
    Best-effort probe: try TLS1.2 with each cipher and record which succeed.
    Note: depends on client OpenSSL cipher availability.
    """
    accepted = []
    weak_accepted = []

    if not hasattr(ssl, "TLSVersion"):
        return accepted, weak_accepted

    for cipher in _WEAK_TLS12_CIPHERS:
        try:
            ctx = _make_context(verify=False)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                ctx.set_ciphers(cipher)
            except Exception:
                # cipher not supported by client
                continue
            s, err = _handshake(host, port, ctx, timeout)
            if s:
                accepted.append(cipher)
                weak_accepted.append(cipher)
                try:
                    s.close()
                except Exception:
                    pass
        except Exception:
            continue

    return accepted, weak_accepted


def _forward_secrecy_possible(tls_version: str, cipher_name: str) -> bool:
    if tls_version == "TLSv1.3":
        return True
    c = (cipher_name or "").upper()
    return ("ECDHE" in c) or ("DHE" in c)


def _cert_chain_from_socket(ssock: ssl.SSLSocket, leaf_cert: x509.Certificate) -> Tuple[List[Dict[str, Any]], int, str, str]:
    """
    Return (cert_chain_list, chain_length, chain_issues, chain_source)
    """
    chain: List[x509.Certificate] = []
    source = "get_verified_chain"
    confidence_reason = "Chain comes from get_verified_chain (client-side verified path)."

    # Python may not provide chain APIs; use leaf as fallback.
    try:
        # Python 3.11+ has getpeercert(binary_form=True) for leaf
        if hasattr(ssock, "get_verified_chain"):
            raw_chain = ssock.get_verified_chain()
            for item in raw_chain or []:
                der = None
                if isinstance(item, (bytes, bytearray)):
                    der = bytes(item)
                elif hasattr(item, "public_bytes"):
                    der = item.public_bytes(Encoding.DER)  # type: ignore
                elif hasattr(item, "to_cryptography"):
                    c = item.to_cryptography()
                    der = c.public_bytes(Encoding.DER)
                if der:
                    chain.append(x509.load_der_x509_certificate(der))
        elif hasattr(ssock, "get_peer_cert_chain"):
            raw_chain = ssock.get_peer_cert_chain()
            for der in raw_chain or []:
                if isinstance(der, (bytes, bytearray)):
                    chain.append(x509.load_der_x509_certificate(bytes(der)))
        # Some environments return empty chain; ensure leaf present
        if not chain:
            chain = [leaf_cert]
    except Exception:
        chain = [leaf_cert]
        source = "leaf_only"
        confidence_reason = "Only leaf certificate available via handshake."

    chain_entries: List[Dict[str, Any]] = []
    for i, cert in enumerate(chain):
        kt, kd = _pk_info(cert)
        chain_entries.append({
            "index": i,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": _safe_iso(_to_utc(cert.not_valid_before)),
            "not_after": _safe_iso(_to_utc(cert.not_valid_after)),
            "key_type": kt,
            "key_detail": kd,
            "sig_algorithm": _sig_algorithm(cert),
            "fingerprint_sha256": _cert_fingerprint_sha256(cert),
            "serial_hex": hex(cert.serial_number),
        })

    chain_length = len(chain_entries)
    issues = "none"
    if chain_length <= 1:
        issues = "chain_short_or_unavailable"

    return chain_entries, chain_length, issues, source, confidence_reason


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def scan_host(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    start = time.time()
    out: Dict[str, Any] = {
        "host": host,
        "port": int(port),
        "error": "",
        "verify_mode": "CERT_REQUIRED",
        "verify_error": "",
        "tls_version": "",
        "tls_supported_versions": [],
        "cipher_name": "",
        "cipher_bits": 0,
        "alpn": None,
        "subject": "",
        "issuer": "",
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "key_type": "UNKNOWN",
        "key_detail": "",
        "sig_algorithm": "",
        # extensions / revocation pointers
        "san_dns": [],
        "key_usage": {},
        "eku": [],
        "ocsp_urls": [],
        "ca_issuers_urls": [],
        "crl_urls": [],
        # stapling (best-effort)
        "ocsp_stapled": None,
        "ocsp_stapling_probe": "",
        # chain
        "cert_chain": [],
        "chain_length": 0,
        "chain_issues": "none",
        "chain_source": "get_verified_chain",
        "chain_confidence_reason": "",
        "chain_confidence": "",
        # tls12 cipher probes
        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        # fs
        "forward_secrecy_possible": None,
        # computed
        "findings": [],
        "risk_level": "low",
        "risk": "low",
        "pqc_relevance": "MEDIUM",
        "pqc_recommendation": "",
        "scan_ms": 0,
    }

    # 1) try verified handshake first
    cert_der = None
    ssock = None
    try:
        ctx_v = _make_context(verify=True)
        ssock, verr = _handshake(host, port, ctx_v, timeout)
        if not ssock:
            out["verify_error"] = verr
            out["verify_mode"] = "CERT_REQUIRED"
            # fallback unverified
            ctx_u = _make_context(verify=False)
            ssock, err2 = _handshake(host, port, ctx_u, timeout)
            out["verify_mode"] = "CERT_NONE"
            if not ssock:
                out["error"] = verr or err2 or "TLS handshake failed"
                out["scan_ms"] = int((time.time() - start) * 1000)
                out["findings"] = evaluate_findings(out)
                out["risk_level"] = risk_level_from_findings(out["findings"])
                out["risk"] = out["risk_level"]
                out["pqc_relevance"], out["pqc_recommendation"] = pqc_relevance_and_reco(out)
                return out
        # read connection info
        out["tls_version"] = ssock.version() or ""
        cipher = ssock.cipher() or ("", "", 0)
        out["cipher_name"] = cipher[0] or ""
        out["cipher_bits"] = int(cipher[2] or 0)
        try:
            out["alpn"] = ssock.selected_alpn_protocol()
        except Exception:
            out["alpn"] = None

        cert_der = ssock.getpeercert(binary_form=True)
        if not cert_der:
            out["error"] = "No certificate presented"
            try:
                ssock.close()
            except Exception:
                pass
            out["findings"] = evaluate_findings(out)
            out["risk_level"] = risk_level_from_findings(out["findings"])
            out["risk"] = out["risk_level"]
            out["pqc_relevance"], out["pqc_recommendation"] = pqc_relevance_and_reco(out)
            out["scan_ms"] = int((time.time() - start) * 1000)
            return out

        cert = x509.load_der_x509_certificate(cert_der)

        out["subject"] = cert.subject.rfc4514_string()
        out["issuer"] = cert.issuer.rfc4514_string()
        out["not_before"] = _safe_iso(_to_utc(cert.not_valid_before))
        out["not_after"] = _safe_iso(_to_utc(cert.not_valid_after))
        out["days_until_expiry"] = _days_until(_to_utc(cert.not_valid_after))
        kt, kd = _pk_info(cert)
        out["key_type"] = kt
        out["key_detail"] = kd
        out["sig_algorithm"] = _sig_algorithm(cert)

        out["san_dns"] = _parse_san_dns(cert)
        out["key_usage"] = _parse_key_usage(cert)
        out["eku"] = _parse_eku(cert)
        ocsp_urls, ca_issuers = _parse_aia(cert)
        out["ocsp_urls"] = ocsp_urls
        out["ca_issuers_urls"] = ca_issuers
        out["crl_urls"] = _parse_crl_dp(cert)

        # chain
        chain_entries, chain_len, chain_issues, chain_source, chain_conf_reason = _cert_chain_from_socket(ssock, cert)
        out["cert_chain"] = chain_entries
        out["chain_length"] = chain_len
        out["chain_issues"] = chain_issues
        out["chain_source"] = chain_source
        out["chain_confidence_reason"] = chain_conf_reason
        out["chain_confidence"] = "high" if chain_source == "get_verified_chain" else "medium"

        # probes
        out["tls_supported_versions"] = _probe_supported_versions(host, port, timeout=timeout)
        accepted, weak_accepted = _probe_tls12_accepted_ciphers(host, port, timeout=timeout)
        out["tls12_accepted_ciphers"] = accepted
        out["tls12_weak_accepted_ciphers"] = weak_accepted

        out["forward_secrecy_possible"] = _forward_secrecy_possible(out["tls_version"], out["cipher_name"])

        # OCSP stapling best-effort using openssl (optional but valuable)
        stapled, probe_text = _openssl_ocsp_stapling(host, port, timeout=max(6.0, timeout))
        out["ocsp_stapled"] = stapled if stapled is not None else False  # keep boolean for UI simplicity
        out["ocsp_stapling_probe"] = probe_text

        try:
            ssock.close()
        except Exception:
            pass

    except Exception as e:
        out["error"] = str(e)

    # compute findings + risk + pqc
    out["findings"] = evaluate_findings(out)
    out["risk_level"] = risk_level_from_findings(out["findings"])
    out["risk"] = out["risk_level"]
    out["pqc_relevance"], out["pqc_recommendation"] = pqc_relevance_and_reco(out)
    out["scan_ms"] = int((time.time() - start) * 1000)
    return out
