import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import http.client
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import (
    ExtensionOID,
    ExtendedKeyUsageOID,
    AuthorityInformationAccessOID,
)

from policy import evaluate_policies, derive_risk_and_score, derive_pqc_relevance

_SSLCertVerificationError = getattr(ssl, "SSLCertVerificationError", ssl.SSLError)

DEFAULT_TIMEOUT = 6

TLS12_CIPHER_PROBES = [
    # Modern AEAD ciphers
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    # Older / weaker (we probe to see if accepted)
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
]

WEAK_CIPHER_KEYWORDS = ["rc4", "des", "3des", "md5", "null", "export", "anon"]
WEAK_SIG_KEYWORDS = ["sha1", "md5"]


def _utc_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _normalize_tls_version(v: str) -> str:
    """
    Normalize ssl.SSLSocket.version() outputs across platforms.
    Common outputs:
      - "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"
    We normalize "TLSv1" -> "TLSv1.0".
    """
    s = (v or "").strip()
    if s == "TLSv1":
        return "TLSv1.0"
    return s


def _parse_target(t: str) -> Tuple[str, int]:
    s = (t or "").strip()
    if not s:
        return "", 443
    if "://" in s:
        try:
            u = urlparse(s)
            host = u.hostname or ""
            port = int(u.port or 443)
            return host, port
        except Exception:
            pass
    if ":" in s:
        host, p = s.rsplit(":", 1)
        try:
            return host.strip(), int(p.strip())
        except Exception:
            return s.strip(), 443
    return s.strip(), 443


def _is_weak_cipher(cipher_name: str) -> bool:
    c = (cipher_name or "").lower()
    return any(k in c for k in WEAK_CIPHER_KEYWORDS)


def _is_weak_sig(sig_name: str) -> bool:
    s = (sig_name or "").lower()
    return any(k in s for k in WEAK_SIG_KEYWORDS)


def _make_context(protocol_const: int, verify: bool, alpn: Optional[List[str]] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(protocol_const)

    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except Exception:
        pass

    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass

    return ctx


def _client_tls13_capable() -> bool:
    """
    We only claim a server lacks TLS 1.3 if the *client* can actually negotiate TLS 1.3.
    Python 3.6 on Windows often isn't reliably TLS 1.3 capable.
    """
    # Newer Python: TLSVersion exists
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.SSLContext, "minimum_version"):
        return True
    # Older builds may still support TLS 1.3 via OP_NO_TLSv1_3
    if hasattr(ssl, "OP_NO_TLSv1_3"):
        return True
    return False


def _connect_handshake(
    host: str,
    port: int,
    protocol_const: int,
    verify: bool,
    alpn: Optional[List[str]] = None,
    sni: bool = True,
    ciphers: Optional[str] = None,
) -> Dict[str, Any]:
    ctx = _make_context(protocol_const, verify=verify, alpn=alpn)

    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            pass

    out: Dict[str, Any] = {
        "success": False,
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "verify_error": "",
    }

    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            if sni:
                ssock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                ssock = ctx.wrap_socket(sock)

            with ssock:
                out["success"] = True
                out["tls_version"] = _normalize_tls_version(ssock.version() or "")
                c = ssock.cipher()
                if c:
                    out["cipher_name"] = c[0] or ""
                    out["cipher_bits"] = c[2]
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
    """
    More reliable strategy on older Python:
    - Use PROTOCOL_TLSv1 / TLSv1_1 / TLSv1_2 to *attempt* a negotiation.
    - For TLS 1.3 we can only test if client is capable.
    - Record supported versions only when the negotiated version matches our expected family.
    """
    supported: List[str] = []
    support_map: Dict[str, bool] = {}
    probe_errors: List[str] = []

    # TLS 1.3 probe: only if client can do it
    tls13_testable = _client_tls13_capable()
    if tls13_testable:
        try:
            r = _connect_handshake(host, port, ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
            # If TLS 1.3 is supported, we should sometimes see TLSv1.3 (not guaranteed if server picks 1.2)
            # So we do a stronger test on newer Python via minimum_version; but on 3.6 we can't.
            # For old envs, we treat TLSv1.3 as "unknown unless observed".
            if r.get("success") and r.get("tls_version") == "TLSv1.3":
                supported.append("TLSv1.3")
                support_map["TLSv1.3"] = True
            else:
                support_map["TLSv1.3"] = False
        except Exception as e:
            probe_errors.append("TLSv1.3:%s" % str(e))
            support_map["TLSv1.3"] = False
    else:
        support_map["TLSv1.3"] = False

    # TLS 1.2
    try:
        r = _connect_handshake(host, port, getattr(ssl, "PROTOCOL_TLSv1_2", ssl.PROTOCOL_TLS), verify=False, alpn=["h2", "http/1.1"])
        ok = bool(r.get("success")) and (r.get("tls_version") in ("TLSv1.2", "TLSv1.3"))
        # If we asked for TLS1.2 method but got 1.3, that's fine (server prefers higher).
        if ok:
            supported.append("TLSv1.2")
            support_map["TLSv1.2"] = True
        else:
            support_map["TLSv1.2"] = False
    except Exception as e:
        probe_errors.append("TLSv1.2:%s" % str(e))
        support_map["TLSv1.2"] = False

    # TLS 1.1
    try:
        r = _connect_handshake(host, port, getattr(ssl, "PROTOCOL_TLSv1_1", ssl.PROTOCOL_TLS), verify=False, alpn=["h2", "http/1.1"])
        ok = bool(r.get("success")) and (r.get("tls_version") in ("TLSv1.1",))
        if ok:
            supported.append("TLSv1.1")
            support_map["TLSv1.1"] = True
        else:
            support_map["TLSv1.1"] = False
    except Exception as e:
        probe_errors.append("TLSv1.1:%s" % str(e))
        support_map["TLSv1.1"] = False

    # TLS 1.0
    try:
        r = _connect_handshake(host, port, getattr(ssl, "PROTOCOL_TLSv1", ssl.PROTOCOL_TLS), verify=False, alpn=["h2", "http/1.1"])
        ok = bool(r.get("success")) and (_normalize_tls_version(r.get("tls_version", "")) in ("TLSv1.0",))
        if ok:
            supported.append("TLSv1.0")
            support_map["TLSv1.0"] = True
        else:
            support_map["TLSv1.0"] = False
    except Exception as e:
        probe_errors.append("TLSv1.0:%s" % str(e))
        support_map["TLSv1.0"] = False

    return {
        "tls13_testable": tls13_testable,
        "tls_supported_versions": supported,
        "tls_support_map": support_map,
        "tls_probe_errors": probe_errors,
    }


def _probe_tls12_accepted_ciphers(host: str, port: int) -> Dict[str, Any]:
    """
    IMPORTANT: TLS 1.3 ignores ctx.set_ciphers(); so we only count acceptance
    when the negotiated version is actually TLSv1.2.
    """
    accepted: List[str] = []
    weak_accepted: List[str] = []
    errors: List[str] = []

    proto = getattr(ssl, "PROTOCOL_TLSv1_2", ssl.PROTOCOL_TLS)

    for c in TLS12_CIPHER_PROBES:
        try:
            r = _connect_handshake(
                host,
                port,
                protocol_const=proto,
                verify=False,
                alpn=["h2", "http/1.1"],
                ciphers=c,
                sni=True,
            )
            if r.get("success") and r.get("tls_version") == "TLSv1.2":
                accepted.append(c)
                if _is_weak_cipher(c):
                    weak_accepted.append(c)
        except Exception as e:
            errors.append("%s:%s" % (c, str(e)))

    return {
        "tls12_accepted_ciphers": accepted,
        "tls12_weak_accepted_ciphers": weak_accepted,
        "tls_probe_errors": list(dict.fromkeys(errors)),
    }


def _get_ext(cert: x509.Certificate, oid) -> Optional[Any]:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except Exception:
        return None


def _extract_leaf_cert_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "cert_san_dns": [],
        "cert_san_ip": [],
        "cert_key_usage": {},
        "cert_eku": [],
        "cert_ocsp_urls": [],
        "cert_ca_issuers_urls": [],
        "cert_crl_urls": [],
        "cert_policies": [],
        "cert_has_sct": False,
        "cert_sct_count": 0,
        "cert_must_staple": False,
        "cert_basic_constraints": {},
        "cert_is_ca": False,
    }

    san = _get_ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san:
        try:
            out["cert_san_dns"] = list(san.get_values_for_type(x509.DNSName))
        except Exception:
            pass
        try:
            ips = san.get_values_for_type(x509.IPAddress)
            out["cert_san_ip"] = [str(ip) for ip in ips]
        except Exception:
            pass

    ku = _get_ext(cert, ExtensionOID.KEY_USAGE)
    if ku:
        try:
            out["cert_key_usage"] = {
                "digital_signature": bool(getattr(ku, "digital_signature", False)),
                "content_commitment": bool(getattr(ku, "content_commitment", False)),
                "key_encipherment": bool(getattr(ku, "key_encipherment", False)),
                "data_encipherment": bool(getattr(ku, "data_encipherment", False)),
                "key_agreement": bool(getattr(ku, "key_agreement", False)),
                "key_cert_sign": bool(getattr(ku, "key_cert_sign", False)),
                "crl_sign": bool(getattr(ku, "crl_sign", False)),
            }
        except Exception:
            pass

    eku = _get_ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku:
        try:
            names: List[str] = []
            for oid in eku:
                if oid == ExtendedKeyUsageOID.SERVER_AUTH:
                    names.append("serverAuth")
                elif oid == ExtendedKeyUsageOID.CLIENT_AUTH:
                    names.append("clientAuth")
                else:
                    names.append(getattr(oid, "dotted_string", str(oid)))
            out["cert_eku"] = names
        except Exception:
            pass

    bc = _get_ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if bc:
        try:
            out["cert_basic_constraints"] = {"ca": bool(bc.ca), "path_length": bc.path_length}
            out["cert_is_ca"] = bool(bc.ca)
        except Exception:
            pass

    aia = _get_ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if aia:
        ocsp_urls: List[str] = []
        ca_issuers: List[str] = []
        try:
            for access in aia:
                if access.access_method == AuthorityInformationAccessOID.OCSP:
                    if isinstance(access.access_location, x509.UniformResourceIdentifier):
                        ocsp_urls.append(access.access_location.value)
                elif access.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(access.access_location, x509.UniformResourceIdentifier):
                        ca_issuers.append(access.access_location.value)
        except Exception:
            pass
        out["cert_ocsp_urls"] = list(dict.fromkeys(ocsp_urls))
        out["cert_ca_issuers_urls"] = list(dict.fromkeys(ca_issuers))

    return out


def _probe_hsts(host: str, port: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "hsts_present": False,
        "hsts_header": "",
        "hsts_max_age": None,
        "hsts_include_subdomains": False,
        "hsts_preload": False,
        "hsts_error": "",
    }
    try:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, port, timeout=DEFAULT_TIMEOUT, context=ctx)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hdr = resp.getheader("Strict-Transport-Security")
        if hdr:
            out["hsts_present"] = True
            out["hsts_header"] = hdr

            parts = [p.strip() for p in hdr.split(";") if p.strip()]
            for p in parts:
                low = p.lower()
                if low.startswith("max-age"):
                    try:
                        _, v = p.split("=", 1)
                        out["hsts_max_age"] = int(v.strip())
                    except Exception:
                        pass
                elif low == "includesubdomains":
                    out["hsts_include_subdomains"] = True
                elif low == "preload":
                    out["hsts_preload"] = True
        try:
            conn.close()
        except Exception:
            pass
    except Exception as e:
        out["hsts_error"] = str(e)
    return out


def _pk_info(cert: x509.Certificate) -> Tuple[str, str]:
    try:
        pk = cert.public_key()
        cls = pk.__class__.__name__.lower()
        if "rsa" in cls:
            bits = getattr(pk, "key_size", None)
            return "RSA", str(bits) if bits else ""
        if "ec" in cls:
            curve = getattr(pk, "curve", None)
            name = getattr(curve, "name", "") if curve else ""
            return "EC", name or ""
        return pk.__class__.__name__, ""
    except Exception:
        return "", ""


def _analyze_cert_chain_leaf_only(cert: x509.Certificate) -> Dict[str, Any]:
    # On older Python, full chain extraction is unreliable; don’t over-claim.
    sig = ""
    try:
        sig = cert.signature_algorithm_oid._name
    except Exception:
        pass

    return {
        "cert_chain": [cert.subject.rfc4514_string()],
        "chain_length": 1,
        "chain_has_weak_sig": _is_weak_sig(sig),
        "chain_issues": ["chain_short_or_unavailable"],
    }


def scan_host(host: str, port: int = 443) -> Dict[str, Any]:
    facts: Dict[str, Any] = {
        "host": host,
        "port": port,

        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "verify_error": "",

        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,
        "key_type": "",
        "key_detail": "",
        "sig_algorithm": "",

        "cert_san_dns": [],
        "cert_san_ip": [],
        "cert_key_usage": {},
        "cert_eku": [],
        "cert_ocsp_urls": [],
        "cert_ca_issuers_urls": [],
        "cert_is_ca": False,
        "cert_basic_constraints": {},

        "hsts_present": False,
        "hsts_header": "",
        "hsts_max_age": None,
        "hsts_include_subdomains": False,
        "hsts_preload": False,
        "hsts_error": "",

        "weak_cipher": False,
        "forward_secrecy_possible": False,

        "tls12_accepted_ciphers": [],
        "tls12_weak_accepted_ciphers": [],
        "tls_probe_errors": [],
        "tls_supported_versions": [],
        "tls_support_map": {},
        "tls13_testable": False,

        "cert_chain": [],
        "chain_length": 0,
        "chain_has_weak_sig": False,
        "chain_issues": [],

        "findings": [],
        "risk": "",
        "risk_level": "",
        "quantum_risk_score": 0,
        "quantum_risk_level": "",
        "pqc_relevance": "",
        "pqc_recommendation": "",

        "error": "",
    }

    # Basic handshake (verified if possible, else unverified)
    main = _connect_handshake(host, port, ssl.PROTOCOL_TLS, verify=True, alpn=["h2", "http/1.1"])
    if main["success"]:
        facts["tls_version"] = main.get("tls_version", "") or ""
        facts["cipher_name"] = main.get("cipher_name", "") or ""
        facts["cipher_bits"] = main.get("cipher_bits", None)
        facts["alpn"] = main.get("alpn", "") or ""
    else:
        facts["verify_error"] = main.get("verify_error", "") or ""
        fb = _connect_handshake(host, port, ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
        if not fb["success"]:
            facts["error"] = fb.get("verify_error", "") or "handshake failed"
            return facts
        facts["tls_version"] = fb.get("tls_version", "") or ""
        facts["cipher_name"] = fb.get("cipher_name", "") or ""
        facts["cipher_bits"] = fb.get("cipher_bits", None)
        facts["alpn"] = fb.get("alpn", "") or ""

    facts["weak_cipher"] = _is_weak_cipher(facts.get("cipher_name", ""))

    cn = (facts.get("cipher_name") or "").upper()
    tv = (facts.get("tls_version") or "")
    facts["forward_secrecy_possible"] = (tv == "TLSv1.3") or ("ECDHE" in cn) or ("DHE" in cn)

    # Leaf cert parse (unverified)
    try:
        ctx = _make_context(ssl.PROTOCOL_TLS, verify=False, alpn=["h2", "http/1.1"])
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

                    facts.update(_extract_leaf_cert_extensions(cert))
                    facts.update(_analyze_cert_chain_leaf_only(cert))

                    not_after = getattr(cert, "not_valid_after", None)
                    if not_after:
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        now = datetime.utcnow().replace(tzinfo=timezone.utc)
                        facts["days_until_expiry"] = (not_after - now).days

    except Exception as e:
        facts["error"] = (facts["error"] + " | " if facts["error"] else "") + "cert: %s" % str(e)

    # Probes (reliable on older Python)
    facts.update(_probe_tls_versions(host, port))
    facts.update(_probe_tls12_accepted_ciphers(host, port))

    # HTTP header probe
    try:
        facts.update(_probe_hsts(host, port))
    except Exception as e:
        facts["hsts_error"] = str(e)

    # Policy -> findings
    findings = evaluate_policies(facts)
    scoring = derive_risk_and_score(findings)
    pqc = derive_pqc_relevance(findings)

    facts["findings"] = findings
    facts["risk"] = scoring["risk_label"]
    facts["risk_level"] = scoring["risk_level"]
    facts["quantum_risk_score"] = scoring["quantum_risk_score"]
    facts["quantum_risk_level"] = scoring["quantum_risk_level"]
    facts["pqc_relevance"] = pqc["pqc_relevance"]
    facts["pqc_recommendation"] = pqc["pqc_recommendation"]

    return facts


def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for t in targets:
        host, port = _parse_target(t)
        if not host:
            continue
        out.append(scan_host(host, port))
    return out


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scanner.py targets.txt")
        raise SystemExit(1)

    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        targets = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    results = run_scan(targets)
    for r in results:
        print("%s:%s -> %s" % (r.get("host"), r.get("port"), r.get("risk")))
        for fd in r.get("findings", [])[:6]:
            print("  - %s %s" % (fd.get("severity", "").upper(), fd.get("rule_id")))
