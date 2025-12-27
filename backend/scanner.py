# scanner.py
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID


from policy import evaluate_findings, pqc_relevance_and_reco, risk_level_from_findings


DEFAULT_TIMEOUT = 6.0


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _dt_to_iso(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="seconds")


def _parse_target(target: str) -> Tuple[str, int]:
    t = (target or "").strip()
    if not t:
        raise ValueError("Empty target")
    if "://" in t:
        # allow https://example.com:443
        t = t.split("://", 1)[1]
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        host, port_s = t.rsplit(":", 1)
        return host.strip(), int(port_s.strip())
    return t, 443


def _match_hostname(host: str, san_dns: List[str]) -> bool:
    """
    Very small wildcard match:
      - exact match
      - wildcard like *.example.com matches a.example.com (one label)
    """
    host = (host or "").lower().strip(".")
    sans = [(s or "").lower().strip(".") for s in san_dns]

    if host in sans:
        return True

    for pat in sans:
        if pat.startswith("*."):
            suffix = pat[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
    return False


def _connect_handshake(
    host: str,
    port: int,
    *,
    timeout: float,
    min_v: Optional[ssl.TLSVersion] = None,
    max_v: Optional[ssl.TLSVersion] = None,
    ciphers: Optional[str] = None,
    verify: bool = True,
) -> Tuple[Optional[ssl.SSLSocket], Optional[str], Optional[str]]:
    """
    Returns (ssock, verify_error, error)
    verify_error is only for verify=True (trust store / hostname checks).
    """
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)

    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # Tighten versions if provided
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v

    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            # OpenSSL build may not support some cipher strings
            pass

    verify_error = None
    try:
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        ssock.do_handshake()
        return ssock, verify_error, None
    except ssl.SSLCertVerificationError as e:
        verify_error = str(e)
        # try to still return unverified details elsewhere
        try:
            raw.close()
        except Exception:
            pass
        return None, verify_error, None
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return None, verify_error, str(e)


def _tls_version_label(v: ssl.TLSVersion) -> str:
    if v == ssl.TLSVersion.TLSv1_3:
        return "TLSv1.3"
    if v == ssl.TLSVersion.TLSv1_2:
        return "TLSv1.2"
    if v == ssl.TLSVersion.TLSv1_1:
        return "TLSv1.1"
    if v == ssl.TLSVersion.TLSv1:
        return "TLSv1.0"
    return str(v)


def _probe_supported_versions(host: str, port: int, timeout: float) -> Tuple[List[str], Dict[str, bool], List[str]]:
    versions = [
        ssl.TLSVersion.TLSv1_3,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1,
    ]
    supported: List[str] = []
    support_map: Dict[str, bool] = {}
    errors: List[str] = []

    for v in versions:
        lab = _tls_version_label(v)
        ssock, _, err = _connect_handshake(host, port, timeout=timeout, min_v=v, max_v=v, verify=False)
        if ssock:
            support_map[lab] = True
            supported.append(lab)
            try:
                ssock.close()
            except Exception:
                pass
        else:
            support_map[lab] = False
            if err:
                errors.append(f"{lab}: {err}")

    return supported, support_map, errors


def _probe_tls12_weak_ciphers(host: str, port: int, timeout: float) -> Tuple[List[str], List[str]]:
    """
    Best-effort:
      For each candidate cipher string, force TLS1.2 + that cipher list and see if handshake succeeds.
    """
    candidates = [
        "AES128-SHA",
        "AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
    ]

    accepted: List[str] = []
    errors: List[str] = []

    for c in candidates:
        ssock, _, err = _connect_handshake(
            host,
            port,
            timeout=timeout,
            min_v=ssl.TLSVersion.TLSv1_2,
            max_v=ssl.TLSVersion.TLSv1_2,
            ciphers=c,
            verify=False,
        )
        if ssock:
            accepted.append(c)
            try:
                ssock.close()
            except Exception:
                pass
        else:
            if err:
                errors.append(f"{c}: {err}")

    # "accepted" is what the server allowed to negotiate (at least once)
    # "errors" is just debugging (not shown unless you want)
    return accepted, errors


def _load_chain_from_socket(ssock: ssl.SSLSocket) -> Tuple[List[x509.Certificate], str]:
    """
    Try to load as much chain as possible.
    Python 3.14 on some builds provides get_verified_chain().
    Fallback: leaf only.
    """
    chain: List[x509.Certificate] = []
    source = "peer_cert_only"

    # get_verified_chain() is not universal; best-effort
    try:
        if hasattr(ssock, "get_verified_chain"):
            ders = ssock.get_verified_chain()
            if ders:
                for der in ders:
                    chain.append(x509.load_der_x509_certificate(der))
                source = "get_verified_chain"
                return chain, source
    except Exception:
        pass

    # Fallback leaf
    try:
        der = ssock.getpeercert(binary_form=True)
        if der:
            chain.append(x509.load_der_x509_certificate(der))
    except Exception:
        pass

    return chain, source


def _cert_chain_table(chain: List[x509.Certificate]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, cert in enumerate(chain):
        try:
            pub = cert.public_key()
            key_s = ""
            if isinstance(pub, rsa.RSAPublicKey):
                key_s = f"RSA / {pub.key_size}"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                key_s = f"EC / {pub.curve.name}"
            else:
                key_s = pub.__class__.__name__

            fp = cert.fingerprint(hashes.SHA256()).hex()
            out.append(
                {
                    "idx": i,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": _dt_to_iso(cert.not_valid_before),
                    "not_after": _dt_to_iso(cert.not_valid_after),
                    "key": key_s,
                    "sig": cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "",
                    "fp_sha256": fp,
                }
            )
        except Exception:
            continue
    return out


def _extract_leaf_facts(host: str, leaf: x509.Certificate) -> Dict[str, Any]:
    facts: Dict[str, Any] = {}

    facts["subject"] = leaf.subject.rfc4514_string()
    facts["issuer"] = leaf.issuer.rfc4514_string()
    facts["not_before"] = _dt_to_iso(leaf.not_valid_before)
    facts["not_after"] = _dt_to_iso(leaf.not_valid_after)

    # Expiry
    try:
        days = int((leaf.not_valid_after - _now_utc()).total_seconds() // 86400)
    except Exception:
        days = None
    facts["days_until_expiry"] = days

    # Signature algorithm name
    try:
        facts["sig_algorithm"] = leaf.signature_algorithm_oid._name if leaf.signature_algorithm_oid else ""
    except Exception:
        facts["sig_algorithm"] = ""

    # Public key
    try:
        pub = leaf.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            facts["key_type"] = "RSA"
            facts["key_size"] = str(pub.key_size)
            facts["key_detail"] = f"RSA / {pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            facts["key_type"] = "EC"
            facts["curve"] = pub.curve.name
            facts["key_detail"] = f"EC / {pub.curve.name}"
        else:
            facts["key_type"] = pub.__class__.__name__
            facts["key_detail"] = pub.__class__.__name__
    except Exception:
        facts["key_type"] = ""
        facts["key_detail"] = ""

    # SAN DNS
    san_dns: List[str] = []
    try:
        ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ext.value
        san_dns = list(san.get_values_for_type(x509.DNSName))
    except Exception:
        san_dns = []
    facts["san_dns"] = san_dns
    facts["host"] = host
    facts["host_match"] = _match_hostname(host, san_dns) if san_dns else True  # if no SAN, don't over-flag here

    # CRL Distribution Points URLs
    crl_urls: List[str] = []
    try:
        crl_ext = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dp in crl_ext:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_urls.append(name.value)
    except Exception:
        crl_urls = []
    facts["crl_urls"] = crl_urls

    # Authority Information Access: OCSP URLs (+ caIssuers if you want later)
    ocsp_urls: List[str] = []
    try:
        aia = leaf.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for ad in aia:
            # ✅ FIX: compare using cryptography.x509.oid.AuthorityInformationAccessOID.OCSP
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                    ocsp_urls.append(ad.access_location.value)
    except Exception:
        ocsp_urls = []
    facts["ocsp_urls"] = ocsp_urls

    return facts


def scan_host(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    One target scan: TLS facts -> findings -> risk + PQC recommendations.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "error": "",
        "verify_error": "",
        "tls_version": "",
        "cipher_name": "",
        "cipher_bits": None,
        "alpn": "",
        "tls_supported_versions": [],
        "tls_support_map": {},
        "tls_probe_errors": [],
        "tls12_weak_accepted_ciphers": [],
        "tls12_accepted_ciphers": [],
        "key_type": "",
        "key_detail": "",
        "sig_algorithm": "",
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,
        "san_dns": [],
        "host_match": True,
        "crl_urls": [],
        "ocsp_urls": [],
        "ocsp_stapled": False,
        "ocsp_stapled_sha256": "",
        "cert_chain": [],
        "chain_length": 0,
        "chain_source": "",
        "chain_issues": [],
        "findings": [],
        "risk": "low",
        "risk_level": "low",
        "pqc_relevance": "LOW",
        "pqc_recommendation": "",
    }

    # 1) Supported versions probe
    supported_versions, support_map, probe_errors = _probe_supported_versions(host, port, timeout)
    result["tls_supported_versions"] = supported_versions
    result["tls_support_map"] = support_map
    result["tls_probe_errors"] = probe_errors

    # 2) Verified handshake (for verify_error visibility)
    ssock_v, verify_error, err_v = _connect_handshake(host, port, timeout=timeout, verify=True)
    if verify_error:
        result["verify_error"] = verify_error
    if err_v:
        # network errors etc
        result["error"] = err_v

    # 3) Unverified handshake to extract cert details even if verify failed
    ssock, _, err = _connect_handshake(host, port, timeout=timeout, verify=False)
    if not ssock:
        if err and not result["error"]:
            result["error"] = err
        # still produce findings from whatever we have
        facts = dict(result)
        findings = evaluate_findings(facts)
        result["findings"] = findings
        risk_label, risk_level = risk_level_from_findings(findings)
        result["risk"] = risk_label
        result["risk_level"] = risk_level
        pqc_rel, pqc_rec = pqc_relevance_and_reco(facts, findings)
        result["pqc_relevance"] = pqc_rel
        result["pqc_recommendation"] = pqc_rec
        return result

    # negotiated
    try:
        result["tls_version"] = ssock.version() or ""
    except Exception:
        result["tls_version"] = ""
    try:
        c = ssock.cipher()
        if c:
            result["cipher_name"] = c[0]
            result["cipher_bits"] = c[2]
    except Exception:
        pass
    try:
        a = ssock.selected_alpn_protocol()
        result["alpn"] = a or ""
    except Exception:
        pass

    # Forward secrecy heuristic (fix TLS1.3 correctness)
    cipher_name = (result.get("cipher_name") or "").upper()
    if (result.get("tls_version") or "").startswith("TLSv1.3"):
        result["forward_secrecy_possible"] = True
    else:
        result["forward_secrecy_possible"] = ("ECDHE" in cipher_name) or ("DHE" in cipher_name)

    # OCSP stapling best-effort (may be unavailable depending on Python/OpenSSL build)
    try:
        resp = getattr(ssock, "ocsp_response", None)
        if isinstance(resp, (bytes, bytearray)) and len(resp) > 0:
            result["ocsp_stapled"] = True
            h = hashes.Hash(hashes.SHA256())
            h.update(bytes(resp))  # ✅ FIX: actually hash the response bytes
            result["ocsp_stapled_sha256"] = h.finalize().hex()
        else:
            result["ocsp_stapled"] = False
    except Exception:
        result["ocsp_stapled"] = False

    # Certificate chain
    chain, chain_source = _load_chain_from_socket(ssock)
    result["chain_source"] = chain_source
    result["chain_length"] = len(chain)
    result["cert_chain"] = _cert_chain_table(chain)

    # Leaf extraction
    if chain:
        leaf = chain[0]
        leaf_facts = _extract_leaf_facts(host, leaf)
        # merge into result
        for k, v in leaf_facts.items():
            result[k] = v

    # TLS 1.2 weak ciphers probe (best-effort)
    weak_accepted, _errs = _probe_tls12_weak_ciphers(host, port, timeout)
    result["tls12_weak_accepted_ciphers"] = weak_accepted
    # (We can also keep a general list if you want; for now it’s same)
    result["tls12_accepted_ciphers"] = weak_accepted

    try:
        ssock.close()
    except Exception:
        pass
    try:
        if ssock_v:
            ssock_v.close()
    except Exception:
        pass

    # 4) Findings + risk + PQC recommendation
    facts = dict(result)
    findings = evaluate_findings(facts)
    result["findings"] = findings

    risk_label, risk_level = risk_level_from_findings(findings)
    result["risk"] = risk_label
    result["risk_level"] = risk_level

    pqc_rel, pqc_rec = pqc_relevance_and_reco(facts, findings)
    result["pqc_relevance"] = pqc_rel
    result["pqc_recommendation"] = pqc_rec

    return result


def run_scan(targets: List[str], max_workers: int = 12) -> List[Dict[str, Any]]:
    """
    Parallel scan for CLI + API usage.
    """
    parsed: List[Tuple[str, int]] = []
    for t in targets:
        try:
            parsed.append(_parse_target(t))
        except Exception:
            continue

    results: List[Dict[str, Any]] = []
    if not parsed:
        return results

    workers = max(1, min(max_workers, len(parsed)))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_host, host, port, DEFAULT_TIMEOUT): (host, port) for host, port in parsed}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                host, port = futs[fut]
                results.append({"host": host, "port": port, "error": str(e), "findings": []})

    # stable ordering
    results.sort(key=lambda r: (r.get("host") or "", int(r.get("port") or 0)))
    return results


