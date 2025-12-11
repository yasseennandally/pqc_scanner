#!/usr/bin/env python
import argparse
import csv
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def parse_host(host_str: str) -> Tuple[str, int]:
    """
    Parse host[:port] into (host, port).
    Default port is 443 if not specified.
    """
    host_str = host_str.strip()
    if not host_str:
        raise ValueError("Empty host string")

    if ":" in host_str:
        host, port_str = host_str.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port in host string: {host_str}")
    else:
        host, port = host_str, 443

    return host.strip(), port


def get_certificate(host: str, port: int, timeout: float = 5.0) -> bytes:
    """
    Open a TLS connection and return the peer certificate in DER format.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            if not der_cert:
                raise RuntimeError("No certificate received from server")
            return der_cert


def analyze_certificate(der_cert: bytes) -> Dict[str, Any]:
    """
    Parse a DER certificate and extract useful fields.
    """
    cert = x509.load_der_x509_certificate(der_cert)

    # Subject and issuer
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Validity
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # Normalize to timezone-aware UTC for safety
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    days_until_expiry = (not_after - now).days

    # Public key details
    pub_key = cert.public_key()
    key_type = "unknown"
    key_detail = ""

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_detail = f"{pub_key.key_size} bits"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
        try:
            key_detail = pub_key.curve.name
        except Exception:
            key_detail = "unknown curve"

    # Signature algorithm
    sig_algo = ""
    try:
        hash_name = cert.signature_hash_algorithm.name  # e.g. 'sha256'
        sig_algo = hash_name
    except Exception:
        try:
            sig_algo = cert.signature_algorithm_oid._name
        except Exception:
            sig_algo = "unknown"

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "key_type": key_type,
        "key_detail": key_detail,
        "sig_algorithm": sig_algo,
    }


def classify_risk(key_type: str, days_until_expiry: int) -> str:
    """
    Very simple risk classification for now.
    """
    if days_until_expiry < 0:
        return "high (expired)"
    if days_until_expiry <= 30:
        return "high (expiring soon)"
    if key_type == "RSA":
        return "medium (RSA, PQC-relevant)"

    return "low"


def scan_target(raw_host: str) -> Dict[str, Any]:
    """
    Scan a single host[:port] and return a result dict.
    """
    raw_host = raw_host.strip()
    if not raw_host:
        return {}

    try:
        host, port = parse_host(raw_host)
    except ValueError as e:
        return {
            "host": raw_host,
            "port": "",
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "days_until_expiry": "",
            "key_type": "",
            "key_detail": "",
            "sig_algorithm": "",
            "risk": "",
            "error": str(e),
        }

    base_result: Dict[str, Any] = {
        "host": host,
        "port": port,
    }

    try:
        der_cert = get_certificate(host, port)
        cert_info = analyze_certificate(der_cert)
        risk = classify_risk(
            cert_info["key_type"],
            cert_info["days_until_expiry"],
        )

        base_result.update(cert_info)
        base_result["risk"] = risk
        base_result["error"] = ""
    except Exception as e:
        base_result.update(
            {
                "subject": "",
                "issuer": "",
                "not_before": "",
                "not_after": "",
                "days_until_expiry": "",
                "key_type": "",
                "key_detail": "",
                "sig_algorithm": "",
                "risk": "",
                "error": str(e),
            }
        )

    return base_result


def run_scan(targets: List[str]) -> List[Dict[str, Any]]:
    """
    Scan a list of targets and return a list of result dicts.
    This is what the API will call.
    """
    results: List[Dict[str, Any]] = []
    for t in targets:
        if not t.strip():
            continue
        res = scan_target(t)
        if res:
            results.append(res)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Simple TLS certificate scanner for PQC readiness."
    )
    parser.add_argument(
        "input_file",
        help="Path to a text file with one host[:port] per line.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="scan_results.csv",
        help="Output CSV file (default: scan_results.csv)",
    )
    args = parser.parse_args()

    with open(args.input_file, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f.readlines() if line.strip()]

    fieldnames = [
        "host",
        "port",
        "subject",
        "issuer",
        "not_before",
        "not_after",
        "days_until_expiry",
        "key_type",
        "key_detail",
        "sig_algorithm",
        "risk",
        "error",
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for result in run_scan(targets):
            writer.writerow(result)

    print(f"Scan completed. Results saved to {args.output}")


if __name__ == "__main__":
    main()
