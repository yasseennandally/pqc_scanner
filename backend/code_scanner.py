import io
import re
import zipfile
from typing import List, Dict, Any, Tuple

from py_ast_scanner import scan_python_source

MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_FILES = 3000
MAX_SINGLE_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_EXTRACT_BYTES = 40 * 1024 * 1024

REGEX_RULES = [
    (re.compile(r"\bmd5\b", re.IGNORECASE), "medium", "Weak hash reference (MD5)",
     "Replace with SHA-256/SHA-3; avoid MD5."),
    (re.compile(r"\bsha1\b", re.IGNORECASE), "high", "Weak hash reference (SHA-1)",
     "Replace with SHA-256/SHA-3; avoid SHA-1."),

    (re.compile(r'"\s*crypto/rsa\s*"'), "high", "Go RSA usage (import crypto/rsa)",
     "Inventory RSA usage; plan PQC/hybrid migration."),
    (re.compile(r'"\s*crypto/ecdsa\s*"'), "medium", "Go ECDSA usage (import crypto/ecdsa)",
     "Inventory ECC usage; plan PQC/hybrid migration."),
    (re.compile(r'"\s*crypto/elliptic\s*"'), "medium", "Go elliptic curve crypto usage",
     "Inventory ECC usage; plan PQC/hybrid migration."),

    (re.compile(r"\bRSA_generate_key\b|\bRSA_new\b|\bRSA_private_encrypt\b", re.IGNORECASE),
     "high", "C/C++ RSA usage", "Inventory RSA usage; plan PQC/hybrid migration."),
    (re.compile(r"\bECDSA_sign\b|\bECDSA_verify\b|\bEC_KEY_new\b|\bEVP_PKEY_EC\b", re.IGNORECASE),
     "medium", "C/C++ ECC usage", "Inventory ECC usage; plan PQC/hybrid migration."),

    (re.compile(r"java\.security\.Signature", re.IGNORECASE), "medium", "Java signature usage",
     "Inventory signature usage; plan PQC migration."),
    (re.compile(r"Signature\.getInstance\(\s*\".*RSA.*\"\s*\)", re.IGNORECASE),
     "high", "Java RSA signature usage", "Inventory RSA signature usage; plan PQC migration."),
    (re.compile(r"Signature\.getInstance\(\s*\".*ECDSA.*\"\s*\)", re.IGNORECASE),
     "medium", "Java ECDSA signature usage", "Inventory ECDSA; plan PQC signature migration."),

    (re.compile(r"crypto\.createSign\(", re.IGNORECASE), "medium", "Node.js signing usage",
     "Inventory signature usage; plan PQC migration."),
    (re.compile(r"createSign\(\s*['\"]RSA", re.IGNORECASE), "high", "Node.js RSA signature usage",
     "Inventory RSA signatures; plan PQC migration."),
    (re.compile(r"createSign\(\s*['\"]ecdsa", re.IGNORECASE), "medium", "Node.js ECDSA signature usage",
     "Inventory ECDSA; plan PQC migration."),

    (re.compile(r"BEGIN\s+PRIVATE\s+KEY", re.IGNORECASE), "high", "Hardcoded private key material",
     "Remove hardcoded keys, rotate immediately, store secrets in a vault."),
]

ALLOWED_EXTS = {
    ".py", ".js", ".ts", ".java", ".go", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".cs", ".kt", ".swift", ".rs",
}


def _safe_filename(name: str) -> str:
    name = name.replace("\\", "/")
    while name.startswith("/"):
        name = name[1:]
    if ".." in name:
        return ""
    return name


def _ext(name: str) -> str:
    name = name.lower()
    i = name.rfind(".")
    return name[i:] if i >= 0 else ""


def scan_zip_bytes(data: bytes) -> List[Dict[str, Any]]:
    if not data:
        return []
    if len(data) > MAX_ZIP_BYTES:
        return [{"file": "", "line": 1, "severity": "high", "rule_name": "ZIP too large",
                 "line_preview": "", "recommendation": "Reduce archive size or split scanning."}]

    findings: List[Dict[str, Any]] = []

    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()

    if len(infos) > MAX_FILES:
        return [{"file": "", "line": 1, "severity": "high", "rule_name": "Too many files",
                 "line_preview": "", "recommendation": "Reduce archive file count or scope."}]

    total_extracted = 0

    for info in infos:
        if info.is_dir():
            continue

        name = _safe_filename(info.filename or "")
        if not name:
            continue

        ext = _ext(name)
        if ext not in ALLOWED_EXTS:
            continue

        if info.file_size > MAX_SINGLE_FILE_BYTES:
            continue

        try:
            raw = zf.read(info)
        except Exception:
            continue

        total_extracted += len(raw)
        if total_extracted > MAX_TOTAL_EXTRACT_BYTES:
            break

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        if ext == ".py":
            findings.extend(scan_python_source(name, text))
            continue

        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            for (rx, sev, rule_name, rec) in REGEX_RULES:
                if rx.search(line):
                    findings.append({
                        "file": name,
                        "line": i,
                        "severity": sev,
                        "rule_name": rule_name,
                        "line_preview": line[:200],
                        "recommendation": rec,
                    })

    return findings
