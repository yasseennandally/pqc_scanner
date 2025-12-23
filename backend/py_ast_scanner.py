import ast
from typing import List, Dict, Any

PEM_MARKERS = [
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
]

SUSPICIOUS_NAMES = {"private_key", "secret_key", "key_bytes", "pem", "pfx", "pkcs12"}


class _CryptoVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []
        self.imports: List[str] = []

    def _add(self, node: ast.AST, severity: str, rule_name: str, line_preview: str, recommendation: str):
        line = getattr(node, "lineno", 1) or 1
        self.findings.append({
            "file": self.filename,
            "line": int(line),
            "severity": severity,
            "rule_name": rule_name,
            "line_preview": (line_preview or "")[:200],
            "recommendation": recommendation,
        })

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            self.imports.append(mod + "." + alias.name if mod else alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fn = ""
        if isinstance(node.func, ast.Attribute):
            fn = (node.func.attr or "")
        elif isinstance(node.func, ast.Name):
            fn = (node.func.id or "")

        fn_low = fn.lower()

        if fn_low in ("generate_private_key", "generate_key", "generate_key_pair"):
            self._add(
                node, "medium",
                "Key generation call",
                "generate_*",
                "Inventory key generation usage and ensure crypto-agility for PQC migration."
            )

        if fn_low in ("generate_private_key",):
            self._add(
                node, "medium",
                "Python key generation (cryptography)",
                "generate_private_key",
                "Inventory asymmetric key usage; plan PQC migration (Kyber/Dilithium) where applicable."
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        try:
            val = node.value
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                s = val.value
                for marker in PEM_MARKERS:
                    if marker in s:
                        self._add(
                            node, "high",
                            "Hardcoded private key material",
                            marker,
                            "Hardcoded private key material detected. Remove from source, rotate keys, and store secrets in a vault."
                        )
                        break
        except Exception:
            pass
        self.generic_visit(node)


def scan_python_source(filename: str, source_text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for marker in PEM_MARKERS:
        if marker in source_text:
            findings.append({
                "file": filename,
                "line": 1,
                "severity": "high",
                "rule_name": "Hardcoded private key material",
                "line_preview": marker,
                "recommendation": "Hardcoded private key material detected. Remove from source, rotate keys, and store secrets in a vault.",
            })
            break

    try:
        tree = ast.parse(source_text)
    except Exception:
        return findings

    v = _CryptoVisitor(filename)
    v.visit(tree)

    imports_joined = " ".join(v.imports).lower()
    if "cryptography.hazmat.primitives.asymmetric.rsa" in imports_joined or "crypto.rsa" in imports_joined:
        findings.append({
            "file": filename,
            "line": 1,
            "severity": "medium",
            "rule_name": "Python RSA import",
            "line_preview": "import rsa (cryptography)",
            "recommendation": "RSA import detected. Ensure RSA usage is inventoried for PQC migration and crypto-agility.",
        })
    if "cryptography.hazmat.primitives.asymmetric.ec" in imports_joined:
        findings.append({
            "file": filename,
            "line": 1,
            "severity": "medium",
            "rule_name": "Python EC import",
            "line_preview": "import ec (cryptography)",
            "recommendation": "ECC import detected. Ensure ECC usage is inventoried for PQC migration and crypto-agility.",
        })

    findings.extend(v.findings)
    return findings
