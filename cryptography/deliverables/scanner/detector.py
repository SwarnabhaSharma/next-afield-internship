"""Crypto vulnerability detection using AST analysis."""

import ast
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    """Represents a detected cryptographic vulnerability."""
    cwe_id: str
    cwe_name: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    file_path: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    lines_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)


class CryptoDetector(ast.NodeVisitor):
    """AST-based detector for cryptographic anti-patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.vulnerabilities: list[Vulnerability] = []
        self.current_line = 0
        self.lines: list[str] = []

    def scan(self, source: str) -> ScanResult:
        """Scan source code for vulnerabilities."""
        self.lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=self.file_path)
            self.visit(tree)
        except SyntaxError as e:
            return ScanResult(
                file_path=self.file_path,
                errors=[f"Syntax error: {e}"],
            )
        except Exception as e:
            return ScanResult(
                file_path=self.file_path,
                errors=[f"Parse error: {e}"],
            )

        return ScanResult(
            file_path=self.file_path,
            vulnerabilities=self.vulnerabilities,
            lines_scanned=len(self.lines),
        )

    def _add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    def _get_code_snippet(self, line_number: int, context: int = 1) -> str:
        if 0 < line_number <= len(self.lines):
            start = max(0, line_number - context - 1)
            end = min(len(self.lines), line_number + context)
            return "\n".join(self.lines[start:end])
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for crypto anti-patterns."""
        self.current_line = node.lineno or 0

        func_name = self._get_func_name(node.func)
        module = self._get_module(node.func)

        if func_name in ("md5", "sha1", "sha256"):
            if "hashlib" in module:
                self._check_weak_hash(node, func_name)

        elif func_name == "new":
            if module == "Crypto.Cipher" or module.endswith(".Cipher"):
                self._check_insecure_cipher(node)

        elif "random" in func_name:
            self._check_weak_random(node, func_name)

        elif func_name in ("encode", "decode"):
            self._check_jwt_weak_signature(node)

        elif func_name in ("loads", "load") and module == "pickle":
            self._add_vulnerability(Vulnerability(
                cwe_id="CWE-502",
                cwe_name="Deserialization of Untrusted Data",
                severity=Severity.HIGH,
                title="Unsafe pickle deserialization",
                description="Using pickle.loads() with untrusted data allows remote code execution.",
                file_path=self.file_path,
                line_number=node.lineno or 0,
                code_snippet=self._get_code_snippet(node.lineno or 0),
                remediation="Use JSON for data exchange or a safer serialization format. "
                           "If pickle is required, validate and sign data first.",
                confidence=0.9,
            ))

        self.generic_visit(node)

    def _get_func_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _get_module(self, node: ast.expr) -> str:
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Attribute):
                parent = node.value
                if isinstance(parent.value, ast.Name):
                    return f"{parent.value.id}.{parent.attr}.{node.attr}"
            elif isinstance(node.value, ast.Name):
                return node.value.id
        return ""

    def _check_weak_hash(self, node: ast.Call, algo: str) -> None:
        is_for_password = self._check_context_for_password(node)

        severity = Severity.CRITICAL if is_for_password else Severity.HIGH
        cwe_id = "CWE-328" if algo == "md5" else "CWE-327"

        self._add_vulnerability(Vulnerability(
            cwe_id=cwe_id,
            cwe_name="Use of Weak Hash",
            severity=severity,
            title=f"Weak cryptographic hash: {algo}",
            description=f"Using {algo.upper()} for hashing is insecure. "
                        f"{'This appears to be used for password storage.' if is_for_password else ''}",
            file_path=self.file_path,
            line_number=node.lineno or 0,
            code_snippet=self._get_code_snippet(node.lineno or 0),
            remediation="Use password hashing functions like Argon2id, bcrypt, or scrypt. "
                       "Example: from argon2 import PasswordHasher; ph = PasswordHasher()",
            confidence=0.9,
        ))

    def _check_context_for_password(self, node: ast.Call) -> bool:
        keywords = {"password", "pwd", "passwd", "secret", "credential"}
        for kw in keywords:
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and kw in str(child.value).lower():
                    return True
        return False

    def _check_insecure_cipher(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "mode":
                if hasattr(keyword.value, "attr") and keyword.value.attr == "MODE_ECB":
                    self._add_vulnerability(Vulnerability(
                        cwe_id="CWE-327",
                        cwe_name="Use of Weak Cryptographic Algorithm",
                        severity=Severity.CRITICAL,
                        title="Insecure cipher mode: ECB",
                        description="ECB mode reveals patterns in encrypted data. "
                                   "Same plaintext blocks produce same ciphertext blocks.",
                        file_path=self.file_path,
                        line_number=node.lineno or 0,
                        code_snippet=self._get_code_snippet(node.lineno or 0),
                        remediation="Use authenticated encryption modes like GCM or CTR. "
                                   "Example: AESGCM from cryptography.hazmat.primitives.ciphers.aead",
                        confidence=0.95,
                    ))

    def _check_weak_random(self, node: ast.Call, func_name: str) -> None:
        if func_name in ("random", "randint", "choice"):
            self._add_vulnerability(Vulnerability(
                cwe_id="CWE-338",
                cwe_name="Use of Cryptographically Weak PRNG",
                severity=Severity.HIGH,
                title=f"Weak random: {func_name}",
                description=f"Using random.{func_name} for cryptographic purposes is insecure. "
                           "Python's random module uses Mersenne Twister which is predictable.",
                file_path=self.file_path,
                line_number=node.lineno or 0,
                code_snippet=self._get_code_snippet(node.lineno or 0),
                remediation="Use secrets module for cryptographic randomness. "
                           "Example: secrets.token_urlsafe(32), secrets.randbits(256)",
                confidence=0.8,
            ))

    def _check_jwt_weak_signature(self, node: ast.Call) -> None:
        has_algorithm_none = False
        has_jwt_import = False

        for child in ast.walk(node):
            if isinstance(child, ast.Constant):
                if str(child.value).lower() == "none":
                    has_algorithm_none = True
            if isinstance(child, ast.Name):
                if child.id == "jwt":
                    has_jwt_import = True

        if has_algorithm_none and has_jwt_import:
            self._add_vulnerability(Vulnerability(
                cwe_id="CWE-347",
                cwe_name="Improper Verification of Cryptographic Signature",
                severity=Severity.CRITICAL,
                title="JWT 'none' algorithm allowed",
                description="JWT library allowing 'none' algorithm allows attackers "
                           "to forge tokens by removing signature.",
                file_path=self.file_path,
                line_number=node.lineno or 0,
                code_snippet=self._get_code_snippet(node.lineno or 0),
                remediation="Always verify algorithm and reject 'none'. "
                           "Example: pyjwt library with verify=True and algorithms=['HS256']",
                confidence=0.85,
            ))

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded keys and secrets."""
        self.current_line = node.lineno or 0
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(kw in var_name for kw in ("key", "secret", "password", "token", "api")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 8 and not node.value.value.startswith("${"):
                            self._add_vulnerability(Vulnerability(
                                cwe_id="CWE-798",
                                cwe_name="Use of Hard-coded Credentials",
                                severity=Severity.CRITICAL,
                                title="Hardcoded cryptographic key/secret",
                                description="Hardcoded secrets in source code can be exposed "
                                           "in version control and binaries.",
                                file_path=self.file_path,
                                line_number=node.lineno or 0,
                                code_snippet=self._get_code_snippet(node.lineno or 0),
                                remediation="Use environment variables or secrets management "
                                           "(HashiCorp Vault, AWS Secrets Manager)",
                                confidence=0.7,
                            ))

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check for insecure deserialization patterns."""
        self.current_line = node.lineno or 0

        if isinstance(node.value, ast.Attribute):
            if isinstance(node.value.value, ast.Name):
                if node.value.value.id == "pickle" and node.value.attr == "loads":
                    self._add_vulnerability(Vulnerability(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data",
                        severity=Severity.HIGH,
                        title="Unsafe pickle deserialization",
                        description="Using pickle.loads() with untrusted data allows remote code execution.",
                        file_path=self.file_path,
                        line_number=node.lineno or 0,
                        code_snippet=self._get_code_snippet(node.lineno or 0),
                        remediation="Use JSON for data exchange or a safer serialization format. "
                                   "If pickle is required, validate and sign data first.",
                        confidence=0.9,
                    ))

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check for insecure protocol usage."""
        if node.attr in ("create_default_context", "wrap_socket"):
            if hasattr(node, "lineno"):
                self.current_line = node.lineno
                self._check_ssl_context(node)

        self.generic_visit(node)

    def _check_ssl_context(self, node: ast.Attribute) -> None:
        code = self._get_code_snippet(node.lineno or 0)
        if "CERT_NONE" in code or "CERT_OPTIONAL" in code:
            self._add_vulnerability(Vulnerability(
                cwe_id="CWE-295",
                cwe_name="Improper Certificate Validation",
                severity=Severity.HIGH,
                title="Insecure SSL certificate verification",
                description="Disabling certificate verification allows man-in-the-middle attacks.",
                file_path=self.file_path,
                line_number=node.lineno or 0,
                code_snippet=code,
                remediation="Use default certificate verification. "
                           "ssl.create_default_context() with verify_mode=ssl.CERT_REQUIRED",
                confidence=0.9,
            ))