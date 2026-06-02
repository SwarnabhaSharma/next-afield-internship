"""Pre-defined vulnerability patterns and CWE mappings."""

from dataclasses import dataclass
from typing import Callable, AsyncIterator


@dataclass
class Pattern:
    """Represents a detection pattern."""
    name: str
    description: str
    cwe_id: str
    severity: str
    detector: Callable


WEAK_HASH_PATTERNS = {
    "md5": {
        "cwe": "CWE-328",
        "severity": "HIGH",
        "description": "MD5 is cryptographically broken",
    },
    "sha1": {
        "cwe": "CWE-327",
        "severity": "HIGH",
        "description": "SHA-1 is deprecated for security purposes",
    },
}

WEAK_RANDOM_PATTERNS = {
    "random.random": {
        "cwe": "CWE-338",
        "severity": "HIGH",
        "description": " Mersenne Twister is predictable",
    },
    "random.randint": {
        "cwe": "CWE-338",
        "severity": "HIGH",
        "description": "Random integer is predictable",
    },
    "random.choice": {
        "cwe": "CWE-338",
        "severity": "HIGH",
        "description": "Random choice is predictable",
    },
}

ECB_MODE_PATTERNS = {
    "MODE_ECB": {
        "cwe": "CWE-327",
        "severity": "CRITICAL",
        "description": "ECB mode reveals encrypted data patterns",
    },
}

HARDCODED_KEY_PATTERNS = [
    "api_key",
    "api_key",
    "secret_key",
    "encryption_key",
    "private_key",
    "password",
    "auth_token",
]

INSECURE_JWT_PATTERNS = {
    "algorithm": "none",
    "cwe": "CWE-347",
    "severity": "CRITICAL",
    "description": "JWT with algorithm 'none' can be forged",
}

INSECURE_DESERIALIZATION = {
    "pickle.load": {
        "cwe": "CWE-502",
        "severity": "HIGH",
        "description": "Pickle can execute arbitrary code",
    },
    "yaml.load": {
        "cwe": "CWE-502",
        "severity": "HIGH",
        "description": "YAML deserialization can execute arbitrary code",
    },
}

CWE_MAPPINGS = {
    "CWE-328": {
        "name": "Use of Weak Hash",
        "description": "The product uses a cryptographic hash function incorrectly",
        "remediation": "Use SHA-256 or stronger for non-password hashing. Use Argon2id for passwords.",
    },
    "CWE-327": {
        "name": "Use of Weak Cryptographic Algorithm",
        "description": "The product uses a cryptographic algorithm that is weak",
        "remediation": "Use AES-256-GCM, ChaCha20-Poly1305, or similar modern algorithms.",
    },
    "CWE-338": {
        "name": "Use of Cryptographically Weak PRNG",
        "description": "The product uses a pseudo-random number generator in a security context",
        "remediation": "Use secrets.token_urlsafe() or secrets.randbits() for cryptographic randomness.",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The product contains hard-coded credentials",
        "remediation": "Store credentials in environment variables or secrets management systems.",
    },
    "CWE-347": {
        "name": "Improper Verification of Cryptographic Signature",
        "description": "The product does not verify or improperly verifies cryptographic signatures",
        "remediation": "Always verify algorithm field and reject 'none' in JWT.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The product deserializes untrusted data without adequate validation",
        "remediation": "Use JSON instead of pickle, or validate YAML with safe_load().",
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "description": "The product does not validate or incorrectly validates certificates",
        "remediation": "Use ssl.create_default_context() without disabling verification.",
    },
}


def get_cwe_info(cwe_id: str) -> dict:
    """Get CWE information by ID."""
    return CWE_MAPPINGS.get(cwe_id, {"name": "Unknown", "description": ""})


def get_severity_weight(severity: str) -> int:
    """Get numeric weight for severity."""
    weights = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    return weights.get(severity.upper(), 0)