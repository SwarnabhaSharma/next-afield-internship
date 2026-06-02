"""High-level scanning functions."""

import os
import glob
from typing import Optional
from .detector import CryptoDetector, ScanResult
from .report import format_report


def scan_file(file_path: str) -> ScanResult:
    """Scan a single Python file for cryptographic vulnerabilities."""
    if not os.path.exists(file_path):
        return ScanResult(
            file_path=file_path,
            errors=[f"File not found: {file_path}"],
        )

    if not file_path.endswith(".py"):
        return ScanResult(
            file_path=file_path,
            errors=["Not a Python file"],
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        return ScanResult(
            file_path=file_path,
            errors=[f"Error reading file: {e}"],
        )

    detector = CryptoDetector(file_path)
    return detector.scan(source)


def scan_directory(directory: str, pattern: str = "**/*.py") -> list[ScanResult]:
    """Recursively scan directory for Python files."""
    results = []

    for file_path in glob.glob(os.path.join(directory, pattern), recursive=True):
        result = scan_file(file_path)
        results.append(result)

    return results


def scan_code(source: str, file_name: str = "<string>") -> ScanResult:
    """Scan source code string directly."""
    detector = CryptoDetector(file_name)
    return detector.scan(source)


def scan_multiple_files(file_paths: list[str]) -> list[ScanResult]:
    """Scan multiple specific files."""
    return [scan_file(fp) for fp in file_paths]


def scan_and_report(directory: str = None, file_path: str = None,
                   output: str = None, format: str = "text") -> str:
    """Convenience function to scan and generate report."""
    results = []

    if directory:
        results = scan_directory(directory)
    elif file_path:
        results = [scan_file(file_path)]

    return format_report(results, format, output)


def create_sample_vulnerable_code() -> str:
    """Create sample vulnerable code for testing."""
    return '''
import hashlib
import random
import pickle
import jwt

# VULNERABILITY 1: Weak hash for password
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 2: Weak random for token
def generate_token():
    return str(random.random())[2:]

# VULNERABILITY 3: Hardcoded secret
API_SECRET = "hardcoded_secret_key_12345"

# VULNERABILITY 4: Insecure JWT
def create_jwt(payload):
    return jwt.encode(payload, "secret", algorithm="none")

# VULNERABILITY 5: Insecure deserialization
def load_data(data):
    return pickle.loads(data)

# VULNERABILITY 6: Insecure SSL
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# VULNERABILITY 7: ECB mode encryption
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB, iv)
'''


def demonstrate_scanner() -> None:
    """Demonstrate the scanner on sample code."""
    print("Crypto Scanner Demonstration")
    print("=" * 60)

    sample_code = create_sample_vulnerable_code()

    print("Scanning sample vulnerable code...")
    print()

    result = scan_code(sample_code, "sample.py")

    print(f"Found {len(result.vulnerabilities)} vulnerabilities:")
    print()

    for vuln in result.vulnerabilities:
        print(f"[{vuln.severity.value}] {vuln.cwe_id}: {vuln.title}")
        print(f"  Line {vuln.line_number}: {vuln.description[:60]}...")
        print(f"  Fix: {vuln.remediation[:50]}...")
        print()