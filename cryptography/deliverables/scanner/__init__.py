"""Cryptographic Code Scanner - Find crypto mistakes in Python code."""

from .detector import CryptoDetector, ScanResult, Vulnerability
from .patterns import (
    WEAK_HASH_PATTERNS,
    WEAK_RANDOM_PATTERNS,
    ECB_MODE_PATTERNS,
    HARDCODED_KEY_PATTERNS,
    INSECURE_JWT_PATTERNS,
    INSECURE_DESERIALIZATION,
)
from .report import ReportGenerator, Severity, format_report
from .scanner import scan_file, scan_directory, scan_code

__version__ = "0.1.0"

__all__ = [
    "CryptoDetector",
    "ScanResult",
    "Vulnerability",
    "format_report",
    "scan_file",
    "scan_directory",
    "scan_code",
    "ReportGenerator",
    "Severity",
]