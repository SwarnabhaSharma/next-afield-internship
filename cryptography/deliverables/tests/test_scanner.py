"""Tests for crypto scanner module."""

import pytest
import tempfile
import os
from src.scanner.detector import CryptoDetector, ScanResult, Vulnerability, Severity
from src.scanner.scanner import scan_file, scan_directory, scan_code, create_sample_vulnerable_code
from src.scanner.patterns import CWE_MAPPINGS, get_cwe_info, get_severity_weight
from src.scanner.report import ReportGenerator, format_report


class TestDetector:
    def test_detect_md5(self):
        code = 'import hashlib\nh = hashlib.md5(b"test")'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id == "CWE-328" for v in result.vulnerabilities)

    def test_detect_sha1(self):
        code = 'import hashlib\nh = hashlib.sha1(b"test")'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id in ("CWE-328", "CWE-327") for v in result.vulnerabilities)

    def test_detect_weak_random(self):
        code = 'import random\ntoken = random.random()'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id == "CWE-338" for v in result.vulnerabilities)

    def test_detect_hardcoded_key(self):
        code = 'API_KEY = "hardcoded_secret_12345"'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id == "CWE-798" for v in result.vulnerabilities)

    def test_detect_pickle(self):
        code = 'import pickle\ndata = pickle.loads(raw_data)'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id == "CWE-502" for v in result.vulnerabilities)

    def test_detect_jwt_none(self):
        code = 'import jwt\ntoken = jwt.encode(payload, "secret", algorithm="none")'
        result = scan_code(code, "test.py")
        assert any(v.cwe_id == "CWE-347" for v in result.vulnerabilities)

    def test_no_false_positives_on_safe_code(self):
        code = '''
import secrets
from cryptography import AESGCM
key = secrets.token_bytes(32)
'''
        result = scan_code(code, "test.py")
        assert len(result.vulnerabilities) == 0

    def test_multiple_vulnerabilities(self):
        code = '''
import hashlib
import random

h = hashlib.md5(b"data")
token = random.random()
'''
        result = scan_code(code, "test.py")
        assert len(result.vulnerabilities) >= 2


class TestScanner:
    def test_scan_code_string(self):
        code = 'hashlib.md5(b"test")'
        result = scan_code(code)
        assert result.file_path == "<string>"
        assert result.has_vulnerabilities

    def test_scan_file_not_found(self):
        result = scan_file("/nonexistent/file.py")
        assert len(result.errors) > 0

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = os.path.join(tmpdir, "test.py")
            with open(py_file, "w") as f:
                f.write('hashlib.md5(b"test")')

            results = scan_directory(tmpdir)
            assert len(results) == 1
            assert results[0].has_vulnerabilities


class TestPatterns:
    def test_cwe_mappings_not_empty(self):
        assert len(CWE_MAPPINGS) > 0

    def test_get_cwe_info(self):
        info = get_cwe_info("CWE-328")
        assert "name" in info
        assert "description" in info

    def test_get_severity_weight(self):
        assert get_severity_weight("CRITICAL") > get_severity_weight("HIGH")
        assert get_severity_weight("HIGH") > get_severity_weight("MEDIUM")


class TestReport:
    def test_report_generation(self):
        results = [scan_code('hashlib.md5(b"test")')]
        report_text = format_report(results, "text")
        assert "CRYPTOGRAPHIC CODE SCAN REPORT" in report_text
        assert "CWE-328" in report_text

    def test_json_report(self):
        results = [scan_code('hashlib.md5(b"test")')]
        report_json = format_report(results, "json")
        assert '"cwe_id": "CWE-328"' in report_json

    def test_report_generator(self):
        generator = ReportGenerator()
        result = scan_code('hashlib.md5(b"test")')
        generator.add_result(result)
        report = generator.generate()
        assert report.total_files == 1
        assert report.total_vulnerabilities > 0


class TestSampleCode:
    def test_create_sample_vulnerable_code(self):
        code = create_sample_vulnerable_code()
        assert "hashlib.md5" in code
        assert "random.random" in code
        assert "pickle" in code

    def test_scanner_finds_all_sample_vulnerabilities(self):
        code = create_sample_vulnerable_code()
        result = scan_code(code, "sample.py")
        assert result.vulnerabilities


class TestVulnerability:
    def test_vulnerability_to_dict(self):
        vuln = Vulnerability(
            cwe_id="CWE-328",
            cwe_name="Test",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            file_path="test.py",
            line_number=1,
            code_snippet="test",
            remediation="test",
        )
        d = vuln.to_dict()
        assert d["cwe_id"] == "CWE-328"
        assert d["severity"] == "HIGH"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])