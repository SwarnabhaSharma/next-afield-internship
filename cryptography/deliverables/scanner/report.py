"""Report generation for scan results."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from .detector import ScanResult, Vulnerability, Severity
from .patterns import get_cwe_info, get_severity_weight


@dataclass
class Report:
    """Complete scan report."""
    timestamp: str
    total_files: int
    total_vulnerabilities: int
    by_severity: dict
    by_cwe: dict
    results: list[ScanResult]
    summary: str


class ReportGenerator:
    """Generate reports from scan results."""

    def __init__(self):
        self.results: list[ScanResult] = []

    def add_result(self, result: ScanResult) -> None:
        self.results.append(result)

    def generate(self, project_name: str = "CryptoScan") -> Report:
        """Generate complete report."""
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)

        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_cwe: dict = {}

        for result in self.results:
            for vuln in result.vulnerabilities:
                by_severity[vuln.severity.value] += 1
                by_cwe[vuln.cwe_id] = by_cwe.get(vuln.cwe_id, 0) + 1

        critical = by_severity["CRITICAL"]
        high = by_severity["HIGH"]
        if critical > 0:
            summary = f"CRITICAL: {critical} critical vulnerabilities found!"
        elif high > 0:
            summary = f"WARNING: {high} high severity vulnerabilities found."
        else:
            summary = "No critical or high vulnerabilities found."

        return Report(
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_files=len(self.results),
            total_vulnerabilities=total_vulns,
            by_severity=by_severity,
            by_cwe=by_cwe,
            results=self.results,
            summary=summary,
        )

    def to_json(self, report: Report, output_path: str = None) -> str:
        """Export report as JSON."""
        data = {
            "timestamp": report.timestamp,
            "project": "CryptoScan",
            "total_files": report.total_files,
            "total_vulnerabilities": report.total_vulnerabilities,
            "summary": report.summary,
            "by_severity": report.by_severity,
            "by_cwe": report.by_cwe,
            "vulnerabilities": [],
        }

        for result in report.results:
            for vuln in result.vulnerabilities:
                data["vulnerabilities"].append(vuln.to_dict())

        json_str = json.dumps(data, indent=2)

        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)

        return json_str

    def to_text(self, report: Report) -> str:
        """Export report as plain text."""
        lines = [
            "=" * 60,
            "CRYPTOGRAPHIC CODE SCAN REPORT",
            "=" * 60,
            f"Timestamp: {report.timestamp}",
            f"Files Scanned: {report.total_files}",
            f"Total Vulnerabilities: {report.total_vulnerabilities}",
            "",
            "SEVERITY BREAKDOWN:",
            f"  CRITICAL: {report.by_severity.get('CRITICAL', 0)}",
            f"  HIGH:     {report.by_severity.get('HIGH', 0)}",
            f"  MEDIUM:   {report.by_severity.get('MEDIUM', 0)}",
            f"  LOW:      {report.by_severity.get('LOW', 0)}",
            f"  INFO:     {report.by_severity.get('INFO', 0)}",
            "",
            "CWE BREAKDOWN:",
        ]

        for cwe_id, count in sorted(report.by_cwe.items(), key=lambda x: x[1], reverse=True):
            cwe_info = get_cwe_info(cwe_id)
            lines.append(f"  {cwe_id} ({cwe_info.get('name', 'Unknown')}): {count}")

        lines.extend(["", "SUMMARY:", f"  {report.summary}", "", "FINDINGS:"])

        for result in sorted(report.results, key=lambda r: len(r.vulnerabilities), reverse=True):
            for vuln in sorted(result.vulnerabilities, key=lambda v: get_severity_weight(v.severity.value), reverse=True):
                lines.extend([
                    "",
                    f"[{vuln.severity.value}] {vuln.title}",
                    f"  File: {vuln.file_path}:{vuln.line_number}",
                    f"  CWE: {vuln.cwe_id}",
                    f"  Remediation: {vuln.remediation[:60]}...",
                ])

        lines.append("")
        return "\n".join(lines)


def format_report(results: list[ScanResult], format: str = "text", output_path: str = None) -> str:
    """Format scan results into a report."""
    generator = ReportGenerator()
    for result in results:
        generator.add_result(result)

    report = generator.generate()

    if format == "json":
        return generator.to_json(report, output_path)
    else:
        text = generator.to_text(report)
        if output_path:
            with open(output_path, "w") as f:
                f.write(text)
        return text