"""Structured report generation — JSON, Markdown, and HTML output.

Generates professional security assessment reports from scan results
with severity ratings, evidence, and remediation guidance.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from web_recon.core.scanner import ScanResult


class ReportGenerator:
    """Generate structured security assessment reports.

    Converts ScanResult objects into professional reports in JSON,
    Markdown, or HTML format with severity ratings and remediation.

    Usage:
        gen = ReportGenerator()
        gen.generate_json(result, output="report.json")
        gen.generate_markdown(result, output="report.md")
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, title: str = "Web Recon Suite — Security Assessment") -> None:
        """Initialize report generator.

        Args:
            title: Report title.
        """
        self.title = title

    def generate_json(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate a JSON report from scan results.

        Args:
            result: Scan result data.
            output: Output file path. If None, returns string.

        Returns:
            JSON string of the report.
        """
        report = {
            "title": self.title,
            "generated": datetime.now().isoformat(),
            "target": result.target,
            "status": result.status,
            "summary": result.summary(),
            "findings": sorted(
                result.vulnerabilities,
                key=lambda v: self.SEVERITY_ORDER.get(v.get("severity", "info"), 99),
            ),
            "endpoints": result.endpoints,
            "auth_endpoints": result.auth_endpoints,
            "technologies": result.technologies,
            "security_headers": result.security_headers,
            "forms": result.forms,
        }

        json_str = json.dumps(report, indent=2, ensure_ascii=False)

        if output:
            Path(output).write_text(json_str, encoding="utf-8")

        return json_str

    def generate_markdown(self, result: ScanResult, output: Optional[str] = None) -> str:
        """Generate a Markdown report from scan results.

        Args:
            result: Scan result data.
            output: Output file path. If None, returns string.

        Returns:
            Markdown string of the report.
        """
        summary = result.summary()
        lines = [
            f"# {self.title}",
            "",
            f"**Target:** {result.target}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Status:** {result.status}",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Endpoints | {summary['endpoints']} |",
            f"| Parameters | {summary['parameters']} |",
            f"| Forms | {summary['forms']} |",
            f"| Auth Endpoints | {summary['auth_endpoints']} |",
            f"| Vulnerabilities | {summary['vulnerabilities']} |",
            "",
            "## Technologies Detected",
            "",
        ]

        for tech in result.technologies:
            lines.append(f"- {tech}")

        lines.append("")
        lines.append("## Security Headers")
        lines.append("")
        lines.append("| Header | Status |")
        lines.append("|--------|--------|")

        for header, value in result.security_headers.items():
            status = "✅ Set" if value != "MISSING" else "❌ Missing"
            lines.append(f"| {header} | {status} |")

        if result.vulnerabilities:
            lines.append("")
            lines.append("## Findings")
            lines.append("")

            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: self.SEVERITY_ORDER.get(v.get("severity", "info"), 99),
            )

            for i, vuln in enumerate(sorted_vulns, 1):
                severity = vuln.get("severity", "info").upper()
                lines.append(f"### {i}. [{severity}] {vuln.get('type', 'Unknown')}")
                lines.append("")
                lines.append(f"**Description:** {vuln.get('description', 'No description')}")
                if vuln.get("header"):
                    lines.append(f"**Header:** {vuln['header']}")
                lines.append("")

        md = "\n".join(lines)

        if output:
            Path(output).write_text(md, encoding="utf-8")

        return md
