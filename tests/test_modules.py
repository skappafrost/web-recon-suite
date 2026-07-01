"""Tests for modules — CORS and credential testing."""

from __future__ import annotations

import pytest

from web_recon.modules.cors import CORSAnalyzer, CORSResult
from web_recon.modules.credentials import CredentialTester, CredResult
from web_recon.modules.report import ReportGenerator
from web_recon.core.scanner import ScanResult


class TestCORSAnalyzer:
    """Test CORS configuration analysis."""

    def test_initialization(self) -> None:
        """Analyzer should initialize with target."""
        analyzer = CORSAnalyzer(target="https://example.com")
        assert analyzer.target == "https://example.com"
        assert analyzer.timeout == 10

    def test_test_origins_defined(self) -> None:
        """Should have test origins configured."""
        assert len(CORSAnalyzer.TEST_ORIGINS) > 0
        assert any("evil.com" in o for o, _, _ in CORSAnalyzer.TEST_ORIGINS)


class TestCORSResult:
    """Test CORSResult dataclass."""

    def test_to_dict(self) -> None:
        """to_dict should return proper dictionary."""
        result = CORSResult(
            origin_tested="https://evil.com",
            allowed=True,
            severity="critical",
        )
        d = result.to_dict()
        assert d["origin_tested"] == "https://evil.com"
        assert d["allowed"] is True
        assert d["severity"] == "critical"


class TestCredentialTester:
    """Test credential testing configuration."""

    def test_initialization(self) -> None:
        """Tester should initialize with correct fields."""
        tester = CredentialTester(target="https://example.com/login")
        assert tester.target == "https://example.com/login"
        assert tester.method == "POST"
        assert tester.username_field == "username"
        assert tester.password_field == "password"

    def test_custom_fields(self) -> None:
        """Custom field names should be stored."""
        tester = CredentialTester(
            target="https://example.com/login",
            username_field="email",
            password_field="passwd",
        )
        assert tester.username_field == "email"
        assert tester.password_field == "passwd"


class TestReportGenerator:
    """Test report generation."""

    def test_generate_json(self) -> None:
        """JSON report should contain all fields."""
        result = ScanResult(
            target="https://example.com",
            endpoints=["/api"],
            technologies=["Nginx"],
            status="completed",
        )
        gen = ReportGenerator()
        json_str = gen.generate_json(result)
        assert "example.com" in json_str
        assert "Nginx" in json_str

    def test_generate_markdown(self) -> None:
        """Markdown report should contain target and findings."""
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=[{"type": "missing_header", "severity": "medium", "description": "CSP missing"}],
            status="completed",
        )
        gen = ReportGenerator()
        md = gen.generate_markdown(result)
        assert "example.com" in md
        assert "MEDIUM" in md
