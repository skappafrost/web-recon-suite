"""Tests for core.scanner — WebScanner and ScanResult."""

from __future__ import annotations

from unittest.mock import MagicMock


from web_recon.core.scanner import ScanResult, WebScanner


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_default_values(self) -> None:
        """Default values should be empty lists/dicts."""
        result = ScanResult(target="https://example.com")
        assert result.endpoints == []
        assert result.parameters == []
        assert result.forms == []
        assert result.vulnerabilities == []
        assert result.status == "pending"

    def test_summary(self) -> None:
        """Summary should return correct counts."""
        result = ScanResult(
            target="https://example.com",
            endpoints=["/api", "/login"],
            parameters=["id", "page"],
            forms=[{"action": "/login", "method": "POST"}],
            vulnerabilities=[{"type": "missing_header", "severity": "medium"}],
            status="completed",
        )
        summary = result.summary()
        assert summary["endpoints"] == 2
        assert summary["parameters"] == 2
        assert summary["forms"] == 1
        assert summary["vulnerabilities"] == 1
        assert summary["status"] == "completed"


class TestWebScanner:
    """Test WebScanner initialization and configuration."""

    def test_initialization(self) -> None:
        """Scanner should initialize with correct defaults."""
        scanner = WebScanner(target="https://example.com")
        assert scanner.target == "https://example.com"
        assert scanner.timeout == 30
        assert scanner.user_agent == "NEXUS-WebRecon/1.0"
        assert scanner.max_depth == 3

    def test_custom_values(self) -> None:
        """Custom values should be stored."""
        scanner = WebScanner(
            target="https://example.com",
            timeout=60,
            user_agent="CustomAgent/1.0",
            max_depth=5,
        )
        assert scanner.timeout == 60
        assert scanner.user_agent == "CustomAgent/1.0"
        assert scanner.max_depth == 5

    def test_target_stripped(self) -> None:
        """Trailing slash should be stripped."""
        scanner = WebScanner(target="https://example.com//")
        assert scanner.target == "https://example.com"

    def test_get_result_empty(self) -> None:
        """get_result should return None before scanning."""
        scanner = WebScanner(target="https://example.com")
        assert scanner.get_result() is None

    def test_detect_technologies_nginx(self) -> None:
        """Nginx should be detected from server header."""
        scanner = WebScanner(target="https://example.com")
        techs = scanner._detect_technologies("", {"server": "nginx/1.24"})
        assert "Nginx" in techs

    def test_detect_technologies_react(self) -> None:
        """React should be detected from HTML content."""
        scanner = WebScanner(target="https://example.com")
        techs = scanner._detect_technologies('<div id="_reactRootContainer">', {})
        assert "React" in techs

    def test_detect_technologies_aspnet(self) -> None:
        """ASP.NET should be detected from __VIEWSTATE."""
        scanner = WebScanner(target="https://example.com")
        techs = scanner._detect_technologies('<input name="__VIEWSTATE"', {})
        assert "ASP.NET" in techs

    def test_analyze_security_headers(self) -> None:
        """Missing security headers should be flagged."""
        scanner = WebScanner(target="https://example.com")
        headers = MagicMock()
        headers.get = lambda k, d="": "max-age=31536000" if k == "Strict-Transport-Security" else d
        result = scanner._analyze_security_headers(headers)
        assert result["Strict-Transport-Security"] == "max-age=31536000"
        assert result["Content-Security-Policy"] == "MISSING"
