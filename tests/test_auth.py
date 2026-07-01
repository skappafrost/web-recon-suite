"""Tests for core.auth — AuthAnalyzer."""

from __future__ import annotations

import pytest

from web_recon.core.auth import AuthAnalyzer


class TestAuthAnalyzer:
    """Test authentication endpoint analysis."""

    def test_find_auth_endpoints(self) -> None:
        """Auth endpoints should be identified by patterns."""
        analyzer = AuthAnalyzer()
        endpoints = [
            "https://example.com/login",
            "https://example.com/api/users",
            "https://example.com/auth/verify",
        ]
        auth = analyzer.find_auth_endpoints(endpoints)
        assert len(auth) == 2
        assert "https://example.com/login" in auth
        assert "https://example.com/auth/verify" in auth

    def test_analyze_auth_methods(self) -> None:
        """Auth methods should be classified."""
        analyzer = AuthAnalyzer()
        endpoints = ["https://example.com/login", "https://example.com/oauth/callback"]
        methods = analyzer.analyze_auth_methods(endpoints)
        assert methods["https://example.com/login"] == "Unknown"
        assert methods["https://example.com/oauth/callback"] == "OAuth/SSO"

    def test_find_bypass_candidates(self) -> None:
        """Bypass candidates should be identified."""
        analyzer = AuthAnalyzer()
        endpoints = [
            "https://example.com/api/v1/users",
            "https://example.com/admin/dashboard",
            "https://example.com/login",
        ]
        candidates = analyzer.find_bypass_candidates(endpoints)
        assert len(candidates) >= 1
        assert any("admin" in c["endpoint"] for c in candidates)
