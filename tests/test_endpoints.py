"""Tests for core.endpoints — EndpointDiscoverer."""

from __future__ import annotations

import pytest

from web_recon.core.endpoints import EndpointDiscoverer


class TestEndpointDiscoverer:
    """Test endpoint extraction from HTML."""

    def test_sensitive_paths(self) -> None:
        """Sensitive paths list should be populated."""
        discoverer = EndpointDiscoverer()
        paths = discoverer.get_sensitive_paths()
        assert len(paths) > 0
        assert "/.env" in paths
        assert "/robots.txt" in paths

    def test_extract_parameters(self) -> None:
        """Parameters should be extracted from query strings."""
        discoverer = EndpointDiscoverer()
        html = '<a href="/page?id=1&page=2">Link</a>'
        params = discoverer.extract_parameters(html)
        assert "id" in params
        assert "page" in params

    def test_extract_forms(self) -> None:
        """Forms should be parsed with inputs."""
        discoverer = EndpointDiscoverer()
        html = '''<form action="/login" method="POST">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>'''
        forms = discoverer.extract_forms(html)
        assert len(forms) == 1
        assert forms[0]["action"] == "/login"
        assert forms[0]["method"] == "POST"
        assert len(forms[0]["inputs"]) == 2

    def test_extract_from_html(self) -> None:
        """Endpoints should be extracted from links."""
        discoverer = EndpointDiscoverer()
        html = '<a href="/about">About</a><a href="/api/users">API</a>'
        endpoints = discoverer.extract_from_html(html, "https://example.com")
        assert any("/about" in e for e in endpoints)
        assert any("/api/users" in e for e in endpoints)

    def test_is_internal(self) -> None:
        """Internal URLs should be identified correctly."""
        discoverer = EndpointDiscoverer()
        assert discoverer._is_internal("https://example.com/page", "https://example.com")
        assert discoverer._is_internal("/page", "https://example.com")
        assert not discoverer._is_internal("https://other.com/page", "https://example.com")
