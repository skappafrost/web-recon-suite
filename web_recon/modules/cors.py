"""CORS misconfiguration analyzer.

Tests Cross-Origin Resource Sharing configurations for common
misconfigurations that could enable cross-origin data theft.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class CORSResult:
    """Result of a CORS configuration test.

    Attributes:
        origin_tested: The origin used in the test.
        allowed: Whether the origin was permitted.
        allow_methods: Access-Control-Allow-Methods header value.
        allow_headers: Access-Control-Allow-Headers header value.
        allow_credentials: Whether credentials are allowed.
        severity: Assessed severity of the misconfiguration.
    """

    origin_tested: str
    allowed: bool
    allow_methods: str = ""
    allow_headers: str = ""
    allow_credentials: bool = False
    severity: str = "info"

    def to_dict(self) -> dict:
        """Convert to dictionary for reporting."""
        return {
            "origin_tested": self.origin_tested,
            "allowed": self.allowed,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "allow_credentials": self.allow_credentials,
            "severity": self.severity,
        }


class CORSAnalyzer:
    """Analyze CORS configurations for security misconfigurations.

    Tests target endpoints with various Origin headers to detect
    common CORS misconfigurations like reflecting any origin,
    allowing null origin, or subdomain bypass.

    Usage:
        analyzer = CORSAnalyzer(target="https://api.example.com")
        results = await analyzer.analyze()
        for r in results:
            if r.allowed:
                print(f"  [!] {r.origin_tested} — {r.severity}")
    """

    # Test origins for misconfiguration detection
    TEST_ORIGINS = [
        ("https://evil.com", "reflects_any_origin", "critical"),
        ("null", "null_origin_allowed", "high"),
        ("https://example.evil.com", "subdomain_bypass", "high"),
        ("https://example.com.evil.com", "suffix_bypass", "high"),
        ("https://evil.example.com", "subdomain_reflection", "medium"),
    ]

    def __init__(self, target: str, endpoint: str = "/", timeout: int = 10) -> None:
        """Initialize CORS analyzer.

        Args:
            target: Target base URL.
            endpoint: Specific endpoint to test.
            timeout: Request timeout in seconds.
        """
        self.target = target.rstrip("/")
        self.endpoint = endpoint
        self.timeout = timeout

    async def _test_origin(self, url: str, origin: str) -> CORSResult:
        """Test a specific origin against the target endpoint.

        Args:
            url: Full URL to test.
            origin: Origin header value to send.

        Returns:
            CORSResult with the test outcome.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization",
                    },
                )
                acao = response.headers.get("access-control-allow-origin", "")
                allowed = acao == origin or acao == "*"
                return CORSResult(
                    origin_tested=origin,
                    allowed=allowed,
                    allow_methods=response.headers.get("access-control-allow-methods", ""),
                    allow_headers=response.headers.get("access-control-allow-headers", ""),
                    allow_credentials=response.headers.get("access-control-allow-credentials", "false").lower() == "true",
                    severity="critical" if allowed and acao == origin else "info",
                )
            except httpx.HTTPError:
                return CORSResult(origin_tested=origin, allowed=False)

    async def analyze(self) -> list[CORSResult]:
        """Run all CORS misconfiguration tests.

        Returns:
            List of CORSResult for each origin tested.
        """
        url = f"{self.target}{self.endpoint}"
        tasks = []
        for origin, _, _ in self.TEST_ORIGINS:
            tasks.append(self._test_origin(url, origin))

        results = await asyncio.gather(*tasks)

        # Assign severity based on test type
        for result, (_, test_type, severity) in zip(results, self.TEST_ORIGINS):
            if result.allowed:
                result.severity = severity

        return list(results)
