"""Authentication endpoint analysis — detect and classify auth mechanisms.

Identifies authentication-related endpoints, classifies their methods,
and flags potential bypass candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class BypassCandidate:
    """Endpoint that may be vulnerable to auth bypass."""

    endpoint: str
    reason: str


class AuthAnalyzer:
    """Analyze authentication endpoints and methods.

    Detects auth-related URLs, classifies their authentication
    mechanism, and identifies potential bypass candidates.

    Usage:
        analyzer = AuthAnalyzer()
        auth_eps = analyzer.find_auth_endpoints(urls)
        methods = analyzer.analyze_auth_methods(urls)
        candidates = analyzer.find_bypass_candidates(urls)
    """

    AUTH_PATTERNS: list[str] = [
        "login", "signin", "sign-in", "auth", "oauth",
        "sso", "token", "session", "callback", "verify",
    ]

    OAUTH_PATTERNS: list[str] = ["oauth", "sso", "openid", "callback"]

    def find_auth_endpoints(self, endpoints: list[str]) -> list[str]:
        """Filter endpoints that appear to be authentication-related.

        Args:
            endpoints: List of URL paths to analyze.

        Returns:
            Subset of endpoints matching auth patterns.
        """
        auth_endpoints: list[str] = []
        for ep in endpoints:
            lower = ep.lower()
            if any(pattern in lower for pattern in self.AUTH_PATTERNS):
                auth_endpoints.append(ep)
        return auth_endpoints

    def analyze_auth_methods(self, endpoints: list[str]) -> dict[str, str]:
        """Classify the authentication method for each endpoint.

        Args:
            endpoints: List of URL paths to classify.

        Returns:
            Mapping of endpoint → auth method string.
        """
        methods: dict[str, str] = {}
        for ep in endpoints:
            lower = ep.lower()
            if any(p in lower for p in self.OAUTH_PATTERNS):
                methods[ep] = "OAuth/SSO"
            elif "token" in lower or "api" in lower:
                methods[ep] = "API Token"
            elif "session" in lower:
                methods[ep] = "Session Cookie"
            else:
                methods[ep] = "Unknown"
        return methods

    def find_bypass_candidates(self, endpoints: list[str]) -> list[dict[str, str]]:
        """Identify endpoints that may be vulnerable to auth bypass.

        Flags admin panels, API versioned endpoints, and
        other patterns that commonly have weak auth.

        Args:
            endpoints: List of URL paths to check.

        Returns:
            List of dicts with 'endpoint' and 'reason' keys.
        """
        candidates: list[dict[str, str]] = []
        bypass_patterns = [
            (r"admin", "Admin panel — often has weaker auth"),
            (r"api/v\d+", "Versioned API — may lack consistent auth"),
            (r"debug|dev|test|staging", "Non-production endpoint"),
            (r"graphql", "GraphQL — may expose unauthorized fields"),
        ]
        for ep in endpoints:
            for pattern, reason in bypass_patterns:
                if re.search(pattern, ep, re.IGNORECASE):
                    candidates.append({"endpoint": ep, "reason": reason})
                    break
        return candidates
