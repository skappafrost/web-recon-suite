"""Authentication endpoint analysis and bypass detection.

Identifies login, registration, password reset, and OAuth endpoints,
then analyzes their authentication mechanisms for potential bypasses.
"""

from __future__ import annotations

import re
from typing import Optional


class AuthAnalyzer:
    """Identify and analyze authentication endpoints.

    Discovers login, logout, registration, and password reset endpoints
    from a list of URLs. Classifies each endpoint by its likely
    authentication method (session cookie, JWT, OAuth, etc.).

    Usage:
        analyzer = AuthAnalyzer()
        auth_endpoints = analyzer.find_auth_endpoints(all_endpoints)
        methods = analyzer.analyze_auth_methods(auth_endpoints)
    """

    # Patterns that indicate authentication-related endpoints
    AUTH_PATTERNS = [
        r"login",
        r"signin",
        r"sign-in",
        r"authenticate",
        r"auth[/]",
        r"register",
        r"signup",
        r"sign-up",
        r"password",
        r"reset",
        r"forgot",
        r"token",
        r"oauth",
        r"saml",
        r"callback",
        r"session",
        r"logout",
        r"signout",
        r"sign-out",
    ]

    # Patterns that suggest specific auth methods
    METHOD_PATTERNS: dict[str, list[str]] = {
        "OAuth/SSO": ["oauth", "sso", "saml", "openid", "cas/", "callback"],
        "JWT": ["jwt", "token/refresh", "token/verify", "jwks"],
        "API Key": ["api-key", "apikey", "api_key", "x-api-key"],
        "Session Cookie": ["session", "cookie", "csrf", "login", "signin"],
    }

    def __init__(self, custom_patterns: Optional[list[str]] = None) -> None:
        """Initialize auth analyzer.

        Args:
            custom_patterns: Additional regex patterns for auth endpoint detection.
        """
        patterns = self.AUTH_PATTERNS[:]
        if custom_patterns:
            patterns.extend(custom_patterns)
        self._pattern = re.compile("|".join(patterns), re.IGNORECASE)

    def find_auth_endpoints(self, endpoints: list[str]) -> list[str]:
        """Filter endpoints that likely handle authentication.

        Args:
            endpoints: List of all discovered endpoint URLs.

        Returns:
            List of authentication-related endpoints.
        """
        auth_endpoints: list[str] = []
        for endpoint in endpoints:
            if self._pattern.search(endpoint):
                auth_endpoints.append(endpoint)
        return auth_endpoints

    def analyze_auth_methods(self, endpoints: list[str]) -> dict[str, str]:
        """Analyze authentication methods used by endpoints.

        Classifies each authentication endpoint by its likely auth
        mechanism based on URL path patterns.

        Args:
            endpoints: List of authentication endpoints.

        Returns:
            Dict mapping endpoint URL to detected auth method.
        """
        methods: dict[str, str] = {}
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            detected = "Unknown"
            for method, patterns in self.METHOD_PATTERNS.items():
                if any(p in endpoint_lower for p in patterns):
                    detected = method
                    break
            methods[endpoint] = detected
        return methods

    def find_bypass_candidates(self, endpoints: list[str]) -> list[dict]:
        """Identify endpoints that may be vulnerable to auth bypass.

        Looks for patterns like forced password change endpoints,
        API routes that may lack auth middleware, and admin paths
        that might be directly accessible.

        Args:
            endpoints: List of all discovered endpoints.

        Returns:
            List of bypass candidate dictionaries with reasoning.
        """
        candidates: list[dict] = []

        bypass_patterns = [
            (r"/api/v[0-9]+/(?!auth)", "API endpoint may lack authentication middleware"),
            (r"force.*change|changepassword|reset-password", "Forced password change may be bypassable"),
            (r"/admin(?!/login)", "Admin path may be accessible without auth"),
            (r"/debug|/dev|/test", "Debug/dev/test endpoints may bypass auth"),
            (r"/graphql", "GraphQL endpoint may expose unauthorized data"),
        ]

        for endpoint in endpoints:
            for pattern, reason in bypass_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    candidates.append({
                        "endpoint": endpoint,
                        "reason": reason,
                        "severity": "high",
                    })
                    break

        return candidates
