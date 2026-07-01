"""Credential testing module — authentication endpoint brute-force and spray testing.

Tests authentication endpoints with credential combinations to identify
weak or default credentials in authorized environments.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class CredResult:
    """Result of a credential test attempt.

    Attributes:
        username: Username tested.
        password: Password tested.
        success: Whether authentication succeeded.
        status_code: HTTP response status code.
        response_length: Response body length (for diffing).
    """

    username: str
    password: str
    success: bool = False
    status_code: int = 0
    response_length: int = 0


class CredentialTester:
    """Test authentication endpoints for weak credentials.

    Supports both brute-force (single username, many passwords) and
    password spraying (many usernames, single password) modes.

    WARNING: Only use on systems you own or have explicit authorization
    to test. Unauthorized credential testing is illegal.

    Usage:
        tester = CredentialTester(
            target="https://example.com/api/login",
            method="POST",
        )
        results = await tester.brute_force(
            username="admin",
            passwords=["admin123", "password", "letmein"],
        )
        for r in results:
            if r.success:
                print(f"  [!] {r.username}:{r.password}")
    """

    # Default headers for credential testing
    DEFAULT_HEADERS = {
        "Content-Type": "application/json",
        "User-Agent": "NEXUS-WebRecon/1.0",
    }

    # Common indicators of successful authentication
    SUCCESS_INDICATORS = [200, 201, 301, 302]
    FAILURE_INDICATORS = [401, 403, 400]

    def __init__(
        self,
        target: str,
        method: str = "POST",
        username_field: str = "username",
        password_field: str = "password",
        timeout: int = 10,
        delay: float = 0.5,
    ) -> None:
        """Initialize credential tester.

        Args:
            target: Login endpoint URL.
            method: HTTP method (POST or GET).
            username_field: JSON field name for username.
            password_field: JSON field name for password.
            timeout: Request timeout in seconds.
            delay: Delay between requests to avoid rate limiting.
        """
        self.target = target
        self.method = method.upper()
        self.username_field = username_field
        self.password_field = password_field
        self.timeout = timeout
        self.delay = delay

    async def _test_credential(self, username: str, password: str) -> CredResult:
        """Test a single credential pair.

        Args:
            username: Username to test.
            password: Password to test.

        Returns:
            CredResult with the test outcome.
        """
        payload = {self.username_field: username, self.password_field: password}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                if self.method == "POST":
                    response = await client.post(self.target, json=payload, headers=self.DEFAULT_HEADERS)
                else:
                    response = await client.get(self.target, params=payload, headers=self.DEFAULT_HEADERS)

                success = response.status_code in self.SUCCESS_INDICATORS
                return CredResult(
                    username=username,
                    password=password,
                    success=success,
                    status_code=response.status_code,
                    response_length=len(response.content),
                )
            except httpx.HTTPError:
                return CredResult(username=username, password=password)

    async def brute_force(
        self,
        username: str,
        passwords: list[str],
    ) -> list[CredResult]:
        """Brute-force a single username with multiple passwords.

        Args:
            username: Target username.
            passwords: List of passwords to test.

        Returns:
            List of CredResult for each attempt.
        """
        results: list[CredResult] = []
        for password in passwords:
            result = await self._test_credential(username, password)
            results.append(result)
            if self.delay > 0:
                await asyncio.sleep(self.delay)
        return results

    async def password_spray(
        self,
        usernames: list[str],
        password: str,
    ) -> list[CredResult]:
        """Password spray a single password across multiple usernames.

        Args:
            usernames: List of usernames to test.
            password: Password to spray.

        Returns:
            List of CredResult for each attempt.
        """
        results: list[CredResult] = []
        for username in usernames:
            result = await self._test_credential(username, password)
            results.append(result)
            if self.delay > 0:
                await asyncio.sleep(self.delay)
        return results
