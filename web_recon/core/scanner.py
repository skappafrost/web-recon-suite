"""Web scanner — main entry point for web application reconnaissance.

Provides systematic discovery of endpoints, parameters, technologies,
and attack surfaces for web applications. Supports both active and
passive scanning modes with configurable depth and concurrency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import httpx

from web_recon.core.endpoints import EndpointDiscoverer
from web_recon.core.auth import AuthAnalyzer


@dataclass
class ScanResult:
    """Result of a web application security scan.

    Attributes:
        target: The scanned URL.
        endpoints: Discovered URL endpoints.
        parameters: Discovered query parameter names.
        forms: Discovered HTML forms with their inputs.
        technologies: Detected web technologies and frameworks.
        auth_endpoints: Endpoints related to authentication.
        security_headers: Security header analysis results.
        vulnerabilities: Identified potential vulnerabilities.
        status: Scan status (pending, completed, failed).
    """

    target: str
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict] = field(default_factory=list)
    status: str = "pending"

    def summary(self) -> dict:
        """Generate a summary of the scan results."""
        return {
            "target": self.target,
            "endpoints": len(self.endpoints),
            "parameters": len(self.parameters),
            "forms": len(self.forms),
            "technologies": self.technologies,
            "auth_endpoints": len(self.auth_endpoints),
            "missing_headers": [k for k, v in self.security_headers.items() if v == "MISSING"],
            "vulnerabilities": len(self.vulnerabilities),
            "status": self.status,
        }


class WebScanner:
    """Systematic web application security assessment.

    Orchestrates endpoint discovery, parameter enumeration, technology
    fingerprinting, authentication analysis, and security header auditing
    in a single scan workflow.

    Usage:
        scanner = WebScanner(target="https://example.com")
        result = await scanner.scan()
        print(f"Found {len(result.endpoints)} endpoints")
    """

    # Common technology fingerprint patterns
    TECH_SIGNATURES: dict[str, list[str]] = {
        "WordPress": ["wp-content", "wp-includes", "wp-json"],
        "Next.js": ["__NEXT_DATA__", "_next/static"],
        "Nuxt.js": ["__NUXT__", "_nuxt/"],
        "React": ["react", "react-dom", "_reactRootContainer"],
        "Vue.js": ["vue", "__vue__", "v-cloak"],
        "Angular": ["ng-version", "angular", "_ngcontent"],
        "jQuery": ["jquery", "jQuery"],
        "Laravel": ["laravel_session", "csrf-token"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
        "Express": ["x-powered-by: Express"],
        "Rails": ["csrf-token", "turbolinks"],
    }

    # Security headers to check
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def __init__(
        self,
        target: str,
        timeout: int = 30,
        follow_redirects: bool = True,
        user_agent: str = "NEXUS-WebRecon/1.0",
        max_depth: int = 3,
        concurrency: int = 10,
    ) -> None:
        """Initialize web scanner.

        Args:
            target: Target URL to scan.
            timeout: Request timeout in seconds.
            follow_redirects: Whether to follow HTTP redirects.
            user_agent: Custom User-Agent header.
            max_depth: Maximum crawl depth.
            concurrency: Maximum concurrent requests.
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent
        self.max_depth = max_depth
        self.concurrency = concurrency
        self._result: Optional[ScanResult] = None
        self._visited: set[str] = set()

    async def _fetch(self, url: str) -> Optional[httpx.Response]:
        """Fetch a URL and return the response.

        Args:
            url: URL to fetch.

        Returns:
            httpx.Response or None on error.
        """
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            headers={"User-Agent": self.user_agent},
        ) as client:
            try:
                response = await client.get(url)
                return response
            except httpx.HTTPError:
                return None

    def _detect_technologies(self, html: str, headers: dict[str, str]) -> list[str]:
        """Detect web technologies from HTML content and HTTP headers.

        Analyzes HTML markup, script sources, meta tags, and HTTP headers
        to identify the target's technology stack.

        Args:
            html: Page HTML content.
            headers: HTTP response headers.

        Returns:
            List of detected technology names.
        """
        technologies: set[str] = set()
        html_lower = html.lower()

        # Check HTML signatures
        for tech, signatures in self.TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in html_lower:
                    technologies.add(tech)
                    break

        # Check server header
        server = headers.get("server", "").lower()
        if "nginx" in server:
            technologies.add("Nginx")
        elif "apache" in server:
            technologies.add("Apache")
        elif "cloudflare" in server:
            technologies.add("Cloudflare")
        elif "iis" in server:
            technologies.add("IIS")

        # Check X-Powered-By
        powered_by = headers.get("x-powered-by", "").lower()
        if "express" in powered_by:
            technologies.add("Express")
        elif "php" in powered_by:
            technologies.add("PHP")
        elif "asp.net" in powered_by:
            technologies.add("ASP.NET")

        return sorted(technologies) if technologies else ["Unknown"]

    def _analyze_security_headers(self, headers: httpx.Headers) -> dict[str, str]:
        """Analyze security headers for missing or misconfigured policies.

        Args:
            headers: HTTP response headers.

        Returns:
            Dict mapping header name to its value or "MISSING".
        """
        result: dict[str, str] = {}
        for header in self.SECURITY_HEADERS:
            value = headers.get(header)
            if value:
                result[header] = value
            else:
                result[header] = "MISSING"
        return result

    async def scan(self) -> ScanResult:
        """Execute full web application security scan.

        Performs endpoint discovery, technology fingerprinting,
        authentication analysis, and security header auditing.

        Returns:
            ScanResult with all discovered endpoints and findings.
        """
        self._result = ScanResult(target=self.target)

        # Fetch main page
        response = await self._fetch(self.target)
        if not response:
            self._result.status = "failed"
            return self._result

        html = response.text
        self._visited.add(self.target)

        # Discover endpoints
        discoverer = EndpointDiscoverer()
        self._result.endpoints = discoverer.extract_from_html(html, self.target)
        self._result.parameters = discoverer.extract_parameters(html)
        self._result.forms = discoverer.extract_forms(html)

        # Detect technologies
        self._result.technologies = self._detect_technologies(html, dict(response.headers))

        # Analyze security headers
        self._result.security_headers = self._analyze_security_headers(response.headers)

        # Analyze authentication endpoints
        auth = AuthAnalyzer()
        self._result.auth_endpoints = auth.find_auth_endpoints(self._result.endpoints)

        # Identify missing header vulnerabilities
        for header, value in self._result.security_headers.items():
            if value == "MISSING":
                self._result.vulnerabilities.append({
                    "type": "missing_header",
                    "header": header,
                    "severity": "medium",
                    "description": f"Security header {header} is not set",
                })

        self._result.status = "completed"
        return self._result

    def get_result(self) -> Optional[ScanResult]:
        """Get the last scan result."""
        return self._result
