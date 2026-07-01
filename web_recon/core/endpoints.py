"""Endpoint discovery and parameter extraction from web content.

Parses HTML and JavaScript to discover URLs, API endpoints, form
parameters, and hidden paths for security assessment.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


class EndpointDiscoverer:
    """Extract endpoints and parameters from web content.

    Parses HTML/JavaScript to discover URLs, API endpoints, and
    form parameters for security assessment.

    Usage:
        discoverer = EndpointDiscoverer()
        endpoints = discoverer.extract_from_html(html, base_url)
        params = discoverer.extract_parameters(html)
        forms = discoverer.extract_forms(html)
    """

    # Regex patterns for endpoint discovery
    URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')
    JS_URL_PATTERN = re.compile(r'["\']([^"\s]+)["\']')
    API_PATTERN = re.compile(r'/(api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)')
    PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]*)=([^"\s&>]+)')

    # Common sensitive paths to probe
    SENSITIVE_PATHS = [
        "/.env",
        "/.git/config",
        "/.htaccess",
        "/wp-config.php",
        "/config.json",
        "/package.json",
        "/composer.json",
        "/.DS_Store",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/graphql",
        "/admin",
        "/debug",
        "/phpinfo.php",
        "/server-status",
        "/.svn/entries",
    ]

    def extract_from_html(self, html: str, base_url: str) -> list[str]:
        """Extract all endpoints from HTML content.

        Parses anchor tags, script sources, link hrefs, form actions,
        and embedded JavaScript to build a comprehensive endpoint map.

        Args:
            html: Page HTML content.
            base_url: Base URL for relative link resolution.

        Returns:
            List of discovered endpoint URLs (deduplicated, sorted).
        """
        endpoints: set[str] = set()
        soup = BeautifulSoup(html, "lxml")

        # Extract from href attributes (links, stylesheets, etc.)
        for tag in soup.find_all(href=True):
            href = tag["href"]
            full_url = urljoin(base_url, href)
            if self._is_internal(full_url, base_url):
                endpoints.add(full_url.split("#")[0])

        # Extract from src attributes (scripts, images, etc.)
        for tag in soup.find_all(src=True):
            src = tag["src"]
            full_url = urljoin(base_url, src)
            if self._is_internal(full_url, base_url):
                endpoints.add(full_url.split("#")[0])

        # Extract from action attributes (forms)
        for tag in soup.find_all(action=True):
            action = tag["action"]
            full_url = urljoin(base_url, action)
            if self._is_internal(full_url, base_url):
                endpoints.add(full_url.split("#")[0])

        # Extract API endpoints from inline JavaScript
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string:
                endpoints.update(self._extract_from_js(script.string, base_url))

        # Extract from data-* attributes that may contain URLs
        for tag in soup.find_all(attrs={"data-url": True}):
            url = tag.get("data-url", "")
            if url:
                full_url = urljoin(base_url, url)
                if self._is_internal(full_url, base_url):
                    endpoints.add(full_url)

        return sorted(endpoints)

    def _is_internal(self, url: str, base_url: str) -> bool:
        """Check if URL belongs to the target domain.

        Args:
            url: URL to check.
            base_url: Base URL of the target.

        Returns:
            True if URL is on the same domain.
        """
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            return parsed.netloc == base_parsed.netloc or parsed.netloc == ""
        except Exception:
            return False

    def _extract_from_js(self, js: str, base_url: str) -> list[str]:
        """Extract endpoints from JavaScript code.

        Looks for API-style URL patterns, fetch/AJAX calls, and
        string literals that resemble paths.

        Args:
            js: JavaScript source code.
            base_url: Base URL for resolution.

        Returns:
            List of discovered endpoint URLs.
        """
        endpoints: list[str] = []

        # Find API-style endpoints (e.g., /api/users, /v1/products)
        for match in self.API_PATTERN.finditer(js):
            endpoint = urljoin(base_url, match.group(1))
            endpoints.append(endpoint)

        # Find fetch/AJAX URLs in string literals
        for match in self.JS_URL_PATTERN.finditer(js):
            url = match.group(1)
            if url.startswith(("/", "http")) and not url.startswith(("//", "javascript:")):
                full = urljoin(base_url, url)
                if self._is_internal(full, base_url):
                    endpoints.append(full)

        return endpoints

    def extract_parameters(self, html: str) -> list[str]:
        """Extract parameter names from URLs in HTML.

        Identifies query parameter names from href attributes and
        form inputs for parameter-level security testing.

        Args:
            html: Page HTML content.

        Returns:
            Sorted list of unique parameter names.
        """
        params: set[str] = set()
        for match in self.PARAM_PATTERN.finditer(html):
            params.add(match.group(1))
        return sorted(params)

    def extract_forms(self, html: str) -> list[dict]:
        """Extract form definitions from HTML.

        Parses each form element to extract its action URL, HTTP method,
        and all input fields with their names, types, and default values.

        Args:
            html: Page HTML content.

        Returns:
            List of form dictionaries with action, method, and inputs.
        """
        forms: list[dict] = []
        soup = BeautifulSoup(html, "lxml")

        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "id": form.get("id", ""),
                "inputs": [],
            }
            for inp in form.find_all("input"):
                form_data["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            for textarea in form.find_all("textarea"):
                form_data["inputs"].append({
                    "name": textarea.get("name", ""),
                    "type": "textarea",
                    "value": textarea.string or "",
                })
            for select in form.find_all("select"):
                form_data["inputs"].append({
                    "name": select.get("name", ""),
                    "type": "select",
                    "value": "",
                })
            forms.append(form_data)

        return forms

    def get_sensitive_paths(self) -> list[str]:
        """Return list of common sensitive paths to probe.

        Returns:
            List of path strings commonly exposing sensitive data.
        """
        return self.SENSITIVE_PATHS.copy()
