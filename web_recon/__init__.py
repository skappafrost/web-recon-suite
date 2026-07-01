"""Web Recon Suite — Systematic web application security assessment framework.

API endpoint discovery, authentication bypass analysis, credential testing,
CORS auditing, and structured reporting for authorized security assessments.
"""

__version__ = "1.0.0"
__author__ = "NEXUS"

from web_recon.core.scanner import WebScanner
from web_recon.core.endpoints import EndpointDiscoverer
from web_recon.core.auth import AuthAnalyzer

__all__ = ["WebScanner", "EndpointDiscoverer", "AuthAnalyzer"]
