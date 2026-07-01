"""Operational modules — CORS auditing, credential testing, and reporting."""

from web_recon.modules.cors import CORSAnalyzer
from web_recon.modules.credentials import CredentialTester
from web_recon.modules.report import ReportGenerator

__all__ = ["CORSAnalyzer", "CredentialTester", "ReportGenerator"]
