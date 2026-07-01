"""Recon configuration — global settings and environment management."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ReconConfig:
    """Global configuration for the Web Recon Suite.

    Manages target settings, output directories, request parameters,
    and environment-specific configuration.
    """

    timeout: int = 30
    concurrency: int = 10
    user_agent: str = "NEXUS-WebRecon/1.0"
    output_dir: Path = Path("reports")
    log_level: str = "INFO"
    follow_redirects: bool = True
    max_depth: int = 3
    delay: float = 0.5
    verbose: bool = False

    @classmethod
    def from_env(cls) -> ReconConfig:
        """Load configuration from environment variables.

        Returns:
            ReconConfig with values from environment.
        """
        return cls(
            timeout=int(os.getenv("WEBRECON_TIMEOUT", "30")),
            concurrency=int(os.getenv("WEBRECON_CONCURRENCY", "10")),
            user_agent=os.getenv("WEBRECON_USER_AGENT", "NEXUS-WebRecon/1.0"),
            output_dir=Path(os.getenv("WEBRECON_OUTPUT_DIR", "reports")),
            log_level=os.getenv("WEBRECON_LOG_LEVEL", "INFO"),
            verbose=os.getenv("WEBRECON_VERBOSE", "").lower() in ("1", "true", "yes"),
        )

    def ensure_dirs(self) -> None:
        """Create output directory if it doesn't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
