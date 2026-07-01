"""Tests for utils — configuration."""

from __future__ import annotations

import os
from unittest.mock import patch


from web_recon.utils.config import ReconConfig


class TestReconConfig:
    """Test configuration loading."""

    def test_default_values(self) -> None:
        """Default values should be sensible."""
        config = ReconConfig()
        assert config.timeout == 30
        assert config.concurrency == 10
        assert config.user_agent == "NEXUS-WebRecon/1.0"

    def test_from_env_defaults(self) -> None:
        """from_env should use defaults when env vars are not set."""
        with patch.dict(os.environ, {}, clear=True):
            config = ReconConfig.from_env()
            assert config.timeout == 30

    def test_from_env_custom(self) -> None:
        """from_env should read from environment."""
        env = {"WEBRECON_TIMEOUT": "60", "WEBRECON_VERBOSE": "true"}
        with patch.dict(os.environ, env, clear=False):
            config = ReconConfig.from_env()
            assert config.timeout == 60
            assert config.verbose is True
