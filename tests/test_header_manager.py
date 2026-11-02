"""
Tests for NightCrawler Researcher Header Configuration
Validates header toggle, env loading, custom values, masking, and scope isolation.
"""

import os
import pytest
from src.core.header_manager import HeaderManager
from src.core.scope import ScopeManager


def test_header_disabled_by_default_behavior():
    """Verify header manager is inactive when disabled."""
    hm = HeaderManager(enabled=False, header_name="X-User-Id", header_value="researcher@test.com")
    assert hm.is_active() is False
    headers = hm.get_headers_for_url("https://app.uxcam.com")
    assert "X-User-Id" not in headers


def test_header_custom_name_and_value():
    """Verify enabled header with custom name and value."""
    hm = HeaderManager(enabled=True, header_name="X-Bug-Bounty", header_value="hacker_123")
    assert hm.is_active() is True
    assert hm.header_name == "X-Bug-Bounty"
    assert hm.header_value == "hacker_123"


def test_environment_variable_loading(monkeypatch):
    """Verify header value is loaded automatically from environment variable."""
    monkeypatch.setenv("NIGHTCRAWLER_RESEARCHER_ID", "researcher_from_env@example.com")
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value_env="NIGHTCRAWLER_RESEARCHER_ID")
    assert hm.is_active() is True
    assert hm.header_value == "researcher_from_env@example.com"


def test_header_masking_in_logs_and_reports():
    """Verify sensitive researcher email/id is never exposed in cleartext."""
    # Email masking
    hm_email = HeaderManager(enabled=True, header_value="security_expert@domain.com")
    masked_email = hm_email.get_masked_value()
    assert masked_email != "security_expert@domain.com"
    assert "@domain.com" in masked_email
    assert "s" in masked_email
    assert "*" in masked_email
    assert "security_expert" not in masked_email

    # Token / string masking
    hm_token = HeaderManager(enabled=True, header_value="secret_bounty_token_999")
    masked_token = hm_token.get_masked_value()
    assert masked_token != "secret_bounty_token_999"
    assert "secret_bounty_token_999" not in masked_token
    assert "*" in masked_token


def test_header_not_sent_to_unrelated_third_parties():
    """
    CRITICAL: Verify that the researcher identification header is NEVER attached
    when making requests to out-of-scope or third-party domains.
    """
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"], enabled=True)
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value="researcher@test.com")

    # In-scope URL: header MUST be attached
    in_scope_headers = hm.get_headers_for_url("https://api.uxcam.com/v1", scope_manager=scope)
    assert in_scope_headers.get("X-User-Id") == "researcher@test.com"

    # Out-of-scope / third-party URL: header MUST NOT be attached
    third_party_headers = hm.get_headers_for_url("https://google.com/oauth", scope_manager=scope)
    assert "X-User-Id" not in third_party_headers

    github_headers = hm.get_headers_for_url("https://github.com/login", scope_manager=scope)
    assert "X-User-Id" not in github_headers

    lookalike_headers = hm.get_headers_for_url("https://eviluxcam.com/steal", scope_manager=scope)
    assert "X-User-Id" not in lookalike_headers


def test_format_cli_header_flag():
    """Verify CLI header flag generation for external tools."""
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value="researcher@uxcam-tester.com")
    flag = hm.format_cli_header_flag()
    assert flag == "X-User-Id: researcher@uxcam-tester.com"

    hm_off = HeaderManager(enabled=False)
    assert hm_off.format_cli_header_flag() is None


def test_subprocess_env_passing_not_cli_args():
    """
    CRITICAL: Verify that when launching a scan subprocess from run.py,
    the sensitive header value is passed via process environment (env),
    NEVER in sys.argv / command-line arguments (preventing ps aux exposure).
    """
    from unittest.mock import patch, MagicMock
    from run import run_scan_subprocess
    from src.core.request_config import NightCrawlerConfig

    cfg = NightCrawlerConfig(
        custom_header_enabled=True,
        header_name="X-User-Id",
        header_value="secret_researcher@example.com"
    )

    with patch("subprocess.run") as mock_subproc:
        mock_subproc.return_value = MagicMock(returncode=0)
        run_scan_subprocess("uxcam.com", cfg)

        assert mock_subproc.call_count == 1
        called_args, called_kwargs = mock_subproc.call_args
        cmd_called = called_args[0]
        env_called = called_kwargs.get("env", {})

        # The raw secret MUST NOT be in command line arguments!
        assert "--header-value" not in cmd_called
        assert "secret_researcher@example.com" not in " ".join(cmd_called)

        # The raw secret MUST be present in the subprocess environment dictionary
        assert env_called.get("NIGHTCRAWLER_RESEARCHER_ID") == "secret_researcher@example.com"
        assert env_called.get("NIGHTCRAWLER_HEADER_VALUE") == "secret_researcher@example.com"

