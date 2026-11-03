"""
NightCrawler - Scope and Header Integration Tests
Verifies that:
1. Default invocation enforces scope.
2. Non-positive RPS values are rejected and hard maximum of 5 is enforced for UXCam profile.
3. Excluded hosts (tara.uxcam.com, connect.uxcam.com, and subdomains) are NEVER fetched.
4. Out-of-scope redirect destinations are NEVER fetched.
5. Every in-scope request carries the required researcher header.
"""

import pytest
import os
from unittest.mock import AsyncMock, MagicMock
from click.testing import CliRunner

from main import main
from src.core.request_config import load_config, NightCrawlerConfig
from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.http_client import NightCrawlerHttpClient


def test_default_invocation_enforces_scope():
    """Prove that default invocation strictly enforces scope and rejects out-of-scope targets."""
    # 1. Base configuration has scope enabled by default
    cfg = load_config()
    assert cfg.scope_enabled is True
    assert "uxcam.com" in cfg.allowed_domains
    assert "uxc.am" in cfg.allowed_domains
    assert "tara.uxcam.com" in cfg.excluded_domains

    scope = cfg.get_scope_manager()
    assert scope.enabled is True
    assert scope.is_host_allowed("app.uxcam.com") is True
    assert scope.is_host_allowed("eviluxcam.com") is False
    assert scope.is_host_allowed("tara.uxcam.com") is False

    # 2. CLI execution without extra flags rejects out-of-scope targets
    runner = CliRunner()
    res_evil = runner.invoke(main, ["-t", "eviluxcam.com", "--no-prompt"])
    assert "ERROR: Target 'eviluxcam.com' is OUT OF SCOPE!" in res_evil.output

    res_excluded = runner.invoke(main, ["-t", "tara.uxcam.com", "--no-prompt"])
    assert "ERROR: Target 'tara.uxcam.com' is OUT OF SCOPE!" in res_excluded.output

    # 3. Attempting to disable strict compliance mode (--no-strict-scope) is rejected when profile requires strict scope
    res_no_strict = runner.invoke(main, ["-t", "eviluxcam.com", "--no-strict-scope", "--no-prompt"])
    assert res_no_strict.exit_code != 0
    assert "Disabling strict scope is prohibited" in res_no_strict.output


def test_reject_non_positive_rps_and_enforce_uxcam_max():
    """Verify that non-positive RPS values are rejected and UXCam profile enforces max 5 RPS."""
    # RateLimiter rejects <= 0 RPS
    with pytest.raises(ValueError, match="must be positive"):
        GlobalRateLimiter(max_requests_per_second=0)

    with pytest.raises(ValueError, match="must be positive"):
        GlobalRateLimiter(max_requests_per_second=-3.0)

    # NightCrawlerConfig rejects <= 0 RPS
    cfg_neg = NightCrawlerConfig(max_requests_per_second=0)
    with pytest.raises(ValueError, match="must be positive"):
        cfg_neg.get_rate_limiter()

    # UXCam profile rejects RPS > 5.0
    cfg_uxcam = NightCrawlerConfig(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        max_requests_per_second=6.0
    )
    with pytest.raises(ValueError, match="UXCam bug bounty policy enforces a strict maximum rate limit of 5"):
        cfg_uxcam.get_rate_limiter()

    # UXCam profile accepts RPS <= 5.0
    cfg_uxcam_valid = NightCrawlerConfig(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        max_requests_per_second=5.0
    )
    limiter = cfg_uxcam_valid.get_rate_limiter()
    assert limiter.rate == 5.0

    # CLI rejection
    runner = CliRunner()
    res_zero = runner.invoke(main, ["-t", "uxcam.com", "--max-rps", "0"])
    assert res_zero.exit_code == 1
    assert "max-rps must be a positive number" in res_zero.output

    res_too_high = runner.invoke(main, ["-t", "uxcam.com", "--max-rps", "10"])
    assert res_too_high.exit_code == 1
    assert "UXCam bug bounty policy enforces a strict maximum rate limit of 5" in res_too_high.output


def test_researcher_id_environment_passing():
    """Verify that researcher ID is loaded from the environment securely."""
    os.environ["NIGHTCRAWLER_RESEARCHER_ID"] = "env_tester@example.com"
    try:
        hm = HeaderManager(enabled=True, header_name="X-User-Id")
        assert hm.header_value == "env_tester@example.com"
        assert hm.is_active() is True
        assert hm.get_masked_value() == "e********r@example.com"
        assert "env_tester" not in hm.get_masked_value()
    finally:
        del os.environ["NIGHTCRAWLER_RESEARCHER_ID"]


@pytest.mark.asyncio
async def test_excluded_hosts_are_never_fetched():
    """Integration test proving excluded hosts and their subdomains are NEVER fetched."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        excluded_domains=["tara.uxcam.com", "connect.uxcam.com"],
        enabled=True
    )
    limiter = GlobalRateLimiter(max_requests_per_second=5.0)
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value="researcher@example.com")
    client = NightCrawlerHttpClient(scope_manager=scope, rate_limiter=limiter, header_manager=hm, verify_tls=True)

    mock_session = MagicMock()
    mock_session.get = MagicMock()

    excluded_test_urls = [
        "https://tara.uxcam.com/app.js",
        "https://api.tara.uxcam.com/v1/user",
        "https://connect.uxcam.com/analytics.js",
        "https://sub.connect.uxcam.com/ping"
    ]

    for test_url in excluded_test_urls:
        status, content, final_url = await client.get(mock_session, test_url)
        assert status is None
        assert content is None

    # CRITICAL: mock_session.get must NEVER have been called for any excluded host
    assert mock_session.get.call_count == 0


@pytest.mark.asyncio
async def test_out_of_scope_redirect_destinations_are_never_fetched():
    """Integration test proving out-of-scope and excluded redirect targets are NEVER fetched."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        excluded_domains=["tara.uxcam.com", "connect.uxcam.com"],
        enabled=True
    )
    limiter = GlobalRateLimiter(max_requests_per_second=5.0)
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value="researcher@example.com")
    client = NightCrawlerHttpClient(scope_manager=scope, rate_limiter=limiter, header_manager=hm, verify_tls=True)

    fetched_urls = []

    def mock_get_context(url, **kwargs):
        fetched_urls.append(url)
        ctx = AsyncMock()
        mock_resp = AsyncMock()

        if url == "https://app.uxcam.com/login":
            # Redirects to lookalike domain
            mock_resp.status = 302
            mock_resp.headers = {"Location": "https://eviluxcam.com/auth/steal"}
        elif url == "https://app.uxcam.com/help":
            # Redirects to excluded domain
            mock_resp.status = 301
            mock_resp.headers = {"Location": "https://tara.uxcam.com/docs"}
        elif url == "https://app.uxcam.com/external":
            # Redirects to unrelated third party
            mock_resp.status = 302
            mock_resp.headers = {"Location": "https://attacker.com/malicious.js"}
        else:
            mock_resp.status = 200
            mock_resp.headers = {"content-type": "text/html"}
            mock_resp.text = AsyncMock(return_value="<html>OK</html>")

        ctx.__aenter__.return_value = mock_resp
        return ctx

    mock_session = MagicMock()
    mock_session.get.side_effect = mock_get_context

    # 1. Redirect to lookalike domain
    await client.get(mock_session, "https://app.uxcam.com/login")
    assert "https://app.uxcam.com/login" in fetched_urls
    assert "https://eviluxcam.com/auth/steal" not in fetched_urls

    # 2. Redirect to excluded host
    await client.get(mock_session, "https://app.uxcam.com/help")
    assert "https://app.uxcam.com/help" in fetched_urls
    assert "https://tara.uxcam.com/docs" not in fetched_urls

    # 3. Redirect to external party
    await client.get(mock_session, "https://app.uxcam.com/external")
    assert "https://app.uxcam.com/external" in fetched_urls
    assert "https://attacker.com/malicious.js" not in fetched_urls

    # Verify no out-of-scope URL was ever fetched
    for u in fetched_urls:
        assert scope.is_url_in_scope(u) is True


@pytest.mark.asyncio
async def test_every_in_scope_request_carries_required_header():
    """Integration test proving every in-scope request (including in-scope redirects) carries X-User-Id."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        excluded_domains=["tara.uxcam.com", "connect.uxcam.com"],
        enabled=True
    )
    limiter = GlobalRateLimiter(max_requests_per_second=5.0)
    researcher_id = "authorized_hunter@example.com"
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value=researcher_id)
    client = NightCrawlerHttpClient(scope_manager=scope, rate_limiter=limiter, header_manager=hm, verify_tls=True)

    recorded_requests = []

    def mock_get_context(url, **kwargs):
        headers = kwargs.get("headers", {})
        recorded_requests.append({"url": url, "headers": headers})
        ctx = AsyncMock()
        mock_resp = AsyncMock()

        if url == "https://uxcam.com/start":
            # In-scope redirect to another in-scope URL
            mock_resp.status = 301
            mock_resp.headers = {"Location": "https://app.uxcam.com/dashboard"}
        else:
            mock_resp.status = 200
            mock_resp.headers = {"content-type": "text/html"}
            mock_resp.text = AsyncMock(return_value="<html>OK</html>")

        ctx.__aenter__.return_value = mock_resp
        return ctx

    mock_session = MagicMock()
    mock_session.get.side_effect = mock_get_context

    # Direct in-scope requests
    await client.get(mock_session, "https://app.uxcam.com/api/v1")
    await client.get(mock_session, "https://api.uxc.am/health")

    # In-scope redirect (both hops are in-scope)
    await client.get(mock_session, "https://uxcam.com/start")

    assert len(recorded_requests) == 4
    for req in recorded_requests:
        url = req["url"]
        headers = req["headers"]
        assert scope.is_url_in_scope(url) is True
        assert "X-User-Id" in headers, f"Missing X-User-Id on {url}"
        assert headers["X-User-Id"] == researcher_id, f"Invalid X-User-Id value on {url}"
