"""
Tests for NightCrawler Scope Enforcement
Validates authorized domains, subdomains, out-of-scope targets, lookalikes,
exclusions, redirects, and URL boundary checks.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.scope import ScopeManager
from src.core.http_client import NightCrawlerHttpClient
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager


@pytest.fixture
def uxcam_scope():
    return ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com", "uxc.am", "*.uxc.am"],
        excluded_domains=["tara.uxcam.com", "connect.uxcam.com"],
        enabled=True
    )


def test_authorized_apex_domains(uxcam_scope):
    """Verify apex domains are strictly allowed."""
    assert uxcam_scope.is_host_allowed("uxcam.com") is True
    assert uxcam_scope.is_host_allowed("uxc.am") is True
    assert uxcam_scope.is_url_in_scope("https://uxcam.com") is True
    assert uxcam_scope.is_url_in_scope("https://uxc.am/login") is True


def test_authorized_subdomains(uxcam_scope):
    """Verify proper subdomains are allowed."""
    assert uxcam_scope.is_host_allowed("app.uxcam.com") is True
    assert uxcam_scope.is_host_allowed("api.uxcam.com") is True
    assert uxcam_scope.is_host_allowed("openvpn-test.uxc.am") is True
    assert uxcam_scope.is_host_allowed("v2.api.uxcam.com") is True
    assert uxcam_scope.is_url_in_scope("https://app.uxcam.com/dashboard/app.js") is True


def test_out_of_scope_domains(uxcam_scope):
    """Verify unrelated third-party domains are rejected."""
    assert uxcam_scope.is_host_allowed("google.com") is False
    assert uxcam_scope.is_host_allowed("github.com") is False
    assert uxcam_scope.is_host_allowed("example.org") is False
    assert uxcam_scope.is_url_in_scope("https://google.com/search") is False


def test_lookalike_and_boundary_bypass_rejection(uxcam_scope):
    """Verify suffix boundary checks prevent lookalike and substring domain attacks."""
    # Prefix lookalikes
    assert uxcam_scope.is_host_allowed("eviluxcam.com") is False
    assert uxcam_scope.is_host_allowed("notuxcam.com") is False
    assert uxcam_scope.is_host_allowed("fake-uxc.am") is False
    
    # Suffix hijack (domain as subdomain of attacker)
    assert uxcam_scope.is_host_allowed("uxcam.com.attacker.com") is False
    assert uxcam_scope.is_host_allowed("app.uxcam.com.attacker.com") is False
    assert uxcam_scope.is_host_allowed("uxc.am.evil.net") is False

    # URL form lookalikes
    assert uxcam_scope.is_url_in_scope("https://eviluxcam.com/exploit.js") is False
    assert uxcam_scope.is_url_in_scope("https://uxcam.com.attacker.com/steal") is False
    assert uxcam_scope.is_url_in_scope("https://fake-uxc.am/api") is False


def test_explicit_exclusions(uxcam_scope):
    """Verify explicitly excluded domains and their subdomains are rejected."""
    # Direct excluded hosts
    assert uxcam_scope.is_host_allowed("tara.uxcam.com") is False
    assert uxcam_scope.is_host_allowed("connect.uxcam.com") is False
    
    # Subdomains of excluded hosts
    assert uxcam_scope.is_host_allowed("api.tara.uxcam.com") is False
    assert uxcam_scope.is_host_allowed("staging.connect.uxcam.com") is False

    # URLs
    assert uxcam_scope.is_url_in_scope("https://tara.uxcam.com/index.html") is False
    assert uxcam_scope.is_url_in_scope("https://connect.uxcam.com/app.js") is False
    assert uxcam_scope.is_url_in_scope("https://dev.connect.uxcam.com/v1") is False


def test_misleading_url_parsing(uxcam_scope):
    """Verify that userinfo, path, fragment, or port cannot trick the scope parser."""
    # Path trick: attacker.com/uxcam.com
    assert uxcam_scope.is_url_in_scope("https://attacker.com/uxcam.com") is False
    
    # Fragment trick: attacker.com#uxcam.com
    assert uxcam_scope.is_url_in_scope("https://attacker.com#uxcam.com") is False
    
    # Query trick: attacker.com?domain=uxcam.com
    assert uxcam_scope.is_url_in_scope("https://attacker.com?domain=uxcam.com") is False

    # Userinfo trick: uxcam.com@attacker.com
    assert uxcam_scope.is_url_in_scope("https://uxcam.com@attacker.com/") is False

    # Valid in-scope host with credentials or port
    assert uxcam_scope.is_url_in_scope("https://user:pass@app.uxcam.com:8443/api") is True


def test_filter_subdomains_and_urls(uxcam_scope):
    """Verify batch filtering filters out non-compliant hosts and links."""
    candidates = [
        "app.uxcam.com",
        "eviluxcam.com",
        "tara.uxcam.com",
        "api.uxc.am",
        "uxcam.com.attacker.com",
        "connect.uxcam.com"
    ]
    filtered = uxcam_scope.filter_subdomains(candidates)
    assert "app.uxcam.com" in filtered
    assert "api.uxc.am" in filtered
    assert "eviluxcam.com" not in filtered
    assert "tara.uxcam.com" not in filtered
    assert "connect.uxcam.com" not in filtered
    assert "uxcam.com.attacker.com" not in filtered

    url_candidates = [
        "https://app.uxcam.com/bundle.js",
        "https://eviluxcam.com/bundle.js",
        "https://tara.uxcam.com/secret.js",
        "https://openvpn-test.uxc.am/config"
    ]
    filtered_urls = uxcam_scope.filter_urls(url_candidates)
    assert "https://app.uxcam.com/bundle.js" in filtered_urls
    assert "https://openvpn-test.uxc.am/config" in filtered_urls
    assert "https://eviluxcam.com/bundle.js" not in filtered_urls
    assert "https://tara.uxcam.com/secret.js" not in filtered_urls


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_is_blocked(uxcam_scope):
    """Verify HTTP client blocks following a redirect to an out-of-scope domain."""
    rate_limiter = GlobalRateLimiter(max_requests_per_second=100.0)
    header_manager = HeaderManager(enabled=False)
    client = NightCrawlerHttpClient(uxcam_scope, rate_limiter, header_manager)

    # Mock response returning 302 redirect to evil.com
    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://evil.com/phish"}

    # Mock async context manager for session.get
    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    status, content, final_url = await client.get(mock_session, "https://app.uxcam.com/redirect")
    
    # The redirect was intercepted and blocked because evil.com is out-of-scope
    assert status == 302
    assert content is None
    assert final_url == "https://app.uxcam.com/redirect"
    # Session.get should have been called only once for the in-scope URL, not for evil.com
    assert mock_session.get.call_count == 1


def test_exact_vs_wildcard_domain_separation():
    """Verify exact host and wildcard entries are stored and validated separately."""
    # Apex only: matches example.com, but NOT subdomains
    apex_scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    assert apex_scope.is_host_allowed("example.com") is True
    assert apex_scope.is_host_allowed("sub.example.com") is False
    assert apex_scope.is_host_allowed("evil-example.com") is False

    # Wildcard only: matches subdomains, but NOT apex example.com
    wild_scope = ScopeManager(allowed_domains=["*.example.com"], enabled=True)
    assert wild_scope.is_host_allowed("sub.example.com") is True
    assert wild_scope.is_host_allowed("a.b.example.com") is True
    assert wild_scope.is_host_allowed("example.com") is False
    assert wild_scope.is_host_allowed("evil-example.com") is False

    # Both apex and wildcard: matches both apex and subdomains
    full_scope = ScopeManager(allowed_domains=["example.com", "*.example.com"], enabled=True)
    assert full_scope.is_host_allowed("example.com") is True
    assert full_scope.is_host_allowed("sub.example.com") is True
    assert full_scope.is_host_allowed("api.corp.example.com") is True
    assert full_scope.is_host_allowed("evil-example.com") is False

