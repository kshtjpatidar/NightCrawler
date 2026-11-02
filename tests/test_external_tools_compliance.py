"""
Tests for NightCrawler External Tool Compliance
Validates that in strict compliance mode, tools that cannot guarantee the global 5 RPS
rate limit or header isolation are safely disabled, and passive tools enforce strict scope.
"""

import pytest
from unittest.mock import patch, MagicMock

from src.core.scope import ScopeManager
from src.core.header_manager import HeaderManager
from src.integrations.tools import (
    KatanaIntegration, HakrawlerIntegration, SubJSIntegration,
    GetJSIntegration, SubfinderIntegration, GauIntegration, JSLuiceIntegration
)


def test_uncoordinated_tools_disabled_in_strict_compliance_mode():
    """
    Verify that tools which send active HTTP requests but cannot coordinate
    with the centralized 5 RPS rate limiter are disabled in strict mode.
    """
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"])
    hm = HeaderManager(enabled=True, header_name="X-User-Id", header_value="test@example.com")

    # Katana operates as an independent OS process and cannot guarantee shared 5 RPS rate limit
    katana = KatanaIntegration(scope_manager=scope, header_manager=hm, strict_mode=True)
    with patch.object(katana, "is_available", return_value=True):
        assert katana.crawl(["https://app.uxcam.com"]) == []

    # Hakrawler
    hakrawler = HakrawlerIntegration(scope_manager=scope, strict_mode=True)
    with patch.object(hakrawler, "is_available", return_value=True):
        assert hakrawler.crawl(["https://app.uxcam.com"]) == []

    # SubJS
    subjs = SubJSIntegration(scope_manager=scope, strict_mode=True)
    with patch.object(subjs, "is_available", return_value=True):
        assert subjs.fetch(["https://app.uxcam.com"]) == []

    # GetJS
    getjs = GetJSIntegration(scope_manager=scope, strict_mode=True)
    with patch.object(getjs, "is_available", return_value=True):
        assert getjs.extract(["https://app.uxcam.com"]) == []


def test_passive_subfinder_filters_all_outputs_to_scope():
    """Verify passive DNS tool Subfinder strictly filters subdomains to allowed scope."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com"],
        excluded_domains=["tara.uxcam.com"]
    )
    subfinder = SubfinderIntegration(scope_manager=scope)

    # Mock raw subfinder returning a mix of allowed, lookalike, and excluded subdomains
    mock_raw_output = (
        "app.uxcam.com\n"
        "api.uxcam.com\n"
        "eviluxcam.com\n"
        "uxcam.com.attacker.com\n"
        "tara.uxcam.com\n"
        "sub.tara.uxcam.com\n"
        "connect.google.com\n"
    )

    with patch.object(subfinder, "is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_raw_output)
            results = subfinder.enumerate("uxcam.com")

    # Must only contain in-scope subdomains
    assert "app.uxcam.com" in results
    assert "api.uxcam.com" in results
    assert "eviluxcam.com" not in results
    assert "uxcam.com.attacker.com" not in results
    assert "tara.uxcam.com" not in results
    assert "sub.tara.uxcam.com" not in results
    assert "connect.google.com" not in results


def test_archive_tools_filter_all_scraped_urls():
    """Verify GAU output from public web archives is strictly filtered to authorized scope."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com"],
        excluded_domains=["connect.uxcam.com"]
    )
    gau = GauIntegration(scope_manager=scope)

    mock_archive_output = (
        "https://app.uxcam.com/static/bundle.js\n"
        "https://eviluxcam.com/malicious.js\n"
        "https://connect.uxcam.com/secret.js\n"
        "https://thirdparty-cdn.com/lib.js\n"
    )

    with patch.object(gau, "is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_archive_output)
            results = gau.fetch(["uxcam.com"])

    assert "https://app.uxcam.com/static/bundle.js" in results
    assert "https://eviluxcam.com/malicious.js" not in results
    assert "https://connect.uxcam.com/secret.js" not in results
    assert "https://thirdparty-cdn.com/lib.js" not in results


def test_jsluice_offline_ast_scope_filtering():
    """Verify JSLuice offline parser output is filtered strictly to in-scope URLs."""
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"])
    jsluice = JSLuiceIntegration(scope_manager=scope)

    mock_extracted_urls = (
        "https://api.uxcam.com/v1/auth\n"
        "https://attacker-webhook.com/collector\n"
        "https://eviluxcam.com/stolen\n"
    )

    with patch.object(jsluice, "is_available", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_extracted_urls)
            results = jsluice.extract_urls("const a = 1;")

    assert "https://api.uxcam.com/v1/auth" in results
    assert "https://attacker-webhook.com/collector" not in results
    assert "https://eviluxcam.com/stolen" not in results
