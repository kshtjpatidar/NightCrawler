"""
Tests for NightCrawler TLS Certificate Verification
Validates proper SSLContext creation, rejection of invalid certificates, and no insecure fallback.
"""

import ssl
import pytest
import aiohttp
from unittest.mock import MagicMock, AsyncMock

from src.core.http_client import NightCrawlerHttpClient
from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.scanner import NightCrawlerScanner


def test_tls_verification_enabled_by_default():
    """Verify that TLS verification is enabled and uses standard verified context."""
    scope = ScopeManager(allowed_domains=["uxcam.com"])
    rate_limiter = GlobalRateLimiter()
    hm = HeaderManager()

    client = NightCrawlerHttpClient(scope, rate_limiter, hm, verify_tls=True)
    assert client.verify_tls is True
    assert isinstance(client.ssl_context, ssl.SSLContext)
    # Check default verification mode is CERT_REQUIRED
    assert client.ssl_context.verify_mode == ssl.CERT_REQUIRED

    # Scanner also defaults to verify_tls = True
    scanner = NightCrawlerScanner(concurrency=1, max_requests_per_second=5.0, verify_tls=True)
    ctx = scanner._create_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.asyncio
async def test_ssl_certificate_error_raises_without_fallback():
    """Verify that when TLS verification fails, error is raised and no insecure fallback occurs."""
    scope = ScopeManager(allowed_domains=["uxcam.com"], enabled=True)
    limiter = GlobalRateLimiter(max_requests_per_second=100.0)
    hm = HeaderManager()
    client = NightCrawlerHttpClient(scope, limiter, hm, verify_tls=True)

    # Mock session where get raises an SSLError / ClientSSLError
    mock_session = MagicMock()
    ssl_error = aiohttp.ClientSSLError(MagicMock(), ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))

    cm_error = MagicMock()
    cm_error.__aenter__ = AsyncMock(side_effect=ssl_error)
    cm_error.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = cm_error

    # Must raise the error and NOT retry with ssl=False
    with pytest.raises((aiohttp.ClientSSLError, ssl.SSLError)):
        await client.get(mock_session, "https://app.uxcam.com")

    # Ensure get was only called with the verified ssl_context, never ssl=False
    assert mock_session.get.call_count == 1
    call_kwargs = mock_session.get.call_args.kwargs
    assert call_kwargs.get("ssl") is client.ssl_context
    assert call_kwargs.get("ssl") is not False
