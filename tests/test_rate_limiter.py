"""
Tests for NightCrawler Global Rate Limiter
Validates 5 RPS enforcement, concurrency coordination, pacing, redirects, and retries.
"""

import asyncio
import time
import pytest
from unittest.mock import MagicMock, AsyncMock

from src.core.rate_limiter import GlobalRateLimiter
from src.core.http_client import NightCrawlerHttpClient
from src.core.scope import ScopeManager
from src.core.header_manager import HeaderManager


@pytest.mark.asyncio
async def test_maximum_5_rps_under_concurrency():
    """
    Verify that across concurrent tasks, rate limiter strictly enforces 5 RPS.
    Acquiring 6 tokens at 5 RPS requires at least 1.0 second.
    """
    # 5.0 requests per second, burst=1 (strict pacing)
    limiter = GlobalRateLimiter(max_requests_per_second=5.0, burst=1)

    start_time = time.monotonic()

    # Launch 6 concurrent workers attempting to acquire immediately
    tasks = [limiter.acquire() for _ in range(6)]
    await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start_time
    # 6 requests at 5 RPS: request 1 is immediate (elapsed=0), request 2 at 0.2s,
    # request 3 at 0.4s, request 4 at 0.6s, request 5 at 0.8s, request 6 at 1.0s.
    assert elapsed >= 0.95, f"Expected elapsed >= 0.95s, but got {elapsed:.2f}s"
    assert limiter.total_requests == 6


@pytest.mark.asyncio
async def test_rate_limiter_accounts_for_redirects():
    """Verify each redirect hop consumes a token from the centralized rate limiter."""
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"], enabled=True)
    limiter = GlobalRateLimiter(max_requests_per_second=100.0)
    hm = HeaderManager(enabled=False)
    client = NightCrawlerHttpClient(scope, limiter, hm)

    # 1st response: 302 -> /step2
    resp1 = MagicMock()
    resp1.status = 302
    resp1.headers = {"Location": "https://app.uxcam.com/step2"}

    # 2nd response: 200 OK
    resp2 = MagicMock()
    resp2.status = 200
    resp2.headers = {"content-type": "text/html"}
    resp2.text = AsyncMock(return_value="<html>OK</html>")

    mock_session = MagicMock()
    # Mocking sequential context manager results
    cm1 = MagicMock()
    cm1.__aenter__ = AsyncMock(return_value=resp1)
    cm1.__aexit__ = AsyncMock(return_value=None)

    cm2 = MagicMock()
    cm2.__aenter__ = AsyncMock(return_value=resp2)
    cm2.__aexit__ = AsyncMock(return_value=None)

    mock_session.get.side_effect = [cm1, cm2]

    status, content, final_url = await client.get(mock_session, "https://app.uxcam.com/step1")

    assert status == 200
    assert final_url == "https://app.uxcam.com/step2"
    # Both initial request and the redirect hop must have acquired tokens
    assert limiter.total_requests == 2


@pytest.mark.asyncio
async def test_rate_limiter_accounts_for_retries():
    """Verify each retry attempt consumes a rate limiter token."""
    import aiohttp
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"], enabled=True)
    limiter = GlobalRateLimiter(max_requests_per_second=100.0)
    hm = HeaderManager(enabled=False)
    client = NightCrawlerHttpClient(scope, limiter, hm, max_retries=2)

    # 1st attempt: raises ClientError
    cm_fail = MagicMock()
    cm_fail.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("network glitch"))
    cm_fail.__aexit__ = AsyncMock(return_value=None)

    # 2nd attempt: succeeds
    resp_ok = MagicMock()
    resp_ok.status = 200
    resp_ok.headers = {"content-type": "application/json"}
    resp_ok.text = AsyncMock(return_value='{"status":"ok"}')
    cm_ok = MagicMock()
    cm_ok.__aenter__ = AsyncMock(return_value=resp_ok)
    cm_ok.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get.side_effect = [cm_fail, cm_ok]

    status, content, final_url = await client.get(mock_session, "https://app.uxcam.com/api/test")
    assert status == 200
    # Both the failed attempt and the retry attempt must be counted
    assert limiter.total_requests == 2
