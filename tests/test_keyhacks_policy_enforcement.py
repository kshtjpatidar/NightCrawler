"""
Tests for NightCrawler KeyHacks Policy Enforcement & Transport Security Audit
Verifies complete elimination of policy bypasses, fail-closed dependency enforcement,
centralized transport routing, scope, DNS pinning, shared concurrency, rate limiting,
authentication protection, and backwards compatibility.
"""

import asyncio
import inspect
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.core.audit_logger import AuditLogger
from src.core.header_manager import HeaderManager
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.core.request_policy import RequestPolicyManager
from src.core.scanner import NightCrawlerScanner
from src.core.scope import ScopeManager
from src.validators.keyhacks import (
    KEYHACKS_VALIDATORS,
    KeyHacksPolicyError,
    KeyHacksValidator,
    ValidationResult,
    ValidationStatus,
    ValidationSideEffect,
    validate_key,
)


class MockAsyncContext:
    """Helper context manager for mocking aiohttp response context managers."""
    def __init__(self, resp=None, exc=None):
        self.resp = resp
        self.exc = exc

    async def __aenter__(self):
        if self.exc:
            raise self.exc
        return self.resp

    async def __aexit__(self, exc_type, exc, tb):
        pass


# ============================================================================
# Category 1: Missing Dependency Tests (1 - 6)
# ============================================================================

@pytest.mark.asyncio
async def test_missing_scope_manager_blocks_http_validation():
    """Verify that a missing ScopeManager fails closed before transport execution."""
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=None, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=None, request_policy_manager=rpm, http_client=client)

    with pytest.raises(KeyHacksPolicyError) as exc_info:
        validator.validate_policy_dependencies()
    assert "scopemanager is missing" in str(exc_info.value).lower()

    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}
    with patch("aiohttp.ClientSession.get") as mock_get:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_missing_request_policy_manager_blocks_http_validation():
    """Verify that a missing RequestPolicyManager fails closed before transport execution."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=None)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=None, http_client=client)

    with pytest.raises(KeyHacksPolicyError) as exc_info:
        validator.validate_policy_dependencies()
    assert "requestpolicymanager is missing" in str(exc_info.value).lower()

    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}
    with patch("aiohttp.ClientSession.get") as mock_get:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_missing_policy_transport_blocks_http_validation():
    """Verify that a missing NightCrawlerHttpClient fails closed before transport execution."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=None)

    with pytest.raises(KeyHacksPolicyError) as exc_info:
        validator.validate_policy_dependencies()
    assert "httpclient is missing" in str(exc_info.value).lower()

    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}
    with patch("aiohttp.ClientSession.get") as mock_get:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_missing_dns_resolver_blocks_http_validation():
    """Verify that missing PolicyAwareResolver fails closed before transport execution."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client.get_resolver = MagicMock(return_value=None)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with pytest.raises(KeyHacksPolicyError) as exc_info:
        validator.validate_policy_dependencies()
    assert "dns resolver is missing" in str(exc_info.value).lower()

    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}
    with patch("aiohttp.ClientSession.get") as mock_get:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_missing_rate_limiter_blocks_http_validation():
    """Verify that a missing shared rate limiter fails closed before transport execution."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    rpm.global_limiter = None
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with pytest.raises(KeyHacksPolicyError) as exc_info:
        validator.validate_policy_dependencies()
    assert "ratelimiter is missing" in str(exc_info.value).lower()

    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}
    with patch("aiohttp.ClientSession.get") as mock_get:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_incomplete_policy_never_creates_fallback_session():
    """Verify that incomplete policy dependencies never create an unrestricted fallback session."""
    validator = KeyHacksValidator()
    cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/api?key={key}", "success_indicators": ["ok"]}

    with patch("aiohttp.ClientSession.__init__", return_value=None) as mock_init:
        with pytest.raises(KeyHacksPolicyError):
            await validator.validate_http(cfg, "secret123")
        mock_init.assert_not_called()

        res = await validator.validate_secret("Google API Key", "AIzaSyFakeKey123")
        assert res.status == ValidationStatus.ERROR
        assert "policy dependency missing" in res.message.lower()
        mock_init.assert_not_called()


# ============================================================================
# Category 2: Scope Tests (7 - 11)
# ============================================================================

@pytest.mark.asyncio
async def test_out_of_scope_initial_url_never_reaches_transport():
    """Verify out-of-scope initial validation URLs are blocked before any network activity."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    cfg = {
        "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
        "method": "GET",
        "url": "https://unauthorized-external-domain.com/check?key={key}",
        "success_indicators": ["ok"]
    }
    with patch.object(client, "request") as mock_req:
        res = await validator.validate_http(cfg, "test_secret_123")
        assert res.status == ValidationStatus.ERROR
        assert "out of scope" in res.message.lower()
        mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_out_of_scope_redirect_is_rejected():
    """Verify redirect destinations escaping the authorized scope are rejected."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    cfg = {
        "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
        "method": "GET",
        "url": "https://example.com/check?key={key}",
        "success_indicators": ["valid"]
    }

    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://attacker.org/exfil"}
    cm = MockAsyncContext(mock_resp)

    with patch("aiohttp.ClientSession.get", return_value=cm):
        res = await validator.validate_http(cfg, "test_key")
        assert res.status == ValidationStatus.ERROR
        assert "redirect" in res.message.lower() or "blocked" in res.message.lower()


@pytest.mark.asyncio
async def test_cross_origin_redirect_does_not_leak_auth_headers():
    """Verify sensitive authorization headers are stripped when following a cross-origin redirect."""
    scope = ScopeManager(allowed_domains=["example.com", "partner.org"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    client._pinned_ips["partner.org"] = ["93.184.216.35"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    captured_headers = []
    step = 0

    def mock_get(url, headers=None, **kwargs):
        nonlocal step
        captured_headers.append((url, dict(headers or {})))
        mock_resp = MagicMock()
        if step == 0:
            step += 1
            mock_resp.status = 302
            mock_resp.headers = {"Location": "https://partner.org/api"}
            mock_resp.text = AsyncMock(return_value="")
        else:
            mock_resp.status = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(mock_resp)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {
            "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
            "method": "GET",
            "url": "https://example.com/init",
            "headers": {
                "Authorization": "Bearer super-secret-token",
                "X-Api-Key": "api-key-12345",
                "X-Custom-Public": "public-info"
            },
            "success_indicators": ["valid"]
        }
        res = await validator.validate_http(cfg, "key123")
        assert res.status == ValidationStatus.VALID

    assert len(captured_headers) == 2
    init_url, init_h = captured_headers[0]
    redir_url, redir_h = captured_headers[1]
    assert "Authorization" in init_h or "authorization" in init_h
    # Cross origin redirect must NOT contain sensitive auth
    assert "Authorization" not in redir_h
    assert "authorization" not in redir_h
    assert "X-Api-Key" not in redir_h
    assert "x-api-key" not in redir_h


@pytest.mark.asyncio
async def test_https_to_http_downgrade_is_rejected_when_policy_disallows():
    """Verify HTTPS-to-HTTP downgrade redirects are rejected in strict mode."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0, strict_scope=True, verify_tls=True)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, strict_mode=True, verify_tls=True)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "http://example.com/insecure"}
    cm = MockAsyncContext(mock_resp)

    with patch("aiohttp.ClientSession.get", return_value=cm):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
        res = await validator.validate_http(cfg, "secret")
        assert res.status == ValidationStatus.ERROR
        assert "redirect" in res.message.lower() or "blocked" in res.message.lower()


@pytest.mark.asyncio
async def test_redirect_loop_is_bounded():
    """Verify redirect loops are bounded by max_redirects and do not loop indefinitely."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, max_redirects=3)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    loop_count = 0

    def mock_get(url, **kwargs):
        nonlocal loop_count
        loop_count += 1
        mock_resp = MagicMock()
        mock_resp.status = 302
        target = "https://example.com/loop2" if "loop1" in url else "https://example.com/loop1"
        mock_resp.headers = {"Location": target}
        mock_resp.text = AsyncMock(return_value="")
        return MockAsyncContext(mock_resp)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/loop1", "success_indicators": ["ok"]}
        res = await validator.validate_http(cfg, "secret")
        assert res.status == ValidationStatus.ERROR
        assert loop_count <= 4


# ============================================================================
# Category 3: DNS Tests (12 - 17)
# ============================================================================

@pytest.mark.asyncio
async def test_keyhacks_uses_policy_aware_dns_resolver():
    """Verify that KeyHacks HTTP transport creates TCPConnectors using PolicyAwareResolver."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    resolver = client.get_resolver()
    assert isinstance(resolver, PolicyAwareResolver)

    with patch("aiohttp.TCPConnector") as mock_conn:
        with patch("aiohttp.ClientSession"):
            with patch.object(client, "request", return_value=(200, '{"valid": true}', "https://example.com/check")):
                cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
                await validator.validate_http(cfg, "key123")
                mock_conn.assert_called_once()
                kwargs = mock_conn.call_args[1]
                assert isinstance(kwargs["resolver"], PolicyAwareResolver)
                assert kwargs["resolver"].http_client == client


@pytest.mark.asyncio
async def test_keyhacks_rejects_loopback_resolution():
    """Verify destinations resolving to loopback addresses are blocked."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with patch.object(client, "validate_host_network_safety", return_value=(False, "Prohibited loopback/private IP: 127.0.0.1")):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
        res = await validator.validate_http(cfg, "key123")
        assert res.status == ValidationStatus.ERROR
        assert "blocked" in res.message.lower() or "error" in res.message.lower()


@pytest.mark.asyncio
async def test_keyhacks_rejects_private_ip_resolution():
    """Verify destinations resolving to RFC 1918 private IP ranges are blocked."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    for private_ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
        with patch.object(client, "validate_host_network_safety", return_value=(False, f"Prohibited private IP: {private_ip}")):
            cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
            res = await validator.validate_http(cfg, "key123")
            assert res.status == ValidationStatus.ERROR


@pytest.mark.asyncio
async def test_keyhacks_rejects_cloud_metadata_resolution():
    """Verify destinations resolving to cloud metadata IP (169.254.169.254) are blocked."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with patch.object(client, "validate_host_network_safety", return_value=(False, "Prohibited IP 169.254.169.254")):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
        res = await validator.validate_http(cfg, "key123")
        assert res.status == ValidationStatus.ERROR


@pytest.mark.asyncio
async def test_keyhacks_dns_rebinding_is_blocked():
    """Verify that DNS pinning prevents DNS rebinding between validation and connection."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    resolver = client.get_resolver()

    client._pinned_ips["example.com"] = ["93.184.216.34"]

    # Rebinding attempt returns 127.0.0.1
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
        resolved = await resolver.resolve("example.com", 443)
        for entry in resolved:
            assert entry["host"] == "93.184.216.34", "Must return pinned authorized IP, rejecting rebound IP"


@pytest.mark.asyncio
async def test_keyhacks_dns_failure_fails_closed():
    """Verify that DNS resolution failure fails closed."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
        res = await validator.validate_http(cfg, "key123")
        assert res.status == ValidationStatus.ERROR


# ============================================================================
# Category 4: Concurrency Tests (18 - 22)
# ============================================================================

@pytest.mark.asyncio
async def test_keyhacks_uses_shared_concurrency_semaphore():
    """Verify KeyHacks requests acquire the shared RequestPolicyManager semaphore."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sem = rpm.get_semaphore()
    assert sem._value == 2

    acquired_during_execution = False

    async def spy_do(*args, **kwargs):
        nonlocal acquired_during_execution
        if sem._value < 2:
            acquired_during_execution = True
        return ValidationResult(status=ValidationStatus.VALID, message="OK")

    with patch.object(validator, "_do_validate_http", side_effect=spy_do):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
        await validator.validate_http(cfg, "key")

    assert acquired_during_execution is True
    assert sem._value == 2


@pytest.mark.asyncio
async def test_keyhacks_direct_invocation_cannot_bypass_semaphore():
    """Verify direct calls to validate_http acquire the shared semaphore."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sem = rpm.get_semaphore()
    observed_values = []

    async def spy_request(*args, **kwargs):
        observed_values.append(sem._value)
        return (200, '{"valid": true}', "https://example.com/check")

    with patch.object(client, "request", side_effect=spy_request):
        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession"):
                cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
                await validator.validate_http(cfg, "key")

    assert observed_values == [0], "Semaphore must have been acquired during request execution"
    assert sem._value == 1


@pytest.mark.asyncio
async def test_keyhacks_concurrency_never_exceeds_profile_ceiling():
    """Verify multiple concurrent KeyHacks requests strictly obey the concurrency ceiling."""
    ceiling = 2
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=ceiling, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    active_requests = 0
    max_active = 0

    async def mock_request(*args, **kwargs):
        nonlocal active_requests, max_active
        active_requests += 1
        if active_requests > max_active:
            max_active = active_requests
        await asyncio.sleep(0.04)
        active_requests -= 1
        return (200, '{"valid": true}', "https://example.com/check")

    with patch.object(client, "request", side_effect=mock_request):
        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession"):
                cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
                tasks = [validator.validate_http(cfg, f"key_{i}") for i in range(6)]
                await asyncio.gather(*tasks)

    assert max_active <= ceiling, f"Max active {max_active} exceeded ceiling {ceiling}"


@pytest.mark.asyncio
async def test_keyhacks_exception_releases_semaphore():
    """Verify that exceptions inside request execution properly release the semaphore slot."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sem = rpm.get_semaphore()
    assert sem._value == 2

    with patch.object(client, "request", side_effect=RuntimeError("Socket error")):
        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession"):
                cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
                res = await validator.validate_http(cfg, "key")
                assert res.status == ValidationStatus.ERROR

    assert sem._value == 2, "Semaphore slot must be released after exception"


@pytest.mark.asyncio
async def test_keyhacks_cancellation_releases_semaphore():
    """Verify that cancellation of an in-flight request properly releases the semaphore slot."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sem = rpm.get_semaphore()
    started = asyncio.Event()

    async def mock_hang(*args, **kwargs):
        started.set()
        await asyncio.sleep(10.0)
        return (200, "OK", "https://example.com/check")

    with patch.object(client, "request", side_effect=mock_hang):
        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession"):
                cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["ok"]}
                task = asyncio.create_task(validator.validate_http(cfg, "key"))
                await started.wait()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    assert sem._value == 2, "Semaphore slot must be released on cancellation"


# ============================================================================
# Category 5: Rate-Limit Tests (23 - 26)
# ============================================================================

@pytest.mark.asyncio
async def test_keyhacks_uses_shared_global_rate_limiter():
    """Verify KeyHacks requests consume tokens from the shared GlobalRateLimiter."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = AsyncMock(return_value='{"valid": true}')
    cm = MockAsyncContext(mock_resp)

    with patch.object(rpm.global_limiter, "acquire", AsyncMock()) as mock_acquire:
        with patch("aiohttp.ClientSession.get", return_value=cm):
            cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
            await validator.validate_http(cfg, "key")
            assert mock_acquire.call_count >= 1


@pytest.mark.asyncio
async def test_keyhacks_uses_shared_per_host_rate_limiter():
    """Verify KeyHacks requests invoke the shared RequestPolicyManager.acquire with host."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = AsyncMock(return_value='{"valid": true}')
    cm = MockAsyncContext(mock_resp)

    with patch.object(rpm, "acquire", AsyncMock()) as mock_acquire:
        with patch("aiohttp.ClientSession.get", return_value=cm):
            cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
            await validator.validate_http(cfg, "key")
            mock_acquire.assert_called_with(host="example.com")


@pytest.mark.asyncio
async def test_keyhacks_retries_obey_rate_limits():
    """Verify every retry attempt consumes a rate-limit token."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, max_retries=2)
    client._pinned_ips["example.com"] = ["93.184.216.34"]

    acquire_count = 0
    original_acquire = rpm.acquire

    async def spy_acquire(*args, **kwargs):
        nonlocal acquire_count
        acquire_count += 1
        return await original_acquire(*args, **kwargs)

    rpm.acquire = spy_acquire

    attempt = 0

    def mock_get(url, **kwargs):
        nonlocal attempt
        attempt += 1
        if attempt <= 2:
            return MockAsyncContext(exc=aiohttp.ClientError("Temporary network reset"))
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(resp=mock_resp)

    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
        res = await validator.validate_http(cfg, "key")
        assert res.status == ValidationStatus.VALID
        assert acquire_count == 3


@pytest.mark.asyncio
async def test_keyhacks_redirects_obey_rate_limits():
    """Verify every redirect hop consumes a rate-limit token."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]

    acquire_count = 0
    original_acquire = rpm.acquire

    async def spy_acquire(*args, **kwargs):
        nonlocal acquire_count
        acquire_count += 1
        return await original_acquire(*args, **kwargs)

    rpm.acquire = spy_acquire

    step = 0

    def mock_get(url, **kwargs):
        nonlocal step
        step += 1
        mock_resp = MagicMock()
        if step == 1:
            mock_resp.status = 302
            mock_resp.headers = {"Location": "https://example.com/dest"}
            mock_resp.text = AsyncMock(return_value="")
        else:
            mock_resp.status = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(resp=mock_resp)

    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
        res = await validator.validate_http(cfg, "key")
        assert res.status == ValidationStatus.VALID
        assert acquire_count == 2


# ============================================================================
# Category 6: Authentication Tests (27 - 30)
# ============================================================================

@pytest.mark.asyncio
async def test_keyhacks_preserves_required_program_headers():
    """Verify required program identification headers are attached to in-scope requests."""
    hm = HeaderManager(enabled=True, header_name="X-Bug-Bounty-Researcher", header_value="researcher_123")
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, header_manager=hm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sent_headers = {}

    def mock_get(url, headers=None, **kwargs):
        nonlocal sent_headers
        sent_headers = dict(headers or {})
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(resp=mock_resp)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {"type": "http", "side_effect": ValidationSideEffect.READ_ONLY, "method": "GET", "url": "https://example.com/check", "success_indicators": ["valid"]}
        await validator.validate_http(cfg, "key")

    assert sent_headers.get("X-Bug-Bounty-Researcher") == "researcher_123"


@pytest.mark.asyncio
async def test_keyhacks_does_not_leak_auth_across_origins():
    """Verify cross-origin redirect strips sensitive Authorization headers."""
    scope = ScopeManager(allowed_domains=["example.com", "other-allowed.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    client._pinned_ips["other-allowed.com"] = ["93.184.216.35"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    second_headers = None
    step = 0

    def mock_get(url, headers=None, **kwargs):
        nonlocal step, second_headers
        step += 1
        mock_resp = MagicMock()
        if step == 1:
            mock_resp.status = 302
            mock_resp.headers = {"Location": "https://other-allowed.com/verify"}
            mock_resp.text = AsyncMock(return_value="")
        else:
            second_headers = dict(headers or {})
            mock_resp.status = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(resp=mock_resp)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {
            "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
            "method": "GET",
            "url": "https://example.com/check",
            "headers": {"Authorization": "Bearer secret_api_token"},
            "success_indicators": ["valid"]
        }
        await validator.validate_http(cfg, "key")

    assert second_headers is not None
    assert "Authorization" not in second_headers
    assert "authorization" not in second_headers


@pytest.mark.asyncio
async def test_keyhacks_mandatory_headers_cannot_be_overridden():
    """Verify user or validator headers cannot override mandatory program policy headers."""
    hm = HeaderManager(enabled=True, header_name="X-Researcher", header_value="authentic_val")
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, header_manager=hm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    sent_headers = {}

    def mock_get(url, headers=None, **kwargs):
        nonlocal sent_headers
        sent_headers = dict(headers or {})
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.text = AsyncMock(return_value='{"valid": true}')
        return MockAsyncContext(resp=mock_resp)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        cfg = {
            "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
            "method": "GET",
            "url": "https://example.com/check",
            "headers": {"X-Researcher": "spoofed_val"},
            "success_indicators": ["valid"]
        }
        await validator.validate_http(cfg, "key")

    assert sent_headers["X-Researcher"] == "authentic_val"


@pytest.mark.asyncio
async def test_keyhacks_does_not_log_credentials(caplog):
    """Verify sensitive keys and secrets in headers or body are never logged in plaintext."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=50.0)
    audit_logger = MagicMock()
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, audit_logger=audit_logger)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    secret_str = "SUPER_SECRET_TOKEN_DO_NOT_LEAK_999"

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = AsyncMock(return_value='{"valid": true}')
    cm = MockAsyncContext(mock_resp)

    with patch("aiohttp.ClientSession.get", return_value=cm):
        cfg = {
            "type": "http", "side_effect": ValidationSideEffect.READ_ONLY,
            "method": "GET",
            "url": "https://example.com/check",
            "headers": {"Authorization": "Bearer {key}"},
            "success_indicators": ["valid"]
        }
        await validator.validate_http(cfg, secret_str)

    for record in caplog.records:
        assert secret_str not in record.message
    for call in audit_logger.log_event.call_args_list:
        kwargs = call[1]
        for v in kwargs.values():
            assert secret_str not in str(v)


# ============================================================================
# Category 7: Compatibility Tests (31 - 34)
# ============================================================================

@pytest.mark.asyncio
async def test_passive_keyhacks_operations_work_without_http_policy():
    """Verify offline/passive validation operations succeed without HTTP policy dependencies."""
    validator = KeyHacksValidator()

    spec = validator.get_validator("AWS Access Key")
    assert spec is not None
    assert spec["type"] == "command"

    res = await validator.validate_secret(
        "AWS Access Key",
        "AKIAIOSFODNN7EXAMPLE",
        extra_params={"secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
    )
    assert res.status == ValidationStatus.UNKNOWN
    assert "manual command" in res.message.lower()


def test_existing_keyhacks_validators_remain_compatible():
    """Verify all 50+ definitions in KEYHACKS_VALIDATORS have required structural keys."""
    assert len(KEYHACKS_VALIDATORS) >= 30
    for name, v in KEYHACKS_VALIDATORS.items():
        assert "type" in v
        assert v["type"] in ("http", "command")
        if v["type"] == "http":
            assert "url" in v
            has_placeholder = (
                ("{" in v["url"] and "}" in v["url"]) or
                ("auth_user" in v and "{" in v["auth_user"] and "}" in v["auth_user"]) or
                ("auth_pass" in v and "{" in v["auth_pass"] and "}" in v["auth_pass"]) or
                ("headers" in v and any("{" in str(val) for val in v["headers"].values())) or
                ("body" in v and "{" in v["body"]) or
                ("data" in v and any("{" in str(val) for val in v["data"].values()))
            )
            assert has_placeholder, f"Validator '{name}' has no placeholder"
        elif v["type"] == "command":
            assert "command" in v
            assert "{" in v["command"] and "}" in v["command"]


def test_scanner_passes_all_required_policy_dependencies():
    """Verify NightCrawlerScanner initializes and wires KeyHacksValidator with all policy dependencies."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=5.0)
    scanner = NightCrawlerScanner(
        concurrency=2,
        scope_manager=scope,
        request_policy_manager=rpm,
        max_requests_per_second=5.0,
        verify_tls=True,
        strict_scope=True
    )
    assert hasattr(scanner, "keyhacks_validator")
    assert scanner.keyhacks_validator is not None
    scanner.keyhacks_validator.validate_policy_dependencies()


def test_no_unrestricted_aiohttp_session_remains():
    """AST audit: prove zero raw aiohttp.ClientSession() instances exist in keyhacks.py without connector."""
    from src.validators import keyhacks
    source = inspect.getsource(keyhacks)

    import ast
    tree = ast.parse(source)
    session_count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            is_client_session = False
            if isinstance(func, ast.Attribute) and func.attr == "ClientSession":
                is_client_session = True
            elif isinstance(func, ast.Name) and func.id == "ClientSession":
                is_client_session = True

            if is_client_session:
                session_count += 1
                keyword_names = [kw.arg for kw in node.keywords]
                assert "connector" in keyword_names, (
                    "Found unrestricted aiohttp.ClientSession() in keyhacks.py without policy connector!"
                )
    assert session_count >= 1, "At least one policy-restricted session must exist in keyhacks.py"
