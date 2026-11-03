"""
NightCrawler - KeyHacks Security Hardening & Isolation Regression Suite
Validates:
1. TLS certificate verification enforcement by default and fail-closed behavior.
2. Complete credential, token, and webhook redaction across commands, logs, and reports.
3. Strict dependency instance identity enforcement against EffectivePolicy.
4. Side-effect classification and disablement of state-changing operations by default.
5. External provider authorization enforcement without automatic scope expansion.
"""

import ssl
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import aiohttp
import pytest

from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.core.audit_logger import AuditLogger
from src.core.effective_policy import EffectivePolicy
from src.core.request_config import NightCrawlerConfig
from src.output.report_manager import ReportManager
from src.validators.keyhacks import (
    KeyHacksValidator,
    KeyHacksPolicyError,
    ValidationStatus,
    ValidationSideEffect,
    KEYHACKS_VALIDATORS
)


class MockAsyncContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


# ============================================================================
# 1. TLS Certificate Verification Enforcement
# ============================================================================

def test_tls_verification_enabled_by_default():
    """Verify TLS certificate verification is strictly enabled by default across all components."""
    validator = KeyHacksValidator()
    assert validator.verify_ssl is True

    client = NightCrawlerHttpClient()
    assert client.verify_tls is True
    assert client.ssl_context is not False
    assert isinstance(client.ssl_context, ssl.SSLContext)

    policy = EffectivePolicy.build()
    assert policy.verify_tls is True

    val_from_policy = KeyHacksValidator.from_policy(policy)
    assert val_from_policy.verify_ssl is True


@pytest.mark.asyncio
async def test_invalid_tls_certificate_rejected():
    """Verify connections to hosts with invalid/untrusted TLS certificates fail closed without fallback."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, verify_tls=True)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client, verify_ssl=True)

    ssl_error = aiohttp.ClientSSLError(MagicMock(), ssl.SSLCertVerificationError("certificate verify failed"))

    with patch("aiohttp.ClientSession.get", side_effect=ssl_error):
        cfg = {
            "type": "http",
            "method": "GET",
            "url": "https://example.com/api?key={key}",
            "success_indicators": ["valid"]
        }
        res = await validator.validate_http(cfg, "SYNTHETIC_TEST_TOKEN_12345")
        assert res.status == ValidationStatus.ERROR
        assert "validation error" in res.message.lower()
        # Verify TLS was never disabled in fallback
        assert validator.verify_ssl is True
        assert client.verify_tls is True


def test_missing_tls_policy_fails_securely():
    """Verify missing verify_tls values default securely to True and insecure TLS is rejected in strict mode."""
    cfg = NightCrawlerConfig()
    cfg.verify_tls = None  # Missing / unconfigured
    policy = EffectivePolicy.build(config=cfg)
    assert policy.verify_tls is True

    # Insecure TLS in strict mode must fail closed
    with pytest.raises(ValueError, match="Insecure TLS configuration is prohibited"):
        EffectivePolicy.build(cli_overrides={"verify_tls": False, "strict_scope": True})


# ============================================================================
# 2. Secret Redaction & Anti-Leakage
# ============================================================================

def test_query_string_secret_redaction():
    """Verify secrets in query strings are strictly redacted from URLs, validation commands, and logs."""
    raw_url = "https://example.com/oauth?access_token=SYNTHETIC_QUERY_TOKEN_12345&key=SYNTHETIC_QUERY_KEY_67890&safe_param=visible"
    redacted_url = AuditLogger.redact_url(raw_url)

    assert "SYNTHETIC_QUERY_TOKEN_12345" not in redacted_url
    assert "SYNTHETIC_QUERY_KEY_67890" not in redacted_url
    assert "[REDACTED]" in redacted_url
    assert "safe_param=visible" in redacted_url

    cfg = {"type": "http", "method": "GET", "url": "https://example.com/check?circle-token={key}"}
    cmd = KeyHacksValidator.build_sanitized_command(cfg, "SYNTHETIC_QUERY_TOKEN_12345")
    assert "SYNTHETIC_QUERY_TOKEN_12345" not in cmd
    assert "[REDACTED]" in cmd


def test_url_path_webhook_token_redaction():
    """Verify webhook tokens embedded in URL paths are strictly redacted."""
    slack_webhook = "https://hooks.slack.com/services/T111/B222/SYNTHETIC_SLACK_WEBHOOK_99999"
    redacted_slack = AuditLogger.redact_url(slack_webhook)
    assert "SYNTHETIC_SLACK_WEBHOOK_99999" not in redacted_slack
    assert "[REDACTED]" in redacted_slack

    discord_webhook = "https://discord.com/api/webhooks/123456789/SYNTHETIC_DISCORD_TOKEN_88888"
    redacted_discord = AuditLogger.redact_url(discord_webhook)
    assert "SYNTHETIC_DISCORD_TOKEN_88888" not in redacted_discord
    assert "[REDACTED]" in redacted_discord

    telegram_bot = "https://api.telegram.org/bot123456:SYNTHETIC_TELEGRAM_BOT_TOKEN_77777/getMe"
    redacted_telegram = AuditLogger.redact_url(telegram_bot)
    assert "SYNTHETIC_TELEGRAM_BOT_TOKEN_77777" not in redacted_telegram
    assert "[REDACTED]" in redacted_telegram


def test_header_secret_redaction():
    """Verify Authorization and custom API key headers are sanitized in commands and outputs."""
    cfg = {
        "type": "http",
        "method": "GET",
        "url": "https://example.com/api",
        "headers": {
            "Authorization": "Bearer {key}",
            "X-Api-Key": "{key}",
            "Content-Type": "application/json"
        }
    }
    secret_val = "SYNTHETIC_HEADER_SECRET_44444"
    cmd = KeyHacksValidator.build_sanitized_command(cfg, secret_val)

    assert secret_val not in cmd
    assert "Authorization: Bearer [REDACTED]" in cmd
    assert "X-Api-Key: [REDACTED]" in cmd
    assert "Content-Type: application/json" in cmd


def test_basic_auth_redaction():
    """Verify Basic Auth credentials in curl validation commands are strictly redacted."""
    cfg = {
        "type": "http",
        "method": "GET",
        "url": "https://example.com/api/v1/resource",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}"
    }
    user_secret = "SYNTHETIC_USER_KEY_11111"
    pass_secret = "SYNTHETIC_PASS_SECRET_22222"
    cmd = KeyHacksValidator.build_sanitized_command(cfg, user_secret, extra_params={"secret": pass_secret})

    assert user_secret not in cmd
    assert pass_secret not in cmd
    assert "-u '[REDACTED]:[REDACTED]'" in cmd


@pytest.mark.asyncio
async def test_exception_message_redaction():
    """Verify exception messages containing raw secret credentials are redacted before user display."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    secret_str = "SYNTHETIC_LEAKY_SECRET_55555"
    leaky_err = RuntimeError(f"Connection failed for {secret_str} at https://example.com/api?token={secret_str}")

    with patch.object(client, "request", side_effect=leaky_err):
        cfg = {"type": "http", "method": "GET", "url": "https://example.com/api?token={key}", "success_indicators": ["valid"]}
        res = await validator.validate_http(cfg, secret_str)

        assert res.status == ValidationStatus.ERROR
        assert secret_str not in res.message
        assert "[REDACTED]" in res.message
        assert secret_str not in res.validation_command


def test_report_redaction():
    """Verify ReportManager reports (JSON and Markdown) mask secrets in URLs, assets, and context."""
    secret_val = "SYNTHETIC_REPORT_SECRET_66666"
    finding = {
        "pattern_name": "Google API Key",
        "matched_value": secret_val,
        "url": f"https://example.com/script.js?key={secret_val}",
        "line_number": 10,
        "context": f"const apiKey = '{secret_val}';",
        "severity": "CRITICAL"
    }

    rm = ReportManager()
    json_report = rm.generate_json([finding], None)
    md_report = rm.generate_markdown([finding], None)

    assert secret_val not in json_report
    assert secret_val not in md_report
    # Verify masked format is used
    assert "***" in json_report
    assert "***" in md_report


# ============================================================================
# 3. Policy Dependency Identity Enforcement
# ============================================================================

def test_mismatched_scope_manager_rejected():
    """Verify substituting an alternate ScopeManager instance raises KeyHacksPolicyError."""
    policy = EffectivePolicy.build()
    validator = KeyHacksValidator.from_policy(policy)

    # Substitute an unbonded ScopeManager
    validator.scope_manager = ScopeManager(allowed_domains=["attacker.org"], enabled=True)
    with pytest.raises(KeyHacksPolicyError, match="Mismatched ScopeManager"):
        validator.validate_policy_dependencies()


def test_mismatched_request_policy_manager_rejected():
    """Verify substituting an alternate RequestPolicyManager instance raises KeyHacksPolicyError."""
    policy = EffectivePolicy.build()
    validator = KeyHacksValidator.from_policy(policy)

    validator.request_policy_manager = RequestPolicyManager(concurrency_limit=999, max_rps=999.0)
    with pytest.raises(KeyHacksPolicyError, match="Mismatched RequestPolicyManager"):
        validator.validate_policy_dependencies()


def test_mismatched_global_rate_limiter_rejected():
    """Verify substituting an alternate GlobalRateLimiter on HttpClient raises KeyHacksPolicyError."""
    policy = EffectivePolicy.build()
    validator = KeyHacksValidator.from_policy(policy)

    validator.http_client.rate_limiter = GlobalRateLimiter(max_requests_per_second=9999.0)
    with pytest.raises(KeyHacksPolicyError, match="Mismatched RateLimiter"):
        validator.validate_policy_dependencies()


@pytest.mark.asyncio
async def test_mismatched_dns_resolver_rejected():
    """Verify unbonded DNS resolver or mismatched TCPConnector resolver raises KeyHacksPolicyError."""
    policy = EffectivePolicy.build()
    validator = KeyHacksValidator.from_policy(policy)

    # 1. Unbonded resolver
    validator.http_client._resolver = MagicMock()
    with pytest.raises(KeyHacksPolicyError, match="Mismatched Resolver"):
        validator.validate_policy_dependencies()

    # Restore correct resolver
    validator.http_client._resolver = PolicyAwareResolver(validator.http_client)

    # 2. Foreign connector resolver
    other_client = NightCrawlerHttpClient()
    foreign_resolver = PolicyAwareResolver(other_client)
    connector = aiohttp.TCPConnector(resolver=foreign_resolver)

    with pytest.raises(KeyHacksPolicyError, match="Mismatched Connector Resolver"):
        validator.validate_policy_dependencies(connector=connector)


# ============================================================================
# 4. Side-Effect Classification & Controls
# ============================================================================

@pytest.mark.asyncio
async def test_side_effecting_validators_disabled_by_default():
    """Verify state-changing validators are classified and disabled by default without network calls."""
    policy = EffectivePolicy.build()
    validator = KeyHacksValidator.from_policy(policy)  # allow_state_changing is False by default

    state_changing_patterns = [
        "Firebase Key",
        "Slack Webhook",
        "Segment Write Key",
        "Anthropic API Key"
    ]

    for pattern in state_changing_patterns:
        spec = validator.get_validator(pattern)
        assert spec is not None
        assert spec.get("side_effect") == ValidationSideEffect.STATE_CHANGING

        res = await validator.validate_secret(pattern, "SYNTHETIC_SIDE_EFFECT_TOKEN_77777")
        assert res.status == ValidationStatus.UNKNOWN
        assert "disabled by default" in res.message.lower()
        assert "explicit authorization" in res.message.lower()


@pytest.mark.asyncio
async def test_explicit_authorization_required_for_state_changing_validation():
    """Verify state-changing validators execute only when explicitly authorized."""
    policy = EffectivePolicy.build()
    # Explicitly authorize state changing validation and provider
    validator = KeyHacksValidator.from_policy(
        policy,
        allow_state_changing=True,
        authorized_providers={"firebase"}
    )
    validator.http_client._pinned_ips["identitytoolkit.googleapis.com"] = ["142.250.190.42"]

    mock_resp = (200, '{"idToken": "tok_123", "refreshToken": "ref_123", "kind": "identitytoolkit#SignupNewUserResponse"}', "https://identitytoolkit.googleapis.com/v1/accounts:signUp")

    with patch.object(validator.http_client, "request", AsyncMock(return_value=mock_resp)) as mock_req:
        res = await validator.validate_secret("Firebase Key", "SYNTHETIC_FIREBASE_KEY_88888")
        assert mock_req.called
        assert res.status == ValidationStatus.VALID


# ============================================================================
# 5. External Provider Authorization & Scope Isolation
# ============================================================================

@pytest.mark.asyncio
async def test_third_party_api_destinations_rejected_without_explicit_authorization():
    """Verify third-party provider destinations are blocked when external authorization is missing."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    # authorized_providers is empty
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client, authorized_providers=set())

    with patch.object(client, "request") as mock_req:
        res = await validator.validate_secret("Stripe Live Secret Key", "sk_live_SYNTHETIC99999")
        assert res.status == ValidationStatus.ERROR
        assert "out of scope" in res.message.lower()
        assert "not authorized" in res.message.lower()
        assert not mock_req.called


@pytest.mark.asyncio
async def test_no_automatic_program_scope_expansion():
    """Verify authorizing an external provider does not contaminate or expand the target program scope."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(
        scope_manager=scope,
        request_policy_manager=rpm,
        http_client=client,
        authorized_providers={"stripe"}
    )
    validator.http_client._pinned_ips["api.stripe.com"] = ["3.220.122.138"]

    # Initial scope check
    assert list(scope.allowed_domains) == ["example.com"]
    assert not scope.is_url_in_scope("https://api.stripe.com/v1/charges")

    mock_resp = (200, '{"data": [], "object": "list", "has_more": false}', "https://api.stripe.com/v1/charges")

    with patch.object(client, "request", AsyncMock(return_value=mock_resp)):
        res = await validator.validate_secret("Stripe Live Secret Key", "sk_live_SYNTHETIC99999")
        assert res.status == ValidationStatus.VALID

    # Scope post-validation must remain strictly untouched
    assert list(scope.allowed_domains) == ["example.com"]
    assert not scope.is_url_in_scope("https://api.stripe.com/v1/charges")


# ============================================================================
# 6. Backward Compatibility for Passive Operations
# ============================================================================

def test_existing_passive_keyhacks_behavior_remains_compatible():
    """Verify passive/offline KeyHacks features continue to function without policy infrastructure."""
    validator = KeyHacksValidator()

    # Spec lookup
    spec = validator.get_validator("Stripe Live Secret Key")
    assert spec is not None
    assert spec["provider"] == "stripe"
    assert spec["side_effect"] == ValidationSideEffect.READ_ONLY

    # Unknown pattern lookup
    assert validator.get_validator("NonExistentPatternXYZ") is None

    # Disclaimer and manual verification note
    assert "ETHICAL USE WARNING" in validator.DISCLAIMER
    note = validator.get_manual_verification_note()
    assert "MANUAL VERIFICATION" in note
