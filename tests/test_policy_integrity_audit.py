"""
NightCrawler - Adversarial Policy Integrity & Release Readiness Audit Test Suite
tests/test_policy_integrity_audit.py

Comprehensive regression tests covering:
1. Boolean parsing and policy precedence.
2. Provider authorization boundaries (lookalikes, Unicode, trailing-dots, IP/port bypasses).
3. State-changing validation controls and side-effect classifications.
4. Secret protection across HTML, JSON, Markdown reports, URLs, and commands.
5. HTTP transport and redirect integrity.
6. External tool and subprocess security (timeout, memory bounding, environment sanitization).
7. Scan lifecycle, cancellation, and cleanup.
8. Fail-closed startup behaviors.
"""

import asyncio
import os
import ssl
import subprocess
from unittest.mock import patch, MagicMock, AsyncMock
from urllib.parse import quote, quote_plus
from pathlib import Path

import pytest
import aiohttp

from src.core.program_profile import ProgramProfile, ScopeDefinition, RequestPolicyDefinition, TestingPermissionsDefinition, strict_bool
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.validators.keyhacks import KeyHacksValidator, ValidationStatus, ValidationSideEffect, KeyHacksPolicyError
from src.output.report_manager import ReportManager
from src.output.html_report import HtmlReportGenerator, ReportConfig, mask_secret
from src.integrations.tools import get_sanitized_env, run_bounded_tool, DEFAULT_TOOL_TIMEOUT, MAX_TOOL_OUTPUT_BYTES


# ==============================================================================
# 1. BOOLEAN PARSING & POLICY PRECEDENCE
# ==============================================================================

@pytest.mark.parametrize("falsy_str", ["false", "0", "no", "off", "FALSE", "No", "Off"])
def test_strict_bool_falsy_strings(falsy_str):
    """Verify string representations of false are strictly parsed as False."""
    assert strict_bool(falsy_str, "test_field") is False


@pytest.mark.parametrize("truthy_str", ["true", "1", "yes", "on", "TRUE", "Yes", "On"])
def test_strict_bool_truthy_strings(truthy_str):
    """Verify string representations of true are strictly parsed as True."""
    assert strict_bool(truthy_str, "test_field") is True


@pytest.mark.parametrize("invalid_val", ["maybe", "none", "", "2", -1, 10, [], {}, None])
def test_strict_bool_invalid_values_rejected(invalid_val):
    """Verify ambiguous, empty, or non-boolean representations fail closed."""
    with pytest.raises((ValueError, TypeError)):
        strict_bool(invalid_val, "test_field")


@pytest.mark.parametrize("falsy_input", ["false", "0", "no", False])
def test_allow_state_changing_falsy_string_does_not_enable(falsy_input):
    """Ensure 'false' string does not inadvertently enable state-changing operations via bool('false')."""
    policy = EffectivePolicy.build(cli_overrides={"allow_state_changing": falsy_input})
    assert policy.allow_state_changing is False


@pytest.mark.parametrize("falsy_input", ["false", "0", "no", False])
def test_validate_keys_falsy_string_does_not_enable(falsy_input):
    """Ensure 'false' string does not enable active key validation."""
    policy = EffectivePolicy.build(cli_overrides={"validate_keys": falsy_input})
    assert policy.validate_keys is False


def test_cannot_override_mandatory_strict_scope():
    """CLI override cannot disable strict scope when program policy requires it."""
    prof = ProgramProfile(
        id="test-strict",
        name="Strict Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        request_policy=RequestPolicyDefinition(strict_scope=True)
    )
    with pytest.raises(ValueError, match="Disabling strict scope is prohibited"):
        EffectivePolicy.build(profile=prof, cli_overrides={"strict_scope": False})

    with pytest.raises(ValueError, match="Disabling target scope is prohibited"):
        EffectivePolicy.build(profile=prof, cli_overrides={"scope_enabled": False})


def test_cli_concurrency_cannot_exceed_profile_ceiling():
    """CLI concurrency override is capped to program profile ceiling."""
    prof = ProgramProfile(
        id="test-conc",
        name="Concurrency Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        request_policy=RequestPolicyDefinition(concurrency=2)
    )
    policy = EffectivePolicy.build(profile=prof, cli_overrides={"concurrency": 10})
    assert policy.concurrency == 2


# ==============================================================================
# 2. PROVIDER AUTHORIZATION BOUNDARIES
# ==============================================================================

def test_profile_authorized_providers_enforced():
    """Profile specifies authorized providers; CLI cannot expand beyond profile allowlist."""
    prof = ProgramProfile(
        id="test-prov",
        name="Provider Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        authorized_providers=["aws", "google"]
    )
    # CLI narrowing is permitted
    narrowed_policy = EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["aws"]})
    assert narrowed_policy.authorized_providers == {"aws"}

    # CLI expansion with unauthorized provider is strictly rejected
    with pytest.raises(ValueError, match="CLI cannot expand program 'test-prov' authorized providers"):
        EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["slack", "aws"]})


@pytest.mark.parametrize("target_url, expected_auth", [
    ("https://example.com/api", True),
    ("https://sub.example.com/api", True),
    ("https://deep.sub.example.com/api", True),
    ("https://ExAmPle.COM/api", True),
    ("https://example.com./api", True),
    ("https://evil-example.com/api", False),
    ("https://example.com.attacker.test/api", False),
    ("https://attacker-example.com/api", False),
    ("https://exämple.com/api", False),
    ("http://192.168.1.1/api", False),
    ("https://127.0.0.1/api", False),
    ("https://example.com:8443/api", True),
    ("https://evil-example.com:8443/api", False),
])
def test_hostname_normalization_and_lookalike_rejection(target_url, expected_auth):
    """
    Ensure domain authorization uses strict boundaries (exact or proper subdomain),
    normalizes casing and trailing dots, decodes IDNA, and blocks lookalikes and IP spoofs.
    """
    client = NightCrawlerHttpClient(authorized_providers={"example.com"})
    assert client.is_provider_authorized("example.com", target_url) is expected_auth


def test_provider_name_boundary_matching():
    """Provider name matching ('slack') allows legitimate provider domains, blocks attacker lookalikes."""
    client = NightCrawlerHttpClient(authorized_providers={"slack"})
    assert client.is_provider_authorized("slack", "https://slack.com/api/auth.test") is True
    assert client.is_provider_authorized("slack", "https://api.slack.com/methods") is True
    assert client.is_provider_authorized("slack", "https://hooks.slack.com/services/T1/B1/X1") is True
    assert client.is_provider_authorized("slack", "https://evil-slack.com/api") is False
    assert client.is_provider_authorized("slack", "https://slack.attacker.com/api") is False
    assert client.is_provider_authorized("slack", "https://attacker.com/slack.com") is False


# ==============================================================================
# 3. STATE-CHANGING VALIDATION CONTROLS
# ==============================================================================

@pytest.mark.asyncio
async def test_state_changing_operations_disabled_by_default():
    """State-changing validators must return UNKNOWN with a sanitized reproduction command by default."""
    scope = ScopeManager(allowed_domains=["googleapis.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    cfg = {
        "type": "http",
        "method": "POST",
        "url": "https://googleapis.com/v1/write?key={key}",
        "side_effect": ValidationSideEffect.STATE_CHANGING,
        "description": "Mutating write test"
    }
    res = await validator.validate_http(cfg, "SYNTHETIC_CANARY_SECRET_11111")
    assert res.status == ValidationStatus.UNKNOWN
    assert "disabled by default" in res.message
    assert "SYNTHETIC_CANARY_SECRET_11111" not in res.validation_command


@pytest.mark.asyncio
async def test_unknown_side_effect_operation_blocked():
    """Validators with unknown or unclassified side effects are blocked from network transmission."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    cfg = {
        "type": "http",
        "method": "POST",
        "url": "https://example.com/api?key={key}",
        "side_effect": ValidationSideEffect.UNKNOWN,
        "description": "Unclassified check"
    }
    res = await validator.validate_http(cfg, "SYNTHETIC_CANARY_SECRET_22222")
    assert res.status == ValidationStatus.UNKNOWN
    assert "unknown side effects and is blocked" in res.message


@pytest.mark.asyncio
async def test_destructive_operation_permanently_prohibited():
    """Destructive validators are permanently blocked under all circumstances."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(
        scope_manager=scope,
        request_policy_manager=rpm,
        http_client=client,
        allow_state_changing=True
    )

    cfg = {
        "type": "http",
        "method": "DELETE",
        "url": "https://example.com/api/delete?key={key}",
        "side_effect": ValidationSideEffect.DESTRUCTIVE,
        "description": "Destructive drop database"
    }
    res = await validator.validate_http(cfg, "SYNTHETIC_CANARY_SECRET_33333")
    assert res.status == ValidationStatus.UNKNOWN
    assert "Destructive validation" in res.message


def test_cli_cannot_enable_state_changing_against_profile_prohibition():
    """CLI override cannot enable state-changing operations when profile prohibits it."""
    prof = ProgramProfile(
        id="test-no-state-changing",
        name="No State Changing Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        testing_permissions=TestingPermissionsDefinition(state_changing_allowed=False)
    )
    with pytest.raises(ValueError, match="does not authorize state-changing validation operations"):
        EffectivePolicy.build(profile=prof, cli_overrides={"allow_state_changing": True})


# ==============================================================================
# 4. SECRET PROTECTION ACROSS REPORTS & OUTPUTS
# ==============================================================================

def test_secret_redaction_across_all_report_templates():
    """
    Verify that synthetic canary secrets (raw, URL-encoded, mixed-case, and duplicate query keys)
    are strictly scrubbed across HTML reports, Bugcrowd JSON, and Markdown exports.
    """
    canary_raw = "SYNTHETIC_CANARY_SECRET_98765"
    canary_encoded = quote_plus(canary_raw)
    raw_url = f"https://example.com/auth.js?token={canary_raw}&access_token={canary_encoded}&other={canary_raw}"

    finding = MagicMock()
    finding.pattern_name = "Slack Token"
    finding.matched_value = canary_raw
    finding.url = raw_url
    finding.category = "API Key"
    finding.confidence = 90
    finding.line_number = 42
    finding.context = f"const apiKey = '{canary_raw}'; const enc = '{canary_encoded}';"
    finding.severity = lambda: "HIGH"
    finding.is_keyhacks_valid = lambda: False
    finding.validated = True

    scan_res = MagicMock()
    scan_res.target = "example.com"
    scan_res.scan_time = 1.23
    scan_res.total_js_files = 5
    scan_res.total_urls_scanned = 10
    scan_res.subdomains_found = 2
    scan_res.errors = []
    scan_res.discovered_endpoints = [f"https://example.com/api?secret={canary_raw}"]

    # 1. HTML Generator
    html_gen = HtmlReportGenerator(ReportConfig(template="bugcrowd"))
    h1_report = html_gen.generate_hackerone_report([finding], scan_res)
    bc_report = html_gen.generate_bugcrowd_report([finding], scan_res)
    email_report = html_gen.generate_email_report([finding], scan_res)
    bc_json = html_gen.generate_bugcrowd_json([finding], scan_res)

    for report_text in (h1_report, bc_report, email_report, str(bc_json)):
        assert canary_raw not in report_text, "Raw canary secret leaked into HTML/JSON output!"
        assert canary_encoded not in report_text, "URL-encoded canary secret leaked into HTML/JSON output!"

    # 2. Report Manager (JSON & Markdown)
    policy = EffectivePolicy.build(cli_overrides={"allowed_domains": ["example.com"]})
    mgr = ReportManager(policy=policy)
    md_report = mgr.generate_markdown([finding], scan_res)
    json_report = mgr.generate_json([finding], scan_res)

    assert canary_raw not in md_report, "Canary secret leaked into Markdown report!"
    assert canary_encoded not in md_report, "URL-encoded canary leaked into Markdown report!"
    assert canary_raw not in json_report, "Canary secret leaked into ReportManager JSON!"
    assert canary_encoded not in json_report, "URL-encoded canary leaked into ReportManager JSON!"


def test_keyhacks_command_sanitization():
    """Verify KeyHacks generated validation commands scrub secrets, basic auth, and webhook tokens."""
    canary = "xoxb-123456789-abcdefg-SYNTHETIC"
    cfg = {
        "type": "http",
        "method": "POST",
        "url": "https://hooks.slack.com/services/T123/B456/{key}",
        "headers": {"Authorization": "Bearer {key}", "X-Api-Key": "{key}"},
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "secret_pass",
        "body": '{"token": "{key}"}'
    }
    cmd = KeyHacksValidator.build_sanitized_command(cfg, canary)
    assert canary not in cmd
    assert "[REDACTED]" in cmd
    assert "hooks.slack.com/services/T123/B456/[REDACTED]" in cmd
    assert "-u '[REDACTED]:[REDACTED]'" in cmd


# ==============================================================================
# 5. HTTP TRANSPORT & REDIRECT INTEGRITY
# ==============================================================================

@pytest.mark.asyncio
async def test_redirect_to_unauthorized_lookalike_blocked():
    """Redirect from authorized provider to lookalike host is blocked out-of-scope."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=5.0)
    client = NightCrawlerHttpClient(
        scope_manager=scope,
        request_policy_manager=rpm,
        authorized_providers={"example.com"}
    )
    client._pinned_ips["example.com"] = ["93.184.216.34"]

    mock_resp_1 = MagicMock()
    mock_resp_1.status = 302
    mock_resp_1.headers = {"Location": "https://evil-example.com/leak"}
    mock_resp_1.__aenter__ = AsyncMock(return_value=mock_resp_1)
    mock_resp_1.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get = MagicMock(return_value=mock_resp_1)

    status, content, final_url = await client.request(
        session=session,
        method="GET",
        url="https://example.com/login",
        authorized_provider="example.com"
    )
    # The redirect is intercepted and blocked: returns status 302, content None, current_url
    assert status == 302
    assert content is None
    assert "evil-example.com" not in (final_url or "")


@pytest.mark.asyncio
async def test_sensitive_headers_stripped_across_origins():
    """Authorization and Cookie headers are stripped when redirected cross-origin."""
    scope = ScopeManager(allowed_domains=["example.com", "partner.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=5.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]
    client._pinned_ips["partner.com"] = ["93.184.216.35"]

    requests_recorded = []

    def mock_get(url, **kwargs):
        ctx = MagicMock()
        resp = MagicMock()
        requests_recorded.append((url, kwargs.get("headers", {})))
        if len(requests_recorded) == 1:
            resp.status = 302
            resp.headers = {"Location": "https://partner.com/dashboard"}
        else:
            resp.status = 200
            resp.headers = {}
            resp.text = AsyncMock(return_value="OK")
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=None)
        return ctx

    session = MagicMock()
    session.get = mock_get

    extra = {
        "Authorization": "Bearer SYNTHETIC_TOKEN",
        "Cookie": "session=12345",
        "X-Custom-Tracking": "safe-value"
    }
    await client.request(
        session=session,
        method="GET",
        url="https://example.com/profile",
        extra_headers=extra
    )

    assert len(requests_recorded) == 2
    init_headers = requests_recorded[0][1]
    redirect_headers = requests_recorded[1][1]

    # Sensitive headers must be stripped on cross-origin redirect
    assert "Authorization" not in redirect_headers
    assert "Cookie" not in redirect_headers
    assert redirect_headers.get("X-Custom-Tracking") == "safe-value"


# ==============================================================================
# 6. EXTERNAL PROCESS & SUBPROCESS EXECUTION
# ==============================================================================

def test_subprocess_sanitized_environment():
    """Ensure sensitive credentials and tokens in parent os.environ are stripped from child processes."""
    test_env = {
        "PATH": "/usr/bin:/bin",
        "USER": "researcher",
        "AWS_SECRET_ACCESS_KEY": "LEAKY_SECRET_VAL",
        "SLACK_BOT_TOKEN": "xoxb-secret-token",
        "NIGHTCRAWLER_RESEARCHER_ID": "user@target.test",
        "API_KEY": "secret-api-key"
    }
    with patch.dict(os.environ, test_env, clear=True):
        clean = get_sanitized_env()
        assert "PATH" in clean
        assert "USER" in clean
        assert "AWS_SECRET_ACCESS_KEY" not in clean
        assert "SLACK_BOT_TOKEN" not in clean
        assert "NIGHTCRAWLER_RESEARCHER_ID" not in clean
        assert "API_KEY" not in clean


def test_subprocess_timeout_and_memory_bounding():
    """Verify tool execution terminates on timeout and bounds memory output."""
    # Timeout test
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["subfinder"], timeout=1)):
        out = run_bounded_tool(["subfinder"], timeout=1)
        assert out is None

    # Memory bounding test
    large_stdout = "A" * (MAX_TOOL_OUTPUT_BYTES + 1024)
    proc_mock = MagicMock(returncode=0, stdout=large_stdout)
    with patch("subprocess.run", return_value=proc_mock):
        out = run_bounded_tool(["subfinder"])
        assert out is not None
        assert len(out) <= MAX_TOOL_OUTPUT_BYTES


# ==============================================================================
# 7. SCAN LIFECYCLE, CANCELLATION & CLEANUP
# ==============================================================================

@pytest.mark.asyncio
async def test_request_cancellation_releases_semaphore():
    """When an HTTP coroutine is cancelled, the shared RequestPolicyManager semaphore is released."""
    rpm = RequestPolicyManager(concurrency_limit=1, max_rps=10.0)
    sem = rpm.get_semaphore()
    assert sem._value == 1

    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    client._pinned_ips["example.com"] = ["93.184.216.34"]

    class SlowContextManager:
        async def __aenter__(self):
            await asyncio.sleep(10)
            mock_resp = MagicMock()
            mock_resp.status = 200
            return mock_resp

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    async def hanging_request():
        session = MagicMock()
        session.get.return_value = SlowContextManager()
        await client.request(session=session, method="GET", url="https://example.com/hang")

    task = asyncio.create_task(hanging_request())
    await asyncio.sleep(0.05)
    # Semaphore is acquired
    assert sem._value == 0

    # Cancel task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Semaphore slot must be freed immediately
    assert sem._value == 1


# ==============================================================================
# 8. FAIL-CLOSED STARTUP & VALIDATION
# ==============================================================================

def test_startup_fails_closed_on_empty_scope():
    """EffectivePolicy fails closed when scope enforcement is enabled without valid target assets."""
    with pytest.raises(ValueError, match="Target scope cannot be empty"):
        EffectivePolicy.build(cli_overrides={"scope_enabled": True, "allowed_domains": []})


def test_startup_fails_closed_on_non_positive_rps():
    """EffectivePolicy rejects zero or negative request rates."""
    with pytest.raises(ValueError, match="max_rps must be strictly positive"):
        EffectivePolicy.build(cli_overrides={"max_rps": 0.0})

    with pytest.raises(ValueError, match="max_rps must be strictly positive"):
        EffectivePolicy.build(cli_overrides={"max_rps": -5.0})


def test_startup_fails_closed_on_insecure_tls_in_strict_mode():
    """EffectivePolicy rejects disabling TLS verification when strict scope is required."""
    with pytest.raises(ValueError, match="Insecure TLS configuration is prohibited in strict compliance mode"):
        EffectivePolicy.build(cli_overrides={"strict_scope": True, "verify_tls": False})
