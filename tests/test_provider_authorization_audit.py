"""
NightCrawler - Provider Authorization & Side-Effect Adversarial Audit Test Suite
tests/test_provider_authorization_audit.py

Comprehensive adversarial verification covering:
1. Provider authorization fails closed (None, empty, malformed, wrong types, wildcards).
2. Schema validation (YAML, JSON, CLI, env) rejects invalid types, wildcards, numbers, and unknown keys.
3. Strict boolean parsing rejects ambiguous values and non-boolean types.
4. Hostname normalization and URL edge cases (schemes, userinfo, IP literals, encoding, lookalikes).
5. Multi-hop and cross-origin redirect re-evaluation at the network boundary.
6. Centralized transport enforcement: all requests go through NightCrawlerHttpClient; no live requests.
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import aiohttp

from src.core.program_profile import (
    ProgramProfile,
    ScopeDefinition,
    RequestPolicyDefinition,
    TestingPermissionsDefinition,
    PolicyParser,
    PolicyValidator,
    strict_bool,
    parse_authorized_providers,
)
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.validators.keyhacks import (
    KEYHACKS_VALIDATORS,
    KeyHacksValidator,
    ValidationStatus,
    ValidationSideEffect,
)
from src.core.request_config import load_config, NightCrawlerConfig


# ==============================================================================
# 1. PROVIDER AUTHORIZATION FAILS CLOSED
# ==============================================================================

def test_provider_authorization_fails_closed_on_none_or_empty():
    """Missing or empty authorized_providers allowlist strictly denies all provider requests."""
    # 1. authorized_providers=None
    client_none = NightCrawlerHttpClient(authorized_providers=None)
    assert client_none.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False

    # 2. authorized_providers=set()
    client_empty = NightCrawlerHttpClient(authorized_providers=set())
    assert client_empty.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False

    # 3. authorized_providers=[]
    client_list_empty = NightCrawlerHttpClient(authorized_providers=[])
    assert client_list_empty.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False


def test_provider_authorization_fails_closed_on_wrong_types():
    """Wrong-type, malformed, or nested allowlists fail closed and deny all provider requests."""
    # String instead of collection
    client_str = NightCrawlerHttpClient(authorized_providers="slack")
    assert client_str.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False

    # Integer instead of collection
    client_int = NightCrawlerHttpClient(authorized_providers=123)
    assert client_int.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False

    # List with invalid mixed types
    client_mixed = NightCrawlerHttpClient(authorized_providers=["slack", 123])
    assert client_mixed.is_provider_authorized("slack", "https://slack.com/api/auth.test") is False


def test_wildcard_providers_cannot_disable_enforcement():
    """Wildcards ('*' or 'all') are rejected or ignored and cannot disable provider enforcement."""
    # Wildcard in allowlist fails closed
    client_star = NightCrawlerHttpClient(authorized_providers={"*"})
    assert client_star.is_provider_authorized("slack", "https://slack.com/api") is False
    assert client_star.is_provider_authorized("evil", "https://evil.com/api") is False

    client_all = NightCrawlerHttpClient(authorized_providers={"all"})
    assert client_all.is_provider_authorized("slack", "https://slack.com/api") is False
    assert client_all.is_provider_authorized("evil", "https://evil.com/api") is False


def test_invalid_provider_or_url_arguments_fail_closed():
    """Empty, non-string, or malformed provider or URL arguments always return False."""
    client = NightCrawlerHttpClient(authorized_providers={"slack"})
    assert client.is_provider_authorized("", "https://slack.com/api") is False
    assert client.is_provider_authorized(None, "https://slack.com/api") is False
    assert client.is_provider_authorized(123, "https://slack.com/api") is False
    assert client.is_provider_authorized("slack", "") is False
    assert client.is_provider_authorized("slack", None) is False
    assert client.is_provider_authorized("slack", 123) is False
    assert client.is_provider_authorized("slack", "not_a_valid_url") is False


# ==============================================================================
# 2. SCHEMA VALIDATION FOR AUTHORIZED PROVIDERS
# ==============================================================================

@pytest.mark.parametrize("invalid_raw", [
    "aws",                  # string instead of list
    123,                    # integer instead of list
    True,                   # boolean instead of list
    {"provider": "aws"},    # dictionary instead of list
    ["aws", 123],           # mixed list with integer
    [["aws"]],              # nested list
    [{"name": "aws"}],      # list of dictionaries
    ["aws", None],          # list with None
    ["aws", ""],            # list with empty string
    ["aws", "   "],         # list with whitespace-only string
    ["*"],                  # wildcard star
    ["all"],                # wildcard all
    ["aws; rm -rf /"],      # command injection chars
    ["aws/bucket"],         # slash character
    ["192.168.1.1"],        # IP literal
    ["10.0.0.1"],           # private IP literal
    ["::1"],                # IPv6 literal
    ["com"],                # single TLD
    [".net"],               # single TLD with dot
])
def test_parse_authorized_providers_rejects_invalid_inputs(invalid_raw):
    """parse_authorized_providers strictly rejects non-list types, wildcards, IPs, and malformed names."""
    with pytest.raises(ValueError):
        parse_authorized_providers(invalid_raw)


def test_parse_authorized_providers_normalizes_and_deduplicates():
    """Valid provider entries are trimmed, lowercased, deduplicated, and IDNA punycoded."""
    raw = ["  AWS  ", "aws", "Google", "  google  ", "exämple.com"]
    result = parse_authorized_providers(raw)
    assert "aws" in result
    assert "google" in result
    assert "xn--exmple-cua.com" in result
    assert len(result) == 3


def test_program_profile_from_dict_rejects_malformed_providers():
    """ProgramProfile.from_dict fails closed on malformed authorized_providers."""
    with pytest.raises(ValueError, match="authorized_providers"):
        ProgramProfile.from_dict({
            "id": "test-malformed",
            "name": "Test",
            "scope": {"allowed_domains": ["example.com"]},
            "authorized_providers": "aws"  # string instead of list
        })

    with pytest.raises(ValueError, match="authorized_providers"):
        ProgramProfile.from_dict({
            "id": "test-wildcard",
            "name": "Test",
            "scope": {"allowed_domains": ["example.com"]},
            "authorized_providers": ["*"]  # wildcard
        })


def test_program_profile_from_dict_rejects_unknown_keys():
    """ProgramProfile.from_dict rejects unknown top-level and section keys with actionable errors."""
    # Unknown top-level key
    with pytest.raises(ValueError, match="Unknown policy key"):
        ProgramProfile.from_dict({
            "id": "test-unknown",
            "name": "Test",
            "scope": {"allowed_domains": ["example.com"]},
            "insecure_mode": True
        })

    # Unknown key in scope
    with pytest.raises(ValueError, match="Unknown key"):
        ProgramProfile.from_dict({
            "id": "test-unknown-scope",
            "name": "Test",
            "scope": {
                "allowed_domains": ["example.com"],
                "bypass_all_checks": True
            }
        })

    # Unknown key in request_policy
    with pytest.raises(ValueError, match="Unknown key"):
        ProgramProfile.from_dict({
            "id": "test-unknown-rp",
            "name": "Test",
            "scope": {"allowed_domains": ["example.com"]},
            "request_policy": {
                "max_rps": 5.0,
                "disable_rate_limiting": True
            }
        })


def test_cli_overrides_reject_unknown_keys():
    """EffectivePolicy.build rejects unrecognized CLI override flags."""
    with pytest.raises(ValueError, match="Unknown CLI override"):
        EffectivePolicy.build(cli_overrides={"insecure_skip_verify": True})


def test_load_config_rejects_unknown_sections(tmp_path):
    """load_config rejects unknown configuration sections in YAML."""
    cfg_file = tmp_path / "bad_config.yaml"
    cfg_file.write_text("unknown_section:\n  dangerous_option: true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown configuration section"):
        load_config(str(cfg_file))


# ==============================================================================
# 3. STRICT BOOLEAN PARSING SCHEMA
# ==============================================================================

@pytest.mark.parametrize("truthy", ["true", "True", "TRUE", "1", "yes", "YES", "on", "On", True, 1, 1.0])
def test_strict_bool_truthy_values(truthy):
    """Strict boolean correctly parses all canonical truthy representations."""
    assert strict_bool(truthy) is True


@pytest.mark.parametrize("falsy", ["false", "False", "FALSE", "0", "no", "NO", "off", "Off", False, 0, 0.0])
def test_strict_bool_falsy_values(falsy):
    """Strict boolean correctly parses all canonical falsy representations."""
    assert strict_bool(falsy) is False


@pytest.mark.parametrize("ambiguous", ["maybe", "disabled", "enabled", "2", "-1", "none", "null", ""])
def test_strict_bool_rejects_ambiguous_strings(ambiguous):
    """Strict boolean rejects ambiguous strings instead of guessing or coercing."""
    with pytest.raises(ValueError, match="Invalid boolean"):
        strict_bool(ambiguous)


@pytest.mark.parametrize("invalid_type", [None, [], {}, ()])
def test_strict_bool_rejects_invalid_types(invalid_type):
    """Strict boolean raises TypeError for non-boolean types."""
    with pytest.raises(TypeError, match="Expected boolean"):
        strict_bool(invalid_type)


# ==============================================================================
# 4. HOSTNAME NORMALIZATION & URL ATTACKS
# ==============================================================================

@pytest.mark.parametrize("attack_url, reason", [
    ("ftp://slack.com/api", "Unsupported scheme ftp"),
    ("file:///etc/passwd", "Unsupported scheme file"),
    ("javascript:alert(1)", "Unsupported scheme javascript"),
    ("data:text/html,test", "Unsupported scheme data"),
    ("https://slack.com@evil.com/api", "Embedded userinfo spoofing host"),
    ("https://user:pass@slack.com/api", "Embedded basic auth credentials in URL"),
    ("http://192.168.1.1/api", "IPv4 literal target"),
    ("https://127.0.0.1/api", "Localhost IPv4 literal"),
    ("https://[::1]/api", "IPv6 literal target"),
    ("https://evil-slack.com/api", "Lookalike domain with hyphen prefix"),
    ("https://slack.com.attacker.test/api", "Suffix hijack subdomain attack"),
    ("https://attacker-slack.com/api", "Prefix hijack lookalike domain"),
    ("https://slack.com.evil.com/api", "Subdomain on malicious domain"),
    ("https://exämple.com/api", "IDNA homograph domain does not match example.com"),
])
def test_provider_authorization_blocks_host_and_url_attacks(attack_url, reason):
    """is_provider_authorized rejects all scheme, userinfo, IP literal, and lookalike attacks."""
    client = NightCrawlerHttpClient(authorized_providers={"slack", "example.com"})
    assert client.is_provider_authorized("slack", attack_url) is False, f"Failed to block: {reason}"


def test_provider_authorization_normalizes_trailing_dots_and_subdomains():
    """Legitimate trailing dots, proper subdomains, and official provider domains match safely."""
    client = NightCrawlerHttpClient(authorized_providers={"slack", "google", "facebook", "twitter"})

    # Legitimate provider endpoints
    assert client.is_provider_authorized("slack", "https://slack.com/api/auth.test") is True
    assert client.is_provider_authorized("slack", "https://api.slack.com/methods") is True
    assert client.is_provider_authorized("slack", "https://slack.com./api/auth.test") is True  # trailing dot
    assert client.is_provider_authorized("google", "https://www.googleapis.com/oauth2/v1/tokeninfo") is True
    assert client.is_provider_authorized("google", "https://google.com/api") is True
    assert client.is_provider_authorized("facebook", "https://graph.facebook.com/v18.0/me") is True
    assert client.is_provider_authorized("twitter", "https://api.twitter.com/2/tweets") is True


# ==============================================================================
# 5. CLI OVERRIDES CANNOT EXPAND PROFILE ALLOWLIST
# ==============================================================================

def test_cli_cannot_expand_profile_provider_allowlist():
    """CLI cannot add external providers beyond what the program profile explicitly authorizes."""
    prof = ProgramProfile(
        id="strict-providers",
        name="Strict Providers Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        authorized_providers=["aws"]
    )

    # Permitted narrowing
    policy_narrow = EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["aws"]})
    assert policy_narrow.authorized_providers == {"aws"}

    # Unauthorized expansion rejected
    with pytest.raises(ValueError, match="CLI cannot expand program 'strict-providers' authorized providers"):
        EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["aws", "slack"]})

    # Empty profile allowlist cannot be expanded by CLI
    prof_empty = ProgramProfile(
        id="empty-providers",
        name="Empty Providers Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        authorized_providers=[]
    )
    with pytest.raises(ValueError, match="CLI cannot expand program 'empty-providers' authorized providers"):
        EffectivePolicy.build(profile=prof_empty, cli_overrides={"authorized_providers": ["aws"]})


# ==============================================================================
# 6. NETWORK BOUNDARY & REDIRECT ENFORCEMENT
# ==============================================================================

@pytest.mark.asyncio
async def test_out_of_scope_unauthorized_provider_never_touches_transport():
    """Out-of-scope request with unauthorized provider is blocked with 0 transport calls."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    # Authorized only for slack, not for unauthorized-provider.com
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, authorized_providers={"slack"})

    session = MagicMock()
    with patch.object(session, "get") as mock_get:
        status, content, final_url = await client.get(session, "https://unauthorized-provider.com/api")
        assert status is None
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_redirect_to_unauthorized_provider_destination_is_blocked():
    """In-scope request redirecting to an unauthorized external provider is blocked at the redirect hop."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    # No authorized providers
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, authorized_providers=set())

    # Initial response is a 302 redirecting to external provider
    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://api.slack.com/oauth/authorize"}
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get.return_value = cm

    with patch.object(client, "validate_host_network_safety", return_value=(True, "Public IP")):
        status, content, final_url = await client.get(session, "https://example.com/login")
        # Blocked at redirect hop
        assert status == 302
        assert content is None
        assert final_url == "https://example.com/login"


@pytest.mark.asyncio
async def test_provider_redirect_to_unauthorized_destination_is_blocked():
    """Authorized provider request redirecting to an unauthorized domain is blocked at the redirect hop."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    # Authorized only for slack
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, authorized_providers={"slack"})

    # Hop 1 (slack.com) redirects to malicious evil-slack.com
    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://evil-slack.com/steal"}
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get.return_value = cm

    with patch.object(client, "validate_host_network_safety", return_value=(True, "Public IP")):
        status, content, final_url = await client.request(
            session=session,
            method="GET",
            url="https://slack.com/api/auth.test",
            authorized_provider="slack"
        )
        assert status == 302
        assert content is None
        assert final_url == "https://slack.com/api/auth.test"


@pytest.mark.asyncio
async def test_provider_redirect_to_another_authorized_provider_domain_succeeds():
    """Authorized provider request redirecting to another valid domain of the same provider succeeds."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, authorized_providers={"slack"})

    # Hop 1 (slack.com) redirects to api.slack.com (both legitimate slack domains)
    resp1 = MagicMock()
    resp1.status = 302
    resp1.headers = {"Location": "https://api.slack.com/auth.test"}
    cm1 = MagicMock()
    cm1.__aenter__ = AsyncMock(return_value=resp1)
    cm1.__aexit__ = AsyncMock(return_value=None)

    # Hop 2 (api.slack.com) returns 200 OK
    resp2 = MagicMock()
    resp2.status = 200
    resp2.text = AsyncMock(return_value='{"ok": true}')
    cm2 = MagicMock()
    cm2.__aenter__ = AsyncMock(return_value=resp2)
    cm2.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get.side_effect = [cm1, cm2]

    with patch.object(client, "validate_host_network_safety", return_value=(True, "Public IP")):
        status, content, final_url = await client.request(
            session=session,
            method="GET",
            url="https://slack.com/api/auth.test",
            authorized_provider="slack"
        )
        assert status == 200
        assert content == '{"ok": true}'
        assert final_url == "https://api.slack.com/auth.test"


@pytest.mark.asyncio
async def test_keyhacks_uses_policy_aware_resolver_and_tcp_connector():
    """KeyHacksValidator enforces that sessions use PolicyAwareResolver to pin validated DNS answers."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    resolver = validator.http_client.get_resolver()
    assert isinstance(resolver, PolicyAwareResolver)
    connector = aiohttp.TCPConnector(resolver=resolver, ssl=validator.http_client.ssl_context)
    try:
        # validate_policy_dependencies succeeds with proper connector
        validator.validate_policy_dependencies(connector=connector)
    finally:
        await connector.close()
