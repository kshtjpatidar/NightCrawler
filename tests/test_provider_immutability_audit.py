"""
NightCrawler - Final Provider Allowlist Immutability & Boundary Enforcement Suite

Verifies:
1. Profile allows slack.com; constructor attempts to add attacker.test — rejected.
2. Profile allows slack.com and github.com; constructor narrows to slack.com — succeeds only for Slack.
3. Profile has an empty provider allowlist; constructor supplies slack.com — rejected.
4. Mutating the original set/list after client construction cannot expand client authorization.
5. Mutating EffectivePolicy.authorized_providers after construction cannot silently expand client authorization.
6. Scanner, CLI, KeyHacks, and direct HTTP client construction all preserve the same authorization boundary.
7. Redirects to a provider outside the effective allowlist are denied before transport.
8. Invalid or missing policy dependencies fail closed.
"""

import pytest
import aiohttp
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.program_profile import ProgramProfile, ScopeDefinition, RequestPolicyDefinition, TestingPermissionsDefinition
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.core.audit_logger import AuditLogger
from src.core.scanner import NightCrawlerScanner
from src.validators.keyhacks import KeyHacksValidator, KeyHacksPolicyError


def create_profile(providers=None):
    """Helper to build a deterministic test profile."""
    return ProgramProfile(
        id="test-immutability-prog",
        name="Test Immutability Program",
        version="1.0.0",
        platform="HackerOne",
        scope=ScopeDefinition(
            enabled=True,
            allowed_domains=["example.com"]
        ),
        request_policy=RequestPolicyDefinition(
            max_rps=10.0,
            concurrency=2,
            strict_scope=True,
            verify_tls=True
        ),
        testing_permissions=TestingPermissionsDefinition(
            credential_validation=True,
            state_changing_allowed=True
        ),
        authorized_providers=providers if providers is not None else ["slack.com"]
    )


# ==============================================================================
# 1. Constructor Expansion Rejection
# ==============================================================================

def test_constructor_expansion_rejected_when_profile_allows_slack():
    """Profile allows slack.com; HTTP client constructor attempts to add attacker.test — rejected."""
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)

    with pytest.raises(ValueError, match="cannot expand authorized_providers beyond EffectivePolicy allowlist"):
        NightCrawlerHttpClient(effective_policy=policy, authorized_providers=["attacker.test"])

    with pytest.raises(ValueError, match="cannot expand authorized_providers beyond EffectivePolicy allowlist"):
        NightCrawlerHttpClient(effective_policy=policy, authorized_providers=["slack.com", "attacker.test"])


# ==============================================================================
# 2. Constructor Narrowing Enforcement
# ==============================================================================

def test_constructor_narrowing_succeeds_only_for_narrowed_provider():
    """Profile allows slack.com and github.com; constructor narrows to slack.com — succeeds only for Slack."""
    prof = create_profile(providers=["slack.com", "github.com"])
    policy = EffectivePolicy.build(profile=prof)

    # Narrows to slack.com only
    client = NightCrawlerHttpClient(effective_policy=policy, authorized_providers=["slack.com"])
    assert client.authorized_providers == frozenset({"slack.com"})

    # Authorized for Slack
    assert client.is_provider_authorized("slack", "https://slack.com/api/test") is True

    # Denied for GitHub (narrowed out)
    assert client.is_provider_authorized("github", "https://github.com/api/test") is False


# ==============================================================================
# 3. Empty Allowlist Expansion Rejection
# ==============================================================================

def test_constructor_expansion_rejected_when_profile_allowlist_is_empty():
    """Profile has an empty provider allowlist; constructor supplies slack.com — rejected."""
    prof = create_profile(providers=[])
    policy = EffectivePolicy.build(profile=prof)

    with pytest.raises(ValueError, match="cannot expand authorized_providers beyond EffectivePolicy allowlist"):
        NightCrawlerHttpClient(effective_policy=policy, authorized_providers=["slack.com"])


# ==============================================================================
# 4. Input Mutation Resistance
# ==============================================================================

def test_mutation_of_original_input_collection_does_not_expand_client():
    """Mutating the original set/list after client construction cannot expand client authorization."""
    # Test with standalone client
    raw_list = ["slack.com"]
    client_standalone = NightCrawlerHttpClient(authorized_providers=raw_list)
    raw_list.append("attacker.test")

    assert "attacker.test" not in client_standalone.authorized_providers
    assert client_standalone.is_provider_authorized("attacker", "https://attacker.test/api") is False

    # Test with raw set
    raw_set = {"slack.com"}
    client_from_set = NightCrawlerHttpClient(authorized_providers=raw_set)
    raw_set.add("evil.com")

    assert "evil.com" not in client_from_set.authorized_providers
    assert client_from_set.is_provider_authorized("evil", "https://evil.com/api") is False

    # Test with policy-backed client
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)
    constructor_list = ["slack.com"]
    client_policy = NightCrawlerHttpClient(effective_policy=policy, authorized_providers=constructor_list)
    constructor_list.append("attacker.test")

    assert "attacker.test" not in client_policy.authorized_providers
    assert client_policy.is_provider_authorized("attacker", "https://attacker.test/api") is False


# ==============================================================================
# 5. EffectivePolicy Immutability & Client Isolation
# ==============================================================================

def test_mutation_of_effective_policy_providers_cannot_expand_client():
    """Mutating EffectivePolicy.authorized_providers after construction cannot silently expand client authorization."""
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)
    client = NightCrawlerHttpClient(effective_policy=policy)

    # 1. Attempting .add() on EffectivePolicy.authorized_providers raises AttributeError
    with pytest.raises(AttributeError):
        policy.authorized_providers.add("attacker.test")

    # 2. Attempting reassignment on EffectivePolicy.authorized_providers raises AttributeError
    with pytest.raises(AttributeError, match="immutable"):
        policy.authorized_providers = {"attacker.test"}

    # 3. Attempting .add() on client.authorized_providers raises AttributeError
    with pytest.raises(AttributeError):
        client.authorized_providers.add("attacker.test")

    # 4. Attempting reassignment to expand client.authorized_providers raises ValueError
    with pytest.raises(ValueError, match="Cannot expand authorized_providers"):
        client.authorized_providers = {"attacker.test"}

    # 5. Even if EffectivePolicy attribute was forcibly overwritten at low-level, client remains isolated
    object.__setattr__(policy, "authorized_providers", frozenset({"attacker.test"}))
    assert client.is_provider_authorized("attacker", "https://attacker.test/api") is False
    assert client.is_provider_authorized("slack", "https://slack.com/api/test") is True


# ==============================================================================
# 6. Authorization Boundary Preservation Across Components
# ==============================================================================

def test_consistent_authorization_boundary_across_scanner_cli_keyhacks_and_http_client():
    """Scanner, CLI, KeyHacks, and direct HTTP client construction all preserve the same authorization boundary."""
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)

    # A. CLI expansion rejection
    with pytest.raises(ValueError, match="CLI cannot expand"):
        EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["attacker.test"]})

    # B. KeyHacksValidator constructor expansion rejection
    with pytest.raises(ValueError, match="KeyHacksValidator constructor cannot expand"):
        KeyHacksValidator(effective_policy=policy, authorized_providers={"attacker.test"})

    # C. KeyHacksValidator.from_policy expansion rejection
    with pytest.raises(ValueError, match="KeyHacksValidator.from_policy cannot expand"):
        KeyHacksValidator.from_policy(policy, authorized_providers={"attacker.test"})

    # D. Direct HTTP client constructor expansion rejection
    with pytest.raises(ValueError, match="Constructor cannot expand"):
        NightCrawlerHttpClient(effective_policy=policy, authorized_providers={"attacker.test"})

    # E. Scanner component boundary consistency
    scanner = NightCrawlerScanner(effective_policy=policy)
    assert scanner.http_client.authorized_providers == frozenset({"slack.com"})
    assert scanner.keyhacks_validator.authorized_providers == frozenset({"slack.com"})

    # Ensure none of the scanner components authorize attacker.test
    assert scanner.http_client.is_provider_authorized("attacker", "https://attacker.test") is False
    assert scanner.keyhacks_validator.is_provider_authorized({"provider": "attacker"}, "https://attacker.test") is False


# ==============================================================================
# 7. Pre-Transport Redirect Boundary Enforcement
# ==============================================================================

@pytest.mark.asyncio
async def test_redirect_to_unauthorized_provider_denied_before_transport():
    """Redirects to a provider outside the effective allowlist are denied before transport."""
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)
    audit = MagicMock()
    policy.audit_logger = audit

    client = NightCrawlerHttpClient(effective_policy=policy)
    client._pinned_ips["slack.com"] = ["127.0.0.1"]

    # Initial response is a 302 redirecting to unauthorized external host
    mock_resp = MagicMock()
    mock_resp.status = 302
    mock_resp.headers = {"Location": "https://unauthorized-attacker.test/callback"}
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get.return_value = cm

    with patch.object(client, "validate_host_network_safety", return_value=(True, "OK")):
        status, content, final_url = await client.request(
            session=session,
            method="GET",
            url="https://slack.com/api/auth.test",
            authorized_provider="slack"
        )
        # Transport must be called exactly once for initial URL; redirect target must NEVER be contacted
        assert session.get.call_count == 1
        call_url = session.get.call_args[0][0]
        assert "unauthorized-attacker.test" not in call_url

        # Redirect target was rejected
        assert status == 302
        assert content is None
        assert final_url == "https://slack.com/api/auth.test"

        # Verify audit logger recorded the blocked redirect
        assert audit.log_event.called
        redirect_calls = [
            kwargs for _, kwargs in audit.log_event.call_args_list
            if kwargs.get("redirect_decision") == "BLOCKED_OUT_OF_SCOPE" or kwargs.get("scope_decision") == "BLOCKED"
        ]
        assert len(redirect_calls) > 0


# ==============================================================================
# 8. Dependency Validation & Fail-Closed Behavior
# ==============================================================================

def test_invalid_or_missing_policy_dependencies_fail_closed():
    """Invalid or missing policy dependencies fail closed with KeyHacksPolicyError."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)

    # 1. Missing scope manager
    v1 = KeyHacksValidator(scope_manager=None, request_policy_manager=rpm, http_client=client)
    with pytest.raises(KeyHacksPolicyError, match="ScopeManager is missing"):
        v1.validate_policy_dependencies()

    # 2. Missing request policy manager
    v2 = KeyHacksValidator(scope_manager=scope, request_policy_manager=None, http_client=client)
    with pytest.raises(KeyHacksPolicyError, match="RequestPolicyManager is missing"):
        v2.validate_policy_dependencies()

    # 3. Missing http client
    v3 = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=None)
    with pytest.raises(KeyHacksPolicyError, match="HttpClient is missing"):
        v3.validate_policy_dependencies()

    # 4. Mismatched scope manager with policy
    prof = create_profile(providers=["slack.com"])
    policy = EffectivePolicy.build(profile=prof)
    other_scope = ScopeManager(allowed_domains=["other.com"], enabled=True)
    client_other = NightCrawlerHttpClient(effective_policy=policy)
    client_other.scope_manager = other_scope
    v4 = KeyHacksValidator(effective_policy=policy, http_client=client_other)
    with pytest.raises(KeyHacksPolicyError, match="Mismatched ScopeManager"):
        v4.validate_policy_dependencies()

    # 5. Expanded authorized_providers on validator fails closed
    client_valid = NightCrawlerHttpClient(effective_policy=policy)
    v5 = KeyHacksValidator(effective_policy=policy, http_client=client_valid)
    object.__setattr__(v5, "_authorized_providers", frozenset({"slack.com", "evil.com"}))
    with pytest.raises(KeyHacksPolicyError, match="authorized_providers expanded"):
        v5.validate_policy_dependencies()
