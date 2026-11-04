"""
NightCrawler - KeyHacks Validator Side-Effect Inventory & Semantic Audit Test Suite
tests/test_validator_side_effect_inventory.py

Enforces:
1. Machine-readable inventory: every validator in KEYHACKS_VALIDATORS must have a documented
   provider identifier and side-effect classification (no unclassified entries allowed).
2. Semantic behavior: verifies side-effect classifications (read_only, state_changing, destructive, unknown).
3. State-changing operations require BOTH program-profile authorization and explicit operator opt-in.
4. Destructive and unknown operations are permanently blocked and never touch the network transport.
"""

import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from src.core.program_profile import ProgramProfile, ScopeDefinition, RequestPolicyDefinition, TestingPermissionsDefinition
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.http_client import NightCrawlerHttpClient
from src.validators.keyhacks import (
    KEYHACKS_VALIDATORS,
    ValidationSideEffect,
    ValidationStatus,
    KeyHacksValidator,
    KeyHacksPolicyError
)


# ==============================================================================
# 1. MACHINE-READABLE VALIDATOR INVENTORY AUDIT
# ==============================================================================

def test_machine_readable_validator_inventory_completeness():
    """
    Every validator registered in KEYHACKS_VALIDATORS must define:
    - 'provider': valid non-empty string identifier or domain
    - 'side_effect': explicit ValidationSideEffect instance (not None, not UNKNOWN)
    - 'url' or 'type' == 'command'
    """
    assert len(KEYHACKS_VALIDATORS) >= 62, f"Expected at least 62 validators, got {len(KEYHACKS_VALIDATORS)}"

    unclassified_side_effects = []
    missing_providers = []
    invalid_side_effects = []

    for name, config in KEYHACKS_VALIDATORS.items():
        # 1. Provider must be documented
        provider = config.get("provider")
        if not provider or not isinstance(provider, str) or not provider.strip():
            missing_providers.append(name)

        # 2. Side effect must be present and valid
        side_effect = config.get("side_effect")
        if side_effect is None:
            unclassified_side_effects.append(name)
        elif not isinstance(side_effect, ValidationSideEffect):
            invalid_side_effects.append((name, type(side_effect)))
        elif side_effect in (ValidationSideEffect.UNKNOWN, ValidationSideEffect.DESTRUCTIVE):
            # Production validators in the registry should never be UNKNOWN or DESTRUCTIVE
            invalid_side_effects.append((name, side_effect))

    assert not missing_providers, f"Validators missing documented 'provider': {missing_providers}"
    assert not unclassified_side_effects, f"Validators missing 'side_effect' classification: {unclassified_side_effects}"
    assert not invalid_side_effects, f"Validators with invalid side-effect states: {invalid_side_effects}"


def test_semantic_side_effect_classification_correctness():
    """
    Semantically verifies that validators performing remote mutations, event emissions,
    account creation, or message deliveries are classified as STATE_CHANGING, and pure
    read/query operations are classified as READ_ONLY.
    """
    # Known state-changing validators:
    # 1. Firebase Key creates an anonymous user account via identitytoolkit accounts:signUp
    assert KEYHACKS_VALIDATORS["Firebase Key"]["side_effect"] == ValidationSideEffect.STATE_CHANGING
    assert KEYHACKS_VALIDATORS["Firebase Key"]["provider"] == "firebase"

    # 2. Slack Webhook delivers a message to a channel
    assert KEYHACKS_VALIDATORS["Slack Webhook"]["side_effect"] == ValidationSideEffect.STATE_CHANGING
    assert KEYHACKS_VALIDATORS["Slack Webhook"]["provider"] == "slack"

    # 3. Segment Write Key submits an analytics track event
    assert KEYHACKS_VALIDATORS["Segment Write Key"]["side_effect"] == ValidationSideEffect.STATE_CHANGING
    assert KEYHACKS_VALIDATORS["Segment Write Key"]["provider"] == "segment"

    # 4. Anthropic API Key invokes remote LLM message generation
    assert KEYHACKS_VALIDATORS["Anthropic API Key"]["side_effect"] == ValidationSideEffect.STATE_CHANGING
    assert KEYHACKS_VALIDATORS["Anthropic API Key"]["provider"] == "anthropic"

    # Verified read-only validators (metadata checks, whoami, tokeninfo, viewer)
    read_only_checks = [
        "Google API Key", "AWS Access Key", "GitHub PAT", "GitLab PAT",
        "Slack Bot Token", "Discord Webhook", "Telegram Bot Token",
        "OpenAI API Key", "Stripe Live Secret Key", "Linear API Key", "Monday API Token"
    ]
    for check_name in read_only_checks:
        assert KEYHACKS_VALIDATORS[check_name]["side_effect"] == ValidationSideEffect.READ_ONLY, (
            f"Validator '{check_name}' expected to be READ_ONLY"
        )


# ==============================================================================
# 2. UNCLASSIFIED & DESTRUCTIVE VALIDATORS FAIL CLOSED
# ==============================================================================

@pytest.mark.asyncio
async def test_unclassified_validator_denied_by_default():
    """An unclassified validator (missing side_effect) is treated as UNKNOWN and denied by default."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(scope_manager=scope, request_policy_manager=rpm, http_client=client)

    # Missing side_effect in custom validator
    unclassified_cfg = {
        "type": "http",
        "method": "GET",
        "url": "https://example.com/api?key={key}",
        "description": "Unclassified custom validator",
        "provider": "custom"
    }

    with patch.object(client, "request") as mock_req:
        res = await validator.validate_http(unclassified_cfg, "SYNTHETIC_CANARY_SECRET_11111")
        assert res.status == ValidationStatus.UNKNOWN
        assert "unknown side effects" in res.message.lower()
        mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_destructive_validator_permanently_denied():
    """Destructive validators are always rejected before any network request, even if state-changing is on."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm)
    validator = KeyHacksValidator(
        scope_manager=scope,
        request_policy_manager=rpm,
        http_client=client,
        allow_state_changing=True
    )

    destructive_cfg = {
        "type": "http",
        "method": "DELETE",
        "url": "https://example.com/api/database?key={key}",
        "side_effect": ValidationSideEffect.DESTRUCTIVE,
        "description": "Drop database table",
        "provider": "custom"
    }

    with patch.object(client, "request") as mock_req:
        res = await validator.validate_http(destructive_cfg, "SYNTHETIC_CANARY_SECRET_22222")
        assert res.status == ValidationStatus.UNKNOWN
        assert "destructive" in res.message.lower()
        mock_req.assert_not_called()


# ==============================================================================
# 3. STATE-CHANGING OPERATIONS REQUIRE BOTH PROFILE AND OPERATOR OPT-IN
# ==============================================================================

def test_state_changing_requires_both_profile_and_operator_opt_in():
    """
    Proves that STATE_CHANGING operations require:
    1. Program profile testing_permissions.state_changing_allowed = True
    2. CLI override allow_state_changing = True
    If either is missing, allow_state_changing is False.
    """
    # Case 1: Profile allows, but operator did NOT opt in -> allow_state_changing is False
    prof_allow = ProgramProfile(
        id="profile-allow-state",
        name="Allow State Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        testing_permissions=TestingPermissionsDefinition(
            credential_validation=True,
            state_changing_allowed=True
        )
    )
    policy_no_cli = EffectivePolicy.build(profile=prof_allow, cli_overrides={})
    assert policy_no_cli.allow_state_changing is False

    # Case 2: Operator explicitly requests opt-in, but profile PROHIBITS state changing -> ValueError
    prof_deny = ProgramProfile(
        id="profile-deny-state",
        name="Deny State Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        testing_permissions=TestingPermissionsDefinition(
            credential_validation=True,
            state_changing_allowed=False
        )
    )
    with pytest.raises(ValueError, match="does not authorize state-changing validation operations"):
        EffectivePolicy.build(profile=prof_deny, cli_overrides={"allow_state_changing": True})

    # Case 3: Both profile AND operator authorize state changing -> allow_state_changing is True
    policy_both = EffectivePolicy.build(profile=prof_allow, cli_overrides={"allow_state_changing": True})
    assert policy_both.allow_state_changing is True


@pytest.mark.asyncio
async def test_state_changing_validator_blocked_without_operator_opt_in():
    """When state changing is not authorized, state-changing validators fail closed before transport."""
    scope = ScopeManager(allowed_domains=["googleapis.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    client = NightCrawlerHttpClient(scope_manager=scope, request_policy_manager=rpm, authorized_providers={"firebase"})
    # Not authorized for state changing
    validator = KeyHacksValidator(
        scope_manager=scope,
        request_policy_manager=rpm,
        http_client=client,
        allow_state_changing=False,
        authorized_providers={"firebase"}
    )

    firebase_cfg = KEYHACKS_VALIDATORS["Firebase Key"]
    with patch.object(client, "request") as mock_req:
        res = await validator.validate_http(firebase_cfg, "SYNTHETIC_FIREBASE_KEY_99999")
        assert res.status == ValidationStatus.UNKNOWN
        assert "state-changing validation" in res.message.lower()
        mock_req.assert_not_called()


@pytest.mark.asyncio
async def test_state_changing_validator_proceeds_when_both_authorized():
    """When both profile and operator authorize state changing, validator executes through client."""
    prof = ProgramProfile(
        id="firebase-prog",
        name="Firebase Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        authorized_providers=["firebase"],
        testing_permissions=TestingPermissionsDefinition(
            credential_validation=True,
            state_changing_allowed=True
        )
    )
    policy = EffectivePolicy.build(profile=prof, cli_overrides={"allow_state_changing": True})
    assert policy.allow_state_changing is True

    validator = KeyHacksValidator.from_policy(policy)
    assert validator.allow_state_changing is True

    firebase_cfg = KEYHACKS_VALIDATORS["Firebase Key"]
    # Mock transport response
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value='{"idToken": "token123", "localId": "user123"}')
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession.post", return_value=cm), \
         patch.object(validator.http_client, "validate_host_network_safety", return_value=(True, "Public IP")):
        res = await validator.validate_http(firebase_cfg, "SYNTHETIC_FIREBASE_KEY_99999")
        assert res.status == ValidationStatus.VALID


def test_keyhacks_from_policy_cannot_bypass_policy_state_changing():
    """KeyHacksValidator.from_policy raises ValueError if caller tries to enable state-changing when policy prohibits it."""
    prof = ProgramProfile(
        id="strict-prog",
        name="Strict Program",
        scope=ScopeDefinition(allowed_domains=["example.com"]),
        testing_permissions=TestingPermissionsDefinition(state_changing_allowed=False)
    )
    policy = EffectivePolicy.build(profile=prof, cli_overrides={})
    assert policy.allow_state_changing is False

    with pytest.raises(ValueError, match="EffectivePolicy prohibits state-changing operations"):
        KeyHacksValidator.from_policy(policy, allow_state_changing=True)
