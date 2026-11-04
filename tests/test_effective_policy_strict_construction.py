"""
NightCrawler - EffectivePolicy Strict Construction & Field Audit Suite

Verifies:
1. authorized_providers containing "*", "all", IP literals, numbers, nested collections, and invalid hostnames raise ValueError.
2. Invalid collection types (strings, dicts, integers, booleans) raise ValueError.
3. Valid collections (list, tuple, set, frozenset, None, empty) are normalized and stored as frozensets.
4. Reassignment after initialization is strictly rejected with AttributeError.
5. Invalid direct construction fails before any HTTP transport, scanner, or validator can be initialized.
6. Valid policy construction preserves provider narrowing and immutability invariants.
"""

import pytest
from unittest.mock import MagicMock, patch

from src.core.program_profile import ProgramProfile, ScopeDefinition, RequestPolicyDefinition, TestingPermissionsDefinition
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.http_client import NightCrawlerHttpClient
from src.validators.keyhacks import KeyHacksValidator
from src.core.scanner import NightCrawlerScanner


def make_dummy_policy_args(**kwargs):
    """Generate valid baseline arguments for direct EffectivePolicy construction."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    rpm = RequestPolicyManager(concurrency_limit=2, max_rps=10.0)
    args = {
        "program_id": "test-prog",
        "program_name": "Test Program",
        "version": "1.0.0",
        "platform": "Generic",
        "policy_url": "https://example.com/policy",
        "description": "Test policy",
        "scope_manager": scope,
        "request_policy_manager": rpm,
        "auth_manager": None,
        "permission_manager": None,
        "tool_compatibility_manager": None,
        "audit_logger": None,
        "max_rps": 10.0,
        "per_host_rps": 2.0,
        "concurrency": 2,
        "timeout": 10,
        "crawl_depth": 3,
        "verify_tls": True,
        "strict_scope": True,
        "scope_enabled": True,
        "default_template": "markdown",
        "default_format": "md",
        "reporter_name": "Researcher",
        "reporter_email": "researcher@example.com",
        "validate_keys": False,
        "requires_review": False,
        "review_notes": [],
        "authorized_providers": frozenset({"slack.com"}),
        "allow_state_changing": False
    }
    args.update(kwargs)
    return args


# ==============================================================================
# 1. Rejection of Wildcards, IP Literals, Numbers, and Nested Collections
# ==============================================================================

@pytest.mark.parametrize("invalid_providers", [
    ["*"],
    ["all"],
    ["slack.com", "*"],
    ["all", "github.com"],
    {"*"},
    {"all"},
    ("all",),
    frozenset({"*"}),
])
def test_effective_policy_rejects_wildcard_providers(invalid_providers):
    """Direct EffectivePolicy construction strictly rejects '*' and 'all' wildcards."""
    args = make_dummy_policy_args(authorized_providers=invalid_providers)
    with pytest.raises(ValueError, match="Wildcard '.*' is prohibited"):
        EffectivePolicy(**args)


@pytest.mark.parametrize("ip_literal", [
    ["192.168.1.1"],
    ["10.0.0.1"],
    ["127.0.0.1"],
    ["[::1]"],
    ["::1"],
    {"172.16.0.1"},
    ("1.1.1.1",),
])
def test_effective_policy_rejects_ip_literal_providers(ip_literal):
    """Direct EffectivePolicy construction strictly rejects IP literals in authorized_providers."""
    args = make_dummy_policy_args(authorized_providers=ip_literal)
    with pytest.raises(ValueError, match="(IP address literals|Invalid provider entry)"):
        EffectivePolicy(**args)


@pytest.mark.parametrize("invalid_entries", [
    ["aws", 123],
    [123, 456],
    [["aws"]],
    [{"name": "aws"}],
    ["aws", None],
    ["aws", True],
])
def test_effective_policy_rejects_numbers_and_nested_collections(invalid_entries):
    """Direct EffectivePolicy construction rejects numbers, nested collections, and non-strings."""
    args = make_dummy_policy_args(authorized_providers=invalid_entries)
    with pytest.raises(ValueError, match="authorized_providers entries in EffectivePolicy must be strings"):
        EffectivePolicy(**args)


@pytest.mark.parametrize("bad_name", [
    ["aws; rm -rf /"],
    ["aws/bucket"],
    ["aws?query=1"],
    ["aws#frag"],
    [""],
    ["   "],
    ["com"],
    [".net"],
    [".org"],
])
def test_effective_policy_rejects_invalid_hostname_strings(bad_name):
    """Direct EffectivePolicy construction rejects command injection, slashes, empty strings, and TLDs."""
    args = make_dummy_policy_args(authorized_providers=bad_name)
    with pytest.raises(ValueError):
        EffectivePolicy(**args)


# ==============================================================================
# 2. Rejection of Invalid Collection Types (Strings, Dicts, Ints)
# ==============================================================================

@pytest.mark.parametrize("invalid_type_val", [
    "slack",
    "slack.com",
    123,
    True,
    False,
    {"provider": "slack"},
    {"slack": True},
    object(),
])
def test_effective_policy_rejects_invalid_collection_types(invalid_type_val):
    """Direct EffectivePolicy construction rejects non-collection types (strings, ints, dicts)."""
    args = make_dummy_policy_args(authorized_providers=invalid_type_val)
    with pytest.raises(ValueError, match="authorized_providers in EffectivePolicy must be a list of strings"):
        EffectivePolicy(**args)


# ==============================================================================
# 3. Normalization and Frozen Storage of Valid Collections
# ==============================================================================

def test_effective_policy_normalizes_and_stores_valid_collections_as_frozensets():
    """Valid list, tuple, set, and frozenset inputs are deduplicated, normalized, and stored as frozensets."""
    # List with spaces and casing
    p1 = EffectivePolicy(**make_dummy_policy_args(authorized_providers=["  AWS  ", "aws", "Google", "slack.com"]))
    assert isinstance(p1.authorized_providers, frozenset)
    assert p1.authorized_providers == frozenset({"aws", "google", "slack.com"})

    # Set
    p2 = EffectivePolicy(**make_dummy_policy_args(authorized_providers={"slack.com", "github.com"}))
    assert isinstance(p2.authorized_providers, frozenset)
    assert p2.authorized_providers == frozenset({"slack.com", "github.com"})

    # Tuple
    p3 = EffectivePolicy(**make_dummy_policy_args(authorized_providers=("slack.com",)))
    assert isinstance(p3.authorized_providers, frozenset)
    assert p3.authorized_providers == frozenset({"slack.com"})

    # Frozenset
    p4 = EffectivePolicy(**make_dummy_policy_args(authorized_providers=frozenset({"slack.com"})))
    assert isinstance(p4.authorized_providers, frozenset)
    assert p4.authorized_providers == frozenset({"slack.com"})

    # Empty list
    p5 = EffectivePolicy(**make_dummy_policy_args(authorized_providers=[]))
    assert isinstance(p5.authorized_providers, frozenset)
    assert p5.authorized_providers == frozenset()

    # None
    p6 = EffectivePolicy(**make_dummy_policy_args(authorized_providers=None))
    assert isinstance(p6.authorized_providers, frozenset)
    assert p6.authorized_providers == frozenset()


# ==============================================================================
# 4. Immutability Lock Verification
# ==============================================================================

def test_effective_policy_reassignment_rejected():
    """Attempting to mutate or reassign authorized_providers after construction raises AttributeError."""
    policy = EffectivePolicy(**make_dummy_policy_args(authorized_providers=["slack.com"]))

    # Attribute reassignment must fail
    with pytest.raises(AttributeError, match="immutable"):
        policy.authorized_providers = {"new-provider.com"}

    with pytest.raises(AttributeError, match="immutable"):
        policy.authorized_providers = None

    with pytest.raises(AttributeError, match="immutable"):
        policy.authorized_providers = frozenset({"slack.com"})

    # In-place set mutations must fail
    with pytest.raises(AttributeError):
        policy.authorized_providers.add("attacker.test")


# ==============================================================================
# 5. Invalid Direct Construction Fails Before Transports Can Be Initialized
# ==============================================================================

def test_invalid_direct_construction_fails_before_http_transport_or_scanner():
    """Invalid policy construction aborts before any HTTP client, validator, or scanner can be constructed."""
    args = make_dummy_policy_args(authorized_providers=["attacker; injection"])

    policy_created = False
    try:
        policy = EffectivePolicy(**args)
        policy_created = True
        # If policy creation had succeeded, downstream components would be initialized
        client = NightCrawlerHttpClient(effective_policy=policy)
        validator = KeyHacksValidator(effective_policy=policy)
        scanner = NightCrawlerScanner(effective_policy=policy)
    except ValueError:
        pass

    assert not policy_created, "EffectivePolicy with invalid providers must not be constructed"


# ==============================================================================
# 6. Preservation of Policy Provider Narrowing Behavior
# ==============================================================================

def test_valid_policy_construction_preserves_provider_narrowing():
    """Valid program profile and CLI overrides preserve strict narrowing and immutable boundaries."""
    prof = ProgramProfile(
        id="test-narrowing",
        name="Test Narrowing Program",
        version="1.0.0",
        platform="HackerOne",
        scope=ScopeDefinition(enabled=True, allowed_domains=["example.com"]),
        request_policy=RequestPolicyDefinition(max_rps=10.0, concurrency=2, strict_scope=True, verify_tls=True),
        testing_permissions=TestingPermissionsDefinition(credential_validation=True, state_changing_allowed=True),
        authorized_providers=["slack.com", "github.com"]
    )

    # CLI narrows to slack.com only
    policy = EffectivePolicy.build(profile=prof, cli_overrides={"authorized_providers": ["slack.com"]})
    assert policy.authorized_providers == frozenset({"slack.com"})

    # Client constructed with policy
    client = NightCrawlerHttpClient(effective_policy=policy)
    assert client.authorized_providers == frozenset({"slack.com"})

    assert client.is_provider_authorized("slack", "https://slack.com/api/test") is True
    assert client.is_provider_authorized("github", "https://github.com/api/test") is False
