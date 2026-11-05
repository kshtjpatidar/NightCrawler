"""
NightCrawler - Release Candidate Startup Integration & Numeric Edge-Case Verification
=====================================================================================
Validates all mandatory security invariants during application startup and CLI entry:
1. Invalid profiles, config files, and environment variables fail closed before any scanner,
   HTTP session, TCP connector, or subprocess creation.
2. Strict-scope profiles cannot disable TLS verification through CLI or config overrides.
3. Empty scope cannot start a scoped scan.
4. Provider allowlists cannot be expanded through CLI, scanner, KeyHacks, or direct HTTP client.
5. Startup errors do not leak canary secrets into logs, stderr, or stdout.
6. Extreme integers (10**100, 10**1000) and unusual numeric types (Decimal, complex, Fraction)
   fail consistently with PolicyValidationError (subclass of ValueError and TypeError).
"""

import os
import errno
import math
import tempfile
from pathlib import Path
from decimal import Decimal
from fractions import Fraction
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from main import main
from src.core.effective_policy import EffectivePolicy, PolicyValidationError
from src.core.program_profile import (
    ProgramProfile, ScopeDefinition, RequestPolicyDefinition,
    strict_positive_float, strict_positive_int
)
from src.core.program_manager import ProgramManager, safe_lexists
from src.core.request_config import NightCrawlerConfig
from src.core.http_client import NightCrawlerHttpClient
from src.validators.keyhacks import KeyHacksValidator
from src.core.scanner import NightCrawlerScanner


@pytest.fixture
def example_profile():
    pm = ProgramManager()
    profile = pm.get_profile("example-program")
    assert profile is not None
    return profile


# ============================================================================
# SECTION 1: STARTUP INTEGRATION COVERAGE (CLI ENTRY POINTS & SPIES)
# ============================================================================

def test_startup_nonexistent_profile_fails_before_network_and_scanner():
    """Verify nonexistent profile fails immediately before scanner or network session creation."""
    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["--program", "nonexistent_target_profile_999", "-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()
        assert mock_scanner.call_count == 0, "NightCrawlerScanner must not be instantiated on invalid profile"
        assert mock_session.call_count == 0, "aiohttp.ClientSession must not be created on invalid profile"
        assert mock_conn.call_count == 0, "aiohttp.TCPConnector must not be created on invalid profile"
        assert mock_popen.call_count == 0, "subprocess.Popen must not be invoked on invalid profile"


def test_startup_corrupted_yaml_profile_fails_before_network_and_scanner(tmp_path):
    """Verify malformed/corrupted profile YAML fails before network or scanner initialization."""
    corrupt_file = tmp_path / "corrupt_program.yaml"
    corrupt_file.write_text("id: corrupt-target\nname: Corrupt\nscope: [this is invalid yaml: : :\n")

    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen, \
         patch("src.core.program_manager.ProgramManager.get_profile", side_effect=ValueError("Corrupted YAML")):

        result = runner.invoke(main, ["--program", "corrupt-target", "-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "error" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


@pytest.mark.parametrize("invalid_rps", ["invalid", "0", "-1", "-5.5", "NaN", "Infinity", "1e1000"])
def test_startup_invalid_environment_rps_fails_before_network(invalid_rps):
    """Verify invalid NIGHTCRAWLER_MAX_RPS fails before scanner or network initialization."""
    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"], env={"NIGHTCRAWLER_MAX_RPS": invalid_rps})

        assert result.exit_code != 0
        assert "config error" in result.output.lower() or "error" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


@pytest.mark.parametrize("invalid_concurrency", ["0", "-1", "-10", "NaN", "abc", "1.5"])
def test_startup_invalid_environment_concurrency_fails_before_network(invalid_concurrency):
    """Verify invalid NIGHTCRAWLER_CONCURRENCY fails before scanner or network initialization."""
    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"], env={"NIGHTCRAWLER_CONCURRENCY": invalid_concurrency})

        assert result.exit_code != 0
        assert "config error" in result.output.lower() or "error" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_startup_strict_scope_profile_cannot_disable_tls_via_cli():
    """Verify strict-scope profile (uxcam) rejects --no-verify-tls CLI override before network calls."""
    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn:

        result = runner.invoke(main, ["--program", "uxcam", "-t", "uxcam.com", "--no-verify-tls", "--no-prompt"])

        assert result.exit_code != 0
        assert "security violation" in result.output.lower() or "insecure tls configuration is prohibited" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0


def test_startup_strict_scope_profile_cannot_disable_tls_via_config(tmp_path):
    """Verify strict-scope profile rejects config file setting verify_tls: false."""
    insecure_cfg = tmp_path / "insecure_config.yaml"
    insecure_cfg.write_text("scan:\n  strict_scope: true\n  verify_tls: false\n")

    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn:

        result = runner.invoke(main, ["--config-file", str(insecure_cfg), "-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "security violation" in result.output.lower() or "insecure tls configuration is prohibited" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0


def test_startup_empty_scope_cannot_start_scoped_scan_from_profile():
    """Verify a program profile with scope enabled but no allowed targets fails closed immediately."""
    empty_profile = ProgramProfile(
        id="empty-scope-app",
        name="Empty Scope App",
        scope=ScopeDefinition(enabled=True, allowed_domains=[], allowed_ips=[], allowed_cidrs=[]),
        requires_review=False
    )
    runner = CliRunner()
    with patch("main.ProgramManager.get_profile", return_value=empty_profile), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session:

        result = runner.invoke(main, ["--program", "empty-scope-app", "-t", "https://example.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed policy validation" in result.output.lower() or "defines no allowed domains" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0


def test_startup_empty_scope_cannot_start_scoped_scan_from_config():
    """Verify base config with scope enabled and empty allowed_domains fails closed immediately."""
    empty_cfg = NightCrawlerConfig()
    empty_cfg.scope_enabled = True
    empty_cfg.allowed_domains = []

    runner = CliRunner()
    with patch("main.ProgramManager.get_profile", return_value=None), \
         patch("main.load_config", return_value=empty_cfg), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session:

        result = runner.invoke(main, ["-t", "https://example.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "target scope cannot be empty" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0


def test_startup_provider_allowlist_expansion_rejected_via_cli():
    """Verify CLI --authorized-provider cannot expand beyond profile allowlist."""
    runner = CliRunner()
    with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session:

        result = runner.invoke(main, [
            "--program", "uxcam",
            "--authorized-provider", "unauthorized-malicious-provider.com",
            "-t", "uxcam.com",
            "--no-prompt"
        ])

        assert result.exit_code != 0
        assert "cannot expand" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0


def test_startup_provider_allowlist_expansion_rejected_via_scanner_and_keyhacks(example_profile):
    """Verify scanner and KeyHacksValidator reject allowlist expansion beyond EffectivePolicy."""
    example_profile.authorized_providers = ["slack.com", "api.stripe.com"]
    policy = EffectivePolicy.build(profile=example_profile)

    # 1. Direct construction of KeyHacksValidator with expanded providers is rejected
    with pytest.raises(ValueError, match="cannot expand authorized_providers"):
        KeyHacksValidator(
            effective_policy=policy,
            authorized_providers={"slack.com", "api.stripe.com", "attacker.com"}
        )

    # 2. KeyHacksValidator.from_policy with expanded providers is rejected
    with pytest.raises(ValueError, match="cannot expand authorized_providers"):
        KeyHacksValidator.from_policy(
            effective_policy=policy,
            authorized_providers={"attacker.com"}
        )

    # 3. NightCrawlerHttpClient with expanded providers is rejected
    with pytest.raises(ValueError, match="Constructor cannot expand authorized_providers"):
        NightCrawlerHttpClient(
            effective_policy=policy,
            authorized_providers={"slack.com", "api.stripe.com", "attacker.com"}
        )


def test_startup_errors_do_not_expose_canary_secrets():
    """Verify startup failures (invalid config/profile) do not expose synthetic canary secrets in outputs."""
    canary_researcher = "SYNTHETIC_CANARY_SECRET_RESEARCHER_98765"
    canary_token = "SYNTHETIC_CANARY_TOKEN_ABCDEF123456"

    runner = CliRunner()
    env = {
        "NIGHTCRAWLER_RESEARCHER_ID": canary_researcher,
        "NIGHTCRAWLER_TOKEN": canary_token,
        "NIGHTCRAWLER_MAX_RPS": "invalid_numeric_rps"
    }

    result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"], env=env)

    assert result.exit_code != 0
    assert canary_researcher not in result.output, "Canary researcher secret leaked in error output!"
    assert canary_token not in result.output, "Canary token leaked in error output!"


# ============================================================================
# SECTION 2: NUMERIC EDGE-CASE CONSISTENCY (LARGE INTS, DECIMALS, TYPES)
# ============================================================================

@pytest.fixture
def valid_policy_kwargs(example_profile):
    """Minimal valid kwargs to instantiate EffectivePolicy directly."""
    policy = EffectivePolicy.build(profile=example_profile)
    return {
        "program_id": policy.program_id,
        "program_name": policy.program_name,
        "version": policy.version,
        "platform": policy.platform,
        "policy_url": policy.policy_url,
        "description": policy.description,
        "scope_manager": policy.scope_manager,
        "request_policy_manager": policy.request_policy_manager,
        "auth_manager": policy.auth_manager,
        "permission_manager": policy.permission_manager,
        "tool_compatibility_manager": policy.tool_compatibility_manager,
        "audit_logger": policy.audit_logger,
        "max_rps": 5.0,
        "per_host_rps": 5.0,
        "concurrency": 2,
        "timeout": 30,
        "crawl_depth": 1,
        "verify_tls": True,
        "strict_scope": True,
        "scope_enabled": True,
        "default_template": "bugcrowd",
        "default_format": "html",
        "reporter_name": "Security Researcher",
        "reporter_email": "researcher@example.com",
        "validate_keys": False,
        "requires_review": False,
        "review_notes": [],
        "authorized_providers": frozenset(),
        "allow_state_changing": False
    }


@pytest.mark.parametrize("field_name", ["max_rps", "per_host_rps", "concurrency", "timeout", "crawl_depth"])
@pytest.mark.parametrize("large_val", [10**100, 10**1000])
def test_numeric_edge_case_extremely_large_integers_fail_policy_validation(valid_policy_kwargs, field_name, large_val):
    """Verify extremely large integers (10**100, 10**1000) fail with PolicyValidationError."""
    kwargs = dict(valid_policy_kwargs)
    kwargs[field_name] = large_val

    with pytest.raises(PolicyValidationError) as exc_info:
        EffectivePolicy(**kwargs)
    assert any(keyword in str(exc_info.value).lower() for keyword in ["exceeds", "bounds", "limit", "overflow"])


@pytest.mark.parametrize("field_name", ["max_rps", "per_host_rps", "concurrency", "timeout", "crawl_depth"])
@pytest.mark.parametrize("unusual_val", [
    Decimal("5.0"),
    complex(1, 2),
    Fraction(5, 1),
    {"num": 5},
    [5],
    object()
])
def test_numeric_edge_case_unusual_types_fail_policy_validation(valid_policy_kwargs, field_name, unusual_val):
    """Verify unusual numeric types (Decimal, complex, Fraction, custom object) fail with PolicyValidationError."""
    kwargs = dict(valid_policy_kwargs)
    kwargs[field_name] = unusual_val

    with pytest.raises(PolicyValidationError):
        EffectivePolicy(**kwargs)


@pytest.mark.parametrize("field_name", ["max_rps", "per_host_rps"])
@pytest.mark.parametrize("non_finite_val", [float("nan"), float("inf"), float("-inf")])
def test_numeric_edge_case_non_finite_floats_fail_policy_validation(valid_policy_kwargs, field_name, non_finite_val):
    """Verify NaN, +inf, -inf on float fields fail with PolicyValidationError."""
    kwargs = dict(valid_policy_kwargs)
    kwargs[field_name] = non_finite_val

    with pytest.raises(PolicyValidationError) as exc_info:
        EffectivePolicy(**kwargs)
    assert "finite" in str(exc_info.value).lower() or "nan" in str(exc_info.value).lower()


@pytest.mark.parametrize("field_name", ["max_rps", "per_host_rps", "concurrency", "timeout", "crawl_depth"])
@pytest.mark.parametrize("non_positive_val", [0, -1, -5, -0.001])
def test_numeric_edge_case_zero_and_negative_fail_policy_validation(valid_policy_kwargs, field_name, non_positive_val):
    """Verify zero and negative numbers fail with PolicyValidationError."""
    kwargs = dict(valid_policy_kwargs)
    kwargs[field_name] = non_positive_val

    with pytest.raises(PolicyValidationError) as exc_info:
        EffectivePolicy(**kwargs)
    err = str(exc_info.value).lower()
    assert any(keyword in err for keyword in ["positive", "integer", "numeric"])


@pytest.mark.parametrize("int_field", ["concurrency", "timeout", "crawl_depth"])
@pytest.mark.parametrize("coercible_val", [1.0, 5.5, True, False, "10", "1"])
def test_numeric_edge_case_integer_fields_reject_coercible_types(valid_policy_kwargs, int_field, coercible_val):
    """Verify integer-only fields reject floats, booleans, and strings without coercing."""
    kwargs = dict(valid_policy_kwargs)
    kwargs[int_field] = coercible_val

    with pytest.raises(PolicyValidationError) as exc_info:
        EffectivePolicy(**kwargs)
    assert "integer" in str(exc_info.value).lower()


def test_strict_helpers_convert_overflow_and_unusual_types_to_clean_errors():
    """Verify strict_positive_float and strict_positive_int reject extreme numbers and unusual types."""
    # 1. Float helper: extreme integer conversion overflow
    with pytest.raises(ValueError, match="Invalid numeric value|exceeds"):
        strict_positive_float(10**1000, "rps")

    with pytest.raises(ValueError, match="exceeds"):
        strict_positive_float(10**100, "rps")

    with pytest.raises(TypeError, match="Expected numeric value"):
        strict_positive_float(True, "rps")

    with pytest.raises(TypeError, match="Expected numeric value"):
        strict_positive_float(Decimal("5.0"), "rps")

    with pytest.raises(TypeError, match="Expected numeric value"):
        strict_positive_float(complex(1, 2), "rps")

    # 2. Integer helper: extreme integer conversion overflow
    with pytest.raises(ValueError, match="Invalid integer value|exceeds"):
        strict_positive_int(10**1000, "concurrency")

    with pytest.raises(ValueError, match="exceeds"):
        strict_positive_int(10**100, "concurrency")

    with pytest.raises(TypeError, match="Expected integer"):
        strict_positive_int(True, "concurrency")

    with pytest.raises(TypeError, match="Expected integer"):
        strict_positive_int(1.5, "concurrency")

    with pytest.raises(TypeError, match="Expected integer"):
        strict_positive_int(Decimal("5"), "concurrency")


# ============================================================================
# SECTION 3: FINDING 1 - STRICT PROFILE NUMERIC PARSING (NO SILENT COERCION)
# ============================================================================

@pytest.fixture
def base_profile_dict():
    """Valid base profile dictionary for mutation testing."""
    return {
        "id": "audit-target",
        "name": "Audit Target",
        "version": "1.0.0",
        "scope": {
            "enabled": True,
            "allowed_domains": ["audit.example.com"]
        },
        "request_policy": {
            "max_rps": 5.0,
            "per_host_rps": 5.0,
            "concurrency": 2,
            "timeout": 30,
            "crawl_depth": 1,
            "max_retries": 2,
            "burst": 1
        }
    }


@pytest.mark.parametrize("field_name", ["concurrency", "timeout", "crawl_depth", "max_retries", "burst"])
@pytest.mark.parametrize("coercive_val", [
    True,
    False,
    2.5,
    2.0,
    1.0,
    "10",
    "1",
    "abc",
    Decimal("5"),
    complex(1, 2),
    10**1000,
    10_000_000
])
def test_program_profile_from_dict_rejects_integer_coercion(base_profile_dict, field_name, coercive_val):
    """Verify ProgramProfile.from_dict rejects booleans, floats, strings, and overflow in integer fields."""
    data = dict(base_profile_dict)
    data["request_policy"] = dict(base_profile_dict["request_policy"])
    data["request_policy"][field_name] = coercive_val

    with pytest.raises((ValueError, TypeError, PolicyValidationError)) as exc_info:
        ProgramProfile.from_dict(data)

    err = str(exc_info.value).lower()
    assert field_name in err, f"Error message must identify field '{field_name}', got: {exc_info.value}"


@pytest.mark.parametrize("field_name", ["concurrency", "timeout", "crawl_depth", "burst"])
@pytest.mark.parametrize("non_positive_int", [0, -1, -5])
def test_program_profile_from_dict_rejects_non_positive_integers(base_profile_dict, field_name, non_positive_int):
    """Verify ProgramProfile.from_dict rejects zero and negative values for positive-only integer fields."""
    data = dict(base_profile_dict)
    data["request_policy"] = dict(base_profile_dict["request_policy"])
    data["request_policy"][field_name] = non_positive_int

    with pytest.raises((ValueError, TypeError, PolicyValidationError)) as exc_info:
        ProgramProfile.from_dict(data)

    err = str(exc_info.value).lower()
    assert field_name in err


@pytest.mark.parametrize("field_name", ["max_rps", "per_host_rps"])
@pytest.mark.parametrize("coercive_rate_val", [
    True,
    False,
    "5.0",
    "10",
    "abc",
    0,
    0.0,
    -1,
    -5.0,
    float("nan"),
    float("inf"),
    float("-inf"),
    Decimal("5.0"),
    complex(1, 2),
    10**1000,
    10_000_000
])
def test_program_profile_from_dict_rejects_float_rate_coercion(base_profile_dict, field_name, coercive_rate_val):
    """Verify ProgramProfile.from_dict rejects booleans, strings, non-positive, NaN, Inf, and overflow in rate fields."""
    data = dict(base_profile_dict)
    data["request_policy"] = dict(base_profile_dict["request_policy"])
    data["request_policy"][field_name] = coercive_rate_val

    with pytest.raises((ValueError, TypeError, PolicyValidationError)) as exc_info:
        ProgramProfile.from_dict(data)

    err = str(exc_info.value).lower()
    assert field_name in err, f"Error message must identify field '{field_name}', got: {exc_info.value}"


@pytest.mark.parametrize("invalid_port", [True, False, 80.5, 443.0, "80", "443", 0, -1, 70000, 10**1000])
def test_program_profile_scope_allowed_ports_rejects_coercion(base_profile_dict, invalid_port):
    """Verify ProgramProfile.from_dict rejects booleans, floats, strings, and out-of-range ports."""
    data = dict(base_profile_dict)
    data["scope"] = dict(base_profile_dict["scope"])
    data["scope"]["allowed_ports"] = [80, invalid_port]

    with pytest.raises((ValueError, TypeError, PolicyValidationError)) as exc_info:
        ProgramProfile.from_dict(data)

    err = str(exc_info.value).lower()
    assert "port" in err or "allowed_ports" in err


# ============================================================================
# SECTION 4: FINDING 2 - DEFAULT PROFILE FALLBACK & ERROR DISTINCTION
# ============================================================================

def test_default_profile_missing_falls_back_to_valid_config():
    """Verify that when no default profile exists on disk, main falls back to independent config validation."""
    runner = CliRunner()
    with patch("src.core.program_manager.ProgramManager.profile_exists", return_value=False), \
         patch("src.core.program_manager.ProgramManager.get_profile", return_value=None), \
         patch("src.core.scanner.NightCrawlerScanner.__init__", return_value=None) as mock_scanner, \
         patch("asyncio.run", return_value=None):

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        # Scan should proceed without error using fallback configuration
        assert "failed to load default program profile" not in result.output.lower()
        assert "policy error" not in result.output.lower()
        assert mock_scanner.call_count == 1, "Scanner should be initialized using valid fallback configuration"


def test_default_profile_malformed_yaml_fails_closed_before_network():
    """Verify that malformed YAML in existing default profile aborts startup with non-zero exit."""
    runner = CliRunner()
    with patch("src.core.program_manager.ProgramManager.profile_exists", return_value=True), \
         patch("src.core.program_manager.ProgramManager.get_profile", side_effect=ValueError("YAML syntax error: unclosed bracket at line 4")), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed to load default program profile 'uxcam'" in result.output.lower()
        assert "yaml syntax error" in result.output.lower()
        assert mock_scanner.call_count == 0, "Scanner must not be instantiated when default profile is malformed"
        assert mock_session.call_count == 0, "HTTP session must not be created when default profile is malformed"
        assert mock_conn.call_count == 0, "TCP connector must not be created when default profile is malformed"
        assert mock_popen.call_count == 0, "Subprocess must not be launched when default profile is malformed"


def test_default_profile_unreadable_permission_denied_fails_closed_before_network():
    """Verify that permission error on existing default profile aborts startup with non-zero exit."""
    runner = CliRunner()
    with patch("src.core.program_manager.ProgramManager.profile_exists", return_value=True), \
         patch("src.core.program_manager.ProgramManager.get_profile", side_effect=PermissionError("Permission denied: 'programs/uxcam/program.yaml'")), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed to load default program profile 'uxcam'" in result.output.lower()
        assert "permission denied" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_invalid_policy_fails_closed_before_network():
    """Verify that invalid policy in existing default profile aborts startup before network activity."""
    runner = CliRunner()
    fake_profile = ProgramProfile(id="uxcam", name="UXCam Broken")
    with patch("src.core.program_manager.ProgramManager.profile_exists", return_value=True), \
         patch("src.core.program_manager.ProgramManager.get_profile", return_value=fake_profile), \
         patch("src.core.program_profile.PolicyValidator.validate", return_value=["Insecure TLS configuration is prohibited", "concurrency must be at least 1"]), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "default program profile 'uxcam' failed validation" in result.output.lower()
        assert "insecure tls configuration is prohibited" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_errors_do_not_leak_canary_secrets():
    """Verify default profile load errors do not leak canary secret tokens into output."""
    canary_secret = "SYNTHETIC_CANARY_SECRET_PROFILE_TOKEN_888"
    runner = CliRunner()
    with patch("src.core.program_manager.ProgramManager.profile_exists", return_value=True), \
         patch("src.core.program_manager.ProgramManager.get_profile", side_effect=ValueError("Corrupted profile data: syntax error")), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner:

        result = runner.invoke(
            main,
            ["-t", "uxcam.com", "--no-prompt"],
            env={"NIGHTCRAWLER_RESEARCHER_ID": canary_secret, "NIGHTCRAWLER_SECRET_KEY": canary_secret}
        )

        assert result.exit_code != 0
        assert canary_secret not in result.output, "Canary secret token was leaked in startup error output!"
        assert mock_scanner.call_count == 0


# ============================================================================
# SECTION 5: MULTI-PATH PROFILE INGESTION STRICT NUMERIC TESTS
# ============================================================================

@pytest.mark.parametrize("bad_val", [
    True, False, 2.5, "10", 0, -1, float("nan"), float("inf"), 10**1000
])
def test_all_profile_ingestion_paths_reject_invalid_concurrency(tmp_path, bad_val):
    """Verify that every supported profile ingestion path unconditionally rejects invalid concurrency values."""
    from src.core.program_profile import PolicyParser
    pm = ProgramManager(base_dir=tmp_path / "programs")

    raw_dict = {
        "id": "test-p",
        "name": "Test",
        "scope": {"allowed_domains": ["test.com"]},
        "request_policy": {"concurrency": bad_val}
    }
    # 1. ProgramProfile.from_dict
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        ProgramProfile.from_dict(raw_dict)

    # 2. PolicyParser.from_dict
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        PolicyParser.from_dict(raw_dict)

    # 3. PolicyParser.from_yaml_file
    y_file = tmp_path / "test.yaml"
    import yaml
    with open(y_file, "w") as f:
        yaml.dump(raw_dict, f)
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        PolicyParser.from_yaml_file(y_file)

    # 4. PolicyParser.from_json_file
    j_file = tmp_path / "test.json"
    import json
    try:
        with open(j_file, "w") as f:
            json.dump(raw_dict, f)
        with pytest.raises((ValueError, TypeError, PolicyValidationError)):
            PolicyParser.from_json_file(j_file)
    except (ValueError, OverflowError):
        pass

    # 5. ProgramManager.create_profile
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        pm.create_profile(raw_dict, save=False)


@pytest.mark.parametrize("bad_rps", [
    True, False, "5.0", 0.0, -1.0, float("nan"), float("inf"), 10**1000
])
def test_all_profile_ingestion_paths_reject_invalid_max_rps(tmp_path, bad_rps):
    """Verify that every supported profile ingestion path unconditionally rejects invalid max_rps values."""
    from src.core.program_profile import PolicyParser
    pm = ProgramManager(base_dir=tmp_path / "programs")

    raw_dict = {
        "id": "test-p",
        "name": "Test",
        "scope": {"allowed_domains": ["test.com"]},
        "request_policy": {"max_rps": bad_rps}
    }
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        ProgramProfile.from_dict(raw_dict)

    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        PolicyParser.from_dict(raw_dict)

    y_file = tmp_path / "test_rps.yaml"
    import yaml
    with open(y_file, "w") as f:
        yaml.dump(raw_dict, f)
    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        PolicyParser.from_yaml_file(y_file)

    with pytest.raises((ValueError, TypeError, PolicyValidationError)):
        pm.create_profile(raw_dict, save=False)


# ============================================================================
# SECTION 6: REAL FILESYSTEM & BROKEN INSTALLATION STARTUP SAFETY TESTS
# ============================================================================

def test_default_profile_empty_directory_fails_closed_before_network(tmp_path):
    """Verify empty default profile directory is not misclassified as absent, and fails closed with non-zero exit."""
    programs_dir = tmp_path / "programs"
    (programs_dir / "uxcam").mkdir(parents=True)

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "contains no recognized profile file" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_unexpected_filenames_fails_closed_before_network(tmp_path):
    """Verify default profile directory with only unexpected files fails closed with non-zero exit."""
    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)
    (uxcam_dir / "notes.txt").write_text("Not a profile")
    (uxcam_dir / "settings.ini").write_text("[section]\nfoo=bar")

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "contains no recognized profile file" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_both_yaml_and_json_fails_closed_before_network(tmp_path):
    """Verify presence of both program.yaml and program.json triggers deterministic ambiguous-profile error."""
    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)
    (uxcam_dir / "program.yaml").write_text("id: uxcam\nname: UXCam\nscope:\n  allowed_domains: [uxcam.com]\n")
    (uxcam_dir / "program.json").write_text('{"id": "uxcam", "name": "UXCam", "scope": {"allowed_domains": ["uxcam.com"]}}')

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "ambiguous profile configuration" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_unexpected_filesystem_object_file_fails_closed(tmp_path):
    """Verify regular file at programs/uxcam triggers unexpected filesystem object error and fails closed."""
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    (programs_dir / "uxcam").write_text("I am a regular file, not a directory")

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "unexpected filesystem object" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_broken_symlink_directory_fails_closed(tmp_path):
    """Verify broken symlink at programs/uxcam is not misclassified as absent and fails closed."""
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    sym_path = programs_dir / "uxcam"
    os.symlink("/nonexistent/target/path/uxcam_profile", sym_path)

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "broken symlink" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_profile_file_is_directory_fails_closed(tmp_path):
    """Verify directory named program.yaml inside profile directory triggers unexpected filesystem object error."""
    programs_dir = tmp_path / "programs"
    dir_as_file = programs_dir / "uxcam" / "program.yaml"
    dir_as_file.mkdir(parents=True)

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "unexpected filesystem object" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_profile_file_is_broken_symlink_fails_closed(tmp_path):
    """Verify broken symlink program.yaml triggers broken symlink error and fails closed."""
    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)
    os.symlink("/nonexistent/target/file.yaml", uxcam_dir / "program.yaml")

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: ProgramManager(base_dir=programs_dir)), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "broken symlink" in result.output.lower() or "failed to load default program profile" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_default_profile_valid_symlink_directory_loads_successfully(tmp_path):
    """Verify valid symlink to profile directory loads and validates successfully."""
    real_dir = tmp_path / "real_uxcam"
    real_dir.mkdir(parents=True)
    (real_dir / "program.yaml").write_text("id: uxcam\nname: UXCam\nscope:\n  allowed_domains: [uxcam.com]\nrequest_policy:\n  max_rps: 5.0\n")

    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    os.symlink(real_dir, programs_dir / "uxcam")

    pm = ProgramManager(base_dir=programs_dir)
    assert pm.profile_exists("uxcam") is True
    prof = pm.get_profile("uxcam")
    assert prof is not None
    assert prof.id == "uxcam"
    assert prof.request_policy.max_rps == 5.0


def test_default_profile_valid_symlink_file_loads_successfully(tmp_path):
    """Verify valid symlink to program.yaml loads and validates successfully."""
    real_yaml = tmp_path / "real.yaml"
    real_yaml.write_text("id: uxcam\nname: UXCam\nscope:\n  allowed_domains: [uxcam.com]\nrequest_policy:\n  max_rps: 5.0\n")

    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)
    os.symlink(real_yaml, uxcam_dir / "program.yaml")

    pm = ProgramManager(base_dir=programs_dir)
    assert pm.profile_exists("uxcam") is True
    prof = pm.get_profile("uxcam")
    assert prof is not None
    assert prof.id == "uxcam"
    assert prof.request_policy.max_rps == 5.0


def test_default_profile_genuinely_absent_fallback_independently_validated(tmp_path):
    """
    Verify that when default profile is genuinely absent according to documented rule:
    1. profile_exists returns False.
    2. get_profile returns None.
    3. main falls back to base config.
    4. base config is independently validated before any network initialization.
    """
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    # Genuinely absent: no uxcam directory or file

    pm = ProgramManager(base_dir=programs_dir)
    assert pm.profile_exists("uxcam") is False
    assert pm.get_profile("uxcam") is None

    runner = CliRunner()
    # Scenario A: Valid base configuration proceeds
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__", return_value=None) as mock_scanner, \
         patch("asyncio.run", return_value=None):

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt", "--header-value", "researcher@example.com"])
        assert "failed to load default program profile" not in result.output.lower()
        assert mock_scanner.call_count == 1

    # Scenario B: Invalid base configuration (e.g. max_rps <= 0) fails closed before any network initialization
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt", "--header-value", "researcher@example.com", "--max-rps", "-1.0"])
        assert result.exit_code != 0
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


# ============================================================================
# SECTION 7: FILESYSTEM DISCOVERY ERROR PROPAGATION (FINDING 1)
# ============================================================================

def test_filesystem_discovery_missing_programs_directory(tmp_path):
    """
    Verify that a demonstrably missing programs directory:
    1. Returns None from find_profile_path and get_profile.
    2. Returns False from profile_exists.
    3. Allows clean fallback to base configuration.
    """
    missing_dir = tmp_path / "missing_programs_dir"
    assert not missing_dir.exists()

    pm = ProgramManager(base_dir=missing_dir)
    assert pm.find_profile_path("uxcam") is None
    assert pm.profile_exists("uxcam") is False
    assert pm.get_profile("uxcam") is None

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__", return_value=None) as mock_scanner, \
         patch("asyncio.run", return_value=None):

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt", "--header-value", "researcher@example.com"])
        assert "failed to load default program profile" not in result.output.lower()
        assert mock_scanner.call_count == 1


def test_filesystem_discovery_existing_unreadable_programs_directory(tmp_path):
    """
    Verify that an existing but unreadable programs directory:
    1. Does NOT convert PermissionError to absence.
    2. Propagates PermissionError from find_profile_path, profile_exists, and get_profile.
    3. Fails closed with non-zero exit in main.py before any transport or scanner.
    """
    unreadable_dir = tmp_path / "unreadable_programs"
    unreadable_dir.mkdir(parents=True)
    os.chmod(unreadable_dir, 0o000)

    try:
        pm = ProgramManager(base_dir=unreadable_dir)

        with pytest.raises(PermissionError):
            pm.find_profile_path("uxcam")

        with pytest.raises(PermissionError):
            pm.profile_exists("uxcam")

        with pytest.raises(PermissionError):
            pm.get_profile("uxcam")

        runner = CliRunner()
        with patch("main.ProgramManager", lambda base_dir=None: pm), \
             patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
             patch("aiohttp.ClientSession.__init__") as mock_session, \
             patch("aiohttp.TCPConnector.__init__") as mock_conn, \
             patch("subprocess.Popen") as mock_popen:

            result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

            assert result.exit_code != 0
            assert "failed to load default program profile" in result.output.lower()
            assert "permission denied" in result.output.lower()
            assert mock_scanner.call_count == 0
            assert mock_session.call_count == 0
            assert mock_conn.call_count == 0
            assert mock_popen.call_count == 0
    finally:
        os.chmod(unreadable_dir, 0o755)


def test_filesystem_discovery_permission_failure_during_iteration(tmp_path):
    """
    Verify that PermissionError during directory iteration:
    1. Propagates out of find_profile_path, profile_exists, and get_profile.
    2. Fails closed with non-zero exit in main.py before any transport or scanner.
    """
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    pm = ProgramManager(base_dir=programs_dir)

    with patch.object(Path, "iterdir", side_effect=PermissionError("Iteration permission denied")):
        with pytest.raises(PermissionError):
            pm.find_profile_path("uxcam")

        with pytest.raises(PermissionError):
            pm.profile_exists("uxcam")

        with pytest.raises(PermissionError):
            pm.get_profile("uxcam")

        runner = CliRunner()
        with patch("main.ProgramManager", lambda base_dir=None: pm), \
             patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
             patch("aiohttp.ClientSession.__init__") as mock_session, \
             patch("aiohttp.TCPConnector.__init__") as mock_conn, \
             patch("subprocess.Popen") as mock_popen:

            result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

            assert result.exit_code != 0
            assert "failed to load default program profile" in result.output.lower()
            assert mock_scanner.call_count == 0
            assert mock_session.call_count == 0
            assert mock_conn.call_count == 0
            assert mock_popen.call_count == 0


def test_filesystem_discovery_io_error_during_iteration(tmp_path):
    """
    Verify that unexpected filesystem OSError (e.g. disk I/O error):
    1. Propagates out of find_profile_path, profile_exists, and get_profile.
    2. Fails closed with non-zero exit in main.py before any transport or scanner.
    """
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    pm = ProgramManager(base_dir=programs_dir)

    with patch.object(Path, "iterdir", side_effect=OSError(5, "Input/output error")):
        with pytest.raises(OSError) as exc_info:
            pm.find_profile_path("uxcam")
        assert exc_info.value.errno == 5

        with pytest.raises(OSError):
            pm.profile_exists("uxcam")

        with pytest.raises(OSError):
            pm.get_profile("uxcam")

        runner = CliRunner()
        with patch("main.ProgramManager", lambda base_dir=None: pm), \
             patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
             patch("aiohttp.ClientSession.__init__") as mock_session, \
             patch("aiohttp.TCPConnector.__init__") as mock_conn, \
             patch("subprocess.Popen") as mock_popen:

            result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

            assert result.exit_code != 0
            assert "failed to load default program profile" in result.output.lower()
            assert mock_scanner.call_count == 0
            assert mock_session.call_count == 0
            assert mock_conn.call_count == 0
            assert mock_popen.call_count == 0


def test_filesystem_discovery_genuinely_absent_uxcam_profile(tmp_path):
    """
    Verify that when programs/ exists and is readable, but uxcam is genuinely absent:
    1. find_profile_path returns None.
    2. profile_exists returns False.
    3. get_profile returns None.
    4. main falls back to base config without error.
    """
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    other_dir = programs_dir / "other-program"
    other_dir.mkdir()
    (other_dir / "program.yaml").write_text("id: other-program\nname: Other\n")

    pm = ProgramManager(base_dir=programs_dir)
    assert pm.find_profile_path("uxcam") is None
    assert pm.profile_exists("uxcam") is False
    assert pm.get_profile("uxcam") is None

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__", return_value=None) as mock_scanner, \
         patch("asyncio.run", return_value=None):

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt", "--header-value", "researcher@example.com"])
        assert "failed to load default program profile" not in result.output.lower()
        assert mock_scanner.call_count == 1


def test_filesystem_discovery_existing_invalid_uxcam_entry(tmp_path):
    """
    Verify that an existing but invalid uxcam profile entry:
    1. find_profile_path returns the path to the directory.
    2. profile_exists returns True.
    3. get_profile raises PolicyValidationError / ValueError.
    4. main fails closed with non-zero exit before any network initialization.
    """
    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)
    (uxcam_dir / "program.yaml").write_text("id: uxcam\nname: Broken\nrequest_policy:\n  max_rps: -10\n")

    pm = ProgramManager(base_dir=programs_dir)
    found_path = pm.find_profile_path("uxcam")
    assert found_path is not None
    assert found_path.name.lower() == "uxcam"
    assert pm.profile_exists("uxcam") is True

    with pytest.raises((PolicyValidationError, ValueError)):
        pm.get_profile("uxcam")

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed to load default program profile" in result.output.lower() or "failed validation" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


# ============================================================================
# SECTION 8: ENOTDIR FAIL-CLOSED DISCOVERY & ERROR PROPAGATION AUDIT
# ============================================================================

def test_safe_lexists_strict_absence_vs_errors(tmp_path):
    """
    Verify safe_lexists returns False ONLY for FileNotFoundError / ENOENT,
    and propagates NotADirectoryError (ENOTDIR), PermissionError (EACCES/EPERM),
    and unexpected OSError conditions (EIO).
    """
    # 1. Genuinely absent entry
    missing_entry = tmp_path / "absent_file.txt"
    assert safe_lexists(missing_entry) is False

    # 2. Existing regular file
    reg_file = tmp_path / "regular_file.txt"
    reg_file.write_text("hello")
    assert safe_lexists(reg_file) is True

    # 3. Existing directory
    reg_dir = tmp_path / "regular_dir"
    reg_dir.mkdir()
    assert safe_lexists(reg_dir) is True

    # 4. Broken symlink (must return True because the symlink itself exists)
    broken_sym = tmp_path / "broken_symlink"
    os.symlink("/nonexistent/target/path", broken_sym)
    assert safe_lexists(broken_sym) is True

    # 5. ENOTDIR: path component is a regular file
    file_as_dir = reg_file / "child.txt"
    with pytest.raises(NotADirectoryError):
        safe_lexists(file_as_dir)

    # 6. ENOTDIR via OSError with errno.ENOTDIR
    with patch("os.lstat", side_effect=OSError(20, "Not a directory")):
        with pytest.raises(OSError) as exc_info:
            safe_lexists(tmp_path / "some_path")
        assert exc_info.value.errno == 20

    # 7. EACCES PermissionError
    with patch("os.lstat", side_effect=PermissionError(13, "Permission denied")):
        with pytest.raises(PermissionError):
            safe_lexists(tmp_path / "denied_path")

    # 8. EPERM PermissionError
    with patch("os.lstat", side_effect=PermissionError(1, "Operation not permitted")):
        with pytest.raises(PermissionError):
            safe_lexists(tmp_path / "eperm_path")

    # 9. EIO OSError
    with patch("os.lstat", side_effect=OSError(5, "Input/output error")):
        with pytest.raises(OSError) as exc_info:
            safe_lexists(tmp_path / "eio_path")
        assert exc_info.value.errno == 5


def test_discovery_programs_is_regular_file_aborts_startup(tmp_path):
    """
    Verify that when programs/ exists as a regular file (not a directory):
    1. find_profile_path raises ValueError.
    2. profile_exists raises ValueError.
    3. get_profile raises ValueError.
    4. list_profiles raises ValueError.
    5. main.py aborts with non-zero exit before any transport/scanner/subprocess initialization.
    """
    programs_file = tmp_path / "programs"
    programs_file.write_text("not a directory")

    pm = ProgramManager(base_dir=programs_file)

    with pytest.raises(ValueError) as exc:
        pm.find_profile_path("uxcam")
    assert "not a directory" in str(exc.value).lower() or "unexpected filesystem object" in str(exc.value).lower()

    with pytest.raises(ValueError):
        pm.profile_exists("uxcam")

    with pytest.raises(ValueError):
        pm.get_profile("uxcam")

    with pytest.raises(ValueError):
        pm.list_profiles()

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed to load default program profile" in result.output.lower() or "unexpected filesystem object" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_discovery_ancestor_path_component_is_regular_file_aborts_startup(tmp_path):
    """
    Verify that when an ancestor path component of programs is a regular file:
    1. os.lstat raises NotADirectoryError.
    2. safe_lexists propagates NotADirectoryError (not returning False).
    3. find_profile_path, profile_exists, get_profile, list_profiles propagate NotADirectoryError.
    4. main.py aborts with non-zero exit before any transport/scanner/subprocess initialization.
    """
    file_ancestor = tmp_path / "ancestor_file"
    file_ancestor.write_text("file content")
    programs_dir = file_ancestor / "programs"

    pm = ProgramManager(base_dir=programs_dir)

    with pytest.raises(NotADirectoryError):
        pm.find_profile_path("uxcam")

    with pytest.raises(NotADirectoryError):
        pm.profile_exists("uxcam")

    with pytest.raises(NotADirectoryError):
        pm.get_profile("uxcam")

    with pytest.raises(NotADirectoryError):
        pm.list_profiles()

    runner = CliRunner()
    with patch("main.ProgramManager", lambda base_dir=None: pm), \
         patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
         patch("aiohttp.ClientSession.__init__") as mock_session, \
         patch("aiohttp.TCPConnector.__init__") as mock_conn, \
         patch("subprocess.Popen") as mock_popen:

        result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

        assert result.exit_code != 0
        assert "failed to load default program profile" in result.output.lower() or "not a directory" in result.output.lower()
        assert mock_scanner.call_count == 0
        assert mock_session.call_count == 0
        assert mock_conn.call_count == 0
        assert mock_popen.call_count == 0


def test_discovery_enotdir_during_profile_file_discovery_aborts_startup(tmp_path):
    """
    Verify that ENOTDIR during profile file lookup inside profile directory:
    1. Propagates NotADirectoryError from get_profile.
    2. Does NOT get misclassified as 'contains no recognized profile file' or absence.
    3. main.py aborts with non-zero exit before any transport/scanner/subprocess initialization.
    """
    programs_dir = tmp_path / "programs"
    uxcam_dir = programs_dir / "uxcam"
    uxcam_dir.mkdir(parents=True)

    pm = ProgramManager(base_dir=programs_dir)

    orig_safe_lexists = safe_lexists

    def mock_safe_lexists(p):
        path_str = str(p)
        if "program.yaml" in path_str or "program.json" in path_str:
            raise NotADirectoryError(20, "Not a directory")
        return orig_safe_lexists(p)

    with patch("src.core.program_manager.safe_lexists", side_effect=mock_safe_lexists):
        with pytest.raises(NotADirectoryError):
            pm.get_profile("uxcam")

        runner = CliRunner()
        with patch("main.ProgramManager", lambda base_dir=None: pm), \
             patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
             patch("aiohttp.ClientSession.__init__") as mock_session, \
             patch("aiohttp.TCPConnector.__init__") as mock_conn, \
             patch("subprocess.Popen") as mock_popen:

            result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

            assert result.exit_code != 0
            assert "failed to load default program profile" in result.output.lower()
            assert mock_scanner.call_count == 0
            assert mock_session.call_count == 0
            assert mock_conn.call_count == 0
            assert mock_popen.call_count == 0


def test_discovery_eperm_and_eacces_propagate_and_abort_startup(tmp_path):
    """
    Verify that EPERM and EACCES PermissionErrors:
    1. Propagate out of find_profile_path, profile_exists, and get_profile.
    2. Fail closed with non-zero exit in main.py before any network/scanner/subprocess initialization.
    """
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir(parents=True)
    pm = ProgramManager(base_dir=programs_dir)

    for error_cls, errno_val, msg in [
        (PermissionError, 1, "Operation not permitted"),  # EPERM
        (PermissionError, 13, "Permission denied"),       # EACCES
        (OSError, 5, "Input/output error"),               # EIO
    ]:
        err = error_cls(errno_val, msg)
        with patch.object(Path, "iterdir", side_effect=err):
            with pytest.raises(error_cls):
                pm.find_profile_path("uxcam")

            with pytest.raises(error_cls):
                pm.profile_exists("uxcam")

            with pytest.raises(error_cls):
                pm.get_profile("uxcam")

            runner = CliRunner()
            with patch("main.ProgramManager", lambda base_dir=None: pm), \
                 patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
                 patch("aiohttp.ClientSession.__init__") as mock_session, \
                 patch("aiohttp.TCPConnector.__init__") as mock_conn, \
                 patch("subprocess.Popen") as mock_popen:

                result = runner.invoke(main, ["-t", "uxcam.com", "--no-prompt"])

                assert result.exit_code != 0
                assert "failed to load default program profile" in result.output.lower()
                assert mock_scanner.call_count == 0
                assert mock_session.call_count == 0
                assert mock_conn.call_count == 0
                assert mock_popen.call_count == 0


