"""
NightCrawler - Consolidated Security Findings Regression Tests (NC-SEC-01 through NC-SEC-06)
Verifies:
- NC-SEC-01: Cross-origin credential leakage prevention and conservative header classification
- NC-SEC-02: Program ID path traversal defenses in ProgramManager (find, duplicate, import)
- NC-SEC-03: EffectivePolicy post-initialization immutability and authorized_providers lock
- NC-SEC-04: KeyHacks timeout validation in direct constructor, from_policy, and CLI parsing
- NC-SEC-05: Scope domain validation for allowed_domains and excluded_domains in PolicyValidator
- NC-SEC-06: Async test warning cleanup with proper coroutine closure
"""

import os
import sys
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import pytest
from click.testing import CliRunner

from main import main
from src.core.auth_manager import AuthenticationManager
from src.core.program_manager import ProgramManager, validate_program_id
from src.core.program_profile import (
    ProgramProfile, ScopeDefinition, RequestPolicyDefinition, TestingPermissionsDefinition,
    PolicyParser, PolicyValidator, PolicyValidationError, validate_domain_entry
)
from src.core.effective_policy import EffectivePolicy
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.permissions import TestingPermissionManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.audit_logger import AuditLogger
from src.validators.keyhacks import KeyHacksValidator


# ==============================================================================
# NC-SEC-01: Cross-Origin Credential Leakage Tests
# ==============================================================================

class TestCrossOriginCredentialLeakage:
    """Test suite for NC-SEC-01 credential isolation on cross-origin requests."""

    def test_case_insensitive_sensitive_header_classification(self):
        """Verify AuthenticationManager classifies credential headers case-insensitively."""
        sensitive_samples = [
            "Authorization", "AUTHORIZATION", "authorization", "AuThOrIzAtIoN",
            "Proxy-Authorization", "PROXY-AUTHORIZATION",
            "Cookie", "COOKIE", "cookie", "Set-Cookie", "SET-COOKIE",
            "X-API-Key", "X-Api-Key", "x-api-key", "API-KEY", "apikey",
            "Token", "TOKEN", "x-token", "X-Auth-Token", "x-user-token", "x-access-token",
            "Secret", "SECRET", "x-secret-token", "x-session-token", "Bearer", "x-bearer-token"
        ]
        for h in sensitive_samples:
            assert AuthenticationManager.is_sensitive_credential_header(h) is True, f"Failed to classify '{h}' as sensitive"

    def test_researcher_safe_headers_not_stripped(self):
        """Verify non-sensitive researcher headers are preserved by classifier."""
        safe_samples = [
            "User-Agent", "user-agent",
            "X-User-Id", "x-user-id",
            "X-Researcher-Email", "x-researcher-email",
            "X-Bug-Bounty", "x-bug-bounty",
            "X-Security-Scan", "x-security-scan",
            "X-Custom-Env", "Accept", "Content-Type"
        ]
        for h in safe_samples:
            assert AuthenticationManager.is_sensitive_credential_header(h) is False, f"Erroneously classified safe header '{h}' as sensitive"

    def test_cross_origin_request_strips_sensitive_custom_headers(self):
        """Cross-origin requests must strip custom API keys, tokens, and authorization headers."""
        scope = ScopeManager(allowed_domains=["example.com", "*.example.com", "partner.com"], enabled=True)
        auth = AuthenticationManager(
            required_headers={"X-User-Id": "researcher@example.com", "X-API-Key": "secret-key-123"},
            optional_headers={"X-Auth-Token": "bearer-token-456", "X-Custom-Env": "prod"},
            scope_manager=scope,
            raise_if_missing=False
        )

        # Same origin: all custom headers present
        same_origin = auth.get_headers_for_url(
            "https://example.com/api",
            scope_manager=scope,
            is_cross_origin=False
        )
        assert same_origin.get("X-User-Id") == "researcher@example.com"
        assert same_origin.get("X-Custom-Env") == "prod"
        assert same_origin.get("X-API-Key") == "secret-key-123"
        assert same_origin.get("X-Auth-Token") == "bearer-token-456"

        # Cross origin: sensitive credentials stripped, researcher headers preserved
        cross_origin = auth.get_headers_for_url(
            "https://partner.com/callback",
            scope_manager=scope,
            is_cross_origin=True
        )
        assert cross_origin.get("X-User-Id") == "researcher@example.com", "Researcher ID header should be preserved on cross-origin"
        assert cross_origin.get("X-Custom-Env") == "prod", "Custom non-credential header should be preserved"
        assert "X-API-Key" not in cross_origin, "X-API-Key must be stripped on cross-origin request!"
        assert "X-Auth-Token" not in cross_origin, "X-Auth-Token must be stripped on cross-origin request!"
        assert "Authorization" not in cross_origin, "Authorization must not be present on cross-origin request!"
        assert "Cookie" not in cross_origin, "Cookie must not be present on cross-origin request!"

    def test_out_of_scope_strips_all_program_headers(self):
        """Out of scope destination must receive zero program credentials or headers."""
        scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
        auth = AuthenticationManager(
            required_headers={"X-User-Id": "researcher@example.com"},
            scope_manager=scope,
            raise_if_missing=False
        )
        headers = auth.get_headers_for_url("https://attacker.com/leak", scope_manager=scope)
        assert "X-User-Id" not in headers
        assert "Authorization" not in headers
        assert "Cookie" not in headers


# ==============================================================================
# NC-SEC-02: Program ID Path Traversal Tests
# ==============================================================================

class TestProgramIDPathTraversal:
    """Test suite for NC-SEC-02 path traversal protections in ProgramManager."""

    @pytest.mark.parametrize("bad_id", [
        "../../outside",
        "../profile",
        "/tmp/evil",
        "C:\\Windows\\Temp",
        "profile/../../outside",
        "foo/bar",
        "foo\\bar",
        "id_with\x00null",
        "",
        "   ",
        "program.yaml",
        "id with space",
        "evil;cmd",
    ])
    def test_validate_program_id_rejects_traversal_and_malformed(self, bad_id):
        """Verify centralized validator strictly rejects path traversal patterns."""
        with pytest.raises(ValueError, match="Invalid program profile ID|cannot be empty"):
            validate_program_id(bad_id)

    @pytest.mark.parametrize("valid_id", [
        "uxcam",
        "example-program",
        "my_program_123",
        "TARGET-APP",
        "test-123_abc",
    ])
    def test_validate_program_id_accepts_clean_identifiers(self, valid_id):
        """Verify valid identifiers pass and normalize to lowercase."""
        clean = validate_program_id(valid_id)
        assert clean == valid_id.strip().lower()

    def test_find_profile_path_rejects_traversal(self, tmp_path):
        """Verify find_profile_path raises ValueError on traversal attempt."""
        pm = ProgramManager(base_dir=tmp_path / "programs")
        with pytest.raises(ValueError):
            pm.find_profile_path("../../etc/passwd")

    def test_duplicate_profile_rejects_traversal_and_overwrites(self, tmp_path):
        """Verify duplicate_profile prevents traversal and cannot overwrite existing directory."""
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        src_dir = programs_dir / "src-prog"
        src_dir.mkdir()
        (src_dir / "program.yaml").write_text("id: src-prog\nname: Source\nscope:\n  allowed_domains: [src.com]\nrequest_policy:\n  max_rps: 5.0\n")

        pm = ProgramManager(base_dir=programs_dir)

        # 1. Traversal ID rejected
        with pytest.raises(ValueError):
            pm.duplicate_profile("src-prog", "../../outside_copy")

        # 2. Duplicate to existing profile rejected
        with pytest.raises(ValueError, match="already exists"):
            pm.duplicate_profile("src-prog", "src-prog")

        # 3. Valid duplication succeeds
        dup = pm.duplicate_profile("src-prog", "valid-dup")
        assert dup.id == "valid-dup"
        assert (programs_dir / "valid-dup" / "program.yaml").exists()

    def test_import_profile_rejects_traversal_and_invalid_policy(self, tmp_path):
        """Verify import_profile rejects traversal IDs, prevents overwrites, and validates policy before saving."""
        programs_dir = tmp_path / "programs"
        programs_dir.mkdir()
        pm = ProgramManager(base_dir=programs_dir)

        # 1. Traversal ID in imported YAML string
        traversal_yaml = "id: ../../escape\nname: Escape\nscope:\n  allowed_domains: [escape.com]\nrequest_policy:\n  max_rps: 5.0\n"
        with pytest.raises(ValueError):
            pm.import_profile(traversal_yaml)

        # 2. Invalid policy rejected before writing file
        invalid_policy_yaml = "id: broken-policy\nname: Broken\nscope:\n  allowed_domains: [broken.com]\nrequest_policy:\n  max_rps: -5.0\n"
        with pytest.raises(ValueError, match="Invalid profile configuration"):
            pm.import_profile(invalid_policy_yaml)
        assert not (programs_dir / "broken-policy").exists()

        # 3. Valid import succeeds
        valid_yaml = "id: imported-good\nname: Good\nscope:\n  allowed_domains: [good.com]\nrequest_policy:\n  max_rps: 5.0\n"
        imported = pm.import_profile(valid_yaml)
        assert imported.id == "imported-good"
        assert (programs_dir / "imported-good" / "program.yaml").exists()

        # 4. Overwrite attempt rejected
        with pytest.raises(ValueError, match="already exists"):
            pm.import_profile(valid_yaml)


# ==============================================================================
# NC-SEC-03: EffectivePolicy Immutability Tests
# ==============================================================================

class TestEffectivePolicyImmutability:
    """Test suite for NC-SEC-03 post-initialization immutability lock."""

    def _create_sample_policy(self):
        scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
        rp = RequestPolicyManager(max_rps=5.0, per_host_rps=2.0)
        auth = AuthenticationManager()
        perm = TestingPermissionManager()
        tool = None
        audit = AuditLogger(program_id="test-prog")

        return EffectivePolicy(
            program_id="test-prog",
            program_name="Test Program",
            version="1.0.0",
            platform="HackerOne",
            policy_url="https://hackerone.com/test",
            description="Test Description",
            scope_manager=scope,
            request_policy_manager=rp,
            auth_manager=auth,
            permission_manager=perm,
            tool_compatibility_manager=tool,
            audit_logger=audit,
            max_rps=5.0,
            per_host_rps=2.0,
            concurrency=2,
            timeout=10,
            crawl_depth=2,
            verify_tls=True,
            strict_scope=True,
            scope_enabled=True,
            default_template="hackerone",
            default_format="html",
            reporter_name="Tester",
            reporter_email="tester@example.com",
            validate_keys=True,
            requires_review=False,
            authorized_providers=frozenset(["slack.com"])
        )

    def test_security_critical_fields_cannot_be_mutated(self):
        """Attempting to mutate security-critical policy fields after init must raise AttributeError."""
        policy = self._create_sample_policy()

        with pytest.raises(AttributeError, match="security-critical field 'verify_tls'"):
            policy.verify_tls = False

        with pytest.raises(AttributeError, match="security-critical field 'strict_scope'"):
            policy.strict_scope = False

        with pytest.raises(AttributeError, match="security-critical field 'max_rps'"):
            policy.max_rps = 100.0

        with pytest.raises(AttributeError, match="security-critical field 'concurrency'"):
            policy.concurrency = 10

        with pytest.raises(AttributeError, match="security-critical field 'scope_manager'"):
            policy.scope_manager = None

        with pytest.raises(AttributeError, match="authorized_providers"):
            policy.authorized_providers = ["evil.com"]

    def test_lock_attributes_cannot_be_tampered_with(self):
        """Attempting to clear lock flags must raise AttributeError."""
        policy = self._create_sample_policy()

        with pytest.raises(AttributeError, match="Cannot modify policy lock attribute"):
            policy._policy_locked = False

        with pytest.raises(AttributeError, match="Cannot modify policy lock attribute"):
            policy._authorized_providers_locked = False

    def test_validate_keys_can_only_be_narrowed(self):
        """validate_keys can be narrowed from True to False, but cannot be re-expanded."""
        policy = self._create_sample_policy()
        assert policy.validate_keys is True

        # Narrowing to False is allowed
        policy.validate_keys = False
        assert policy.validate_keys is False

        # Expanding back to True is blocked
        with pytest.raises(AttributeError, match="Cannot expand validate_keys"):
            policy.validate_keys = True

    def test_legitimate_late_binding_allowed(self):
        """Wiring http_client and audit_logger is permitted after construction."""
        policy = self._create_sample_policy()
        mock_client = MagicMock()
        mock_logger = MagicMock()

        policy.http_client = mock_client
        assert policy.http_client is mock_client

        policy.audit_logger = mock_logger
        assert policy.audit_logger is mock_logger


# ==============================================================================
# NC-SEC-04: KeyHacks Validation Timeout Tests
# ==============================================================================

class TestKeyHacksValidationTimeout:
    """Test suite for NC-SEC-04 timeout validation in KeyHacks."""

    @pytest.mark.parametrize("bad_timeout", [
        True, False, 10.5, "10", 0, -1, -10, 1_000_001
    ])
    def test_direct_constructor_rejects_invalid_timeout(self, bad_timeout):
        """KeyHacksValidator direct constructor rejects invalid timeout values."""
        with pytest.raises((TypeError, ValueError)):
            KeyHacksValidator(timeout=bad_timeout)

    @pytest.mark.parametrize("bad_timeout", [
        True, False, 5.5, "5", 0, -3, 2_000_000
    ])
    def test_from_policy_rejects_invalid_timeout_before_http_client(self, bad_timeout):
        """from_policy strictly rejects invalid timeout BEFORE any HTTP client initialization."""
        scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
        policy = EffectivePolicy(
            program_id="test", program_name="Test", version="1.0", platform="P",
            policy_url="", description="",
            scope_manager=scope,
            request_policy_manager=RequestPolicyManager(),
            auth_manager=AuthenticationManager(),
            permission_manager=TestingPermissionManager(),
            tool_compatibility_manager=None,
            audit_logger=AuditLogger(program_id="test"),
            max_rps=5.0, per_host_rps=2.0, concurrency=1, timeout=10, crawl_depth=1,
            verify_tls=True, strict_scope=True, scope_enabled=True,
            default_template="hackerone", default_format="html",
            reporter_name="T", reporter_email="", validate_keys=True, requires_review=False
        )

        with patch("src.core.http_client.NightCrawlerHttpClient.__init__") as mock_client:
            with pytest.raises((TypeError, ValueError)):
                KeyHacksValidator.from_policy(effective_policy=policy, timeout=bad_timeout)
            assert mock_client.call_count == 0, "HTTP client was initialized despite invalid timeout!"

    @pytest.mark.parametrize("cli_val", ["0", "-5", "abc", "10.5", "9999999999"])
    def test_cli_validate_timeout_rejects_invalid_input(self, cli_val):
        """CLI startup rejects invalid --validate-timeout before network operations."""
        runner = CliRunner()
        with patch("src.core.scanner.NightCrawlerScanner.__init__") as mock_scanner, \
             patch("aiohttp.ClientSession.__init__") as mock_session:

            result = runner.invoke(main, ["-t", "example.com", "--validate-timeout", cli_val, "--no-prompt"])
            assert result.exit_code != 0
            assert "invalid validate_timeout" in result.output.lower() or "not a valid integer" in result.output.lower()
            assert mock_scanner.call_count == 0
            assert mock_session.call_count == 0


# ==============================================================================
# NC-SEC-05: Scope Domain Validation Tests
# ==============================================================================

class TestScopeDomainValidation:
    """Test suite for NC-SEC-05 scope domain syntax validation."""

    @pytest.mark.parametrize("valid_domain", [
        "example.com",
        "*.example.com",
        "sub.domain.co.uk",
        "*.sub.domain.example.org",
        "münchen.de",
        "uxc.am",
        "*.uxc.am",
    ])
    def test_validate_domain_entry_accepts_valid_domains(self, valid_domain):
        """Valid DNS hostnames and standard wildcards must be accepted."""
        result = validate_domain_entry(valid_domain)
        assert result is not None

    @pytest.mark.parametrize("bad_domain", [
        "",
        "   ",
        "*",
        "all",
        "*.*",
        "http://example.com",
        "https://example.com",
        "example.com/path",
        "example.com?query=1",
        "example.com#fragment",
        "example .com",
        "example.com:8080",
        "user@example.com",
        "192.168.1.1",
        "10.0.0.1",
        "::1",
        "*example.com",
        "example*.com",
        "*.example.*",
        "*.com",
        "a" * 64 + ".com",
    ])
    def test_validate_domain_entry_rejects_malformed_domains(self, bad_domain):
        """Rejects schemes, paths, ports, IPs, userinfo, spaces, and invalid wildcards."""
        with pytest.raises(ValueError):
            validate_domain_entry(bad_domain)

    def test_policy_validator_flags_invalid_domains_in_profile(self):
        """PolicyValidator.validate flags malformed allowed_domains and excluded_domains."""
        prof = ProgramProfile(
            id="test-profile",
            name="Test Profile",
            scope=ScopeDefinition(
                allowed_domains=["https://example.com", "192.168.1.10", "valid.com"],
                excluded_domains=["bad/domain", "*"]
            ),
            request_policy=RequestPolicyDefinition(max_rps=5.0)
        )
        errors = PolicyValidator.validate(prof)
        assert any("contains URL scheme" in e for e in errors)
        assert any("IP literal" in e for e in errors)
        assert any("URL path" in e for e in errors)
        assert any("Dangerous wildcard" in e for e in errors)


# ==============================================================================
# NC-SEC-06: Async Test Warning Cleanup Verification
# ==============================================================================

class TestAsyncWarningCleanup:
    """Test suite for NC-SEC-06 clean coroutine handling in test mocks."""

    def test_mock_asyncio_run_safely_closes_unexecuted_coroutine(self):
        """Verify _mock_asyncio_run safely closes coroutine objects to avoid RuntimeWarning."""
        try:
            from tests.test_release_candidate_startup import _mock_asyncio_run
        except ImportError:
            from test_release_candidate_startup import _mock_asyncio_run

        async def sample_coro():
            await asyncio.sleep(0.01)

        coro = sample_coro()
        # Passing coro to _mock_asyncio_run closes it
        res = _mock_asyncio_run(coro)
        assert res is None
        # Verify the coroutine object is closed
        assert coro.cr_frame is None
