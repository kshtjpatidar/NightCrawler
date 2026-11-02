"""
NightCrawler - Multi-Program, Policy-Aware Framework Tests
Comprehensive unit and integration test suite covering:
- Program loading, multiple profiles, profile switching, validation, duplication, import/export.
- Scope with wildcards, IPs, CIDR blocks, path exclusions, third-party hosted services.
- Rate limiting, strictest limit logic, per-host pacing, exponential backoff.
- Authentication, credential isolation, environment expansion, session file permissions.
- Testing permissions with permanent DoS/destructive testing prohibitions.
- Tool compatibility evaluation and automatic disabling.
- Structured audit logging with parameter redaction.
- Multi-format reporting (HTML, JSON, Markdown) with finding lifecycle classification.
- CLI subcommands (programs list, show, validate, etc.).
"""

import os
import math
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
from click.testing import CliRunner

from main import main
from src.core.program_manager import ProgramManager
from src.core.program_profile import ProgramProfile, PolicyParser, PolicyValidator
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.auth_manager import AuthenticationManager
from src.core.permissions import TestingPermissionManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.audit_logger import AuditLogger
from src.output.report_manager import ReportManager, FindingStatus
from src.core.scanner import Finding, ScanResult


# -------------------------------------------------------------
# 1. Program Profile & Manager Tests
# -------------------------------------------------------------

def test_program_manager_discovery_and_listing():
    """Verify ProgramManager discovers uxcam and example-program profiles."""
    pm = ProgramManager()
    profiles = pm.list_profiles()
    ids = [p["id"] for p in profiles]
    assert "uxcam" in ids
    assert "example-program" in ids

    uxcam = pm.get_profile("uxcam")
    assert uxcam is not None
    assert uxcam.id == "uxcam"
    assert uxcam.request_policy.max_rps == 5.0
    assert "uxcam.com" in uxcam.scope.allowed_domains


def test_program_validation_rules():
    """Verify PolicyValidator enforces strict safety rules and parameter sanity."""
    # 1. Non-positive RPS rejected
    p1 = PolicyParser.from_dict({
        "id": "bad-rps",
        "name": "Bad RPS",
        "scope": {"allowed_domains": ["test.com"]},
        "request_policy": {"max_rps": 0}
    })
    errors = PolicyValidator.validate(p1)
    assert any("max_rps must be positive" in e for e in errors)

    # 2. NaN / Inf RPS rejected
    p2 = PolicyParser.from_dict({
        "id": "nan-rps",
        "name": "NaN RPS",
        "scope": {"allowed_domains": ["test.com"]},
        "request_policy": {"max_rps": float("nan")}
    })
    errors = PolicyValidator.validate(p2)
    assert any("NaN or Infinity" in e for e in errors)

    # 3. UXCam profile hard max 5.0 RPS enforced
    p3 = PolicyParser.from_dict({
        "id": "uxcam",
        "name": "UXCam Program",
        "scope": {"allowed_domains": ["uxcam.com"]},
        "request_policy": {"max_rps": 8.0}
    })
    errors = PolicyValidator.validate(p3)
    assert any("UXCam program policy enforces hard maximum of 5.0 RPS" in e for e in errors)

    # 4. Destructive testing permanently prohibited
    p4 = PolicyParser.from_dict({
        "id": "dangerous",
        "name": "Dangerous Program",
        "scope": {"allowed_domains": ["test.com"]},
        "testing_permissions": {"destructive_testing": True}
    })
    errors = PolicyValidator.validate(p4)
    # Notice: PolicyParser forces destructive_testing to False, and validator double-checks
    assert p4.testing_permissions.destructive_testing is False

    # 5. Invalid CIDR notation rejected
    p5 = PolicyParser.from_dict({
        "id": "bad-cidr",
        "name": "Bad CIDR",
        "scope": {
            "allowed_domains": ["test.com"],
            "allowed_cidrs": ["999.999.999.999/99"]
        }
    })
    errors = PolicyValidator.validate(p5)
    assert any("Invalid allowed CIDR notation" in e for e in errors)


def test_program_profile_duplication_and_export(tmp_path):
    """Verify duplication, export, and import of program profiles."""
    pm = ProgramManager(base_dir=tmp_path / "programs")
    # Create base
    pm.create_profile({
        "id": "test-prog",
        "name": "Test Program",
        "scope": {"allowed_domains": ["test.com"]},
        "request_policy": {"max_rps": 3.0}
    })

    # Duplicate
    dupe = pm.duplicate_profile("test-prog", "test-prog-dupe", "Duplicated Program")
    assert dupe.id == "test-prog-dupe"
    assert dupe.name == "Duplicated Program"
    assert dupe.request_policy.max_rps == 3.0

    # Export to JSON
    export_json = tmp_path / "exported.json"
    pm.export_profile("test-prog-dupe", str(export_json), export_format="json")
    assert export_json.exists()
    data = json.loads(export_json.read_text())
    assert data["id"] == "test-prog-dupe"

    # Import back under new manager
    pm2 = ProgramManager(base_dir=tmp_path / "programs2")
    imported = pm2.import_profile(str(export_json))
    assert imported.id == "test-prog-dupe"
    assert "test.com" in imported.scope.allowed_domains


def test_policy_parser_text_rules_with_uncertain_rules():
    """Verify parsing text rules flags ambiguous or conditional clauses for operator review."""
    rules_text = """
    # Bug Bounty Policy
    Targets in scope: api.target.com, app.target.com
    Out of scope: admin.target.com
    Rate limit: 4 requests per second
    Note: Do not test third-party vendor services hosted on help.target.com without contacting us first.
    """
    profile = PolicyParser.from_text_rules("target-corp", "Target Corp", rules_text)
    assert "api.target.com" in profile.scope.allowed_domains
    assert "admin.target.com" in profile.scope.excluded_domains
    assert profile.request_policy.max_rps == 4.0
    assert profile.requires_review is True
    assert len(profile.review_notes) >= 1
    # Active recon kept disabled until review is completed
    assert profile.testing_permissions.active_recon is False


# -------------------------------------------------------------
# 2. Scope Extension Tests (IPs, CIDRs, Paths, Protocols, Ports)
# -------------------------------------------------------------

def test_scope_manager_cidr_and_ip_matching():
    """Verify ScopeManager correctly handles IP addresses and CIDR blocks with exclusions."""
    scope = ScopeManager(
        allowed_domains=["example.com"],
        allowed_ips=["192.168.1.50"],
        allowed_cidrs=["10.0.0.0/24"],
        excluded_ips=["10.0.0.254"],
        excluded_cidrs=["10.0.0.128/25"],
        enabled=True
    )

    # Allowed exact IP
    assert scope.is_host_allowed("192.168.1.50") is True
    assert scope.is_url_in_scope("https://192.168.1.50/api") is True

    # Not allowed outside CIDR
    assert scope.is_host_allowed("192.168.1.51") is False

    # Allowed inside CIDR (10.0.0.10 is in 10.0.0.0/24 and not in 10.0.0.128/25)
    assert scope.is_host_allowed("10.0.0.10") is True
    assert scope.is_url_in_scope("https://10.0.0.10/status") is True

    # Excluded exact IP inside allowed CIDR
    assert scope.is_host_allowed("10.0.0.254") is False
    assert scope.is_url_in_scope("https://10.0.0.254/login") is False

    # Excluded sub-CIDR (10.0.0.200 is inside 10.0.0.128/25)
    assert scope.is_host_allowed("10.0.0.200") is False


def test_scope_manager_path_and_port_restrictions():
    """Verify ScopeManager enforces path exclusions, allowed paths, and port boundaries."""
    scope = ScopeManager(
        allowed_domains=["app.example.com"],
        excluded_paths=["/logout", "/delete-account", "/admin/destroy"],
        allowed_paths=["/api/", "/v1/"],
        allowed_ports=[80, 443, 8443],
        allowed_protocols=["https"],
        enabled=True
    )

    # Allowed path and port
    assert scope.is_url_in_scope("https://app.example.com/api/v1/users") is True
    assert scope.is_url_in_scope("https://app.example.com:8443/api/check") is True

    # Prohibited protocol (http when only https is allowed)
    assert scope.is_url_in_scope("http://app.example.com/api/test") is False

    # Prohibited port
    assert scope.is_url_in_scope("https://app.example.com:8080/api/test") is False

    # Excluded path takes precedence
    assert scope.is_url_in_scope("https://app.example.com/logout") is False
    assert scope.is_url_in_scope("https://app.example.com/delete-account") is False

    # Not in allowed_paths (since allowed_paths was explicitly specified)
    assert scope.is_url_in_scope("https://app.example.com/static/style.css") is False


def test_scope_manager_third_party_hosted_service_exclusions():
    """Verify first-party subdomains hosted on third-party SaaS are excluded."""
    scope = ScopeManager(
        allowed_domains=["uxcam.com", "*.uxcam.com"],
        third_party_hosted_exclusions=["help.uxcam.com", "blog.uxcam.com"],
        enabled=True
    )

    assert scope.is_host_allowed("app.uxcam.com") is True
    assert scope.is_host_allowed("api.uxcam.com") is True

    # Excluded third-party hosted subdomains
    assert scope.is_host_allowed("help.uxcam.com") is False
    assert scope.is_host_allowed("blog.uxcam.com") is False
    assert scope.is_url_in_scope("https://help.uxcam.com/hc/en-us") is False


# -------------------------------------------------------------
# 3. Authentication & Credential Isolation Tests
# -------------------------------------------------------------

def test_authentication_manager_headers_and_isolation():
    """Verify AuthenticationManager attaches headers only to authorized in-scope targets."""
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"], enabled=True)
    auth = AuthenticationManager(
        required_headers={"X-User-Id": "researcher@example.com"},
        optional_headers={"X-Custom-Env": "stage1"},
        scope_manager=scope
    )

    # In-scope URL receives researcher headers
    in_scope_hdrs = auth.get_headers_for_url("https://app.uxcam.com/api")
    assert in_scope_hdrs.get("X-User-Id") == "researcher@example.com"
    assert in_scope_hdrs.get("X-Custom-Env") == "stage1"

    # Out-of-scope URL does NOT receive program headers or credentials
    out_scope_hdrs = auth.get_headers_for_url("https://eviluxcam.com/steal")
    assert "X-User-Id" not in out_scope_hdrs
    assert "X-Custom-Env" not in out_scope_hdrs

    third_party_hdrs = auth.get_headers_for_url("https://web.archive.org/cdx/search")
    assert "X-User-Id" not in third_party_hdrs


def test_authentication_manager_bearer_and_session_file_security(tmp_path):
    """Verify session file permission check (rejects group/world readable files)."""
    sess_file = tmp_path / "session.token"
    sess_file.write_text("SUPER_SECRET_BEARER_TOKEN", encoding="utf-8")

    # Insecure mode: 0644 (world readable)
    os.chmod(sess_file, 0o644)
    with pytest.raises(PermissionError, match="insecure permissions"):
        AuthenticationManager(
            auth_def=PolicyParser.from_dict({
                "id": "p", "name": "P",
                "authentication": {"type": "bearer", "session_file": str(sess_file)}
            }).authentication
        )

    # Secure mode: 0600 (owner only)
    os.chmod(sess_file, 0o600)
    auth_sec = AuthenticationManager(
        auth_def=PolicyParser.from_dict({
            "id": "p", "name": "P",
            "authentication": {"type": "bearer", "session_file": str(sess_file)}
        }).authentication
    )
    headers = auth_sec.get_headers_for_url("https://anything")
    assert headers.get("Authorization") == "Bearer SUPER_SECRET_BEARER_TOKEN"


# -------------------------------------------------------------
# 4. Request Policy Manager Tests (Strictest limit, backoff, per-host)
# -------------------------------------------------------------

def test_request_policy_manager_strictest_limit_and_stats():
    """Verify RequestPolicyManager selects the strictest applicable limit."""
    # Profile says 10 RPS, global override says 4 RPS -> picks 4 RPS
    prof = PolicyParser.from_dict({
        "id": "test",
        "name": "Test",
        "request_policy": {"max_rps": 10.0, "concurrency": 2, "per_host_rps": 5.0}
    })
    rpm = RequestPolicyManager.from_profile(prof, global_override_rps=4.0)
    assert rpm.effective_rps == 4.0

    # Backoff calculation
    assert rpm.calculate_backoff(1, base=0.5) == 0.5
    assert rpm.calculate_backoff(2, base=0.5) == 1.0
    assert rpm.calculate_backoff(3, base=0.5) == 2.0

    # Statistics recording
    rpm.record_retry()
    rpm.record_redirect()
    rpm.record_blocked()
    stats = rpm.get_statistics()
    assert stats["total_retries"] == 1
    assert stats["total_redirects"] == 1
    assert stats["blocked_attempts"] == 1


# -------------------------------------------------------------
# 5. Testing Permissions Manager Tests (Fail-Closed Safety)
# -------------------------------------------------------------

def test_testing_permission_manager_safety_ceilings():
    """Verify destructive testing and DoS are permanently prohibited across all programs."""
    prof = PolicyParser.from_dict({
        "id": "safe-test",
        "name": "Safe Test",
        "testing_permissions": {
            "passive_recon": True,
            "active_recon": True,
            "endpoint_discovery": True,
            "credential_validation": True, # Profile requested, but requires operator flag
            "destructive_testing": True,   # Must be ignored
            "denial_of_service": True      # Must be ignored
        }
    })
    tpm = TestingPermissionManager.from_profile(prof, allow_credential_validation=False)

    assert tpm.is_permitted("passive_recon") is True
    assert tpm.is_permitted("active_recon") is True
    # Without operator flag, credential validation fails closed
    assert tpm.is_permitted("credential_validation") is False
    # Destructive and DoS permanently prohibited
    assert tpm.is_permitted("destructive_testing") is False
    assert tpm.is_permitted("denial_of_service") is False

    with pytest.raises(PermissionError, match="PROHIBITED"):
        tpm.assert_permitted("destructive_testing")


# -------------------------------------------------------------
# 6. Tool Compatibility Manager Tests
# -------------------------------------------------------------

def test_tool_compatibility_manager_disabling_logic():
    """Verify ToolCompatibilityManager disables incompatible tools automatically."""
    # Strict compliance mode disables autonomous Katana and Hakrawler
    uxcam_prof = PolicyParser.from_dict({
        "id": "uxcam",
        "name": "UXCam",
        "request_policy": {"strict_scope": True},
        "tool_restrictions": {"disabled_tools": ["katana", "hakrawler"]}
    })
    tcm = ToolCompatibilityManager(uxcam_prof)

    ok_subfinder, _ = tcm.is_tool_compatible("subfinder")
    assert ok_subfinder is True

    ok_gau, _ = tcm.is_tool_compatible("gau")
    assert ok_gau is True

    ok_katana, reason_katana = tcm.is_tool_compatible("katana")
    assert ok_katana is False
    assert "Explicitly disabled" in reason_katana or "strict compliance mode" in reason_katana


# -------------------------------------------------------------
# 7. Audit Logger Tests (Redaction & Structure)
# -------------------------------------------------------------

def test_audit_logger_redaction(tmp_path):
    """Verify AuditLogger redacts sensitive tokens and secret parameters from URLs."""
    log_file = tmp_path / "test_audit.jsonl"
    al = AuditLogger(program_id="test-prog", log_file=log_file)

    al.log_event(
        target_host="app.target.com",
        method="GET",
        url="https://app.target.com/api/user?token=SECRET_JWT_TOKEN&key=API_12345&filter=active",
        scope_decision="ALLOWED",
        policy_decision="PERMITTED",
        response_status=200
    )

    records = al.read_recent_logs()
    assert len(records) == 1
    rec = records[0]
    assert rec["program_id"] == "test-prog"
    assert rec["scope_decision"] == "ALLOWED"

    # Redaction checks
    assert "SECRET_JWT_TOKEN" not in rec["url"]
    assert "API_12345" not in rec["url"]
    assert "REDACTED" in rec["url"]
    assert "filter=active" in rec["url"]


# -------------------------------------------------------------
# 8. Report Manager Tests (HTML, JSON, Markdown)
# -------------------------------------------------------------

def test_report_manager_generates_markdown_and_json(tmp_path):
    """Verify ReportManager generates Markdown and JSON reports with finding lifecycle status."""
    prof = PolicyParser.from_dict({
        "id": "test-bounty",
        "name": "Test Bounty Corp",
        "version": "2.1.0",
        "scope": {"allowed_domains": ["target.com"]}
    })
    rm = ReportManager(profile=prof, reporter_name="Security Auditor")

    finding = Finding(
        url="https://target.com/bundle.js",
        pattern_name="Google API Key",
        category="API",
        matched_value="AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345",
        confidence=90,
        validated=True,
        line_number=42,
        context="const apiKey = 'AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345';"
    )
    scan_res = ScanResult(
        target="target.com",
        total_urls_scanned=5,
        total_js_files=2,
        subdomains_found=1
    )

    # 1. JSON Report
    json_path = tmp_path / "report.json"
    rm.generate([finding], scan_res, str(json_path))
    json_content = json_path.read_text(encoding="utf-8")
    data = json.loads(json_content)

    assert data["program_metadata"]["program_id"] == "test-bounty"
    assert data["program_metadata"]["policy_version"] == "2.1.0"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["lifecycle_classification"] == FindingStatus.PATTERN_MATCHED
    assert "AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345" not in json_content

    # 2. Markdown Report
    md_path = tmp_path / "report.md"
    rm.generate([finding], scan_res, str(md_path))
    md_content = md_path.read_text(encoding="utf-8")

    assert "# 🦇 NightCrawler Reconnaissance Report" in md_content
    assert "Test Bounty Corp" in md_content
    assert "PATTERN_MATCHED" in md_content
    assert "AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345" not in md_content


# -------------------------------------------------------------
# 9. CLI Subcommands Integration Tests
# -------------------------------------------------------------

def test_cli_programs_commands():
    """Verify 'main.py programs list', 'show', and 'validate' subcommands."""
    runner = CliRunner()

    # List
    res_list = runner.invoke(main, ["programs", "list"])
    assert res_list.exit_code == 0
    assert "uxcam" in res_list.output
    assert "example-program" in res_list.output

    # Show
    res_show = runner.invoke(main, ["programs", "show", "uxcam"])
    assert res_show.exit_code == 0
    assert "UXCam Bug Bounty Program" in res_show.output
    assert "Max RPS: 5.0" in res_show.output

    # Validate
    res_val = runner.invoke(main, ["programs", "validate", "uxcam"])
    assert res_val.exit_code == 0
    assert "VALID" in res_val.output
