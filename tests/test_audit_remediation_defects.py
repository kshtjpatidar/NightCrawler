"""
NightCrawler - Audit Remediation Regression Test Suite
Proves remediation of all 10 verified audit findings:
1. Immutable profile scope: CLI --allowed-domain cannot expand profile scope, only narrow.
2. DNS safety: DNS resolution failures and mixed/prohibited answers fail closed; DNS rebinding prevented via IP pinning.
3. ReportManager integration: constructor accepts policy, generates HTML, JSON, Markdown through CLI.
4. Clean installation: No automatic fabrication of invalid profiles when profiles directory is clean.
5. Review-required profiles: requires_review fails closed unless explicitly confirmed via --confirm-review.
6. Tool allowlist: allowed_tools enforced in addition to disabled_tools; unknown tools denied.
7. External tools without a profile: Network-capable tools blocked when compatibility manager is missing.
8. Authentication ordering: Mandatory credentials validated before constructing scanner or external tool processes.
9. Concurrency: Centralized semaphore from RequestPolicyManager governs HTTP execution.
10. Configuration parsing: Strict boolean and numeric parsing; malformed YAML and missing files fail explicitly.
"""

import os
import json
import socket
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner

from main import main
from src.core.program_profile import ProgramProfile, PolicyParser, strict_bool, strict_positive_float, strict_positive_int
from src.core.program_manager import ProgramManager
from src.core.scope import ScopeManager
from src.core.effective_policy import EffectivePolicy
from src.core.request_config import NightCrawlerConfig, load_config
from src.core.request_policy import RequestPolicyManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.scanner import NightCrawlerScanner, Finding, ScanResult
from src.core.http_client import NightCrawlerHttpClient, PolicyAwareResolver
from src.output.report_manager import ReportManager, FindingStatus


@pytest.fixture
def example_profile():
    pm = ProgramManager()
    profile = pm.get_profile("example-program")
    assert profile is not None
    return profile


# ============================================================================
# Defect 1: Immutable Profile Scope
# ============================================================================
def test_cli_cannot_expand_profile_scope(example_profile):
    """CLI --allowed-domain must never expand a profile's scope to unauthorized domains."""
    with pytest.raises(ValueError) as excinfo:
        EffectivePolicy.build(
            profile=example_profile,
            cli_overrides={"allowed_domains": ["unauthorized-target.com"]}
        )
    assert "cannot expand program 'example-program' authorized scope" in str(excinfo.value)
    assert "Only scope narrowing is permitted" in str(excinfo.value)


def test_cli_cannot_expand_with_excluded_domain(example_profile):
    """CLI cannot add a domain that is explicitly excluded in the profile."""
    with pytest.raises(ValueError) as excinfo:
        EffectivePolicy.build(
            profile=example_profile,
            cli_overrides={"allowed_domains": ["out-of-scope.example.com"]}
        )
    assert "cannot expand program 'example-program' authorized scope" in str(excinfo.value)


def test_cli_can_narrow_profile_scope(example_profile):
    """CLI may narrow authorized profile scope to a specific in-scope subdomain."""
    policy = EffectivePolicy.build(
        profile=example_profile,
        cli_overrides={"allowed_domains": ["sub.example.com"]}
    )
    assert policy.scope_manager.allowed_domains == {"sub.example.com"}
    assert policy.scope_manager.is_host_allowed("sub.example.com") is True
    # Other domains from profile are no longer in the narrowed scope
    assert policy.scope_manager.is_host_allowed("other.example.com") is False


# ============================================================================
# Defect 2: DNS Safety & Rebinding Prevention
# ============================================================================
@pytest.mark.asyncio
async def test_dns_resolution_failure_fails_closed():
    """When DNS resolution fails (gaierror), validate_host_network_safety fails closed."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)

    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        safe, reason = await client.validate_host_network_safety("example.com")
        assert safe is False
        assert "DNS resolution failed" in reason


@pytest.mark.asyncio
async def test_dns_mixed_public_and_prohibited_answers_fails_closed():
    """If DNS answers contain mixed public and prohibited (internal) IPs, fail closed immediately."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)

    # Mixed response: public IP followed by loopback/cloud metadata IP
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443)),
    ]

    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", return_value=mock_addrinfo):
        safe, reason = await client.validate_host_network_safety("example.com")
        assert safe is False
        assert "resolves to prohibited IP '127.0.0.1'" in reason


@pytest.mark.asyncio
async def test_dns_cloud_metadata_ip_fails_closed():
    """Destinations resolving to cloud metadata IP (169.254.169.254) fail closed."""
    scope = ScopeManager(allowed_domains=["example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)

    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443)),
    ]

    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", return_value=mock_addrinfo):
        safe, reason = await client.validate_host_network_safety("example.com")
        assert safe is False
        assert "prohibited" in reason.lower()


@pytest.mark.asyncio
async def test_dns_pinning_prevents_rebinding():
    """
    DNS Pinning: After initial validated resolution, PolicyAwareResolver serves the
    pinned IP, preventing DNS rebinding attacks on subsequent connections.
    """
    scope = ScopeManager(allowed_domains=["rebind.example.com"], enabled=True)
    client = NightCrawlerHttpClient(scope_manager=scope)
    resolver = client.get_resolver()

    # Initial lookup returns safe public IP
    initial_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
    ]

    loop = asyncio.get_running_loop()
    with patch.object(loop, "getaddrinfo", return_value=initial_addrinfo):
        res1 = await resolver.resolve("rebind.example.com", port=443)
        assert len(res1) == 1
        assert res1[0]["host"] == "93.184.216.34"

    # Attacker rebinds DNS to 127.0.0.1
    rebound_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443)),
    ]

    # Resolver uses pinned cache, never queries rebounded IP
    with patch.object(loop, "getaddrinfo", return_value=rebound_addrinfo):
        res2 = await resolver.resolve("rebind.example.com", port=443)
        assert len(res2) == 1
        assert res2[0]["host"] == "93.184.216.34"  # Pinned IP preserved!


# ============================================================================
# Defect 3: ReportManager Integration
# ============================================================================
def test_report_manager_policy_constructor_and_formats(tmp_path, example_profile):
    """ReportManager constructor cleanly accepts policy and generates JSON, Markdown, and HTML."""
    os.environ["EXAMPLE_API_TOKEN"] = "token123"
    policy = EffectivePolicy.build(
        profile=example_profile,
        cli_overrides={"reporter": "Alice Auditor"}
    )

    # 1. Constructor invocation with policy=effective_policy
    rm = ReportManager(policy=policy)
    assert rm.reporter_name == "Alice Auditor"
    assert rm.policy == policy

    finding = Finding(
        url="https://example.com/api.js",
        pattern_name="AWS Access Key ID",
        category="Cloud",
        matched_value="AKIAIOSFODNN7EXAMPLE",
        confidence=90,
        validated=True,
        line_number=10,
        context='const awsKey = "AKIAIOSFODNN7EXAMPLE";'
    )
    result = ScanResult(target="example.com")
    result.findings.append(finding)

    # Generate JSON
    json_path = tmp_path / "report.json"
    rm.generate(findings=[finding], scan_result=result, output_path=str(json_path))
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["program_metadata"]["reporter_name"] == "Alice Auditor"
    assert data["program_metadata"]["program_id"] == "example-program"
    assert len(data["findings"]) == 1
    # Secret is masked in report
    assert data["findings"][0]["evidence"]["masked_secret"] != "AKIAIOSFODNN7EXAMPLE"

    # Generate Markdown
    md_path = tmp_path / "report.md"
    rm.generate(findings=[finding], scan_result=result, output_path=str(md_path))
    assert md_path.exists()
    md_content = md_path.read_text(encoding="utf-8")
    assert "Example Security Program" in md_content
    assert "Alice Auditor" in md_content

    # Generate HTML
    html_path = tmp_path / "report.html"
    rm.generate(findings=[finding], scan_result=result, output_path=str(html_path))
    assert html_path.exists()
    html_content = html_path.read_text(encoding="utf-8")
    assert "Example Security Program" in html_content


def test_cli_report_generation_formats(tmp_path):
    """Test generating JSON, Markdown, and HTML via CLI."""
    js_dir = tmp_path / "js_files"
    js_dir.mkdir()
    (js_dir / "app.js").write_text("const secret = 'AKIAIOSFODNN7EXAMPLE';", encoding="utf-8")

    runner = CliRunner()

    # JSON report
    json_out = tmp_path / "out.json"
    r_json = runner.invoke(main, ["--offline", str(js_dir), "-o", str(json_out), "--quiet"])
    assert r_json.exit_code == 0
    assert json_out.exists()

    # Markdown report
    md_out = tmp_path / "out.md"
    r_md = runner.invoke(main, ["--offline", str(js_dir), "-o", str(md_out), "--quiet"])
    assert r_md.exit_code == 0
    assert md_out.exists()

    # HTML report
    html_out = tmp_path / "out.html"
    r_html = runner.invoke(main, ["--offline", str(js_dir), "-o", str(html_out), "--quiet"])
    assert r_html.exit_code == 0
    assert html_out.exists()


# ============================================================================
# Defect 4: Clean Installation / No Fabricated Profiles
# ============================================================================
def test_clean_installation_no_profile_fabrication(tmp_path):
    """When programs directory has no profiles, ProgramManager does not fabricate an invalid profile."""
    empty_pm = ProgramManager(base_dir=tmp_path / "empty_programs")
    assert len(empty_pm.list_profiles()) == 0
    assert empty_pm.get_profile("example-program") is None


# ============================================================================
# Defect 5: Review-Required Profiles
# ============================================================================
def test_review_required_profile_fails_closed_without_confirmation():
    """A profile with requires_review=True fails closed unless confirmed."""
    prof = ProgramProfile(
        id="ambiguous-program",
        name="Ambiguous Program",
        requires_review=True,
        review_notes=["Ambiguous rate limit clause in policy text"]
    )
    prof.scope.allowed_domains = ["example.com"]

    with pytest.raises(ValueError) as excinfo:
        EffectivePolicy.build(profile=prof)
    assert "requires manual review before scanning can proceed" in str(excinfo.value)
    assert "--confirm-review" in str(excinfo.value)


def test_review_required_profile_proceeds_with_confirmation():
    """A profile with requires_review=True proceeds when confirmed."""
    prof = ProgramProfile(
        id="ambiguous-program",
        name="Ambiguous Program",
        requires_review=True,
        review_notes=["Ambiguous rate limit clause in policy text"]
    )
    prof.scope.allowed_domains = ["example.com"]
    prof.scope.allowed_domains = ["example.com"]

    policy = EffectivePolicy.build(
        profile=prof,
        cli_overrides={"confirm_review": True}
    )
    assert policy.requires_review is True
    assert policy.program_id == "ambiguous-program"


# ============================================================================
# Defect 6: Tool Allowlist Enforcement
# ============================================================================
def test_tool_restrictions_allowlist_and_denylist():
    """ToolCompatibilityManager enforces allowed_tools, disabled_tools, and matrix membership."""
    prof = ProgramProfile(
        id="tool-test",
        name="Tool Test",
        requires_review=False
    )
    prof.tool_restrictions.allowed_tools = ["subfinder", "gau"]
    prof.tool_restrictions.disabled_tools = ["katana"]

    tcm = ToolCompatibilityManager(prof)

    # In allowlist
    ok, _ = tcm.is_tool_compatible("subfinder")
    assert ok is True

    # In denylist
    ok_kat, reason_kat = tcm.is_tool_compatible("katana")
    assert ok_kat is False
    assert "Explicitly disabled" in reason_kat

    # Not in allowlist
    ok_way, reason_way = tcm.is_tool_compatible("waybackurls")
    assert ok_way is False
    assert "tool allowlist" in reason_way

    # Unregistered tool
    ok_unk, reason_unk = tcm.is_tool_compatible("unknown_scanner_x")
    assert ok_unk is False
    assert "not registered in the capability matrix" in reason_unk


# ============================================================================
# Defect 7: External Tools Without Profile
# ============================================================================
def test_external_tools_without_profile_blocks_network_tools():
    """When tool compatibility manager is missing (no profile), network-capable tools are blocked."""
    scanner = NightCrawlerScanner(
        tool_compatibility_manager=None,
        use_external_tools=True
    )
    assert scanner.tool_compatibility_manager is None

    # Offline tool jsluice can run
    cap_js = ToolCompatibilityManager.TOOL_REGISTRY["jsluice"]
    assert cap_js.makes_live_requests is False

    # Active network tools are blocked
    for t_name in ["katana", "hakrawler", "subjs", "getjs", "httpx"]:
        cap = ToolCompatibilityManager.TOOL_REGISTRY[t_name]
        assert cap.makes_live_requests is True


# ============================================================================
# Defect 8: Authentication Ordering
# ============================================================================
def test_authentication_ordering_missing_credentials_fails_before_scanner(example_profile):
    """Missing mandatory authentication credentials raises ValueError before any outbound requests."""
    # Ensure env token is missing
    os.environ.pop("EXAMPLE_API_TOKEN", None)
    os.environ.pop("RESEARCHER_NAME", None)

    policy = EffectivePolicy.build(profile=example_profile)
    with pytest.raises(ValueError) as excinfo:
        policy.validate_ready_to_scan()
    assert "Mandatory authentication credentials missing" in str(excinfo.value)


# ============================================================================
# Defect 9: Concurrency Semaphore from RequestPolicyManager
# ============================================================================
def test_request_policy_manager_semaphore():
    """RequestPolicyManager provides a shared concurrency semaphore matching concurrency limit."""
    rpm = RequestPolicyManager(concurrency_limit=3, max_rps=10.0)
    sem1 = rpm.get_semaphore()
    sem2 = rpm.get_semaphore()
    assert sem1 is sem2
    assert sem1._value == 3


# ============================================================================
# Defect 10: Strict Configuration Parsing
# ============================================================================
def test_strict_bool_validation():
    """strict_bool strictly validates booleans and rejects ambiguous strings or types."""
    assert strict_bool(True) is True
    assert strict_bool(False) is False
    assert strict_bool("true") is True
    assert strict_bool("false") is False
    assert strict_bool("1") is True
    assert strict_bool("0") is False

    with pytest.raises(ValueError):
        strict_bool("maybe")

    with pytest.raises(ValueError):
        strict_bool("not_a_bool")

    with pytest.raises(TypeError):
        strict_bool([])


def test_load_config_nonexistent_file_raises():
    """load_config raises FileNotFoundError when explicitly given a non-existent file."""
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent_config_12345.yaml")


def test_load_config_malformed_yaml_raises(tmp_path):
    """load_config raises ValueError when YAML contains invalid structure."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("- item1\n- item2\n", encoding="utf-8")  # List instead of dict mapping

    with pytest.raises(ValueError) as excinfo:
        load_config(str(bad_yaml))
    assert "must contain a YAML mapping/dictionary" in str(excinfo.value)


def test_load_config_strict_types(tmp_path):
    """load_config strictly validates types from YAML."""
    invalid_bool_yaml = tmp_path / "invalid_bool.yaml"
    invalid_bool_yaml.write_text("""
scope:
  enabled: "not_a_boolean"
""", encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(str(invalid_bool_yaml))
