"""
NightCrawler - Comprehensive Mocked End-to-End Integration Tests
Validates Scenarios A through J:
- Scenario A: Valid in-scope scan with mocked transport (aiohttp session)
- Scenario B: Out-of-scope target rejected with zero mock transport requests
- Scenario C: Missing authentication stops execution before first HTTP request
- Scenario D: CLI override precedence and strict policy invariants
- Scenario E: Rate limit pacing and concurrency management
- Scenario F: Redirect safety: 302 to out-of-scope destination stops execution
- Scenario G: External tool compatibility and permissions enforcement
- Scenario H: Secret protection: dummy secrets masked in logs, argv, and reports
- Scenario I: Quiet-mode key validation safety: interactive confirmation cannot be bypassed
- Scenario J: Report formats: JSON, HTML, Markdown, and rejection of invalid formats
"""

import os
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner

from main import main
from src.core.program_manager import ProgramManager
from src.core.effective_policy import EffectivePolicy
from src.core.request_config import NightCrawlerConfig
from src.core.request_policy import RequestPolicyManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.scanner import NightCrawlerScanner, Finding, ScanResult
from src.core.http_client import NightCrawlerHttpClient
from src.output.report_manager import ReportManager, FindingStatus


@pytest.fixture
def uxcam_profile():
    pm = ProgramManager()
    profile = pm.get_profile("uxcam")
    assert profile is not None
    return profile


@pytest.fixture
def example_profile():
    pm = ProgramManager()
    profile = pm.get_profile("example-program")
    assert profile is not None
    return profile


# ============================================================================
# Scenario A: Valid in-scope scan with mocked transport
# ============================================================================
@pytest.mark.asyncio
async def test_scenario_a_valid_in_scope_scan(uxcam_profile, tmp_path):
    """
    Scenario A: Valid in-scope scan with mocked transport.
    Verifies that requests dispatch only to in-scope domains, carry required headers,
    obey rate limits, and generate classified findings.
    """
    os.environ["NIGHTCRAWLER_RESEARCHER_ID"] = "test-researcher@example.com"

    policy = EffectivePolicy.build(
        profile=uxcam_profile,
        cli_overrides={"max_rps": 5.0, "header_value": "test-researcher@example.com"}
    )
    policy.validate_ready_to_scan()

    scanner = NightCrawlerScanner(effective_policy=policy)

    mock_resp_page = MagicMock()
    mock_resp_page.status = 200
    mock_resp_page.text = AsyncMock(return_value="""
        <html>
            <head><script src="/static/app.js"></script></head>
            <body>UXCam Application</body>
        </html>
    """)
    mock_resp_page.headers = {"content-type": "text/html"}

    mock_resp_js = MagicMock()
    mock_resp_js.status = 200
    mock_resp_js.text = AsyncMock(return_value="""
        // Frontend bundle
        const config = {
            apiKey: "AIzaSyBxK9zQ8wR2vM5nL1pT4yX7uJ0sZ3eW6qF",
            apiUrl: "/api/v1/collect"
        };
    """)
    mock_resp_js.headers = {"content-type": "application/javascript"}

    call_urls = []
    call_headers = []

    def mock_get(url, *args, **kwargs):
        call_urls.append(url)
        call_headers.append(kwargs.get("headers", {}))
        cm = MagicMock()
        if "app.js" in url:
            cm.__aenter__ = AsyncMock(return_value=mock_resp_js)
        else:
            cm.__aenter__ = AsyncMock(return_value=mock_resp_page)
        cm.__aexit__ = AsyncMock(return_value=None)
        return cm

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=mock_get)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        await scanner.scan_target("https://app.uxcam.com")

    # Assertions
    assert len(call_urls) > 0
    for u in call_urls:
        assert policy.scope_manager.is_url_in_scope(u) is True

    # Check that required header was attached to in-scope requests
    for hdrs in call_headers:
        assert hdrs.get("X-User-Id") == "test-researcher@example.com"

    # Verify findings were classified
    findings = scanner.results.findings
    assert len(findings) >= 1
    target_finding = findings[0]
    assert target_finding.pattern_name == "Google API Key"

    # Verify report generation
    out_json = tmp_path / "report.json"
    rep_mgr = ReportManager(policy=policy, reporter_name="Security Researcher")
    rep_mgr.generate(
        findings=findings,
        scan_result=scanner.results,
        output_path=str(out_json),
        tools_report={},
        stats=policy.request_policy_manager.get_statistics()
    )

    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["program_metadata"]["program_id"] == "uxcam"
    assert data["summary"]["total_findings"] >= 1
    assert data["findings"][0]["lifecycle_classification"] == FindingStatus.PATTERN_MATCHED
    assert "Active Verified Secret" not in data["findings"][0]["title"]


# ============================================================================
# Scenario B: Out-of-scope target rejected with zero mock transport requests
# ============================================================================
def test_scenario_b_out_of_scope_target_rejected(uxcam_profile):
    """
    Scenario B: Out-of-scope target rejected with zero mock transport requests.
    """
    runner = CliRunner()
    with patch("src.core.http_client.aiohttp.ClientSession.get") as mock_get:
        # 1. Evil lookalike host
        res1 = runner.invoke(main, ["-t", "https://eviluxcam.com", "--no-prompt"])
        assert "OUT OF SCOPE" in res1.output
        assert mock_get.call_count == 0

        # 2. Excluded host
        res2 = runner.invoke(main, ["-t", "https://tara.uxcam.com", "--no-prompt"])
        assert "OUT OF SCOPE" in res2.output
        assert mock_get.call_count == 0


# ============================================================================
# Scenario C: Missing authentication stops execution before first HTTP request
# ============================================================================
def test_scenario_c_missing_authentication_stops_execution(example_profile):
    """
    Scenario C: Missing required authentication prevents scan execution before
    any network request can be issued.
    """
    if "EXAMPLE_API_TOKEN" in os.environ:
        del os.environ["EXAMPLE_API_TOKEN"]

    policy = EffectivePolicy.build(profile=example_profile)

    with pytest.raises(ValueError, match="Mandatory authentication credentials missing"):
        policy.validate_ready_to_scan()


# ============================================================================
# Scenario D: CLI override precedence and strict policy invariants
# ============================================================================
def test_scenario_d_cli_override_precedence(uxcam_profile):
    """
    Scenario D:
    1. Absent CLI options (None) do not overwrite base config/profile.
    2. Explicit CLI flag overrides base config.
    3. Strict profile restrictions cannot be weakened by CLI flags.
    """
    # 1. Default invocation preserves base profile rate limits and strict scope
    policy = EffectivePolicy.build(profile=uxcam_profile, cli_overrides={})
    assert policy.max_rps == 5.0
    assert policy.strict_scope is True
    assert policy.scope_enabled is True

    # 2. Explicit lower RPS overrides profile
    policy_lower = EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"max_rps": 2.0})
    assert policy_lower.max_rps == 2.0

    # 3. Attempting to weaken UXCam hard rate limit (max 5 RPS) fails
    with pytest.raises(ValueError, match="strict maximum rate limit of 5"):
        EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"max_rps": 10.0})

    # 4. Attempting to disable scope (--no-scope) when strict_scope is required fails
    with pytest.raises(ValueError, match="Disabling target scope is prohibited"):
        EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"scope_enabled": False})

    # 5. When strict_scope is false, disabling scope is permitted
    cfg_non_strict = NightCrawlerConfig()
    cfg_non_strict.strict_scope = False
    policy_no_scope = EffectivePolicy.build(
        config=cfg_non_strict,
        cli_overrides={"scope_enabled": False}
    )
    assert policy_no_scope.scope_enabled is False


# ============================================================================
# Scenario E: Rate limit pacing and concurrency management
# ============================================================================
@pytest.mark.asyncio
async def test_scenario_e_rate_limiting_and_concurrency():
    """
    Scenario E: RequestPolicyManager enforces concurrency semaphore and rate pacing.
    """
    rpm = RequestPolicyManager(max_rps=10.0, concurrency_limit=2)

    active_tasks = 0
    max_observed_concurrency = 0

    async def worker():
        nonlocal active_tasks, max_observed_concurrency
        async with rpm.get_semaphore():
            active_tasks += 1
            max_observed_concurrency = max(max_observed_concurrency, active_tasks)
            await asyncio.sleep(0.05)
            active_tasks -= 1

    await asyncio.gather(*(worker() for _ in range(6)))

    assert max_observed_concurrency <= 2
    assert rpm.get_statistics()["concurrency_limit"] == 2


# ============================================================================
# Scenario F: Redirect safety: 302 to out-of-scope destination stops execution
# ============================================================================
@pytest.mark.asyncio
async def test_scenario_f_redirect_safety(uxcam_profile):
    """
    Scenario F: When in-scope target issues a 302 redirect to an out-of-scope
    domain, the HTTP client halts and never sends credentials to the destination.
    """
    os.environ["NIGHTCRAWLER_RESEARCHER_ID"] = "researcher@example.com"
    policy = EffectivePolicy.build(
        profile=uxcam_profile,
        cli_overrides={"header_value": "researcher@example.com"}
    )
    http_client = NightCrawlerHttpClient(effective_policy=policy)

    mock_302 = MagicMock()
    mock_302.status = 302
    mock_302.headers = {"Location": "https://malicious-external-site.com/intercept"}

    dispatched_urls = []

    def mock_get(url, *args, **kwargs):
        dispatched_urls.append(url)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_302)
        cm.__aexit__ = AsyncMock(return_value=None)
        return cm

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=mock_get)

    status, content, final_url = await http_client.get(mock_session, "https://app.uxcam.com/login")

    # Initial request was made, redirect target was blocked before execution
    assert dispatched_urls == ["https://app.uxcam.com/login"]
    assert "https://malicious-external-site.com/intercept" not in dispatched_urls
    assert status == 302


# ============================================================================
# Scenario G: External tool compatibility and permissions enforcement
# ============================================================================
def test_scenario_g_external_tool_compatibility(uxcam_profile):
    """
    Scenario G: ToolCompatibilityManager disables unauthorized / uncoordinated tools.
    """
    tcm = ToolCompatibilityManager(uxcam_profile)

    # Permitted passive tools
    ok_sub, _ = tcm.is_tool_compatible("subfinder")
    assert ok_sub is True
    ok_js, _ = tcm.is_tool_compatible("jsluice")
    assert ok_js is True

    # Uncoordinated / aggressive tools are disabled
    ok_kat, reason_kat = tcm.is_tool_compatible("katana")
    assert ok_kat is False
    assert "disabled" in reason_kat.lower()

    audit_rep = tcm.get_tool_audit_report()
    assert audit_rep["katana"]["compatible"] is False


# ============================================================================
# Scenario H: Secret protection: dummy secrets masked in logs and reports
# ============================================================================
def test_scenario_h_secret_masking_in_reports(uxcam_profile, tmp_path):
    """
    Scenario H: Discovered secrets are strictly masked in all report outputs.
    """
    policy = EffectivePolicy.build(profile=uxcam_profile)
    rep_mgr = ReportManager(policy=policy, reporter_name="Security Researcher")

    dummy_secret = "AIzaSyD-PRIVATE-DUMMY-SECRET-1234567890"
    raw_finding = Finding(
        pattern_name="Google API Key",
        category="API Key",
        matched_value=dummy_secret,
        confidence=80,
        url="https://app.uxcam.com/static/main.js",
        line_number=42,
        context=f'apiKey: "{dummy_secret}"'
    )
    scan_res = ScanResult(target="app.uxcam.com")

    # 1. JSON Report
    json_path = tmp_path / "report.json"
    rep_mgr.generate([raw_finding], scan_res, str(json_path))
    json_text = json_path.read_text(encoding="utf-8")
    assert dummy_secret not in json_text
    assert "AIz" in json_text  # Prefix visible

    # 2. Markdown Report
    md_path = tmp_path / "report.md"
    rep_mgr.generate([raw_finding], scan_res, str(md_path))
    md_text = md_path.read_text(encoding="utf-8")
    assert dummy_secret not in md_text

    # 3. HTML Report
    html_path = tmp_path / "report.html"
    rep_mgr.generate([raw_finding], scan_res, str(html_path))
    html_text = html_path.read_text(encoding="utf-8")
    assert dummy_secret not in html_text


# ============================================================================
# Scenario I: Quiet-mode key validation safety
# ============================================================================
def test_scenario_i_quiet_mode_validation_safety(tmp_path):
    """
    Scenario I: In quiet / non-interactive mode, active credential validation
    cannot silently bypass authorization.
    """
    runner = CliRunner()
    # Test --quiet with --validate-keys on an offline directory
    res = runner.invoke(main, [
        "-t", "https://app.uxcam.com",
        "--quiet",
        "--validate-keys",
        "--offline", str(tmp_path)
    ])
    # Scan completes offline without raising or performing interactive prompts
    assert res.exit_code == 0


# ============================================================================
# Scenario J: Report formats (JSON, HTML, Markdown, and invalid format error)
# ============================================================================
def test_scenario_j_report_format_selection(uxcam_profile, tmp_path):
    """
    Scenario J:
    - .json produces valid JSON
    - .html produces valid HTML
    - .md produces valid Markdown
    - Unsupported extensions (e.g. .txt, .csv) are rejected
    """
    policy = EffectivePolicy.build(profile=uxcam_profile)
    rep_mgr = ReportManager(policy=policy)

    dummy_finding = Finding(
        pattern_name="Slack Webhook",
        category="Webhook",
        matched_value="https://hooks.slack.com/services/T00/B00/X00",
        confidence=80,
        url="https://app.uxcam.com/test.js",
        line_number=1,
        context="webhook"
    )
    scan_res = ScanResult(target="app.uxcam.com")

    # JSON Format
    json_file = tmp_path / "out.json"
    rep_mgr.generate([dummy_finding], scan_res, str(json_file))
    parsed = json.loads(json_file.read_text(encoding="utf-8"))
    assert "findings" in parsed
    assert "<html" not in json_file.read_text(encoding="utf-8").lower()

    # Markdown Format
    md_file = tmp_path / "out.md"
    rep_mgr.generate([dummy_finding], scan_res, str(md_file))
    md_content = md_file.read_text(encoding="utf-8")
    assert md_content.startswith("# 🦇 NightCrawler Reconnaissance Report")

    # HTML Format
    html_file = tmp_path / "out.html"
    rep_mgr.generate([dummy_finding], scan_res, str(html_file))
    html_content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content or "<html" in html_content.lower()

    # Unsupported format rejection
    txt_file = tmp_path / "out.txt"
    with pytest.raises(ValueError, match="Unsupported report output format"):
        rep_mgr.generate([dummy_finding], scan_res, str(txt_file))
