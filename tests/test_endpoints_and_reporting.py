"""
Tests for NightCrawler Endpoint Discovery and Bugcrowd Reporting
Validates endpoint extraction, metadata collection, secret masking, and Bugcrowd VRT report schema.
"""

import json
from pathlib import Path
import pytest

from src.core.endpoints import EndpointExtractor
from src.core.scope import ScopeManager
from src.core.scanner import Finding, ScanResult
from src.output.html_report import HtmlReportGenerator, ReportConfig, mask_secret


def test_endpoint_discovery_and_metadata_extraction():
    """Verify endpoint extractor parses routes, methods, parameters, and source maps."""
    scope = ScopeManager(allowed_domains=["uxcam.com", "*.uxcam.com"])
    extractor = EndpointExtractor(scope_manager=scope)

    js_code = """
    // API client
    fetch("/api/v1/users", { method: "POST" });
    const authUrl = "/auth/oauth/token?grant_type=client_credentials";
    const graphEndpoint = "/graphql";
    const outOfScope = "https://external-service.com/api/test";
    const inScope = "https://api.uxcam.com/v2/events";
    
    //# sourceMappingURL=bundle.js.map
    """

    meta = extractor.extract_from_js(js_code, "https://app.uxcam.com/assets/app.js")

    assert len(meta.source_maps) > 0
    assert any("bundle.js.map" in sm for sm in meta.source_maps)

    endpoints_urls = [ep.url_or_path for ep in meta.endpoints]
    assert "https://app.uxcam.com/api/v1/users" in endpoints_urls
    assert "https://app.uxcam.com/auth/oauth/token?grant_type=client_credentials" in endpoints_urls
    assert "https://app.uxcam.com/graphql" in endpoints_urls
    assert "https://api.uxcam.com/v2/events" in endpoints_urls

    # Out of scope endpoint must be excluded!
    assert "https://external-service.com/api/test" not in endpoints_urls

    # Check method extraction
    user_ep = next(ep for ep in meta.endpoints if "/api/v1/users" in ep.url_or_path)
    assert user_ep.method == "POST"


def test_secret_masking():
    """Verify secret masking hides sensitive keys and passwords."""
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKI**************PLE"
    assert mask_secret("sk_live_123456789") == "sk_***********789"
    assert mask_secret("short") == "*****"
    assert mask_secret("") == ""


def test_bugcrowd_structured_report(tmp_path):
    """Verify generated Bugcrowd report includes all required VRT sections and masks all secrets."""
    rep_config = ReportConfig(
        reporter_name="Security Tester",
        program_name="UXCam Bug Bounty",
        template="bugcrowd"
    )
    generator = HtmlReportGenerator(rep_config)

    finding = Finding(
        url="https://app.uxcam.com/static/main.js",
        pattern_name="Google API Key",
        category="API Keys",
        matched_value="AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345",
        confidence=95,
        validated=True,
        line_number=42,
        context='const apiKey = "AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345";'
    )

    scan_res = ScanResult(
        target="uxcam.com",
        total_urls_scanned=10,
        total_js_files=5,
        total_findings=1,
        total_validated=1,
        scan_time=2.5,
        findings=[finding]
    )

    # Test HTML Generation
    html_output = tmp_path / "report.html"
    generator.generate([finding], scan_res, str(html_output))
    html_content = html_output.read_text(encoding="utf-8")

    # Verify Bugcrowd sections are present
    assert "BugCrowd" in html_content
    assert "Vulnerability Title" in html_content
    assert "Affected Asset" in html_content
    assert "Vulnerability Category" in html_content
    assert "Preconditions" in html_content
    assert "Reproduction Steps" in html_content
    assert "Expected Result" in html_content
    assert "Actual Result" in html_content
    assert "Security Impact" in html_content
    assert "Evidence References" in html_content
    assert "Suggested Remediation" in html_content

    # CRITICAL: Raw secret must NOT be in HTML!
    assert "AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345" not in html_content
    # Masked representation should be present
    assert mask_secret("AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345") in html_content

    # Test JSON Generation
    json_output = tmp_path / "report.json"
    generator.generate([finding], scan_res, str(json_output))
    json_data = json.loads(json_output.read_text(encoding="utf-8"))

    assert json_data["report_format"] == "bugcrowd"
    assert len(json_data["vulnerabilities"]) == 1
    vuln = json_data["vulnerabilities"][0]
    assert "vulnerability_title" in vuln
    assert "affected_asset" in vuln
    assert "vulnerability_category" in vuln
    assert "severity" in vuln
    assert "reproduction_steps" in vuln
    assert "security_impact" in vuln
    assert "suggested_remediation" in vuln

    # Verify pattern validation is distinguished from credential verification
    assert "pattern_validation" in vuln
    assert vuln["pattern_validation"]["is_syntax_valid"] is True
    assert vuln["pattern_validation"]["validation_type"] == "offline_regex_entropy_pattern_match"
    assert "credential_verification" in vuln
    assert vuln["credential_verification"]["verified_against_live_api"] is False
    assert vuln["credential_verification"]["verification_status"] == "NOT_CHECKED"
    assert json_data["summary"]["pattern_validated_findings"] == 1
    assert json_data["summary"]["credential_verified_findings"] == 0

    # Raw secret must NOT be in JSON!
    assert "AIzaSyD-9xEXAMPLE_SECRET_API_KEY_12345" not in json.dumps(json_data)
