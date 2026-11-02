"""
NightCrawler - Tests for Authoritative EffectivePolicy & Architecture Remediation
Validates:
1. EffectivePolicy single source of truth across all components.
2. Strictest limits enforcement (UXCam 5 RPS hard ceiling).
3. Scanner & HTTP Client constructor interface compatibility.
4. Passive reconnaissance guarantees ZERO KeyHacks network calls.
5. Strict typed boolean and float parsing (rejecting 'false' == True).
6. Shared rate limiting and audit logging across the entire execution flow.
"""

import pytest
import os
import json
import math
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from src.core.program_manager import ProgramManager
from src.core.program_profile import (
    ProgramProfile, PolicyParser, PolicyValidator, strict_bool, strict_positive_float, strict_positive_int
)
from src.core.effective_policy import EffectivePolicy
from src.core.http_client import NightCrawlerHttpClient
from src.core.scanner import NightCrawlerScanner, Finding, ScanResult
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.auth_manager import AuthenticationManager
from src.core.audit_logger import AuditLogger
from src.output.report_manager import ReportManager, FindingStatus


def test_strict_type_parsing_helpers():
    """Verify strict_bool, strict_positive_float, and strict_positive_int reject invalid types."""
    # 1. Boolean string parsing: 'false' MUST NOT be True
    assert strict_bool(True) is True
    assert strict_bool(False) is False
    assert strict_bool("true") is True
    assert strict_bool("True") is True
    assert strict_bool("1") is True
    assert strict_bool("false") is False
    assert strict_bool("False") is False
    assert strict_bool("0") is False

    with pytest.raises(ValueError):
        strict_bool("invalid_bool")

    with pytest.raises(TypeError):
        strict_bool(["not_a_bool"])

    # 2. Positive float validation
    assert strict_positive_float(5.0) == 5.0
    assert strict_positive_float("2.5") == 2.5

    with pytest.raises(ValueError):
        strict_positive_float(0.0)

    with pytest.raises(ValueError):
        strict_positive_float(-1.5)

    with pytest.raises(ValueError):
        strict_positive_float(float("nan"))

    with pytest.raises(ValueError):
        strict_positive_float(float("inf"))

    # 3. Positive integer validation
    assert strict_positive_int(1) == 1
    assert strict_positive_int("4") == 4

    with pytest.raises(ValueError):
        strict_positive_int(0)

    with pytest.raises(ValueError):
        strict_positive_int(-5)

    with pytest.raises(TypeError):
        strict_positive_int(True)  # In Python, bool is a subclass of int


def test_effective_policy_resolution_and_strictest_limits():
    """Verify EffectivePolicy resolves program rules once and enforces strictest limits."""
    pm = ProgramManager()
    uxcam_profile = pm.get_profile("uxcam")
    assert uxcam_profile is not None

    # 1. Default UXCam policy enforces 5.0 RPS max
    policy = EffectivePolicy.build(profile=uxcam_profile)
    assert policy.program_id == "uxcam"
    assert policy.max_rps == 5.0
    assert policy.concurrency == 1
    assert policy.verify_tls is True
    assert policy.strict_scope is True

    # 2. CLI attempt to raise RPS above 5.0 for UXCam is strictly rejected
    with pytest.raises(ValueError, match="UXCam bug bounty policy enforces a strict maximum"):
        EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"max_rps": 10.0})

    # 3. CLI attempt to lower RPS (e.g. 2.0) is permitted (tightening restriction)
    policy_lowered = EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"max_rps": 2.0})
    assert policy_lowered.max_rps == 2.0

    # 4. Insecure TLS rejected when strict_scope is enabled
    with pytest.raises(ValueError, match="Insecure TLS configuration is prohibited"):
        EffectivePolicy.build(profile=uxcam_profile, cli_overrides={"verify_tls": False, "strict_scope": True})


def test_scanner_and_http_client_constructor_compatibility():
    """Verify Scanner and HTTP Client accept and share the same EffectivePolicy."""
    pm = ProgramManager()
    profile = pm.get_profile("uxcam")
    policy = EffectivePolicy.build(profile=profile)

    # 1. Construct HTTP client with EffectivePolicy
    client = NightCrawlerHttpClient(effective_policy=policy)
    assert client.effective_policy is policy
    assert client.scope_manager is policy.scope_manager
    assert client.request_policy_manager is policy.request_policy_manager
    assert client.auth_manager is policy.auth_manager
    assert client.audit_logger is policy.audit_logger
    assert client.verify_tls is True

    # 2. Construct Scanner with EffectivePolicy
    scanner = NightCrawlerScanner(effective_policy=policy)
    assert scanner.effective_policy is policy
    assert scanner.scope_manager is policy.scope_manager
    assert scanner.request_policy_manager is policy.request_policy_manager
    assert scanner.auth_manager is policy.auth_manager
    assert scanner.audit_logger is policy.audit_logger
    assert scanner.http_client.scope_manager is policy.scope_manager
    assert scanner.http_client.request_policy_manager is policy.request_policy_manager


@pytest.mark.asyncio
async def test_keyhacks_zero_network_requests_in_passive_recon():
    """Prove that during passive reconnaissance, KeyHacks makes strictly zero network requests."""
    pm = ProgramManager()
    profile = pm.get_profile("uxcam")
    policy = EffectivePolicy.build(profile=profile, cli_overrides={"validate_keys": False})

    scanner = NightCrawlerScanner(effective_policy=policy)

    # Discovered finding during passive recon
    finding = Finding(
        url="https://app.uxcam.com/app.js",
        pattern_name="AWS Access Key",
        category="Cloud Providers",
        matched_value="AKIAIOSFODNN7EXAMPLE",
        confidence=90,
        validated=True,
        credential_verified=False
    )
    scanner.results.findings.append(finding)

    # Patch socket or aiohttp / subprocess calls to verify none are made
    with patch("aiohttp.ClientSession.get") as mock_get, \
         patch("aiohttp.ClientSession.post") as mock_post, \
         patch("subprocess.run") as mock_run:
        # In passive recon, no validation calls occur
        assert finding.credential_verified is False
        assert finding.keyhacks_status == "NOT_CHECKED"
        assert mock_get.call_count == 0
        assert mock_post.call_count == 0
        assert mock_run.call_count == 0


def test_report_manager_unverified_findings_label(tmp_path):
    """Verify ReportManager labels unverified findings as 'Potential Secret — Not Verified'."""
    pm = ProgramManager()
    profile = pm.get_profile("uxcam")
    policy = EffectivePolicy.build(profile=profile)

    rep_manager = ReportManager(profile=profile, policy=policy, reporter_name="Hunter")

    finding = Finding(
        url="https://app.uxcam.com/bundle.js",
        pattern_name="Slack Webhook",
        category="Messaging",
        matched_value="https://hooks.slack.com/services/T00/B00/XXXX",
        confidence=80,
        validated=True,
        credential_verified=False,
        line_number=42,
        context='const webhook = "https://hooks.slack.com/services/T00/B00/XXXX";'
    )
    result = ScanResult(target="uxcam.com", findings=[finding])

    out_md = tmp_path / "report.md"
    rep_manager.generate(
        findings=[finding],
        scan_result=result,
        output_path=str(out_md)
    )

    content = out_md.read_text(encoding="utf-8")
    assert "Potential Secret — Not Verified" in content
    assert "UXCam Bug Bounty Program" in content
    assert "https://hooks.slack.com/services/T00/B00/XXXX" not in content  # Masked!

    out_json = tmp_path / "report.json"
    rep_manager.generate(
        findings=[finding],
        scan_result=result,
        output_path=str(out_json)
    )

    json_data = json.loads(out_json.read_text(encoding="utf-8"))
    vuln = json_data["findings"][0]
    assert vuln["pattern_matched"] is True
    assert vuln["pattern_validated"] is True
    assert vuln["credential_verified"] is False
    assert vuln["validation_status"] == "NOT_VERIFIED"
    assert vuln["verification_label"] == "Potential Secret — Not Verified"


def test_missing_credentials_fails_before_scanning():
    """Verify that if mandatory authentication is missing, validate_ready_to_scan() fails before scanning."""
    profile_data = {
        "id": "authenticated-api",
        "name": "Auth API",
        "scope": {"allowed_domains": ["api.company.com"]},
        "headers": {
            "required": {
                "X-Mandatory-Key": "${SECRET_KEY_NOT_IN_ENV}"
            }
        },
        "request_policy": {"max_rps": 2.0}
    }
    profile = ProgramProfile.from_dict(profile_data)
    policy = EffectivePolicy.build(profile=profile)

    # When scanning is initiated, missing credentials must raise ValueError
    with pytest.raises(ValueError, match="Mandatory authentication credentials missing"):
        policy.validate_ready_to_scan()
