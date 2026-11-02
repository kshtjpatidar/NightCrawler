"""
Tests for NightCrawler KeyHacks Validation Controls
Validates that automatic KeyHacks credential validation is disabled by default
and never transmits discovered secrets to third-party services without authorization.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.core.scanner import NightCrawlerScanner, Finding
from src.core.request_config import load_config


def test_keyhacks_disabled_by_default_in_config():
    """Verify validate_keys is disabled by default in loaded config."""
    cfg = load_config()
    assert cfg.validate_keys is False
    assert cfg.external_secret_validation is False


def test_scanner_preserves_secrets_without_validating_when_disabled():
    """Verify secrets are identified and categorized but never sent to validation APIs."""
    scanner = NightCrawlerScanner(
        concurrency=1,
        validate_keys=False,
        secret_detection=True
    )
    assert scanner.validate_keys is False

    # Simulate sample JS content with a high-entropy AWS key pattern
    fake_js = 'var aws_key = "AKIAJ7XYZ9876543210M";'
    findings = scanner._scan_content("https://app.uxcam.com/static/bundle.js", fake_js)

    assert len(findings) > 0
    finding = findings[0]
    # Finding must exist, but keyhacks_status must remain NOT_CHECKED
    assert finding.keyhacks_status == "NOT_CHECKED"
    assert finding.is_keyhacks_valid() is False
    assert finding.line_number is not None
    assert "AKIAJ7XYZ9876543210M" in finding.matched_value


@patch("src.validators.keyhacks.KeyHacksValidator.validate_secret")
def test_no_external_api_calls_made_when_validation_disabled(mock_validate):
    """Verify validate_secret is never invoked during a scan when validate_keys=False."""
    scanner = NightCrawlerScanner(concurrency=1, validate_keys=False)
    fake_js = 'var aws_key = "AKIAJ7XYZ9876543210M";'
    
    findings = scanner._scan_content("https://app.uxcam.com/pay.js", fake_js)
    # mock_validate must not have been called
    assert mock_validate.call_count == 0
