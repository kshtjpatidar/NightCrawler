"""
NightCrawler - Request & Scope Configuration Module
Loads, validates, and merges configuration from config.yaml, environment variables, and CLI options.
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml
from dataclasses import dataclass, field

from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager


@dataclass
class NightCrawlerConfig:
    # Scope
    scope_enabled: bool = True
    allowed_domains: List[str] = field(default_factory=lambda: ["uxcam.com", "uxc.am"])
    excluded_domains: List[str] = field(default_factory=lambda: ["tara.uxcam.com", "connect.uxcam.com"])

    # Researcher Header
    custom_header_enabled: bool = True
    header_name: str = "X-User-Id"
    header_value: Optional[str] = None
    header_value_env: str = "NIGHTCRAWLER_RESEARCHER_ID"

    # Scan
    concurrency: int = 1
    timeout: int = 30
    depth: int = 1
    max_requests_per_second: float = 5.0
    strict_scope: bool = True
    verify_tls: bool = True

    # Features
    javascript_extraction: bool = True
    endpoint_discovery: bool = True
    secret_detection: bool = True
    validate_keys: bool = False
    external_secret_validation: bool = False

    # Reporting
    default_template: str = "bugcrowd"
    default_format: str = "html"
    reporter_name: str = "Security Researcher"
    reporter_email: str = ""
    program_name: str = "Bug Bounty Program"

    def get_scope_manager(self) -> ScopeManager:
        return ScopeManager(
            allowed_domains=self.allowed_domains,
            excluded_domains=self.excluded_domains,
            enabled=self.scope_enabled
        )

    def get_header_manager(self) -> HeaderManager:
        return HeaderManager(
            enabled=self.custom_header_enabled,
            header_name=self.header_name,
            header_value=self.header_value,
            header_value_env=self.header_value_env
        )

    def get_rate_limiter(self) -> GlobalRateLimiter:
        return GlobalRateLimiter(
            max_requests_per_second=self.max_requests_per_second,
            burst=1  # Strict pacing, no bursts allowed
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary matching config.yaml format (excluding sensitive secrets)."""
        return {
            "scope": {
                "enabled": self.scope_enabled,
                "allowed_domains": list(self.allowed_domains),
                "excluded_domains": list(self.excluded_domains),
            },
            "researcher": {
                "custom_header_enabled": self.custom_header_enabled,
                "header_name": self.header_name,
                "header_value_env": self.header_value_env,
            },
            "scan": {
                "concurrency": self.concurrency,
                "timeout": self.timeout,
                "depth": self.depth,
                "max_requests_per_second": self.max_requests_per_second,
                "strict_scope": self.strict_scope,
                "verify_tls": self.verify_tls,
            },
            "features": {
                "javascript_extraction": self.javascript_extraction,
                "endpoint_discovery": self.endpoint_discovery,
                "secret_detection": self.secret_detection,
                "validate_keys": self.validate_keys,
                "external_secret_validation": self.external_secret_validation,
            },
            "report": {
                "default_template": self.default_template,
                "default_format": self.default_format,
            }
        }

    def save_to_file(self, config_path: str = "config.yaml"):
        """Save non-sensitive configuration back to YAML."""
        data = self.to_dict()
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def load_config(config_file: Optional[str] = None) -> NightCrawlerConfig:
    """Load configuration from config.yaml, environment variables, with defaults."""
    cfg = NightCrawlerConfig()

    paths_to_try = [
        config_file,
        "config.yaml",
        Path(__file__).parent.parent.parent / "config.yaml"
    ]

    for p in paths_to_try:
        if p and Path(p).exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}

                # Scope
                scope = data.get("scope", {})
                if "enabled" in scope:
                    cfg.scope_enabled = bool(scope["enabled"])
                if "allowed_domains" in scope:
                    cfg.allowed_domains = [str(d) for d in scope["allowed_domains"] if d]
                if "excluded_domains" in scope:
                    cfg.excluded_domains = [str(d) for d in scope["excluded_domains"] if d]

                # Researcher
                res = data.get("researcher", {})
                if "custom_header_enabled" in res:
                    cfg.custom_header_enabled = bool(res["custom_header_enabled"])
                if "header_name" in res:
                    cfg.header_name = str(res["header_name"])
                if "header_value_env" in res:
                    cfg.header_value_env = str(res["header_value_env"])
                if "header_value" in res:
                    cfg.header_value = str(res["header_value"])

                # Scan
                scan = data.get("scan", {})
                if "concurrency" in scan:
                    cfg.concurrency = int(scan["concurrency"])
                if "timeout" in scan:
                    cfg.timeout = int(scan["timeout"])
                if "depth" in scan:
                    cfg.depth = int(scan["depth"])
                if "max_requests_per_second" in scan:
                    cfg.max_requests_per_second = float(scan["max_requests_per_second"])
                if "strict_scope" in scan:
                    cfg.strict_scope = bool(scan["strict_scope"])
                if "verify_tls" in scan:
                    cfg.verify_tls = bool(scan["verify_tls"])

                # Features
                feat = data.get("features", {})
                if "javascript_extraction" in feat:
                    cfg.javascript_extraction = bool(feat["javascript_extraction"])
                if "endpoint_discovery" in feat:
                    cfg.endpoint_discovery = bool(feat["endpoint_discovery"])
                if "secret_detection" in feat:
                    cfg.secret_detection = bool(feat["secret_detection"])
                if "validate_keys" in feat:
                    cfg.validate_keys = bool(feat["validate_keys"])
                if "external_secret_validation" in feat:
                    cfg.external_secret_validation = bool(feat["external_secret_validation"])

                # Report
                rep = data.get("report", {})
                if "default_template" in rep:
                    cfg.default_template = str(rep["default_template"])
                if "default_format" in rep:
                    cfg.default_format = str(rep["default_format"])

                break
            except Exception as e:
                pass

    # Environment variables override config
    env_researcher_id = os.getenv(cfg.header_value_env)
    if env_researcher_id:
        cfg.header_value = env_researcher_id

    if os.getenv("NIGHTCRAWLER_MAX_RPS"):
        try:
            cfg.max_requests_per_second = float(os.getenv("NIGHTCRAWLER_MAX_RPS"))
        except ValueError:
            pass

    if os.getenv("NIGHTCRAWLER_CONCURRENCY"):
        try:
            cfg.concurrency = int(os.getenv("NIGHTCRAWLER_CONCURRENCY"))
        except ValueError:
            pass

    return cfg
