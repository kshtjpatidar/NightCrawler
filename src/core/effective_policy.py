"""
NightCrawler - Authoritative Effective Policy Module
Constructs a single, validated, immutable EffectivePolicy object that governs
all reconnaissance operations, rate limits, scope boundaries, authentication,
permissions, and audit logging.

Execution Flow:
Program YAML -> ProgramManager -> PolicyValidator -> CLI Overrides -> EffectivePolicy -> NightCrawlerScanner -> Central HTTP Client -> ReportManager
"""

import os
import math
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set

from src.core.program_profile import (
    ProgramProfile, PolicyValidator, strict_bool, strict_positive_float, strict_positive_int, parse_authorized_providers
)
from src.core.scope import ScopeManager
from src.core.request_policy import RequestPolicyManager
from src.core.auth_manager import AuthenticationManager
from src.core.permissions import TestingPermissionManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.audit_logger import AuditLogger
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.request_config import NightCrawlerConfig


@dataclass
class EffectivePolicy:
    """
    Authoritative, immutable runtime security and operational policy.
    Every scanner component, HTTP client, and reporting module consumes this single instance.
    """
    program_id: str
    program_name: str
    version: str
    platform: str
    policy_url: str
    description: str

    # Centralized Operational Managers
    scope_manager: ScopeManager
    request_policy_manager: RequestPolicyManager
    auth_manager: AuthenticationManager
    permission_manager: TestingPermissionManager
    tool_compatibility_manager: ToolCompatibilityManager
    audit_logger: AuditLogger

    # Typed Configuration Settings
    max_rps: float
    per_host_rps: float
    concurrency: int
    timeout: int
    crawl_depth: int
    verify_tls: bool
    strict_scope: bool
    scope_enabled: bool
    default_template: str
    default_format: str
    reporter_name: str
    reporter_email: str
    validate_keys: bool
    requires_review: bool
    review_notes: List[str] = field(default_factory=list)
    authorized_providers: frozenset = field(default_factory=frozenset)
    allow_state_changing: bool = False
    http_client: Optional[Any] = None

    def __setattr__(self, name: str, value: Any):
        if name == "authorized_providers":
            if getattr(self, "_authorized_providers_locked", False):
                raise AttributeError("Cannot reassign or mutate authorized_providers on EffectivePolicy; permissions are immutable.")
            if value is None:
                val = frozenset()
            else:
                from src.core.program_profile import parse_authorized_providers
                val = frozenset(parse_authorized_providers(value, context="EffectivePolicy"))
            super().__setattr__("authorized_providers", val)
            super().__setattr__("_authorized_providers_locked", True)
            return
        super().__setattr__(name, value)

    def __post_init__(self):
        if self.max_rps <= 0:
            raise ValueError(f"max_rps must be positive, got {self.max_rps}")
        if self.concurrency <= 0:
            raise ValueError(f"concurrency must be a positive integer, got {self.concurrency}")
        if self.timeout <= 0:
            raise ValueError(f"timeout must be a positive integer, got {self.timeout}")
        if self.crawl_depth <= 0:
            raise ValueError(f"crawl_depth must be a positive integer, got {self.crawl_depth}")
        if self.strict_scope and not self.verify_tls:
            raise ValueError("Insecure TLS configuration is prohibited in strict compliance mode.")

    @classmethod
    def build(
        cls,
        profile: Optional[ProgramProfile] = None,
        config: Optional[NightCrawlerConfig] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> "EffectivePolicy":
        """
        Build an authoritative EffectivePolicy from a ProgramProfile or NightCrawlerConfig,
        applying permitted CLI overrides under strict policy validation rules.
        """
        overrides = cli_overrides or {}
        allowed_cli_keys = {
            "concurrency", "depth", "timeout", "max_rps", "verify_tls", "strict_scope",
            "scope_enabled", "allowed_domains", "excluded_domains", "header_name",
            "header_value", "template", "reporter", "reporter_email", "validate_keys",
            "allow_state_changing", "authorized_providers", "confirm_review"
        }
        unknown_cli = set(overrides.keys()) - allowed_cli_keys
        if unknown_cli:
            raise ValueError(f"Unknown CLI override option(s): {sorted(unknown_cli)}.")

        # 1. Base Resolution
        if profile:
            # Validate profile policy first
            errors = PolicyValidator.validate(profile)
            if errors:
                raise ValueError(f"Program profile '{profile.id}' failed policy validation: {'; '.join(errors)}")

            p_id = profile.id
            p_name = profile.name
            version = profile.version
            platform = profile.platform
            policy_url = profile.policy_url
            description = profile.description
            requires_review = profile.requires_review
            review_notes = list(profile.review_notes)

            # Safety Check: Enforce review requirement on imported/unverified profiles
            if requires_review and not overrides.get("confirm_review"):
                notes_str = f" Notes: {'; '.join(review_notes)}" if review_notes else ""
                raise ValueError(
                    f"Program profile '{p_id}' requires manual review before scanning can proceed.{notes_str} "
                    f"Pass --confirm-review to acknowledge and proceed."
                )

            base_rps = profile.request_policy.max_rps
            base_per_host_rps = profile.request_policy.per_host_rps
            base_concurrency = profile.request_policy.concurrency
            base_timeout = profile.request_policy.timeout
            base_crawl_depth = profile.request_policy.crawl_depth
            base_verify_tls = profile.request_policy.verify_tls if getattr(profile.request_policy, "verify_tls", None) is not None else True
            base_strict_scope = profile.request_policy.strict_scope
            base_scope_enabled = profile.scope.enabled

            allowed_domains = list(profile.scope.allowed_domains)
            excluded_domains = list(profile.scope.excluded_domains)
            allowed_ips = list(profile.scope.allowed_ips)
            allowed_cidrs = list(profile.scope.allowed_cidrs)
            excluded_ips = list(profile.scope.excluded_ips)
            excluded_cidrs = list(profile.scope.excluded_cidrs)
            allowed_paths = list(profile.scope.allowed_paths)
            excluded_paths = list(profile.scope.excluded_paths)
            allowed_protocols = list(profile.scope.allowed_protocols)
            allowed_ports = list(profile.scope.allowed_ports)
            tp_exclusions = list(profile.scope.third_party_hosted_exclusions)

            default_template = profile.reporting.default_template
            default_format = profile.reporting.default_format
            reporter_name = overrides.get("reporter") or "Security Researcher"
            reporter_email = overrides.get("reporter_email") or ""
        else:
            cfg = config or NightCrawlerConfig()
            p_id = "uxcam" if cfg.is_uxcam_profile() else "custom-target"
            p_name = cfg.program_name or "Bug Bounty Target"
            version = "1.0.0"
            platform = "Generic"
            policy_url = ""
            description = "Default scan profile"
            requires_review = False
            review_notes = []

            base_rps = cfg.max_requests_per_second
            base_per_host_rps = base_rps
            base_concurrency = cfg.concurrency
            base_timeout = cfg.timeout
            base_crawl_depth = cfg.depth
            base_verify_tls = cfg.verify_tls if getattr(cfg, "verify_tls", None) is not None else True
            base_strict_scope = cfg.strict_scope
            base_scope_enabled = cfg.scope_enabled

            allowed_domains = list(cfg.allowed_domains)
            excluded_domains = list(cfg.excluded_domains)
            allowed_ips = []
            allowed_cidrs = []
            excluded_ips = []
            excluded_cidrs = []
            allowed_paths = []
            excluded_paths = []
            allowed_protocols = ["http", "https"]
            allowed_ports = [80, 443, 8080, 8443]
            tp_exclusions = []

            default_template = cfg.default_template
            default_format = cfg.default_format
            reporter_name = cfg.reporter_name
            reporter_email = cfg.reporter_email

        # 2. Process CLI Overrides with Strict Typed Validation
        # Max RPS: validate strictly positive float
        if "max_rps" in overrides and overrides["max_rps"] is not None:
            cli_rps = strict_positive_float(overrides["max_rps"], "max_rps")
            # If program is UXCam, hard limit of 5.0 RPS applies
            is_uxcam = (p_id == "uxcam" or any("uxcam.com" in d or "uxc.am" in d for d in allowed_domains))
            if is_uxcam and cli_rps > 5.0:
                raise ValueError(
                    f"UXCam bug bounty policy enforces a strict maximum rate limit of 5 requests per second "
                    f"(requested {cli_rps} RPS)."
                )
            # Enforce strictest limit: cannot exceed profile max_rps
            if profile and cli_rps > profile.request_policy.max_rps:
                effective_rps = profile.request_policy.max_rps
            else:
                effective_rps = cli_rps
        else:
            effective_rps = base_rps

        # Concurrency
        if "concurrency" in overrides and overrides["concurrency"] is not None:
            cli_concurrency = strict_positive_int(overrides["concurrency"], "concurrency")
            if profile and cli_concurrency > profile.request_policy.concurrency:
                # CLI concurrency must never exceed profile ceiling: cap to profile maximum
                effective_concurrency = profile.request_policy.concurrency
            else:
                effective_concurrency = cli_concurrency
        else:
            effective_concurrency = base_concurrency

        # Timeout
        if "timeout" in overrides and overrides["timeout"] is not None:
            effective_timeout = strict_positive_int(overrides["timeout"], "timeout")
        else:
            effective_timeout = base_timeout

        # Crawl Depth
        if "depth" in overrides and overrides["depth"] is not None:
            effective_depth = strict_positive_int(overrides["depth"], "depth")
        else:
            effective_depth = base_crawl_depth

        # Strict Scope and Scope Enforcement Precedence
        if "strict_scope" in overrides and overrides["strict_scope"] is not None:
            cli_strict_scope = strict_bool(overrides["strict_scope"], "strict_scope")
        else:
            cli_strict_scope = None

        if "scope_enabled" in overrides and overrides["scope_enabled"] is not None:
            cli_scope_enabled = strict_bool(overrides["scope_enabled"], "scope_enabled")
        else:
            cli_scope_enabled = None

        # Safety Check: If program policy requires strict scope, CLI cannot weaken scope enforcement
        if base_strict_scope:
            if cli_strict_scope is False:
                raise ValueError("Disabling strict scope is prohibited when program policy requires strict scope.")
            if cli_scope_enabled is False:
                raise ValueError("Disabling target scope is prohibited when program policy requires strict scope.")
            effective_strict_scope = True
            effective_scope_enabled = True
        else:
            effective_strict_scope = cli_strict_scope if cli_strict_scope is not None else base_strict_scope
            effective_scope_enabled = cli_scope_enabled if cli_scope_enabled is not None else base_scope_enabled

        # Verify TLS
        if "verify_tls" in overrides and overrides["verify_tls"] is not None:
            effective_verify_tls = strict_bool(overrides["verify_tls"], "verify_tls")
        else:
            effective_verify_tls = base_verify_tls if base_verify_tls is not None else True

        # Safety Check: In strict compliance mode, reject insecure TLS configuration
        if effective_strict_scope and not effective_verify_tls:
            raise ValueError("Insecure TLS configuration is prohibited in strict compliance mode.")

        # External Providers Precedence
        profile_providers = set(getattr(profile, "authorized_providers", []) or []) if profile else set()
        if "authorized_providers" in overrides and overrides["authorized_providers"] is not None:
            cli_providers_raw = overrides["authorized_providers"]
            cli_providers_list = parse_authorized_providers(cli_providers_raw, context="CLI overrides")
            cli_providers = set(cli_providers_list)
            if profile:
                unauthorized_additions = cli_providers - profile_providers
                if unauthorized_additions:
                    raise ValueError(
                        f"CLI cannot expand program '{profile.id}' authorized providers with {sorted(unauthorized_additions)}. "
                        f"Only providers explicitly authorized by the program profile ({sorted(profile_providers) or 'None'}) are permitted."
                    )
                auth_providers = frozenset(cli_providers)
            else:
                auth_providers = frozenset(cli_providers)
        else:
            auth_providers = frozenset(profile_providers)

        # State-Changing Operations Precedence
        if "allow_state_changing" in overrides and overrides["allow_state_changing"] is not None:
            cli_state_changing = strict_bool(overrides["allow_state_changing"], "allow_state_changing")
        else:
            cli_state_changing = None

        profile_state_changing = False
        if profile and hasattr(profile, "testing_permissions") and profile.testing_permissions:
            profile_state_changing = getattr(profile.testing_permissions, "state_changing_allowed", False)
            if not profile.testing_permissions.credential_validation:
                profile_state_changing = False

        if cli_state_changing is True:
            if profile and not profile_state_changing:
                raise ValueError(
                    f"Program profile '{profile.id}' does not authorize state-changing validation operations. "
                    "CLI override cannot enable state-changing operations against program restrictions."
                )
            allow_state_changing = True
        else:
            allow_state_changing = False

        # Scope additions and narrowing
        if "allowed_domains" in overrides and overrides["allowed_domains"] is not None:
            if profile:
                profile_scope = ScopeManager.from_profile(profile)
                narrowed = []
                for d in overrides["allowed_domains"]:
                    d_str = str(d).strip()
                    if not d_str:
                        continue
                    clean_d = ScopeManager._normalize_domain(d_str)
                    if not profile_scope.is_host_allowed(clean_d):
                        raise ValueError(
                            f"CLI cannot expand program '{profile.id}' authorized scope with '{d_str}'. "
                            f"Target is outside authorized profile scope. Only scope narrowing is permitted."
                        )
                    narrowed.append(d_str)
                if not narrowed:
                    raise ValueError(f"Target scope cannot be empty after narrowing program '{profile.id}' scope.")
                allowed_domains = narrowed
            else:
                allowed_domains = [str(d).strip() for d in overrides["allowed_domains"] if str(d).strip()]

        if overrides.get("excluded_domains"):
            for d in overrides["excluded_domains"]:
                d_str = str(d).strip()
                if d_str and d_str not in excluded_domains:
                    excluded_domains.append(d_str)

        # Safety Check: Empty scope rejection (Fail-closed policy initialization)
        if effective_scope_enabled:
            if not allowed_domains and not allowed_ips and not allowed_cidrs:
                raise ValueError("Target scope cannot be empty when scope enforcement is enabled.")

        # Template / Format
        if overrides.get("template"):
            default_template = str(overrides["template"]).lower()
        if overrides.get("reporter"):
            reporter_name = str(overrides["reporter"])
        if overrides.get("reporter_email"):
            reporter_email = str(overrides["reporter_email"])

        # Credential validation check
        if "validate_keys" in overrides and overrides["validate_keys"] is not None:
            validate_keys_requested = strict_bool(overrides["validate_keys"], "validate_keys")
        else:
            validate_keys_requested = False
        if profile:
            # Policy check: is credential validation permitted by program profile?
            perm = TestingPermissionManager.from_profile(profile, allow_credential_validation=validate_keys_requested)
            effective_validate_keys = perm.is_permitted("credential_validation")
        else:
            perm = TestingPermissionManager(allow_credential_validation=validate_keys_requested)
            effective_validate_keys = perm.is_permitted("credential_validation")

        # 3. Instantiate Operational Managers
        scope_manager = ScopeManager(
            allowed_domains=allowed_domains,
            excluded_domains=excluded_domains,
            enabled=effective_scope_enabled,
            allowed_ips=allowed_ips,
            allowed_cidrs=allowed_cidrs,
            excluded_ips=excluded_ips,
            excluded_cidrs=excluded_cidrs,
            allowed_paths=allowed_paths,
            excluded_paths=excluded_paths,
            allowed_protocols=allowed_protocols,
            allowed_ports=allowed_ports,
            third_party_hosted_exclusions=tp_exclusions
        )

        request_policy_manager = RequestPolicyManager(
            max_rps=effective_rps,
            per_host_rps=base_per_host_rps,
            concurrency_limit=effective_concurrency,
            timeout=effective_timeout,
            crawl_depth=effective_depth,
            verify_tls=effective_verify_tls,
            strict_scope=effective_strict_scope
        )

        if profile:
            auth_manager = AuthenticationManager.from_profile(profile, scope_manager=scope_manager, raise_if_missing=False)
            tool_compatibility_manager = ToolCompatibilityManager(profile)
            audit_logger = AuditLogger(program_id=p_id)
        else:
            # Fallback auth manager from config/headers
            req_headers = {}
            if overrides.get("header_name") and overrides.get("header_value"):
                req_headers[overrides["header_name"]] = overrides["header_value"]
            elif config and config.custom_header_enabled:
                val = config.header_value or os.getenv(config.header_value_env or "NIGHTCRAWLER_RESEARCHER_ID", "")
                if val:
                    req_headers[config.header_name] = val

            auth_manager = AuthenticationManager(
                required_headers=req_headers,
                scope_manager=scope_manager
            )
            tool_compatibility_manager = None
            audit_logger = AuditLogger(program_id=p_id)

        # Handle researcher header from CLI overrides
        if overrides.get("header_value"):
            h_name = overrides.get("header_name") or "X-User-Id"
            h_val = overrides["header_value"]
            auth_manager.set_custom_header(h_name, h_val)
            os.environ["NIGHTCRAWLER_RESEARCHER_ID"] = h_val
            os.environ["NIGHTCRAWLER_HEADER_VALUE"] = h_val

        return cls(
            program_id=p_id,
            program_name=p_name,
            version=version,
            platform=platform,
            policy_url=policy_url,
            description=description,
            scope_manager=scope_manager,
            request_policy_manager=request_policy_manager,
            auth_manager=auth_manager,
            permission_manager=perm,
            tool_compatibility_manager=tool_compatibility_manager,
            audit_logger=audit_logger,
            max_rps=effective_rps,
            per_host_rps=base_per_host_rps,
            concurrency=effective_concurrency,
            timeout=effective_timeout,
            crawl_depth=effective_depth,
            verify_tls=effective_verify_tls,
            strict_scope=effective_strict_scope,
            scope_enabled=effective_scope_enabled,
            default_template=default_template,
            default_format=default_format,
            reporter_name=reporter_name,
            reporter_email=reporter_email,
            validate_keys=effective_validate_keys,
            requires_review=requires_review,
            review_notes=review_notes,
            authorized_providers=auth_providers,
            allow_state_changing=allow_state_changing
        )

    def is_uxcam_profile(self) -> bool:
        """Check if this policy targets UXCam assets."""
        if self.program_id == "uxcam":
            return True
        for d in self.scope_manager.allowed_domains:
            if "uxcam.com" in d or "uxc.am" in d:
                return True
        return False

    def validate_ready_to_scan(self):
        """Ensure all required credentials and headers are present before sending HTTP traffic."""
        self.auth_manager.validate_credentials_present()
