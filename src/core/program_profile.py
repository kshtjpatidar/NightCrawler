"""
NightCrawler - Program Profile, Policy Parser & Policy Validator
Modular bug bounty program definition and compliance validation.
"""

import os
import re
import math
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
import yaml
import json


def strict_bool(val: Any, field_name: str = "field") -> bool:
    """Strictly convert value to boolean, preventing 'false' == True bugs."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        if val == 1:
            return True
        elif val == 0:
            return False
        raise ValueError(f"Invalid boolean value for {field_name}: {val}")
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "yes", "on"):
            return True
        elif v in ("false", "0", "no", "off"):
            return False
        raise ValueError(f"Invalid boolean string for {field_name}: '{val}'")
    raise TypeError(f"Expected boolean for {field_name}, got {type(val).__name__}")


class PolicyValidationError(ValueError, TypeError):
    """Raised when an EffectivePolicy or ProgramProfile numeric or security setting fails strict validation."""
    pass


def validate_profile_int(val: Any, field_name: str, min_val: int = 1, max_val: int = 1_000_000, context: str = "profile") -> int:
    """
    Validate integer-only profile fields without permissive type coercion.
    Strictly rejects booleans, floats (including integral floats), numeric strings, and non-ints.
    Rejects values outside [min_val, max_val], and extreme integers causing OverflowError.
    """
    if isinstance(val, bool):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected integer for {field_name}, got bool: {val}")
    if isinstance(val, float):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected integer for {field_name}, got float: {val}")
    if isinstance(val, str):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected integer for {field_name}, got str: '{val}'")
    if type(val) is not int:
        raise PolicyValidationError(f"Program profile failed policy validation: Expected integer for {field_name}, got {type(val).__name__}")
    try:
        if not math.isfinite(val):
            raise PolicyValidationError(f"Program profile failed policy validation: {field_name} must be finite, got {val}")
    except OverflowError:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} value exceeds numeric bounds (OverflowError): {val}")
    if val < min_val:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} must be >= {min_val}, got {val}")
    if val > max_val:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} exceeds maximum allowable limit ({max_val:,}), got {val}")
    return val


def validate_profile_float(val: Any, field_name: str, min_val: float = 0.0001, max_val: float = 1_000_000.0, context: str = "profile") -> float:
    """
    Validate float rate fields without permissive type coercion.
    Strictly rejects booleans, strings, non-numeric types, NaN, infinities, zero/negative, and values above max_val.
    """
    if isinstance(val, bool):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected numeric value for {field_name}, got bool: {val}")
    if isinstance(val, str):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected numeric value for {field_name}, got str: '{val}'")
    if type(val) not in (int, float):
        raise PolicyValidationError(f"Program profile failed policy validation: Expected numeric value for {field_name}, got {type(val).__name__}")
    try:
        f = float(val)
        if not math.isfinite(f):
            raise PolicyValidationError(f"Program profile failed policy validation: {field_name} cannot be NaN or Infinity, got {val}")
    except OverflowError:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} value exceeds numeric bounds (OverflowError): {val}")
    if f <= 0:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} must be strictly positive (> 0), got {val}")
    if f > max_val:
        raise PolicyValidationError(f"Program profile failed policy validation: {field_name} exceeds maximum allowable limit ({int(max_val):,}), got {val}")
    return f


def strict_positive_float(val: Any, field_name: str = "rate") -> float:
    """Strictly validate positive, non-NaN, non-Inf float."""
    if isinstance(val, bool):
        raise TypeError(f"Expected numeric value for {field_name}, got bool: {val}")
    if type(val) not in (int, float, str):
        raise TypeError(f"Expected numeric value for {field_name}, got {type(val).__name__}")
    try:
        f = float(val)
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"Invalid numeric value for {field_name}: {val}")
    try:
        if not math.isfinite(f):
            raise ValueError(f"{field_name} cannot be NaN or Infinity, got {val}")
    except OverflowError:
        raise ValueError(f"{field_name} value exceeds numeric bounds (OverflowError): {val}")
    if f <= 0:
        raise ValueError(f"{field_name} must be strictly positive (> 0), got {val}")
    if f > 1_000_000:
        raise ValueError(f"{field_name} exceeds maximum allowable limit (1,000,000), got {val}")
    return f


def strict_positive_int(val: Any, field_name: str = "integer") -> int:
    """Strictly validate positive integer."""
    if isinstance(val, bool):
        raise TypeError(f"Expected integer for {field_name}, got bool: {val}")
    if isinstance(val, float):
        raise TypeError(f"Expected integer for {field_name}, got float: {val}")
    if type(val) not in (int, str):
        raise TypeError(f"Expected integer for {field_name}, got {type(val).__name__}")
    if isinstance(val, str):
        if not val.strip().isdigit():
            raise ValueError(f"Invalid integer string for {field_name}: '{val}'")
        try:
            i = int(val.strip())
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"Invalid integer value for {field_name}: {val}")
    else:
        try:
            i = int(val)
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"Invalid integer value for {field_name}: {val}")
    try:
        if not math.isfinite(i):
            raise ValueError(f"{field_name} must be finite, got {val}")
    except OverflowError:
        raise ValueError(f"{field_name} value exceeds numeric bounds (OverflowError): {val}")
    if i <= 0:
        raise ValueError(f"{field_name} must be strictly positive (> 0), got {val}")
    if i > 1_000_000:
        raise ValueError(f"{field_name} exceeds maximum allowable limit (1,000,000), got {val}")
    return i


def parse_authorized_providers(val: Any, context: str = "program profile") -> List[str]:
    """
    Strictly parse and validate authorized providers list.
    Fails closed on wrong types, numbers, nested lists, wildcards, empty strings, and malformed names.
    Returns sorted, normalized, deduplicated list of provider identifiers or domain names.
    """
    if val is None:
        return []
    if isinstance(val, str):
        raise ValueError(f"authorized_providers in {context} must be a list of strings, got str: '{val}'")
    if not isinstance(val, (list, tuple, set, frozenset)):
        raise ValueError(f"authorized_providers in {context} must be a list of strings, got {type(val).__name__}")

    cleaned = []
    seen = set()
    for item in val:
        if not isinstance(item, str):
            raise ValueError(f"authorized_providers entries in {context} must be strings, got {type(item).__name__}: {item}")
        p_clean = item.strip()
        if not p_clean:
            raise ValueError(f"authorized_providers entries in {context} cannot be empty strings.")
        if p_clean in ("*", "all"):
            raise ValueError(f"Wildcard '{p_clean}' is prohibited in authorized_providers in {context}.")

        # IDNA normalization first (converts Unicode domain names to ASCII punycode)
        try:
            normalized = p_clean.lower().encode("idna").decode("ascii")
        except Exception:
            raise ValueError(f"Invalid Unicode/IDNA provider name in {context}: '{p_clean}'")

        # Reject invalid characters (injection, control chars, spaces, slashes)
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', normalized):
            raise ValueError(
                f"Invalid provider entry in {context}: '{p_clean}'. "
                f"Provider names must be valid alphanumeric identifiers or domain names."
            )

        # Disallow IP literals
        try:
            ipaddress.ip_address(normalized)
            raise ValueError(f"IP address literals like '{p_clean}' are prohibited in authorized_providers in {context}.")
        except ValueError as e:
            if "prohibited" in str(e):
                raise

        # Disallow single TLDs like 'com', '.com'
        if normalized.startswith(".") or (normalized in ("com", "org", "net", "io", "gov", "edu", "co", "app", "dev")):
            raise ValueError(f"Top-level domain '{p_clean}' is prohibited as an authorized provider in {context}.")

        if normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized)

    return sorted(cleaned)


def validate_domain_entry(entry: Any, list_name: str = "allowed_domains", context: str = "") -> str:
    """
    Validate a single domain entry in allowed_domains or excluded_domains.
    Rejects:
    - Non-string types, empty strings, whitespace
    - Catch-all wildcards ('*', 'all', '*.*')
    - Schemes ('://'), paths ('/'), query strings ('?'), fragments ('#')
    - Ports (':') and userinfo ('@')
    - IP literals (IPv4 and IPv6)
    - Malformed wildcard syntax (must be '*.domain.tld' if wildcard)
    - Hostnames exceeding 253 characters, or labels exceeding 63 characters
    - Non-compliant DNS characters according to RFC 1035 / IDNA.
    Returns normalized string.
    """
    ctx_prefix = f"{context}: " if context else ""
    if not isinstance(entry, str):
        raise ValueError(f"{ctx_prefix}Domain entry in {list_name} must be a string, got {type(entry).__name__}: {entry}")

    val = entry.strip()
    if not val:
        raise ValueError(f"{ctx_prefix}Domain entry in {list_name} cannot be empty or whitespace-only.")

    if val.lower() in ("*", "all", "*.*"):
        raise ValueError(f"{ctx_prefix}Dangerous wildcard/catch-all domain '{entry}' in {list_name} is prohibited.")

    if any(c.isspace() for c in val):
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains forbidden embedded whitespace.")

    if "://" in val:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains URL scheme (must be hostname only).")

    if "/" in val or "\\" in val or "?" in val or "#" in val:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains URL path, query, or fragment characters.")

    if "@" in val:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains userinfo ('@').")

    if ":" in val:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains port or separator (':').")

    # Reject IP literals (IPs belong in allowed_ips / excluded_ips)
    try:
        ipaddress.ip_address(val)
        raise ValueError(f"{ctx_prefix}IP literal '{entry}' in {list_name} is not permitted in domain lists (use allowed_ips/excluded_ips).")
    except ValueError as e:
        if "is not permitted in domain lists" in str(e):
            raise

    # Handle wildcard syntax
    test_val = val
    if "*" in val:
        if not val.startswith("*."):
            raise ValueError(
                f"{ctx_prefix}Malformed wildcard domain '{entry}' in {list_name}. "
                "Wildcard domains must use the standard format '*.example.com'."
            )
        remainder = val[2:]
        if "*" in remainder:
            raise ValueError(f"{ctx_prefix}Malformed wildcard domain '{entry}' in {list_name}: multiple wildcard characters.")
        if not remainder or remainder.startswith("."):
            raise ValueError(f"{ctx_prefix}Malformed wildcard domain '{entry}' in {list_name}: missing base domain after '*.'")
        test_val = remainder

    # Convert IDN / punycode if needed
    try:
        ascii_domain = test_val.encode("idna").decode("ascii").lower()
    except Exception as e:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} failed IDNA encoding: {e}")

    # Enforce DNS length limits
    if len(ascii_domain) > 253:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} exceeds maximum length of 253 characters.")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} must contain at least two labels (e.g., example.com).")

    # Validate each label
    label_pattern = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    for label in labels:
        if not label:
            raise ValueError(f"{ctx_prefix}Domain entry '{entry}' in {list_name} contains empty label.")
        if len(label) > 63:
            raise ValueError(f"{ctx_prefix}Label '{label}' in domain entry '{entry}' exceeds maximum length of 63 characters.")
        if not label_pattern.match(label):
            raise ValueError(f"{ctx_prefix}Label '{label}' in domain entry '{entry}' contains invalid DNS characters.")

    return val.lower()


@dataclass
class ScopeDefinition:
    enabled: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    allowed_cidrs: List[str] = field(default_factory=list)
    excluded_ips: List[str] = field(default_factory=list)
    excluded_cidrs: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    allowed_protocols: List[str] = field(default_factory=lambda: ["http", "https"])
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    third_party_hosted_exclusions: List[str] = field(default_factory=list)


@dataclass
class RequestPolicyDefinition:
    max_rps: float = 5.0
    concurrency: int = 1
    timeout: int = 30
    max_retries: int = 2
    crawl_depth: int = 1
    burst: int = 1
    verify_tls: bool = True
    strict_scope: bool = True
    per_host_rps: float = 5.0


@dataclass
class AuthenticationDefinition:
    type: str = "none"  # none, bearer, api_key, cookie, basic
    token_env: Optional[str] = None
    header_name: Optional[str] = None
    header_prefix: Optional[str] = None
    cookie_env: Optional[str] = None
    username_env: Optional[str] = None
    password_env: Optional[str] = None
    session_file: Optional[str] = None


@dataclass
class TestingPermissionsDefinition:
    __test__ = False
    passive_recon: bool = True
    active_recon: bool = False
    endpoint_discovery: bool = True
    javascript_analysis: bool = True
    secret_detection: bool = True
    credential_validation: bool = False
    fuzzing: bool = False
    injection_testing: bool = False
    destructive_testing: bool = False
    denial_of_service: bool = False
    social_engineering: bool = False
    state_changing_allowed: bool = False


@dataclass
class ToolRestrictionsDefinition:
    allowed_tools: List[str] = field(default_factory=lambda: ["subfinder", "httpx", "gau", "waybackurls", "jsluice"])
    disabled_tools: List[str] = field(default_factory=lambda: ["katana", "hakrawler", "subjs", "getjs"])


@dataclass
class ReportingDefinition:
    default_template: str = "bugcrowd"
    default_format: str = "html"
    program_name: str = "Bug Bounty Program"


@dataclass
class ProgramProfile:
    """Complete bug bounty program profile and compliance rules."""
    id: str
    name: str
    version: str = "1.0.0"
    platform: str = "Bugcrowd"
    policy_url: str = ""
    description: str = ""
    source_reference: str = ""
    requires_review: bool = False
    review_notes: List[str] = field(default_factory=list)

    scope: ScopeDefinition = field(default_factory=ScopeDefinition)
    request_policy: RequestPolicyDefinition = field(default_factory=RequestPolicyDefinition)
    headers: Dict[str, Any] = field(default_factory=lambda: {"required": {}, "optional": {}})
    authentication: AuthenticationDefinition = field(default_factory=AuthenticationDefinition)
    testing_permissions: TestingPermissionsDefinition = field(default_factory=TestingPermissionsDefinition)
    tool_restrictions: ToolRestrictionsDefinition = field(default_factory=ToolRestrictionsDefinition)
    reporting: ReportingDefinition = field(default_factory=ReportingDefinition)
    authorized_providers: List[str] = field(default_factory=list)

    def resolve_headers(self) -> Dict[str, str]:
        """Resolve header values expanding ${ENV_VAR} syntax safely."""
        resolved = {}
        req = self.headers.get("required", {})
        for name, tmpl in req.items():
            val = PolicyParser.expand_env_vars(str(tmpl))
            resolved[name] = val
        return resolved

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to serializable dict."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "policy_url": self.policy_url,
            "description": self.description,
            "source_reference": self.source_reference,
            "requires_review": self.requires_review,
            "review_notes": list(self.review_notes),
            "scope": {
                "enabled": self.scope.enabled,
                "allowed_domains": list(self.scope.allowed_domains),
                "excluded_domains": list(self.scope.excluded_domains),
                "allowed_ips": list(self.scope.allowed_ips),
                "allowed_cidrs": list(self.scope.allowed_cidrs),
                "excluded_ips": list(self.scope.excluded_ips),
                "excluded_cidrs": list(self.scope.excluded_cidrs),
                "allowed_paths": list(self.scope.allowed_paths),
                "excluded_paths": list(self.scope.excluded_paths),
                "allowed_protocols": list(self.scope.allowed_protocols),
                "allowed_ports": list(self.scope.allowed_ports),
                "third_party_hosted_exclusions": list(self.scope.third_party_hosted_exclusions),
            },
            "request_policy": {
                "max_rps": self.request_policy.max_rps,
                "concurrency": self.request_policy.concurrency,
                "timeout": self.request_policy.timeout,
                "max_retries": self.request_policy.max_retries,
                "crawl_depth": self.request_policy.crawl_depth,
                "burst": self.request_policy.burst,
                "verify_tls": self.request_policy.verify_tls,
                "strict_scope": self.request_policy.strict_scope,
                "per_host_rps": self.request_policy.per_host_rps,
            },
            "headers": self.headers,
            "authentication": {
                "type": self.authentication.type,
                "token_env": self.authentication.token_env,
                "header_name": self.authentication.header_name,
                "header_prefix": self.authentication.header_prefix,
                "cookie_env": self.authentication.cookie_env,
                "username_env": self.authentication.username_env,
                "password_env": self.authentication.password_env,
                "session_file": self.authentication.session_file,
            },
            "testing_permissions": {
                "passive_recon": self.testing_permissions.passive_recon,
                "active_recon": self.testing_permissions.active_recon,
                "endpoint_discovery": self.testing_permissions.endpoint_discovery,
                "javascript_analysis": self.testing_permissions.javascript_analysis,
                "secret_detection": self.testing_permissions.secret_detection,
                "credential_validation": self.testing_permissions.credential_validation,
                "fuzzing": self.testing_permissions.fuzzing,
                "injection_testing": self.testing_permissions.injection_testing,
                "destructive_testing": False,  # Always hard-coded false
                "denial_of_service": False,   # Always hard-coded false
                "social_engineering": self.testing_permissions.social_engineering,
                "state_changing_allowed": self.testing_permissions.state_changing_allowed,
            },
            "tool_restrictions": {
                "allowed_tools": list(self.tool_restrictions.allowed_tools),
                "disabled_tools": list(self.tool_restrictions.disabled_tools),
            },
            "reporting": {
                "default_template": self.reporting.default_template,
                "default_format": self.reporting.default_format,
                "program_name": self.reporting.program_name,
            },
            "authorized_providers": list(self.authorized_providers)
        }

    def save_yaml(self, path: Path):
        """Save profile to YAML file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_ref: str = "") -> "ProgramProfile":
        """Convenience method delegating to PolicyParser.from_dict."""
        return PolicyParser.from_dict(data, source_ref=source_ref)


class PolicyParser:
    """Parses program policies from YAML, JSON, dictionaries, or unstructured text."""

    @staticmethod
    def expand_env_vars(text: str) -> str:
        """Expand ${ENV_VAR} or $ENV_VAR safely."""
        def repl(match):
            var_name = match.group(1) or match.group(2)
            return os.getenv(var_name, "")
        return re.sub(r'\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)', repl, text)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_ref: str = "") -> ProgramProfile:
        """Instantiate ProgramProfile from dictionary."""
        if not isinstance(data, dict):
            raise ValueError(f"Program profile data must be a dictionary, got {type(data).__name__}")

        # Validate against unknown top-level keys
        allowed_top_keys = {
            "id", "name", "version", "platform", "policy_url", "description",
            "source_reference", "requires_review", "review_notes", "scope",
            "request_policy", "headers", "authentication", "testing_permissions",
            "tool_restrictions", "reporting", "authorized_providers"
        }
        unknown_top = set(data.keys()) - allowed_top_keys
        if unknown_top:
            raise ValueError(f"Unknown policy key(s) in program profile: {sorted(unknown_top)}. Unrecognized configuration keys are prohibited.")

        p_id = data.get("id", "custom-program").lower().strip()
        p_name = data.get("name", p_id)
        version = str(data.get("version", "1.0.0"))
        platform = data.get("platform", "Generic")
        policy_url = data.get("policy_url", "")
        description = data.get("description", "")

        scope_raw = data.get("scope", {})
        if not isinstance(scope_raw, dict):
            raise ValueError(f"scope section must be a dictionary in profile '{p_id}'")
        allowed_scope_keys = {
            "enabled", "allowed_domains", "excluded_domains", "allowed_ips", "allowed_cidrs",
            "excluded_ips", "excluded_cidrs", "allowed_paths", "excluded_paths",
            "allowed_protocols", "allowed_ports", "third_party_hosted_exclusions"
        }
        unknown_scope = set(scope_raw.keys()) - allowed_scope_keys
        if unknown_scope:
            raise ValueError(f"Unknown key(s) in profile scope configuration: {sorted(unknown_scope)}.")

        scope = ScopeDefinition(
            enabled=strict_bool(scope_raw.get("enabled", True), "scope.enabled") if "enabled" in scope_raw else True,
            allowed_domains=[d.strip() for d in scope_raw.get("allowed_domains", []) if d.strip()],
            excluded_domains=[d.strip() for d in scope_raw.get("excluded_domains", []) if d.strip()],
            allowed_ips=[ip.strip() for ip in scope_raw.get("allowed_ips", []) if ip.strip()],
            allowed_cidrs=[c.strip() for c in scope_raw.get("allowed_cidrs", []) if c.strip()],
            excluded_ips=[ip.strip() for ip in scope_raw.get("excluded_ips", []) if ip.strip()],
            excluded_cidrs=[c.strip() for c in scope_raw.get("excluded_cidrs", []) if c.strip()],
            allowed_paths=[p.strip() for p in scope_raw.get("allowed_paths", []) if p.strip()],
            excluded_paths=[p.strip() for p in scope_raw.get("excluded_paths", []) if p.strip()],
            allowed_protocols=[pr.lower().strip() for pr in scope_raw.get("allowed_protocols", ["http", "https"])],
            allowed_ports=[
                validate_profile_int(p, "scope.allowed_ports", min_val=1, max_val=65535, context=f"profile '{p_id}'")
                for p in scope_raw.get("allowed_ports", [80, 443, 8080, 8443])
            ],
            third_party_hosted_exclusions=[h.strip() for h in scope_raw.get("third_party_hosted_exclusions", []) if h.strip()]
        )

        rp_raw = data.get("request_policy", {})
        if not isinstance(rp_raw, dict):
            raise ValueError(f"request_policy section must be a dictionary in profile '{p_id}'")
        allowed_rp_keys = {
            "max_rps", "concurrency", "timeout", "max_retries", "crawl_depth", "burst",
            "verify_tls", "strict_scope", "per_host_rps"
        }
        unknown_rp = set(rp_raw.keys()) - allowed_rp_keys
        if unknown_rp:
            raise ValueError(f"Unknown key(s) in profile request_policy: {sorted(unknown_rp)}.")

        max_rps_val = rp_raw.get("max_rps", 5.0)
        max_rps = validate_profile_float(max_rps_val, "request_policy.max_rps", context=f"profile '{p_id}'")

        concurrency_val = rp_raw.get("concurrency", 1)
        concurrency = validate_profile_int(concurrency_val, "request_policy.concurrency", min_val=1, context=f"profile '{p_id}'")

        timeout_val = rp_raw.get("timeout", 30)
        timeout = validate_profile_int(timeout_val, "request_policy.timeout", min_val=1, context=f"profile '{p_id}'")

        crawl_depth_val = rp_raw.get("crawl_depth", 1)
        crawl_depth = validate_profile_int(crawl_depth_val, "request_policy.crawl_depth", min_val=1, context=f"profile '{p_id}'")

        per_host_rps_val = rp_raw.get("per_host_rps", max_rps)
        per_host_rps = validate_profile_float(per_host_rps_val, "request_policy.per_host_rps", context=f"profile '{p_id}'")

        max_retries_val = rp_raw.get("max_retries", 2)
        max_retries = validate_profile_int(max_retries_val, "request_policy.max_retries", min_val=0, context=f"profile '{p_id}'")

        burst_val = rp_raw.get("burst", 1)
        burst = validate_profile_int(burst_val, "request_policy.burst", min_val=1, context=f"profile '{p_id}'")

        request_policy = RequestPolicyDefinition(
            max_rps=max_rps,
            concurrency=concurrency,
            timeout=timeout,
            max_retries=max_retries,
            crawl_depth=crawl_depth,
            burst=burst,
            verify_tls=strict_bool(rp_raw.get("verify_tls", True), "request_policy.verify_tls") if "verify_tls" in rp_raw else True,
            strict_scope=strict_bool(rp_raw.get("strict_scope", True), "request_policy.strict_scope") if "strict_scope" in rp_raw else True,
            per_host_rps=per_host_rps
        )

        headers = data.get("headers", {"required": {}, "optional": {}})

        auth_raw = data.get("authentication", {})
        if not isinstance(auth_raw, dict):
            raise ValueError(f"authentication section must be a dictionary in profile '{p_id}'")
        allowed_auth_keys = {
            "type", "token_env", "header_name", "header_prefix", "cookie_env",
            "username_env", "password_env", "session_file"
        }
        unknown_auth = set(auth_raw.keys()) - allowed_auth_keys
        if unknown_auth:
            raise ValueError(f"Unknown key(s) in profile authentication: {sorted(unknown_auth)}.")

        authentication = AuthenticationDefinition(
            type=auth_raw.get("type", "none").lower().strip(),
            token_env=auth_raw.get("token_env"),
            header_name=auth_raw.get("header_name"),
            header_prefix=auth_raw.get("header_prefix"),
            cookie_env=auth_raw.get("cookie_env"),
            username_env=auth_raw.get("username_env"),
            password_env=auth_raw.get("password_env"),
            session_file=auth_raw.get("session_file")
        )

        tp_raw = data.get("testing_permissions", {})
        if not isinstance(tp_raw, dict):
            raise ValueError(f"testing_permissions section must be a dictionary in profile '{p_id}'")
        allowed_tp_keys = {
            "passive_recon", "active_recon", "endpoint_discovery", "javascript_analysis",
            "secret_detection", "credential_validation", "fuzzing", "injection_testing",
            "destructive_testing", "denial_of_service", "social_engineering", "state_changing_allowed",
            "allowed_payload_types", "restricted_file_paths"
        }
        unknown_tp = set(tp_raw.keys()) - allowed_tp_keys
        if unknown_tp:
            raise ValueError(f"Unknown key(s) in profile testing_permissions: {sorted(unknown_tp)}.")

        testing_permissions = TestingPermissionsDefinition(
            passive_recon=strict_bool(tp_raw.get("passive_recon", True), "testing_permissions.passive_recon") if "passive_recon" in tp_raw else True,
            active_recon=strict_bool(tp_raw.get("active_recon", False), "testing_permissions.active_recon") if "active_recon" in tp_raw else False,
            endpoint_discovery=strict_bool(tp_raw.get("endpoint_discovery", True), "testing_permissions.endpoint_discovery") if "endpoint_discovery" in tp_raw else True,
            javascript_analysis=strict_bool(tp_raw.get("javascript_analysis", True), "testing_permissions.javascript_analysis") if "javascript_analysis" in tp_raw else True,
            secret_detection=strict_bool(tp_raw.get("secret_detection", True), "testing_permissions.secret_detection") if "secret_detection" in tp_raw else True,
            credential_validation=strict_bool(tp_raw.get("credential_validation", False), "testing_permissions.credential_validation") if "credential_validation" in tp_raw else False,
            fuzzing=strict_bool(tp_raw.get("fuzzing", False), "testing_permissions.fuzzing") if "fuzzing" in tp_raw else False,
            injection_testing=strict_bool(tp_raw.get("injection_testing", False), "testing_permissions.injection_testing") if "injection_testing" in tp_raw else False,
            destructive_testing=False,  # Enforce hard safety ceiling
            denial_of_service=False,   # Enforce hard safety ceiling
            social_engineering=strict_bool(tp_raw.get("social_engineering", False), "testing_permissions.social_engineering") if "social_engineering" in tp_raw else False,
            state_changing_allowed=strict_bool(tp_raw.get("state_changing_allowed", False), "testing_permissions.state_changing_allowed") if "state_changing_allowed" in tp_raw else False
        )

        tr_raw = data.get("tool_restrictions", {})
        if not isinstance(tr_raw, dict):
            raise ValueError(f"tool_restrictions section must be a dictionary in profile '{p_id}'")
        allowed_tr_keys = {"allowed_tools", "disabled_tools"}
        unknown_tr = set(tr_raw.keys()) - allowed_tr_keys
        if unknown_tr:
            raise ValueError(f"Unknown key(s) in profile tool_restrictions: {sorted(unknown_tr)}.")

        tool_restrictions = ToolRestrictionsDefinition(
            allowed_tools=[t.lower().strip() for t in tr_raw.get("allowed_tools", ["subfinder", "httpx", "gau", "waybackurls", "jsluice"])],
            disabled_tools=[t.lower().strip() for t in tr_raw.get("disabled_tools", ["katana", "hakrawler", "subjs", "getjs"])]
        )

        rep_raw = data.get("reporting", {})
        if not isinstance(rep_raw, dict):
            raise ValueError(f"reporting section must be a dictionary in profile '{p_id}'")
        allowed_rep_keys = {"default_template", "default_format", "program_name"}
        unknown_rep = set(rep_raw.keys()) - allowed_rep_keys
        if unknown_rep:
            raise ValueError(f"Unknown key(s) in profile reporting: {sorted(unknown_rep)}.")

        reporting = ReportingDefinition(
            default_template=rep_raw.get("default_template", "bugcrowd"),
            default_format=rep_raw.get("default_format", "html"),
            program_name=rep_raw.get("program_name", p_name)
        )

        auth_providers_raw = data.get("authorized_providers")
        authorized_providers = parse_authorized_providers(auth_providers_raw, context=f"profile '{p_id}'")

        requires_review = strict_bool(data.get("requires_review", False), "requires_review") if "requires_review" in data else False
        review_notes = list(data.get("review_notes", []))

        source_reference = data.get("source_reference", "")
        return ProgramProfile(
            id=p_id,
            name=p_name,
            version=version,
            platform=platform,
            policy_url=policy_url,
            description=description,
            source_reference=source_reference or source_ref,
            requires_review=requires_review,
            review_notes=review_notes,
            scope=scope,
            request_policy=request_policy,
            headers=headers,
            authentication=authentication,
            testing_permissions=testing_permissions,
            tool_restrictions=tool_restrictions,
            reporting=reporting,
            authorized_providers=authorized_providers
        )

    @classmethod
    def from_yaml_file(cls, path: Path) -> ProgramProfile:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {}, source_ref=str(path))

    @classmethod
    def from_json_file(cls, path: Path) -> ProgramProfile:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data or {}, source_ref=str(path))

    @classmethod
    def from_text_rules(cls, program_id: str, program_name: str, rules_text: str) -> ProgramProfile:
        """
        Parse unstructured policy text into a structured profile,
        marking ambiguous or uncertain statements for operator review.
        """
        review_notes = []
        allowed_domains = []
        excluded_domains = []
        max_rps = 5.0

        for line in rules_text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("#"):
                continue

            # Scope matching heuristics (check out-of-scope first)
            if re.search(r'\b(out of scope|exclude|excluded|prohibited)\b', line_s, re.I):
                domains = re.findall(r'(\*?\.?[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})', line_s)
                excluded_domains.extend(domains)
            elif re.search(r'\b(in scope|allowed|target|targets)\b', line_s, re.I):
                domains = re.findall(r'(\*?\.?[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})', line_s)
                allowed_domains.extend(domains)

            # Rate limit heuristics
            rps_match = re.search(r'(\d+(?:\.\d+)?)\s*(?:rps|req(?:uests)?\s*(?:per|\/)\s*sec)', line_s, re.I)
            if rps_match:
                try:
                    max_rps = float(rps_match.group(1))
                except ValueError:
                    pass

            # Detect ambiguous clauses (e.g. rate limit conditional, third-party mentions)
            if any(k in line_s.lower() for k in ["third party", "third-party", "vendor", "partner", "contact us first", "do not test unless"]):
                review_notes.append(f"Ambiguous or conditional rule detected: \"{line_s}\"")

        requires_review = len(review_notes) > 0

        data = {
            "id": program_id,
            "name": program_name,
            "requires_review": requires_review,
            "review_notes": review_notes,
            "scope": {
                "allowed_domains": list(set(allowed_domains)),
                "excluded_domains": list(set(excluded_domains)),
            },
            "request_policy": {
                "max_rps": max_rps
            },
            "testing_permissions": {
                "active_recon": False if requires_review else True  # Keep inactive if uncertain
            }
        }
        return cls.from_dict(data, source_ref="text_import")


class PolicyValidator:
    """Strictly validates program policy configuration before execution."""

    @classmethod
    def validate(cls, profile: ProgramProfile) -> List[str]:
        """
        Validate profile against safety boundaries and schema requirements.
        Returns list of error messages (empty if valid).
        """
        errors = []

        # 1. Identity
        if not profile.id or not re.match(r'^[a-z0-9_\-]+$', profile.id):
            errors.append(f"Invalid program profile ID: '{profile.id}'. Use alphanumeric, hyphens, and underscores only.")

        # 2. Scope Validation
        if profile.scope.enabled:
            if not (profile.scope.allowed_domains or profile.scope.allowed_ips or profile.scope.allowed_cidrs):
                errors.append(f"Profile '{profile.id}' has scope enabled but defines no allowed domains, IPs, or CIDRs.")

        # Validate domain entries (both allowed and excluded)
        for d in profile.scope.allowed_domains:
            try:
                validate_domain_entry(d, "allowed_domains", context=f"profile '{profile.id}'")
            except ValueError as ve:
                errors.append(str(ve))

        for d in profile.scope.excluded_domains:
            try:
                validate_domain_entry(d, "excluded_domains", context=f"profile '{profile.id}'")
            except ValueError as ve:
                errors.append(str(ve))

        for d in profile.scope.third_party_hosted_exclusions:
            try:
                validate_domain_entry(d, "third_party_hosted_exclusions", context=f"profile '{profile.id}'")
            except ValueError as ve:
                errors.append(str(ve))

        if profile.scope.enabled:
            # Validate CIDR notations
            for cidr in profile.scope.allowed_cidrs:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    errors.append(f"Invalid allowed CIDR notation: '{cidr}'")

            for cidr in profile.scope.excluded_cidrs:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    errors.append(f"Invalid excluded CIDR notation: '{cidr}'")

            # Validate IP notations
            for ip in profile.scope.allowed_ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"Invalid allowed IP notation: '{ip}'")

            for ip in profile.scope.excluded_ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"Invalid excluded IP notation: '{ip}'")

            # Protocols
            for proto in profile.scope.allowed_protocols:
                if proto not in ("http", "https"):
                    errors.append(f"Invalid allowed protocol: '{proto}'. Only 'http' and 'https' are permitted.")

            # Ports
            for port in profile.scope.allowed_ports:
                if not (1 <= port <= 65535):
                    errors.append(f"Invalid port: {port}. Port must be between 1 and 65535.")

        # 3. Request Policy Validation
        rps = profile.request_policy.max_rps
        try:
            if not math.isfinite(rps):
                errors.append("max_rps cannot be NaN or Infinity.")
        except OverflowError:
            errors.append("max_rps exceeds numeric bounds (OverflowError).")
        if rps <= 0:
            errors.append(f"max_rps must be positive (> 0), got {rps}")
        if rps > 1_000_000:
            errors.append(f"max_rps exceeds maximum allowable limit (1,000,000), got {rps}")

        # Program-specific limits: UXCam strict maximum 5.0 RPS
        if profile.id == "uxcam" or any("uxcam.com" in d or "uxc.am" in d for d in profile.scope.allowed_domains):
            if rps > 5.0:
                errors.append(f"UXCam program policy enforces hard maximum of 5.0 RPS (configured: {rps}).")

        conc = profile.request_policy.concurrency
        if conc < 1:
            errors.append(f"concurrency must be at least 1, got {conc}")
        if conc > 1_000_000:
            errors.append(f"concurrency exceeds maximum allowable limit (1,000,000), got {conc}")

        tout = profile.request_policy.timeout
        if tout < 1:
            errors.append(f"timeout must be at least 1, got {tout}")
        if tout > 1_000_000:
            errors.append(f"timeout exceeds maximum allowable limit (1,000,000), got {tout}")

        depth = profile.request_policy.crawl_depth
        if depth < 1:
            errors.append(f"crawl_depth must be at least 1, got {depth}")
        if depth > 1_000_000:
            errors.append(f"crawl_depth exceeds maximum allowable limit (1,000,000), got {depth}")

        if profile.request_policy.strict_scope and not profile.request_policy.verify_tls:
            errors.append("Insecure TLS configuration is prohibited when strict_scope is enabled.")

        # 4. Mandatory Fail-Closed Safety Boundaries
        if profile.testing_permissions.destructive_testing:
            errors.append("Destructive testing is permanently prohibited and cannot be authorized by policy.")

        if profile.testing_permissions.denial_of_service:
            errors.append("Denial of service testing is permanently prohibited and cannot be authorized by policy.")

        # 5. Authentication Validation
        if profile.authentication.type != "none":
            if profile.authentication.type in ("bearer", "api_key") and profile.authentication.token_env:
                # Note: Token env should exist when running live, but allow validation during offline check
                pass
            if profile.authentication.session_file:
                sess_path = Path(profile.authentication.session_file)
                if sess_path.exists():
                    # Check file permissions (should not be world/group readable: 0o077)
                    mode = sess_path.stat().st_mode
                    if mode & 0o077:
                        errors.append(f"Session file '{sess_path}' has insecure permissions ({oct(mode)}). Must be 0600.")

        # 6. Uncertain Rules
        if profile.requires_review:
            # Informational note, not fatal error, but prevents active recon until cleared
            pass

        # 7. Authorized Providers Validation
        if profile.authorized_providers:
            try:
                parse_authorized_providers(profile.authorized_providers, context=f"profile '{profile.id}'")
            except ValueError as e:
                errors.append(str(e))

        return errors
