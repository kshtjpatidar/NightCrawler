"""
NightCrawler - Tool Compatibility Manager Module
Inspects reconnaissance tool capabilities, compares them against the active program policy,
and automatically disables tools that cannot honor policy constraints.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from src.core.program_profile import ProgramProfile


@dataclass
class ToolCapability:
    name: str
    is_active: bool  # Active (live target requests) vs Passive
    makes_live_requests: bool
    follows_redirects: bool
    can_enforce_scope: bool
    can_enforce_rate_limit: bool
    can_attach_headers: bool
    can_verify_tls: bool
    description: str


class ToolCompatibilityManager:
    """
    Evaluates whether external or internal reconnaissance tools meet the security
    and operational requirements of the active program policy.
    """

    TOOL_REGISTRY: Dict[str, ToolCapability] = {
        "nightcrawler_http": ToolCapability(
            name="nightcrawler_http",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=True,
            can_enforce_rate_limit=True,
            can_attach_headers=True,
            can_verify_tls=True,
            description="Built-in policy-aware async HTTP client with strict token pacing."
        ),
        "subfinder": ToolCapability(
            name="subfinder",
            is_active=False,
            makes_live_requests=False,  # Queries passive third-party DNS sources
            follows_redirects=False,
            can_enforce_scope=True,     # Output strictly filtered through ScopeManager
            can_enforce_rate_limit=True,
            can_attach_headers=False,
            can_verify_tls=True,
            description="Passive subdomain discovery via public APIs."
        ),
        "gau": ToolCapability(
            name="gau",
            is_active=False,
            makes_live_requests=False,  # Queries Wayback / AlienVault / CommonCrawl
            follows_redirects=False,
            can_enforce_scope=True,     # Scraped URLs strictly filtered through ScopeManager
            can_enforce_rate_limit=True,
            can_attach_headers=False,
            can_verify_tls=True,
            description="Passive archive URL fetcher (Wayback/CommonCrawl)."
        ),
        "waybackurls": ToolCapability(
            name="waybackurls",
            is_active=False,
            makes_live_requests=False,
            follows_redirects=False,
            can_enforce_scope=True,
            can_enforce_rate_limit=True,
            can_attach_headers=False,
            can_verify_tls=True,
            description="Passive Wayback Machine URL harvester."
        ),
        "jsluice": ToolCapability(
            name="jsluice",
            is_active=False,
            makes_live_requests=False,  # Analyzes local JS files offline
            follows_redirects=False,
            can_enforce_scope=True,
            can_enforce_rate_limit=True,
            can_attach_headers=False,
            can_verify_tls=True,
            description="Offline JavaScript AST parser for endpoint and secret discovery."
        ),
        "httpx": ToolCapability(
            name="httpx",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=False,    # Independent Go process
            can_enforce_rate_limit=False,
            can_attach_headers=True,
            can_verify_tls=True,
            description="Active multi-purpose HTTP prober."
        ),
        "katana": ToolCapability(
            name="katana",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=False,    # Autonomous external crawler
            can_enforce_rate_limit=False, # Cannot share asyncio token bucket
            can_attach_headers=True,
            can_verify_tls=True,
            description="Next-generation active web crawler."
        ),
        "hakrawler": ToolCapability(
            name="hakrawler",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=False,
            can_enforce_rate_limit=False,
            can_attach_headers=False,
            can_verify_tls=True,
            description="Fast Go-based web crawler."
        ),
        "subjs": ToolCapability(
            name="subjs",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=False,
            can_enforce_rate_limit=False,
            can_attach_headers=False,
            can_verify_tls=True,
            description="JavaScript file fetcher."
        ),
        "getjs": ToolCapability(
            name="getjs",
            is_active=True,
            makes_live_requests=True,
            follows_redirects=True,
            can_enforce_scope=False,
            can_enforce_rate_limit=False,
            can_attach_headers=False,
            can_verify_tls=True,
            description="JavaScript asset extractor."
        ),
    }

    def __init__(self, profile: ProgramProfile):
        self.profile = profile

    def is_tool_compatible(self, tool_name: str) -> tuple[bool, str]:
        """
        Evaluate if tool is allowed under the program policy.
        Returns (is_compatible, reason).
        """
        t_name = tool_name.lower().strip()
        if t_name not in self.TOOL_REGISTRY:
            return False, f"Tool '{tool_name}' is not registered in the capability matrix."

        cap = self.TOOL_REGISTRY[t_name]

        # 1. Explicit profile tool restrictions: denylist then allowlist
        disabled = [d.lower().strip() for d in self.profile.tool_restrictions.disabled_tools]
        if t_name in disabled:
            return False, f"Explicitly disabled by program profile '{self.profile.id}'."

        allowed = [a.lower().strip() for a in self.profile.tool_restrictions.allowed_tools]
        if allowed and t_name != "nightcrawler_http" and t_name not in allowed:
            return False, f"Tool '{tool_name}' is disabled: not permitted by profile '{self.profile.id}' tool allowlist."

        # 2. Testing permissions check: if active recon is prohibited, disable active tools
        if cap.is_active and not self.profile.testing_permissions.active_recon:
            return False, "Active reconnaissance is disabled under the active program policy."

        # 3. Strict compliance mode: uncoordinated external crawlers cannot participate
        # in the shared token-bucket rate limiter or header environment isolation
        if self.profile.request_policy.strict_scope:
            if cap.is_active and (not cap.can_enforce_rate_limit or not cap.can_enforce_scope):
                return False, "Cannot coordinate with global rate limiter or strict scope in strict compliance mode."

        return True, "Tool is fully compatible with program policy."

    def get_compatible_tools(self) -> List[str]:
        """Return list of compatible tool names."""
        compatible = []
        for name in self.TOOL_REGISTRY:
            ok, _ = self.is_tool_compatible(name)
            if ok:
                compatible.append(name)
        return compatible

    def get_tool_audit_report(self) -> Dict[str, Any]:
        """Generate full audit report of all tools and compatibility status."""
        report = {}
        for name, cap in self.TOOL_REGISTRY.items():
            ok, reason = self.is_tool_compatible(name)
            report[name] = {
                "compatible": ok,
                "is_active": cap.is_active,
                "reason": reason,
                "description": cap.description
            }
        return report
