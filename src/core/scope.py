"""
NightCrawler - Scope Enforcement Module
Strict, configurable target scope validation with subdomain boundary checks.
"""

from typing import List, Set, Optional, Iterable
from urllib.parse import urlparse
import re
import ipaddress


class ScopeManager:
    """
    Manages and enforces strict target scope.
    Validates hostnames and URLs against allowed and excluded domains
    using strict suffix-boundary matching to prevent subdomain/lookalike bypasses.
    """

    def __init__(
        self,
        allowed_domains: Optional[Iterable[str]] = None,
        excluded_domains: Optional[Iterable[str]] = None,
        enabled: bool = True
    ):
        self.enabled = enabled
        self.allowed_domains: Set[str] = set()
        self.excluded_domains: Set[str] = set()

        if allowed_domains:
            for domain in allowed_domains:
                clean = self._normalize_domain(domain)
                if clean:
                    self.allowed_domains.add(clean)

        if excluded_domains:
            for domain in excluded_domains:
                clean = self._normalize_domain(domain)
                if clean:
                    self.excluded_domains.add(clean)

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize domain string by stripping wildcards, schemes, ports, and whitespace."""
        if not domain:
            return ""
        domain = domain.strip().lower()
        if "://" in domain:
            parsed = urlparse(domain)
            domain = parsed.hostname or ""
        if domain.startswith("*."):
            domain = domain[2:]
        elif domain.startswith("."):
            domain = domain[1:]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain.rstrip(".")

    @staticmethod
    def extract_hostname(target_or_url: str) -> Optional[str]:
        """
        Safely extract normalized lowercase hostname from a URL or raw domain.
        Handles credentials, ports, IPv6 brackets, and malformed inputs.
        """
        if not target_or_url:
            return None
        target_or_url = target_or_url.strip()

        # Reject schemes that are not http/https if scheme is present
        if "://" in target_or_url:
            scheme = target_or_url.split("://")[0].lower()
            if scheme not in ("http", "https"):
                return None
            url_to_parse = target_or_url
        else:
            url_to_parse = f"https://{target_or_url}"

        try:
            parsed = urlparse(url_to_parse)
            host = parsed.hostname
            if not host:
                return None
            host = host.lower().rstrip(".")
            return host if host else None
        except Exception:
            return None

    def _matches_domain_pattern(self, host: str, domain_pattern: str) -> bool:
        """
        Check if host strictly matches domain_pattern or is a proper subdomain of it.
        E.g. for pattern 'uxcam.com':
          - 'uxcam.com' -> True
          - 'app.uxcam.com' -> True
          - 'api.app.uxcam.com' -> True
          - 'eviluxcam.com' -> False
          - 'uxcam.com.attacker.com' -> False
        """
        if not host or not domain_pattern:
            return False
        
        host = host.lower().rstrip(".")
        domain_pattern = domain_pattern.lower().rstrip(".")

        if host == domain_pattern:
            return True

        if host.endswith("." + domain_pattern):
            return True

        return False

    def is_host_allowed(self, host: Optional[str]) -> bool:
        """Check if hostname is in allowed scope and not excluded."""
        if not self.enabled:
            return True

        if not host:
            return False

        host = host.lower().rstrip(".")

        # Explicit exclusions override allowed domains (including all subdomains)
        for excluded in self.excluded_domains:
            if self._matches_domain_pattern(host, excluded):
                return False

        # If no allowed domains configured, nothing is allowed when scope is enabled
        if not self.allowed_domains:
            return False

        # Check if matches any allowed domain (exact or subdomain)
        for allowed in self.allowed_domains:
            if self._matches_domain_pattern(host, allowed):
                return True

        return False

    def is_url_in_scope(self, url: str) -> bool:
        """Check if a full URL's hostname and scheme are within authorized scope."""
        if not self.enabled:
            return True

        if not url:
            return False

        url_str = url.strip()

        # Reject dangerous/invalid pseudo-schemes
        lower_url = url_str.lower()
        if any(lower_url.startswith(bad) for bad in ("javascript:", "data:", "file:", "ftp:", "about:", "blob:", "ws:", "wss:")):
            return False

        # Scheme must be http or https if specified
        if "://" in url_str:
            scheme = url_str.split("://")[0].lower()
            if scheme not in ("http", "https"):
                return False

        host = self.extract_hostname(url_str)
        if not host:
            return False

        return self.is_host_allowed(host)

    def filter_subdomains(self, subdomains: Iterable[str]) -> List[str]:
        """Filter list of subdomains/hostnames to only those strictly in scope."""
        valid = []
        for sub in subdomains:
            host = self.extract_hostname(sub)
            if host and self.is_host_allowed(host):
                valid.append(host)
        return sorted(list(set(valid)))

    def filter_urls(self, urls: Iterable[str]) -> List[str]:
        """Filter list of URLs to only those whose hosts are strictly in scope."""
        valid = []
        seen = set()
        for url in urls:
            url_clean = url.strip()
            if not url_clean or url_clean in seen:
                continue
            if self.is_url_in_scope(url_clean):
                seen.add(url_clean)
                valid.append(url_clean)
        return valid

    def add_allowed_domain(self, domain: str):
        clean = self._normalize_domain(domain)
        if clean:
            self.allowed_domains.add(clean)

    def add_excluded_domain(self, domain: str):
        clean = self._normalize_domain(domain)
        if clean:
            self.excluded_domains.add(clean)
