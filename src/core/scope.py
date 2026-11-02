"""
NightCrawler - Scope Enforcement Module
Strict, configurable multi-program target scope validation with CIDR, IP, wildcard,
path exclusion, protocol, port, and third-party boundary checks.
"""

from typing import List, Set, Optional, Iterable, Dict, Any, Union
from urllib.parse import urlparse
import re
import ipaddress


class ScopeManager:
    """
    Manages and enforces strict multi-program target scope.
    Validates hostnames, IP addresses, CIDR ranges, paths, protocols, and ports.
    Exclusions always take precedence over inclusions.
    """

    def __init__(
        self,
        allowed_domains: Optional[Iterable[str]] = None,
        excluded_domains: Optional[Iterable[str]] = None,
        enabled: bool = True,
        # Multi-program extensions
        allowed_ips: Optional[Iterable[str]] = None,
        allowed_cidrs: Optional[Iterable[str]] = None,
        excluded_ips: Optional[Iterable[str]] = None,
        excluded_cidrs: Optional[Iterable[str]] = None,
        allowed_paths: Optional[Iterable[str]] = None,
        excluded_paths: Optional[Iterable[str]] = None,
        allowed_protocols: Optional[Iterable[str]] = None,
        allowed_ports: Optional[Iterable[int]] = None,
        third_party_hosted_exclusions: Optional[Iterable[str]] = None
    ):
        self.enabled = enabled
        self.exact_domains: Set[str] = set()
        self.wildcard_domains: Set[str] = set()
        self.allowed_domains: Set[str] = set()

        if allowed_domains:
            for domain in allowed_domains:
                d = str(domain).strip().lower()
                if not d:
                    continue
                is_wildcard = d.startswith("*.") or d.startswith(".")
                clean = self._normalize_domain(d)
                if clean:
                    if is_wildcard:
                        self.wildcard_domains.add(clean)
                    else:
                        self.exact_domains.add(clean)
                    self.allowed_domains.add(clean)

        self.excluded_exact_domains: Set[str] = set()
        self.excluded_wildcard_domains: Set[str] = set()
        self.excluded_domains: Set[str] = set()

        if excluded_domains:
            for domain in excluded_domains:
                d = str(domain).strip().lower()
                if not d:
                    continue
                is_wildcard = d.startswith("*.") or d.startswith(".")
                clean = self._normalize_domain(d)
                if clean:
                    if is_wildcard:
                        self.excluded_wildcard_domains.add(clean)
                    else:
                        self.excluded_exact_domains.add(clean)
                    self.excluded_domains.add(clean)

        # IP & CIDR handling
        self.allowed_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        if allowed_ips:
            for ip in allowed_ips:
                try:
                    self.allowed_ips.add(ipaddress.ip_address(ip.strip()))
                except ValueError:
                    pass

        self.excluded_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        if excluded_ips:
            for ip in excluded_ips:
                try:
                    self.excluded_ips.add(ipaddress.ip_address(ip.strip()))
                except ValueError:
                    pass

        self.allowed_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        if allowed_cidrs:
            for cidr in allowed_cidrs:
                try:
                    self.allowed_cidrs.append(ipaddress.ip_network(cidr.strip(), strict=False))
                except ValueError:
                    pass

        self.excluded_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        if excluded_cidrs:
            for cidr in excluded_cidrs:
                try:
                    self.excluded_cidrs.append(ipaddress.ip_network(cidr.strip(), strict=False))
                except ValueError:
                    pass

        # Paths
        self.allowed_paths: List[str] = [p.strip() for p in (allowed_paths or []) if p.strip()]
        self.excluded_paths: List[str] = [p.strip() for p in (excluded_paths or []) if p.strip()]

        # Protocols & Ports
        self.allowed_protocols: Set[str] = {p.lower().strip() for p in (allowed_protocols or ["http", "https"])}
        self.allowed_ports: Set[int] = {int(p) for p in (allowed_ports or [80, 443, 8080, 8443])}

        # Third-party hosted service exclusions
        self.third_party_hosted_exclusions: Set[str] = set()
        if third_party_hosted_exclusions:
            for h in third_party_hosted_exclusions:
                clean = self._normalize_domain(h)
                if clean:
                    self.third_party_hosted_exclusions.add(clean)

    @classmethod
    def from_profile(cls, profile) -> "ScopeManager":
        """Instantiate ScopeManager from a ProgramProfile object."""
        sc = profile.scope
        return cls(
            allowed_domains=sc.allowed_domains,
            excluded_domains=sc.excluded_domains,
            enabled=sc.enabled,
            allowed_ips=sc.allowed_ips,
            allowed_cidrs=sc.allowed_cidrs,
            excluded_ips=sc.excluded_ips,
            excluded_cidrs=sc.excluded_cidrs,
            allowed_paths=sc.allowed_paths,
            excluded_paths=sc.excluded_paths,
            allowed_protocols=sc.allowed_protocols,
            allowed_ports=sc.allowed_ports,
            third_party_hosted_exclusions=sc.third_party_hosted_exclusions
        )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize domain string by stripping wildcards, schemes, ports, and whitespace with IDNA handling."""
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
        domain = domain.rstrip(".")
        try:
            import idna
            domain = idna.encode(domain).decode("ascii")
        except Exception:
            pass
        return domain

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

    def is_ip_allowed(self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """Check if an IP address is within allowed IP/CIDR scope and not excluded."""
        # 1. Check IP exclusions
        if ip_obj in self.excluded_ips:
            return False

        # 2. Check CIDR exclusions
        for exc_net in self.excluded_cidrs:
            if ip_obj in exc_net:
                return False

        # 3. Check allowed IPs
        if ip_obj in self.allowed_ips:
            return True

        # 4. Check allowed CIDRs
        for inc_net in self.allowed_cidrs:
            if ip_obj in inc_net:
                return True

        return False

    def is_host_allowed(self, host: Optional[str]) -> bool:
        """
        Check if hostname or IP is in allowed scope and not excluded.
        Exact and wildcard domains are stored and checked separately:
        - example.com matches only apex example.com
        - *.example.com matches subdomains of example.com (e.g. app.example.com)
        """
        if not self.enabled:
            return True

        if not host:
            return False

        host = host.lower().rstrip(".")
        try:
            import idna
            host = idna.encode(host).decode("ascii")
        except Exception:
            pass

        # Check if host is an IP address
        try:
            ip_obj = ipaddress.ip_address(host)
            return self.is_ip_allowed(ip_obj)
        except ValueError:
            pass

        # Check third-party hosted service exclusions (exact host or any subdomains)
        for tp in self.third_party_hosted_exclusions:
            if host == tp or host.endswith("." + tp):
                return False

        # Explicit exclusions override allowed domains (including all subdomains)
        for excluded in self.excluded_domains:
            if host == excluded or host.endswith("." + excluded):
                return False

        # If no allowed domains/IPs/CIDRs configured, nothing is allowed when scope is enabled
        if not self.exact_domains and not self.wildcard_domains and not self.allowed_ips and not self.allowed_cidrs:
            return False

        # 1. Exact match check (apex domain or exact host)
        if host in self.exact_domains:
            return True

        # 2. Wildcard match check (proper subdomain with dot boundary)
        for w in self.wildcard_domains:
            if host.endswith("." + w):
                return True

        return False

    def is_url_in_scope(self, url: str) -> bool:
        """Check if a full URL's hostname, scheme, port, and path are within authorized scope."""
        if not self.enabled:
            return True

        if not url:
            return False

        url_str = url.strip()

        # Reject dangerous/invalid pseudo-schemes
        lower_url = url_str.lower()
        if any(lower_url.startswith(bad) for bad in ("javascript:", "data:", "file:", "ftp:", "about:", "blob:", "ws:", "wss:")):
            return False

        # Scheme check
        scheme = "https"
        if "://" in url_str:
            scheme = url_str.split("://")[0].lower()
            if scheme not in self.allowed_protocols:
                return False
            url_to_parse = url_str
        else:
            url_to_parse = f"https://{url_str}"

        try:
            parsed = urlparse(url_to_parse)
            host = parsed.hostname
            if not host:
                return False
            host = host.lower().rstrip(".")

            # Port check
            port = parsed.port or (443 if scheme == "https" else 80)
            if self.allowed_ports and port not in self.allowed_ports:
                return False

            # Host check
            if not self.is_host_allowed(host):
                return False

            # Path check
            path = parsed.path or "/"
            for exc_path in self.excluded_paths:
                if exc_path and path.startswith(exc_path):
                    return False

            if self.allowed_paths:
                if not any(path.startswith(inc_path) for inc_path in self.allowed_paths):
                    return False

            return True
        except Exception:
            return False

    def filter_subdomains(self, subdomains: Iterable[str]) -> List[str]:
        """Filter list of subdomains/hostnames to only those strictly in scope."""
        valid = []
        for sub in subdomains:
            host = self.extract_hostname(sub)
            if host and self.is_host_allowed(host):
                valid.append(host)
        return sorted(list(set(valid)))

    def filter_urls(self, urls: Iterable[str]) -> List[str]:
        """Filter list of URLs to only those whose hosts and paths are strictly in scope."""
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
