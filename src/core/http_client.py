"""
NightCrawler - Policy-Aware HTTP Client Module
Asynchronous HTTP client guaranteeing:
1. Strict scope enforcement before every outbound request and redirect hop.
2. Centralized rate limiting where every attempt (initial, retry, redirect) consumes a token.
3. TLS certificate verification with fail-closed rejection of insecure options.
4. Credential isolation: headers and tokens are never sent to out-of-scope hosts.
5. Structured audit logging of all requests and policy decisions.
"""

import asyncio
import contextvars
import logging
import ssl
import socket
import ipaddress
from typing import Optional, Dict, Tuple, Any, List
from urllib.parse import urljoin, urlparse
import aiohttp
import aiohttp.abc
import aiohttp.resolver

from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager

logger = logging.getLogger("nightcrawler.http")

# Context variable to avoid double-acquisition of concurrency semaphore across nested/caller layers
_in_concurrency_scope: contextvars.ContextVar[bool] = contextvars.ContextVar("nc_in_concurrency_scope", default=False)


class ScopeViolationError(Exception):
    """Raised when an HTTP request or redirect targets an out-of-scope host."""
    pass


class PolicyAwareResolver(aiohttp.abc.AbstractResolver):
    """
    DNS Resolver enforcing policy-based IP safety and DNS pinning.
    Prevents DNS rebinding attacks by ensuring connections connect exclusively
    to IP addresses validated by policy.
    """
    def __init__(self, http_client: "NightCrawlerHttpClient"):
        self.http_client = http_client

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> List[aiohttp.resolver.ResolveResult]:
        safe, reason = await self.http_client.validate_host_network_safety(host)
        if not safe:
            raise OSError(f"Connection blocked by network policy: {reason}")

        pinned_ips = self.http_client._pinned_ips.get(host, [])
        if not pinned_ips:
            try:
                ipaddress.ip_address(host)
                pinned_ips = [host]
            except ValueError:
                raise OSError(f"No validated IP available for host '{host}'")

        results = []
        for ip_str in pinned_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            addr_family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
            results.append(
                aiohttp.resolver.ResolveResult(
                    hostname=host,
                    host=ip_str,
                    port=port,
                    family=addr_family,
                    proto=socket.IPPROTO_TCP,
                    flags=socket.AI_NUMERICHOST,
                )
            )
        return results

    async def close(self) -> None:
        pass


class NightCrawlerHttpClient:
    """
    Centralized asynchronous HTTP client that guarantees compliance with
    program scope, rate limits, TLS verification, and audit logging.
    """

    def __init__(
        self,
        scope_manager: Optional[Any] = None,
        rate_limiter: Optional[GlobalRateLimiter] = None,
        header_manager: Optional[HeaderManager] = None,
        timeout_seconds: int = 30,
        verify_tls: bool = True,
        strict_mode: bool = True,
        max_redirects: int = 5,
        max_retries: int = 2,
        request_policy_manager: Optional[Any] = None,
        auth_manager: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        effective_policy: Optional[Any] = None
    ):
        # Support passing an EffectivePolicy as the first argument or explicitly
        if hasattr(scope_manager, "request_policy_manager") and hasattr(scope_manager, "scope_manager"):
            effective_policy = scope_manager
            scope_manager = effective_policy.scope_manager

        if effective_policy:
            self.effective_policy = effective_policy
            self.scope_manager = effective_policy.scope_manager
            self.request_policy_manager = effective_policy.request_policy_manager
            self.auth_manager = effective_policy.auth_manager
            self.audit_logger = effective_policy.audit_logger
            self.rate_limiter = self.request_policy_manager.global_limiter
            self.header_manager = header_manager or HeaderManager()
            self.timeout = aiohttp.ClientTimeout(total=effective_policy.timeout)
            self.verify_tls = effective_policy.verify_tls
            self.strict_mode = effective_policy.strict_scope
            self.max_redirects = max_redirects
            self.max_retries = max_retries
        else:
            self.effective_policy = None
            self.scope_manager = scope_manager
            self.request_policy_manager = request_policy_manager
            self.auth_manager = auth_manager
            self.audit_logger = audit_logger
            if rate_limiter:
                self.rate_limiter = rate_limiter
            elif request_policy_manager:
                self.rate_limiter = request_policy_manager.global_limiter
            else:
                self.rate_limiter = GlobalRateLimiter(max_requests_per_second=5.0)

            self.header_manager = header_manager or HeaderManager()
            self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            self.verify_tls = verify_tls
            self.strict_mode = strict_mode
            self.max_redirects = max_redirects
            self.max_retries = max_retries

        if self.strict_mode and not self.verify_tls:
            raise ValueError("Insecure TLS configuration is prohibited in strict compliance mode.")

        # TLS SSLContext - verified by default
        if self.verify_tls:
            self.ssl_context = ssl.create_default_context()
        else:
            self.ssl_context = False

        # DNS Pinning cache: maps validated host -> list of authorized IP strings
        self._pinned_ips: Dict[str, List[str]] = {}

    def get_resolver(self) -> aiohttp.abc.AbstractResolver:
        """Return a policy-aware DNS resolver that enforces policy validation and DNS pinning."""
        return PolicyAwareResolver(self)

    async def validate_host_network_safety(self, host: Optional[str]) -> Tuple[bool, str]:
        """
        Verify that the host does not resolve to a prohibited private, loopback, or internal IP.
        Fails closed on DNS resolution failures or any prohibited IP in DNS answers.
        Pins validated IP addresses in memory to prevent DNS rebinding.
        """
        if not host:
            return False, "Empty or missing host"

        # Check if host is directly an IP
        try:
            ip_obj = ipaddress.ip_address(host)
            safe, reason = self.scope_manager.validate_destination_ip(str(ip_obj), is_dns_resolution=False)
            if safe:
                self._pinned_ips[host] = [str(ip_obj)]
            return safe, reason
        except ValueError:
            pass

        # If already pinned and validated for this session, return pinned result
        if host in self._pinned_ips:
            pinned = self._pinned_ips[host]
            if not pinned:
                return False, f"DNS resolution failed for host '{host}': Cached failure."
            return True, f"Destination conforms to network policy (pinned IP: {pinned[0]})."

        # Check DNS resolution - fail closed
        try:
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            if not addrinfo:
                return False, f"DNS resolution failed for host '{host}': No DNS records returned."

            validated_ips = []
            for family, socktype, proto, canonname, sockaddr in addrinfo:
                ip_str = sockaddr[0]
                safe, reason = self.scope_manager.validate_destination_ip(ip_str, is_dns_resolution=True)
                if not safe:
                    # Mixed DNS answers: if even one resolved IP is prohibited, fail closed immediately
                    return False, f"Host '{host}' resolves to prohibited IP '{ip_str}': {reason}"
                if ip_str not in validated_ips:
                    validated_ips.append(ip_str)

            if not validated_ips:
                return False, f"DNS resolution failed for host '{host}': No valid IP addresses."

            # Pin validated IPs to prevent DNS rebinding
            self._pinned_ips[host] = validated_ips
            return True, f"Destination conforms to network policy (pinned IP: {validated_ips[0]})."
        except Exception as e:
            return False, f"DNS resolution failed for host '{host}': {e}"

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Execute an HTTP GET request with hop-by-hop redirect verification.
        Every actual attempt (initial, retry, redirect) consumes a rate limit token.
        Guarantees that every network request uses the RequestPolicyManager semaphore.
        Returns: (status_code, content_text, final_url)
        """
        sem = self.request_policy_manager.get_semaphore() if self.request_policy_manager else None
        if sem is not None and not _in_concurrency_scope.get():
            async with sem:
                token = _in_concurrency_scope.set(True)
                try:
                    return await self._get_impl(session, url, extra_headers)
                finally:
                    _in_concurrency_scope.reset(token)
        else:
            return await self._get_impl(session, url, extra_headers)

    async def _get_impl(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        initial_url = url.strip()
        current_url = initial_url

        parsed_init = urlparse(initial_url)
        initial_origin = f"{parsed_init.scheme}://{parsed_init.hostname}:{parsed_init.port or (443 if parsed_init.scheme == 'https' else 80)}"

        # Step 1: Pre-request Scope Check
        if not self.scope_manager.is_url_in_scope(current_url):
            logger.debug(f"[Scope] Blocked out-of-scope URL: {current_url}")
            if self.audit_logger:
                host = self.scope_manager.extract_hostname(current_url) or "unknown"
                self.audit_logger.log_event(
                    target_host=host,
                    method="GET",
                    url=current_url,
                    scope_decision="BLOCKED",
                    policy_decision="DENIED",
                    rate_limiter_decision="N/A"
                )
            return None, None, None

        redirect_count = 0

        while redirect_count <= self.max_redirects:
            parsed_curr = urlparse(current_url)
            curr_origin = f"{parsed_curr.scheme}://{parsed_curr.hostname}:{parsed_curr.port or (443 if parsed_curr.scheme == 'https' else 80)}"
            is_cross_origin = (redirect_count > 0 and curr_origin != initial_origin)

            # Build headers (credentials only attached if current_url is in-scope and not cross-origin)
            if self.auth_manager:
                headers = self.auth_manager.get_headers_for_url(
                    current_url,
                    scope_manager=self.scope_manager,
                    base_headers=extra_headers,
                    is_cross_origin=is_cross_origin
                )
            else:
                headers = self.header_manager.get_headers_for_url(
                    current_url,
                    scope_manager=self.scope_manager,
                    base_headers=extra_headers
                )

            # Retry loop: every attempt consumes a rate-limit token
            retry_count = 0
            while retry_count <= self.max_retries:
                # Scope check before each request attempt
                if not self.scope_manager.is_url_in_scope(current_url):
                    logger.warning(f"[Scope] URL {current_url} is out of scope. Aborting attempt.")
                    if self.audit_logger:
                        host = self.scope_manager.extract_hostname(current_url) or "unknown"
                        self.audit_logger.log_event(
                            target_host=host,
                            method="GET",
                            url=current_url,
                            scope_decision="BLOCKED",
                            policy_decision="DENIED"
                        )
                    return None, None, current_url

                # Validate destination IP safety before sending network request
                host = self.scope_manager.extract_hostname(current_url)
                safe, reason = await self.validate_host_network_safety(host)
                if not safe:
                    logger.warning(f"[Scope] Prohibited IP destination detected for {host}: {reason}")
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            target_host=host or "unknown",
                            method="GET",
                            url=current_url,
                            scope_decision="BLOCKED",
                            policy_decision="DENIED",
                            security_reason=reason
                        )
                    return None, None, current_url

                # Every actual HTTP network attempt consumes a token from the shared limiter
                host = self.scope_manager.extract_hostname(current_url)
                if self.request_policy_manager:
                    await self.request_policy_manager.acquire(host=host)
                else:
                    await self.rate_limiter.acquire()

                try:
                    async with session.get(
                        current_url,
                        headers=headers,
                        ssl=self.ssl_context,
                        allow_redirects=False
                    ) as response:
                        # Log audit event
                        if self.audit_logger:
                            self.audit_logger.log_event(
                                target_host=host or "unknown",
                                method="GET",
                                url=current_url,
                                scope_decision="ALLOWED",
                                policy_decision="PERMITTED",
                                response_status=response.status
                            )

                        # Handle Redirection (301, 302, 303, 307, 308)
                        if response.status in (301, 302, 303, 307, 308):
                            if self.request_policy_manager:
                                self.request_policy_manager.record_redirect()

                            location = response.headers.get("Location")
                            if not location:
                                return response.status, None, current_url

                            next_url = urljoin(current_url, location)

                            # Validate redirect target scope immediately
                            if not self.scope_manager.is_url_in_scope(next_url):
                                logger.warning(
                                    f"[Scope] Redirect from {current_url} to out-of-scope target "
                                    f"{next_url} was blocked!"
                                )
                                if self.audit_logger:
                                    next_host = self.scope_manager.extract_hostname(next_url) or "unknown"
                                    self.audit_logger.log_event(
                                        target_host=next_host,
                                        method="GET",
                                        url=next_url,
                                        scope_decision="BLOCKED",
                                        policy_decision="DENIED",
                                        redirect_decision="BLOCKED_OUT_OF_SCOPE"
                                    )
                                return response.status, None, current_url

                            # Proceed to next hop
                            current_url = next_url
                            redirect_count += 1
                            break  # Breaks inner retry loop to process next redirect hop

                        # Retry on rate limited (429) or transient server errors (502, 503, 504)
                        if response.status in (429, 502, 503, 504) and retry_count < self.max_retries:
                            retry_count += 1
                            if self.request_policy_manager:
                                self.request_policy_manager.record_retry()
                                backoff = self.request_policy_manager.calculate_backoff(retry_count)
                            else:
                                backoff = 0.5 * retry_count
                            await asyncio.sleep(backoff)
                            continue

                        # 200 OK or other final response
                        text_content = None
                        if response.status == 200:
                            content_type = (response.headers.get("content-type") or response.headers.get("Content-Type") or "").lower()
                            if any(ct in content_type for ct in ("text", "javascript", "json", "xml")):
                                text_content = await response.text(errors="replace")

                        return response.status, text_content, current_url

                except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                    # TLS verification failure - do NOT fallback to insecure
                    logger.error(f"[TLS] Certificate verification failed for {current_url}: {ssl_err}")
                    raise ssl_err

                except (aiohttp.ClientError, asyncio.TimeoutError) as net_err:
                    retry_count += 1
                    if self.request_policy_manager:
                        self.request_policy_manager.record_retry()
                        backoff = self.request_policy_manager.calculate_backoff(retry_count)
                    else:
                        backoff = 0.5 * retry_count

                    if retry_count > self.max_retries:
                        logger.debug(f"[HTTP] Failed after {self.max_retries} retries: {current_url} ({net_err})")
                        return None, None, current_url
                    await asyncio.sleep(backoff)

        logger.warning(f"[HTTP] Maximum redirects ({self.max_redirects}) exceeded for {url}")
        return None, None, current_url
