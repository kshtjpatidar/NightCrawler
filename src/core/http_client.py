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
from typing import Optional, Dict, Tuple, Any, List, Set
from urllib.parse import urljoin, urlparse, unquote
import aiohttp
import aiohttp.abc
import aiohttp.resolver

try:
    from typing import TypedDict
except ImportError:  # pragma: no cover
    from typing_extensions import TypedDict  # type: ignore

# In aiohttp >= 3.10, ResolveResult is a TypedDict defined in aiohttp.abc
# and re-exported in aiohttp.resolver. In aiohttp 3.9.1 (and earlier),
# ResolveResult is not present in aiohttp.abc, aiohttp.resolver, or aiohttp.typedefs;
# AbstractResolver.resolve returns List[Dict[str, Any]].
# Provide a compatibility ResolveResult TypedDict for backwards compatibility across versions.
try:
    from aiohttp.abc import ResolveResult
except ImportError:
    try:
        from aiohttp.resolver import ResolveResult  # type: ignore
    except (ImportError, AttributeError):
        class ResolveResult(TypedDict):  # type: ignore[no-redef]
            """ResolveResult structure compatible with aiohttp resolver API."""
            hostname: str
            host: str
            port: int
            family: int
            proto: int
            flags: int

if not hasattr(aiohttp.resolver, "ResolveResult"):
    try:
        aiohttp.resolver.ResolveResult = ResolveResult  # type: ignore[attr-defined]
    except Exception:
        pass

from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.audit_logger import AuditLogger
from src.core.program_profile import parse_authorized_providers

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
    ) -> List[ResolveResult]:
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

        results: List[ResolveResult] = []
        for ip_str in pinned_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            addr_family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
            results.append(
                ResolveResult(
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
        effective_policy: Optional[Any] = None,
        authorized_providers: Optional[Set[str]] = None
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

            # EffectivePolicy.authorized_providers is the authoritative maximum permission set
            raw_policy_providers = getattr(effective_policy, "authorized_providers", None)
            if raw_policy_providers:
                policy_providers = frozenset(parse_authorized_providers(raw_policy_providers, context="EffectivePolicy"))
            else:
                policy_providers = frozenset()

            if authorized_providers is not None:
                parsed_constructor = set(parse_authorized_providers(authorized_providers, context="HttpClient constructor"))
                unauthorized = parsed_constructor - set(policy_providers)
                if unauthorized:
                    raise ValueError(
                        f"Constructor cannot expand authorized_providers beyond EffectivePolicy allowlist. "
                        f"Unauthorized additions: {sorted(unauthorized)}. "
                        f"EffectivePolicy allowlist: {sorted(policy_providers)}."
                    )
                # Narrowing permissions: use set intersection
                self._authorized_providers = frozenset(set(policy_providers) & parsed_constructor)
            else:
                self._authorized_providers = policy_providers
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
            if authorized_providers is not None:
                try:
                    self._authorized_providers = frozenset(parse_authorized_providers(authorized_providers, context="HttpClient"))
                except Exception:
                    self._authorized_providers = frozenset()
            else:
                self._authorized_providers = frozenset()

        if self.strict_mode and not self.verify_tls:
            raise ValueError("Insecure TLS configuration is prohibited in strict compliance mode.")

        # TLS SSLContext - verified by default
        if self.verify_tls:
            self.ssl_context = ssl.create_default_context()
        else:
            self.ssl_context = False

        # DNS Pinning cache: maps validated host -> list of authorized IP strings
        self._pinned_ips: Dict[str, List[str]] = {}

        # Policy-aware DNS Resolver instance
        self._resolver = PolicyAwareResolver(self)

    @property
    def authorized_providers(self) -> frozenset:
        """Immutable view of authorized providers for this HTTP client."""
        return self._authorized_providers

    @authorized_providers.setter
    def authorized_providers(self, value: Any):
        """
        Enforce monotonic permission narrowing on attribute assignment.
        Cannot expand permissions beyond the authoritative EffectivePolicy or initial client allowlist.
        """
        if self.effective_policy is not None:
            ceiling = getattr(self, "_authorized_providers", None)
            if ceiling is None:
                ceiling = frozenset(getattr(self.effective_policy, "authorized_providers", set()) or set())
            parsed = set(parse_authorized_providers(value, context="HttpClient.authorized_providers"))
            unauthorized = parsed - set(ceiling)
            if unauthorized:
                raise ValueError(
                    f"Cannot expand authorized_providers beyond authoritative allowlist via attribute assignment. "
                    f"Unauthorized additions: {sorted(unauthorized)}."
                )
            self._authorized_providers = frozenset(set(ceiling) & parsed)
        else:
            try:
                self._authorized_providers = frozenset(parse_authorized_providers(value, context="HttpClient.authorized_providers"))
            except Exception:
                self._authorized_providers = frozenset()

    @staticmethod
    def _normalize_hostname(host: Optional[str]) -> str:
        """
        Normalize hostname safely:
        - Strip whitespace, trailing dots, userinfo, and port.
        - Decode percent-encoding.
        - Lowercase.
        - Convert Unicode/IDNA to ASCII punycode.
        """
        if not host:
            return ""
        clean = str(host).strip().rstrip(".")
        if "%" in clean:
            try:
                clean = unquote(clean).rstrip(".")
            except Exception:
                pass
        clean = clean.lower()
        if "@" in clean:
            clean = clean.split("@")[-1]
        if ":" in clean:
            if not clean.startswith("[") and clean.count(":") == 1:
                clean = clean.split(":")[0]
            elif clean.startswith("[") and "]" in clean:
                clean = clean[1:clean.index("]")]
        try:
            clean = clean.encode("idna").decode("ascii")
        except Exception:
            pass
        return clean

    def is_provider_authorized(self, provider: str, url: str) -> bool:
        """
        Check if an external provider or URL is authorized for this client.
        Enforces strict hostname boundary matching (no substring or suffix confusion).
        Prevents lookalike domains, unnormalized Unicode, alternate ports, and IP bypasses.
        Fails closed on missing, empty, malformed, or wrong-type provider/URL/allowlist.
        """
        if not provider or not isinstance(provider, str) or not provider.strip():
            return False
        if not url or not isinstance(url, str) or not url.strip():
            return False
        if not self.authorized_providers or not isinstance(self.authorized_providers, (set, frozenset, list, tuple)):
            return False

        try:
            parsed = urlparse(url.strip())
        except Exception:
            return False

        # Reject unsupported schemes (must be http or https)
        if parsed.scheme.lower() not in ("http", "https"):
            return False

        # Reject userinfo tricks (e.g. https://slack.com@evil.com/ or https://user:pass@slack.com/)
        if parsed.username or parsed.password:
            return False

        raw_host = parsed.hostname or ""
        if not raw_host:
            return False

        host = self._normalize_hostname(raw_host)
        if not host:
            return False

        # Disallow IP literals (IPv4 and IPv6) from matching provider domain names
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass

        p_lower = provider.strip().lower()
        try:
            normalized_authorized = set(parse_authorized_providers(self.authorized_providers, context="HttpClient"))
        except Exception:
            return False

        if not normalized_authorized:
            return False

        # Known third-party provider official domains
        provider_domains = {
            "google": ["googleapis.com", "google.com"],
            "firebase": ["googleapis.com", "firebaseio.com"],
            "slack": ["slack.com"],
            "stripe": ["stripe.com"],
            "github": ["github.com"],
            "gitlab": ["gitlab.com"],
            "aws": ["amazonaws.com"],
            "mailgun": ["mailgun.net", "mailgun.com"],
            "sendgrid": ["sendgrid.com"],
            "twilio": ["twilio.com"],
            "segment": ["segment.io", "segment.com"],
            "datadog": ["datadoghq.com"],
            "sentry": ["sentry.io"],
            "anthropic": ["anthropic.com"],
            "openai": ["openai.com"],
            "circleci": ["circleci.com"],
            "travis": ["travis-ci.com", "travis-ci.org"],
            "npm": ["npmjs.org", "npmjs.com"],
            "discord": ["discord.com"],
            "telegram": ["telegram.org"],
            "mailchimp": ["mailchimp.com"],
            "heroku": ["heroku.com"],
            "digitalocean": ["digitalocean.com"],
            "cloudflare": ["cloudflare.com"],
            "vercel": ["vercel.com"],
            "netlify": ["netlify.com"],
            "newrelic": ["newrelic.com"],
            "pagerduty": ["pagerduty.com"],
            "facebook": ["facebook.com", "graph.facebook.com"],
            "twitter": ["twitter.com", "api.twitter.com", "x.com"],
            "instagram": ["instagram.com", "graph.instagram.com"],
            "linkedin": ["linkedin.com", "api.linkedin.com"],
            "shodan": ["shodan.io"],
            "virustotal": ["virustotal.com"],
            "censys": ["censys.io"],
            "algolia": ["algolia.net", "algolianet.com"],
            "mapbox": ["mapbox.com"],
            "hubspot": ["hubapi.com", "hubspot.com"],
            "asana": ["asana.com"],
            "zendesk": ["zendesk.com"],
            "grafana": ["grafana.com"],
            "spotify": ["spotify.com"],
            "notion": ["notion.com", "notion.so"],
            "figma": ["figma.com"],
            "airtable": ["airtable.com"],
            "linear": ["linear.app"],
            "atlassian": ["atlassian.net"],
            "jira": ["atlassian.net"],
            "confluence": ["atlassian.net"],
            "supabase": ["supabase.co"],
            "planetscale": ["planetscale.com"],
            "clerk": ["clerk.com"],
            "auth0": ["auth0.com"],
            "plaid": ["plaid.com"],
            "loom": ["loom.com"],
            "postman": ["getpostman.com", "postman.com"],
            "mixpanel": ["mixpanel.com"],
            "amplitude": ["amplitude.com"],
            "launchdarkly": ["launchdarkly.com"],
            "intercom": ["intercom.io"],
            "freshdesk": ["freshdesk.com"],
            "dropbox": ["dropboxapi.com", "dropbox.com"],
            "box": ["box.com"],
            "monday": ["monday.com"],
            "clickup": ["clickup.com"],
            "trello": ["trello.com"],
            "bitly": ["bitly.com", "api-ssl.bitly.com"],
            "rapidapi": ["geoapify.com", "rapidapi.com"],
            "cohere": ["cohere.ai"],
            "replicate": ["replicate.com"],
            "pinecone": ["pinecone.io"],
            "weaviate": ["weaviate.network", "weaviate.io"],
            "braintree": ["braintreegateway.com"],
            "square": ["squareup.com"],
            "razorpay": ["razorpay.com"],
        }

        for ap_clean in normalized_authorized:
            if not ap_clean:
                continue

            # Case A: ap_clean is a domain name (contains '.')
            if "." in ap_clean:
                parts = [p for p in ap_clean.split(".") if p]
                if len(parts) < 2:
                    continue
                if host == ap_clean or host.endswith("." + ap_clean):
                    return True
            else:
                # Case B: ap_clean is a provider identifier (e.g. 'slack')
                if p_lower == ap_clean:
                    domains = provider_domains.get(ap_clean, [f"{ap_clean}.com"])
                    for d in domains:
                        d_norm = self._normalize_hostname(d)
                        if not d_norm or "." not in d_norm:
                            continue
                        if host == d_norm or host.endswith("." + d_norm):
                            return True
        return False

    def get_resolver(self) -> aiohttp.abc.AbstractResolver:
        """Return a policy-aware DNS resolver that enforces policy validation and DNS pinning."""
        if not hasattr(self, "_resolver") or self._resolver is None:
            self._resolver = PolicyAwareResolver(self)
        return self._resolver

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

    async def request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        auth: Optional[aiohttp.BasicAuth] = None,
        authorized_provider: Optional[str] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Execute an HTTP request (GET, POST, etc.) with hop-by-hop redirect verification.
        Every actual attempt (initial, retry, redirect) consumes a rate limit token.
        Guarantees that every network request uses the RequestPolicyManager semaphore.
        Returns: (status_code, content_text, final_url)
        """
        sem = self.request_policy_manager.get_semaphore() if self.request_policy_manager else None
        if sem is not None and not _in_concurrency_scope.get():
            async with sem:
                token = _in_concurrency_scope.set(True)
                try:
                    return await self._request_impl(session, method, url, extra_headers, data, json_data, auth, authorized_provider=authorized_provider)
                finally:
                    _in_concurrency_scope.reset(token)
        else:
            return await self._request_impl(session, method, url, extra_headers, data, json_data, auth, authorized_provider=authorized_provider)

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Execute an HTTP GET request under shared policy controls."""
        return await self.request(session, "GET", url, extra_headers=extra_headers)

    async def post(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        auth: Optional[aiohttp.BasicAuth] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Execute an HTTP POST request under shared policy controls."""
        return await self.request(session, "POST", url, extra_headers=extra_headers, data=data, json_data=json_data, auth=auth)

    async def _request_impl(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        auth: Optional[aiohttp.BasicAuth] = None,
        authorized_provider: Optional[str] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        initial_url = url.strip()
        current_url = initial_url
        current_method = method.upper()
        current_data = data
        current_json = json_data
        current_auth = auth

        parsed_init = urlparse(initial_url)
        if parsed_init.scheme not in ("http", "https"):
            logger.warning(f"[Security] Unsupported URL scheme '{parsed_init.scheme}' in {AuditLogger.redact_url(initial_url)}")
            return None, None, None

        if parsed_init.username or parsed_init.password:
            logger.warning(f"[Security] Prohibited embedded credentials in URL: {AuditLogger.redact_url(initial_url)}")
            return None, None, None

        initial_origin = f"{parsed_init.scheme}://{parsed_init.hostname}:{parsed_init.port or (443 if parsed_init.scheme == 'https' else 80)}"

        # Step 1: Pre-request Scope Check
        is_in_scope = self.scope_manager.is_url_in_scope(current_url)
        if not is_in_scope:
            if authorized_provider and self.is_provider_authorized(authorized_provider, current_url):
                pass
            else:
                logger.debug(f"[Scope] Blocked out-of-scope URL: {AuditLogger.redact_url(current_url)}")
                if self.audit_logger:
                    host = self.scope_manager.extract_hostname(current_url) or "unknown"
                    self.audit_logger.log_event(
                        target_host=host,
                        method=current_method,
                        url=current_url,
                        scope_decision="BLOCKED",
                        policy_decision="DENIED",
                        rate_limiter_decision="N/A"
                    )
                return None, None, None

        redirect_count = 0
        redirect_history = {current_url}

        while redirect_count <= self.max_redirects:
            parsed_curr = urlparse(current_url)
            curr_origin = f"{parsed_curr.scheme}://{parsed_curr.hostname}:{parsed_curr.port or (443 if parsed_curr.scheme == 'https' else 80)}"
            is_cross_origin = (redirect_count > 0 and curr_origin != initial_origin)

            # Sanitize extra_headers on cross-origin redirects: strip sensitive auth tokens and basic auth
            active_extra_headers = dict(extra_headers or {})
            active_auth = current_auth
            if is_cross_origin:
                sensitive_keys = {
                    "authorization", "proxy-authorization", "cookie",
                    "x-api-key", "api-key", "token", "x-auth-token", "x-user-token"
                }
                active_extra_headers = {
                    k: v for k, v in active_extra_headers.items()
                    if k.lower() not in sensitive_keys
                }
                active_auth = None

            # Build headers (credentials only attached if current_url is in-scope and not cross-origin)
            if self.auth_manager:
                headers = self.auth_manager.get_headers_for_url(
                    current_url,
                    scope_manager=self.scope_manager,
                    base_headers=active_extra_headers,
                    is_cross_origin=is_cross_origin
                )
            else:
                headers = self.header_manager.get_headers_for_url(
                    current_url,
                    scope_manager=self.scope_manager,
                    base_headers=active_extra_headers
                )

            # Retry loop: every attempt consumes a rate-limit token
            retry_count = 0
            while retry_count <= self.max_retries:
                # Scope check before each request attempt
                is_curr_in_scope = self.scope_manager.is_url_in_scope(current_url)
                if not is_curr_in_scope:
                    if not (authorized_provider and self.is_provider_authorized(authorized_provider, current_url)):
                        logger.warning(f"[Scope] URL {AuditLogger.redact_url(current_url)} is out of scope and not an authorized provider. Aborting attempt.")
                        if self.audit_logger:
                            host = self.scope_manager.extract_hostname(current_url) or "unknown"
                            self.audit_logger.log_event(
                                target_host=host,
                                method=current_method,
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
                            method=current_method,
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
                    if current_method == "GET" and hasattr(session, "get"):
                        req_ctx = session.get(
                            current_url,
                            headers=headers,
                            auth=active_auth,
                            ssl=self.ssl_context,
                            allow_redirects=False
                        )
                    elif current_method == "POST" and hasattr(session, "post"):
                        req_ctx = session.post(
                            current_url,
                            headers=headers,
                            data=current_data,
                            json=current_json,
                            auth=active_auth,
                            ssl=self.ssl_context,
                            allow_redirects=False
                        )
                    else:
                        req_ctx = session.request(
                            method=current_method,
                            url=current_url,
                            headers=headers,
                            data=current_data,
                            json=current_json,
                            auth=active_auth,
                            ssl=self.ssl_context,
                            allow_redirects=False
                        )
                    async with req_ctx as response:
                        # Log audit event
                        if self.audit_logger:
                            self.audit_logger.log_event(
                                target_host=host or "unknown",
                                method=current_method,
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
                            parsed_next = urlparse(next_url)

                            # Validate scheme support
                            if parsed_next.scheme not in ("http", "https"):
                                logger.warning(f"[Security] Unsupported scheme in redirect destination: {AuditLogger.redact_url(next_url)}")
                                return response.status, None, current_url

                            # Prohibit credentials in redirect URL
                            if parsed_next.username or parsed_next.password:
                                logger.warning(f"[Security] Credentials in redirect destination prohibited: {AuditLogger.redact_url(next_url)}")
                                return response.status, None, current_url

                            # Reject HTTPS to HTTP downgrade in strict or TLS-verified mode
                            if parsed_curr.scheme == "https" and parsed_next.scheme == "http" and (self.strict_mode or self.verify_tls):
                                logger.warning(f"[Security] HTTPS-to-HTTP downgrade rejected for redirect {AuditLogger.redact_url(current_url)} -> {AuditLogger.redact_url(next_url)}")
                                if self.audit_logger:
                                    next_host = self.scope_manager.extract_hostname(next_url) or "unknown"
                                    self.audit_logger.log_event(
                                        target_host=next_host,
                                        method=current_method,
                                        url=next_url,
                                        scope_decision="BLOCKED",
                                        policy_decision="DENIED",
                                        redirect_decision="BLOCKED_SCHEME_DOWNGRADE"
                                    )
                                return response.status, None, current_url

                            # Detect redirect loop
                            if next_url in redirect_history:
                                logger.warning(f"[HTTP] Redirect loop detected for {AuditLogger.redact_url(next_url)}")
                                return response.status, None, current_url
                            redirect_history.add(next_url)

                            # Validate redirect target scope immediately
                            is_redirect_in_scope = self.scope_manager.is_url_in_scope(next_url)
                            if not is_redirect_in_scope:
                                if not (authorized_provider and self.is_provider_authorized(authorized_provider, next_url)):
                                    logger.warning(
                                        f"[Scope] Redirect from {AuditLogger.redact_url(current_url)} to out-of-scope target "
                                        f"{AuditLogger.redact_url(next_url)} was blocked!"
                                    )
                                    if self.audit_logger:
                                        next_host = self.scope_manager.extract_hostname(next_url) or "unknown"
                                        self.audit_logger.log_event(
                                            target_host=next_host,
                                            method=current_method,
                                            url=next_url,
                                            scope_decision="BLOCKED",
                                            policy_decision="DENIED",
                                            redirect_decision="BLOCKED_OUT_OF_SCOPE"
                                        )
                                    return response.status, None, current_url

                            # Method and payload adjustment on 301, 302, 303
                            if response.status == 303 or (response.status in (301, 302) and current_method == "POST"):
                                current_method = "GET"
                                current_data = None
                                current_json = None

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

                        # Response text read for caller analysis
                        text_content = await response.text(errors="replace")
                        return response.status, text_content, current_url

                except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                    # TLS verification failure - do NOT fallback to insecure
                    logger.error(f"[TLS] Certificate verification failed for {AuditLogger.redact_url(current_url)}: {ssl_err}")
                    raise ssl_err

                except (aiohttp.ClientError, asyncio.TimeoutError) as net_err:
                    retry_count += 1
                    if self.request_policy_manager:
                        self.request_policy_manager.record_retry()
                        backoff = self.request_policy_manager.calculate_backoff(retry_count)
                    else:
                        backoff = 0.5 * retry_count

                    if retry_count > self.max_retries:
                        logger.debug(f"[HTTP] Failed after {self.max_retries} retries: {AuditLogger.redact_url(current_url)} ({net_err})")
                        return None, None, current_url
                    await asyncio.sleep(backoff)

        logger.warning(f"[HTTP] Maximum redirects ({self.max_redirects}) exceeded for {AuditLogger.redact_url(url)}")
        return None, None, current_url
