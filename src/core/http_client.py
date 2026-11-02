"""
NightCrawler - Scope-Aware, Rate-Limited HTTP Client
Centralized HTTP client enforcing global rate limits (5 RPS), strict hop-by-hop
redirect scope validation, verified TLS certificates, and in-scope researcher headers.
"""

import asyncio
import ssl
import logging
from typing import Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager

logger = logging.getLogger("nightcrawler.http")


class ScopeViolationError(Exception):
    """Raised when an HTTP request or redirect targets an out-of-scope host."""
    pass


class NightCrawlerHttpClient:
    """
    Centralized asynchronous HTTP client that guarantees:
    1. Scope enforcement before every outbound request and redirect hop.
    2. Global rate limiting where EVERY actual HTTP attempt (initial, retry, redirect)
       strictly consumes a rate-limit token from a shared limiter.
    3. TLS certificate verification with strict mode rejection of insecure settings.
    4. Safe attachment of researcher identification headers exclusively to in-scope targets.
    """

    def __init__(
        self,
        scope_manager: ScopeManager,
        rate_limiter: GlobalRateLimiter,
        header_manager: HeaderManager,
        timeout_seconds: int = 30,
        verify_tls: bool = True,
        strict_mode: bool = True,
        max_redirects: int = 5,
        max_retries: int = 2
    ):
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter
        self.header_manager = header_manager
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

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Execute an HTTP GET request with hop-by-hop redirect verification.
        Every actual attempt (initial, retry, redirect) consumes a rate limit token.
        Returns: (status_code, content_text, final_url)
        """
        current_url = url.strip()

        # Step 1: Pre-request Scope Check
        if not self.scope_manager.is_url_in_scope(current_url):
            logger.debug(f"[Scope] Blocked out-of-scope URL: {current_url}")
            return None, None, None

        redirect_count = 0

        while redirect_count <= self.max_redirects:
            # Build headers (researcher header only attached if current_url is in-scope)
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
                    return None, None, current_url

                # Every actual HTTP network attempt consumes a token from the shared limiter
                await self.rate_limiter.acquire()

                try:
                    async with session.get(
                        current_url,
                        headers=headers,
                        ssl=self.ssl_context,
                        allow_redirects=False
                    ) as response:
                        # Handle Redirection (301, 302, 303, 307, 308)
                        if response.status in (301, 302, 303, 307, 308):
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
                                return response.status, None, current_url

                            # Proceed to next hop
                            current_url = next_url
                            redirect_count += 1
                            break  # Breaks inner retry loop to process next redirect hop

                        # Retry on rate limited (429) or transient server errors (502, 503, 504)
                        if response.status in (429, 502, 503, 504) and retry_count < self.max_retries:
                            retry_count += 1
                            await asyncio.sleep(0.5 * retry_count)
                            continue

                        # 200 OK or other final response
                        text_content = None
                        if response.status == 200:
                            content_type = response.headers.get("content-type", "")
                            if any(ct in content_type for ct in ("text", "javascript", "json", "xml")):
                                text_content = await response.text(errors="replace")

                        return response.status, text_content, current_url

                except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
                    # TLS verification failure - do NOT fallback to insecure
                    logger.error(f"[TLS] Certificate verification failed for {current_url}: {ssl_err}")
                    raise ssl_err

                except (aiohttp.ClientError, asyncio.TimeoutError) as net_err:
                    retry_count += 1
                    if retry_count > self.max_retries:
                        logger.debug(f"[HTTP] Failed after {self.max_retries} retries: {current_url} ({net_err})")
                        return None, None, current_url
                    await asyncio.sleep(0.5 * retry_count)

        logger.warning(f"[HTTP] Maximum redirects ({self.max_redirects}) exceeded for {url}")
        return None, None, current_url
