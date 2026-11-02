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
    1. Scope enforcement on all URLs and intermediate redirect hops.
    2. Global rate limiting across all requests, redirects, and retries.
    3. TLS certificate verification with no insecure fallback.
    4. Safe attachment of researcher identification headers exclusively to in-scope targets.
    """

    def __init__(
        self,
        scope_manager: ScopeManager,
        rate_limiter: GlobalRateLimiter,
        header_manager: HeaderManager,
        timeout_seconds: int = 30,
        verify_tls: bool = True,
        max_redirects: int = 5,
        max_retries: int = 2
    ):
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter
        self.header_manager = header_manager
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.verify_tls = verify_tls
        self.max_redirects = max_redirects
        self.max_retries = max_retries

        # TLS SSLContext - verified by default
        if self.verify_tls:
            self.ssl_context = ssl.create_default_context()
        else:
            # If explicitly disabled by user configuration
            self.ssl_context = False

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Execute an HTTP GET request with hop-by-hop redirect verification.
        Returns: (status_code, content_text, final_url)
        """
        current_url = url.strip()

        # Step 1: Pre-request Scope Check
        if not self.scope_manager.is_url_in_scope(current_url):
            logger.debug(f"[Scope] Blocked out-of-scope URL: {current_url}")
            return None, None, None

        redirect_count = 0

        while redirect_count <= self.max_redirects:
            # Step 2: Rate limit acquisition (counts each request and each redirect hop)
            await self.rate_limiter.acquire()

            # Step 3: Header construction (only injects researcher header if current_url is in-scope)
            headers = self.header_manager.get_headers_for_url(
                current_url,
                scope_manager=self.scope_manager,
                base_headers=extra_headers
            )

            # Step 4: Perform request with allow_redirects=False for hop-by-hop scope inspection
            retry_count = 0
            while retry_count <= self.max_retries:
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

                            # Validate redirect target scope!
                            if not self.scope_manager.is_url_in_scope(next_url):
                                logger.warning(
                                    f"[Scope] Redirect from {current_url} to out-of-scope target "
                                    f"{next_url} was blocked!"
                                )
                                return response.status, None, current_url

                            current_url = next_url
                            redirect_count += 1
                            break  # Proceed to next redirect hop

                        # 200 OK or other response
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
                        logger.debug(f"[HTTP] Failed after retries: {current_url} ({net_err})")
                        return None, None, current_url
                    # Rate limit retry attempt as well
                    await self.rate_limiter.acquire()

        logger.warning(f"[HTTP] Maximum redirects exceeded for {url}")
        return None, None, current_url
