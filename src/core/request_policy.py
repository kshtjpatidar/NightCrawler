"""
NightCrawler - Request Policy Manager Module
Coordinates global rate limiting, per-host rate limiting, concurrency semaphores,
retry/redirect accounting, and exponential backoff based on program policy.
"""

import asyncio
import math
from typing import Dict, Optional, Any
from urllib.parse import urlparse

from src.core.rate_limiter import GlobalRateLimiter
from src.core.program_profile import RequestPolicyDefinition, ProgramProfile


class RequestPolicyManager:
    """
    Centralized coordinator for all outbound request rate and concurrency policies.
    Enforces the strictest applicable limit across global, program, and per-host boundaries.
    """

    def __init__(
        self,
        policy: Optional[RequestPolicyDefinition] = None,
        global_override_rps: Optional[float] = None,
        max_rps: Optional[float] = None,
        per_host_rps: Optional[float] = None,
        concurrency_limit: Optional[int] = None,
        timeout: Optional[int] = None,
        crawl_depth: Optional[int] = None,
        verify_tls: Optional[bool] = None,
        strict_scope: Optional[bool] = None,
        max_retries: Optional[int] = None,
        burst: Optional[int] = None
    ):
        if policy is None:
            effective_max_rps = max_rps if max_rps is not None else 5.0
            self.policy = RequestPolicyDefinition(
                max_rps=effective_max_rps,
                per_host_rps=per_host_rps if per_host_rps is not None else effective_max_rps,
                concurrency=concurrency_limit if concurrency_limit is not None else 1,
                timeout=timeout if timeout is not None else 30,
                crawl_depth=crawl_depth if crawl_depth is not None else 1,
                verify_tls=verify_tls if verify_tls is not None else True,
                strict_scope=strict_scope if strict_scope is not None else True,
                max_retries=max_retries if max_retries is not None else 2,
                burst=burst if burst is not None else 1
            )
        else:
            self.policy = policy

        # Determine strictest rate limit
        effective_rps = self.policy.max_rps
        if global_override_rps is not None and global_override_rps > 0:
            effective_rps = min(effective_rps, global_override_rps)

        # Validate rate limit strictly
        if math.isnan(effective_rps) or math.isinf(effective_rps) or effective_rps <= 0:
            raise ValueError(f"Invalid request rate limit: {effective_rps}. Must be positive number.")

        self.effective_rps = effective_rps
        self.burst = self.policy.burst
        self.concurrency_limit = max(1, self.policy.concurrency)
        self.timeout = self.policy.timeout
        self.max_retries = self.policy.max_retries
        self.crawl_depth = self.policy.crawl_depth
        self.verify_tls = self.policy.verify_tls
        self.strict_scope = self.policy.strict_scope
        self.per_host_rps = self.policy.per_host_rps

        # Global Rate Limiter
        self.global_limiter = GlobalRateLimiter(
            max_requests_per_second=self.effective_rps,
            burst=self.burst
        )

        # Per-host limiters
        self._host_limiters: Dict[str, GlobalRateLimiter] = {}
        self._host_limiters_lock = asyncio.Lock()

        # Concurrency semaphore
        self._semaphore: Optional[asyncio.Semaphore] = None

        # Request statistics
        self.total_attempts = 0
        self.total_retries = 0
        self.total_redirects = 0
        self.blocked_attempts = 0

    @classmethod
    def from_profile(cls, profile: ProgramProfile, global_override_rps: Optional[float] = None) -> "RequestPolicyManager":
        return cls(policy=profile.request_policy, global_override_rps=global_override_rps)

    def get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency_limit)
        return self._semaphore

    async def _get_host_limiter(self, host: str) -> GlobalRateLimiter:
        clean_host = host.lower().strip()
        async with self._host_limiters_lock:
            if clean_host not in self._host_limiters:
                host_rate = min(self.effective_rps, self.per_host_rps)
                self._host_limiters[clean_host] = GlobalRateLimiter(
                    max_requests_per_second=host_rate,
                    burst=self.burst
                )
            return self._host_limiters[clean_host]

    async def acquire(self, host: Optional[str] = None):
        """
        Acquire a token from the global rate limiter and per-host limiter if applicable.
        Every single HTTP attempt (including initial, retry, and redirect) must call acquire().
        """
        # 1. Global rate limiter token
        await self.global_limiter.acquire()
        self.total_attempts += 1

        # 2. Per-host rate limiter token
        if host and self.per_host_rps > 0:
            host_limiter = await self._get_host_limiter(host)
            await host_limiter.acquire()

    def record_retry(self):
        self.total_retries += 1

    def record_redirect(self):
        self.total_redirects += 1

    def record_blocked(self):
        self.blocked_attempts += 1

    @staticmethod
    def calculate_backoff(attempt: int, base: float = 0.5, max_delay: float = 5.0) -> float:
        """Calculate exponential backoff delay for retries."""
        delay = base * (2 ** (attempt - 1))
        return min(delay, max_delay)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "effective_rps": self.effective_rps,
            "concurrency_limit": self.concurrency_limit,
            "total_attempts": self.total_attempts,
            "total_retries": self.total_retries,
            "total_redirects": self.total_redirects,
            "blocked_attempts": self.blocked_attempts,
            "active_host_limiters": len(self._host_limiters)
        }
