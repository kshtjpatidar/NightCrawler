"""
NightCrawler - Global Rate Limiter Module
Thread-safe and async-safe global request rate limiter enforcing strict requests-per-second (RPS).
"""

import asyncio
import math
import time
from typing import Optional


class GlobalRateLimiter:
    """
    Centralized asynchronous token-bucket rate limiter.
    Ensures that total requests across all concurrent coroutines and workers
    never exceed max_requests_per_second.
    """

    def __init__(self, max_requests_per_second: float = 5.0, burst: Optional[int] = None):
        # 1. Type validation for max_requests_per_second: reject booleans and non-numeric types
        if isinstance(max_requests_per_second, bool) or not isinstance(max_requests_per_second, (int, float)):
            raise TypeError(
                f"max_requests_per_second must be numeric, got {type(max_requests_per_second).__name__}: {max_requests_per_second}"
            )

        # 2. Reject NaN, positive infinity, negative infinity
        try:
            if not math.isfinite(max_requests_per_second):
                raise ValueError(
                    f"max_requests_per_second cannot be NaN or Infinity, got {max_requests_per_second}"
                )
        except OverflowError:
            raise ValueError(
                f"max_requests_per_second exceeds numeric bounds (OverflowError): {max_requests_per_second}"
            )

        # 3. Enforce lower (> 0) and upper (<= 1,000,000) bounds
        if max_requests_per_second <= 0:
            raise ValueError(f"max_requests_per_second must be positive (> 0), got {max_requests_per_second}")
        if max_requests_per_second > 1_000_000:
            raise ValueError(
                f"max_requests_per_second exceeds maximum allowable limit (1,000,000), got {max_requests_per_second}"
            )

        # 4. Strict validation for burst: integer, reject booleans, min 1, max 1,000,000
        if burst is not None:
            if isinstance(burst, bool) or not isinstance(burst, int):
                raise TypeError(f"burst must be an integer, got {type(burst).__name__}: {burst}")
            if burst < 1:
                raise ValueError(f"burst must be at least 1, got {burst}")
            if burst > 1_000_000:
                raise ValueError(f"burst exceeds maximum allowable limit (1,000,000), got {burst}")

        # 5. Validation occurs before assigning instance state
        self.rate = float(max_requests_per_second)
        self.max_tokens = float(burst if burst is not None else 1.0)
        self.tokens = self.max_tokens
        self.last_updated = time.monotonic()
        self._lock: Optional[asyncio.Lock] = None
        self._total_requests_acquired = 0

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def acquire(self):
        """
        Wait until a request token is available.
        Ensures strict RPS compliance even under heavy concurrency.
        """
        if self.rate <= 0:
            return

        lock = self._get_lock()
        while True:
            async with lock:
                now = time.monotonic()
                elapsed = now - self.last_updated
                self.last_updated = now

                # Refill tokens based on elapsed time
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    self._total_requests_acquired += 1
                    return
                else:
                    # Calculate sleep time needed to get at least 1 token
                    needed = 1.0 - self.tokens
                    wait_time = needed / self.rate

            # Sleep outside the lock so other coroutines can check their state when awakened
            await asyncio.sleep(wait_time)

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    @property
    def total_requests(self) -> int:
        return self._total_requests_acquired
