"""
NightCrawler - Header Manager Module
Manages researcher identification headers, environment variable resolution,
sensitive value masking, and scope-based header injection.
"""

import os
from typing import Dict, Optional
from urllib.parse import urlparse
from src.core.scope import ScopeManager


class HeaderManager:
    """
    Manages custom HTTP headers for bug bounty researcher identification.
    Ensures headers are only sent to authorized in-scope targets and never
    leaked to third-party endpoints or logged in cleartext.
    """

    def __init__(
        self,
        enabled: bool = False,
        header_name: str = "X-User-Id",
        header_value: Optional[str] = None,
        header_value_env: Optional[str] = "NIGHTCRAWLER_RESEARCHER_ID"
    ):
        self.enabled = enabled
        self.header_name = header_name.strip() if header_name else "X-User-Id"
        self._header_value = header_value

        # Check environment variable if direct value not provided
        if not self._header_value and header_value_env:
            self._header_value = os.getenv(header_value_env)

        # Also fallback to general env vars if present
        if not self._header_value:
            self._header_value = os.getenv("NIGHTCRAWLER_HEADER_VALUE") or os.getenv("RESEARCHER_HEADER_VALUE")

    @property
    def header_value(self) -> Optional[str]:
        return self._header_value

    @header_value.setter
    def header_value(self, val: Optional[str]):
        self._header_value = val.strip() if val else None

    def is_active(self) -> bool:
        """Returns True if researcher header is enabled and a non-empty value exists."""
        return bool(self.enabled and self.header_name and self._header_value)

    def get_masked_value(self) -> str:
        """
        Return a safely masked representation of the header value for logs and reports.
        Never outputs cleartext sensitive tokens/emails.
        """
        if not self._header_value:
            return "(not configured)"

        val = self._header_value
        if "@" in val:
            # Mask email address: r***r@domain.com
            parts = val.split("@", 1)
            local, domain = parts[0], parts[1]
            if len(local) <= 2:
                masked_local = local[0] + "*"
            else:
                masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
            return f"{masked_local}@{domain}"
        else:
            # Mask generic token/string
            if len(val) <= 4:
                return "****"
            return val[:2] + "*" * (len(val) - 4) + val[-2:]

    def get_headers_for_url(
        self,
        url: str,
        scope_manager: Optional[ScopeManager] = None,
        base_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Returns headers dictionary for a specific request URL.
        CRITICAL: The custom researcher identification header is ONLY added if
        the URL is confirmed to be within authorized scope!
        """
        headers = dict(base_headers) if base_headers else {}

        if not self.is_active():
            return headers

        # Check scope if scope_manager is provided
        if scope_manager is not None:
            if not scope_manager.is_url_in_scope(url):
                # Unrelated third-party or out-of-scope domain: DO NOT attach researcher header
                return headers

        if self.header_name and self._header_value:
            headers[self.header_name] = self._header_value

        return headers

    def format_cli_header_flag(self) -> Optional[str]:
        """Format for CLI tools supporting -H 'Header: Value'."""
        if self.is_active():
            return f"{self.header_name}: {self._header_value}"
        return None
