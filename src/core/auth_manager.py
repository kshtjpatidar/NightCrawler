"""
NightCrawler - Authentication & Credential Manager Module
Safely manages HTTP headers, Bearer tokens, API keys, cookies, and Basic Auth.
Enforces credential isolation: credentials are never sent to out-of-scope hosts,
third-party services, or leaked into logs or process tables.
"""

import os
import base64
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.parse import urlparse

from src.core.program_profile import AuthenticationDefinition, ProgramProfile
from src.core.scope import ScopeManager


class AuthenticationManager:
    """
    Manages program authentication tokens and headers.
    Strictly prevents credential forwarding to out-of-scope hosts and archives.
    """

    def __init__(
        self,
        auth_def: Optional[AuthenticationDefinition] = None,
        required_headers: Optional[Dict[str, str]] = None,
        optional_headers: Optional[Dict[str, str]] = None,
        scope_manager: Optional[ScopeManager] = None,
        raise_if_missing: bool = True
    ):
        self.auth_def = auth_def or AuthenticationDefinition()
        self.required_headers = required_headers or {}
        self.optional_headers = optional_headers or {}
        self.scope_manager = scope_manager
        self.raise_if_missing = raise_if_missing

        # Resolved credentials in memory
        self._auth_header_name: Optional[str] = None
        self._auth_header_value: Optional[str] = None
        self._cookie_header_value: Optional[str] = None
        self._custom_headers: Dict[str, str] = {}
        self._missing_required_credentials: List[str] = []

        self._initialize_credentials()

    @classmethod
    def from_profile(
        cls,
        profile: ProgramProfile,
        scope_manager: Optional[ScopeManager] = None,
        raise_if_missing: bool = False
    ) -> "AuthenticationManager":
        req_headers = profile.resolve_headers()
        opt_headers = profile.headers.get("optional", {})
        return cls(
            auth_def=profile.authentication,
            required_headers=req_headers,
            optional_headers=opt_headers,
            scope_manager=scope_manager,
            raise_if_missing=raise_if_missing
        )

    def set_custom_header(self, name: str, value: str):
        """Set or update a custom header value in memory."""
        if name and value:
            self._custom_headers[name.strip()] = value.strip()

    def _initialize_credentials(self):
        """Resolve and validate credentials from environment variables or secure session files."""
        # 1. Custom Headers
        for k, v in self.required_headers.items():
            val = str(v).strip()
            # If value wasn't expanded (e.g. env var missing)
            if not val:
                # Check if it was an env var name
                env_key = k.upper().replace("-", "_")
                val = os.getenv(env_key, "")
            if not val:
                self._missing_required_credentials.append(f"Required header '{k}'")
                if self.raise_if_missing:
                    raise ValueError(f"Required header '{k}' has no value provided and environment variable is not set.")
            else:
                self._custom_headers[k] = val

        for k, v in self.optional_headers.items():
            if v:
                self._custom_headers[k] = str(v).strip()

        # 2. Authentication Type
        auth_type = self.auth_def.type.lower()
        if auth_type == "none":
            return

        if auth_type == "bearer":
            token_env = self.auth_def.token_env or "PROGRAM_ACCESS_TOKEN"
            token = os.getenv(token_env)
            if not token and self.auth_def.session_file:
                token = self._read_session_file(self.auth_def.session_file)
            if not token:
                self._missing_required_credentials.append(f"Bearer token ({token_env})")
                if self.raise_if_missing:
                    raise ValueError(f"Missing required Bearer token in environment variable '{token_env}'.")
            else:
                header_name = self.auth_def.header_name or "Authorization"
                prefix = self.auth_def.header_prefix or "Bearer "
                self._auth_header_name = header_name
                self._auth_header_value = f"{prefix}{token.strip()}"

        elif auth_type == "api_key":
            key_env = self.auth_def.token_env or "PROGRAM_API_KEY"
            key = os.getenv(key_env)
            if not key:
                self._missing_required_credentials.append(f"API key ({key_env})")
                if self.raise_if_missing:
                    raise ValueError(f"Missing required API key in environment variable '{key_env}'.")
            else:
                header_name = self.auth_def.header_name or "X-API-Key"
                prefix = self.auth_def.header_prefix or ""
                self._auth_header_name = header_name
                self._auth_header_value = f"{prefix}{key.strip()}"

        elif auth_type == "cookie":
            cookie_env = self.auth_def.cookie_env or "PROGRAM_SESSION_COOKIE"
            cookie = os.getenv(cookie_env)
            if not cookie and self.auth_def.session_file:
                cookie = self._read_session_file(self.auth_def.session_file)
            if not cookie:
                self._missing_required_credentials.append(f"Session cookie ({cookie_env})")
                if self.raise_if_missing:
                    raise ValueError(f"Missing required session cookie in environment variable '{cookie_env}'.")
            else:
                self._cookie_header_value = cookie.strip()

        elif auth_type == "basic":
            user_env = self.auth_def.username_env or "PROGRAM_BASIC_USER"
            pass_env = self.auth_def.password_env or "PROGRAM_BASIC_PASS"
            user = os.getenv(user_env, "")
            pwd = os.getenv(pass_env, "")
            if not user or not pwd:
                self._missing_required_credentials.append(f"Basic Auth credentials ({user_env}/{pass_env})")
                if self.raise_if_missing:
                    raise ValueError(f"Missing Basic Auth credentials in environment variables '{user_env}'/'{pass_env}'.")
            else:
                creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                self._auth_header_name = "Authorization"
                self._auth_header_value = f"Basic {creds}"

    def validate_credentials_present(self):
        """Validate that all mandatory headers and credentials have values before scanning begins."""
        if self._missing_required_credentials:
            missing_str = ", ".join(self._missing_required_credentials)
            raise ValueError(
                f"Mandatory authentication credentials missing: {missing_str}. "
                "Set the corresponding environment variable before scanning."
            )

    def _read_session_file(self, file_path_str: str) -> str:
        """Safely read session file, verifying strict permissions (0600)."""
        p = Path(file_path_str)
        if not p.exists():
            raise FileNotFoundError(f"Session file '{p}' does not exist.")

        # Check permissions: must not be group/world readable (mode & 0o077 == 0)
        mode = p.stat().st_mode
        if mode & 0o077:
            raise PermissionError(
                f"Session file '{p}' has insecure permissions ({oct(mode)}). "
                "File permissions must be 0600 (owner read/write only)."
            )

        return p.read_text(encoding="utf-8").strip()

    def get_headers_for_url(
        self,
        url: str,
        scope_manager: Optional[ScopeManager] = None,
        base_headers: Optional[Dict[str, str]] = None,
        is_cross_origin: bool = False
    ) -> Dict[str, str]:
        """
        Build headers for a request destination.
        CRITICAL: If the URL is out of scope or third-party, NO authentication
        or program-specific headers are attached!
        CRITICAL: Cross-origin redirects strip sensitive authentication tokens and cookies!
        """
        headers = dict(base_headers or {})

        # Default User-Agent if not set
        if "User-Agent" not in headers:
            headers["User-Agent"] = "NightCrawler-BugBounty-Recon/5.0"

        sc = scope_manager or self.scope_manager
        # If scope is active and destination is out of scope, NEVER attach credentials or researcher headers
        if sc and sc.enabled:
            if not sc.is_url_in_scope(url):
                # Out-of-scope destination: remove all sensitive headers and return unauthenticated
                headers.pop("Authorization", None)
                headers.pop("authorization", None)
                headers.pop("Cookie", None)
                headers.pop("cookie", None)
                for k in self._custom_headers:
                    headers.pop(k, None)
                return headers

        # Target is authorized and in-scope: safely attach researcher identification headers
        for k, v in self._custom_headers.items():
            headers[k] = v

        # Cross-Origin Protection:
        # If this request is following a cross-origin redirect, sensitive credentials
        # (Authorization header, session cookies, API tokens) must NOT be forwarded!
        if is_cross_origin:
            headers.pop("Authorization", None)
            headers.pop("authorization", None)
            headers.pop("Cookie", None)
            headers.pop("cookie", None)
            return headers

        # Same-origin: attach auth header and cookies if configured
        if self._auth_header_name and self._auth_header_value:
            headers[self._auth_header_name] = self._auth_header_value

        if self._cookie_header_value:
            existing_cookie = headers.get("Cookie", "")
            if existing_cookie:
                headers["Cookie"] = f"{existing_cookie}; {self._cookie_header_value}"
            else:
                headers["Cookie"] = self._cookie_header_value

        return headers

    @staticmethod
    def mask_secret(secret: str) -> str:
        """Mask a sensitive token or password."""
        if not secret:
            return "(empty)"
        s = secret.strip()
        if len(s) <= 4:
            return "****"
        return f"{s[:2]}****{s[-2:]}"
