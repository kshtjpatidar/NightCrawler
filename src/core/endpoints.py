"""
NightCrawler - Endpoint & JavaScript Asset Discovery Module
Extracts endpoints, API routes, parameters, authentication paths, source maps,
and client-side configurations from HTML and JavaScript files.
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from dataclasses import dataclass, field
from src.core.scope import ScopeManager


INTERESTING_KEYWORDS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/admin/", "/auth/", "/login/",
    "/logout/", "/signin/", "/signup/", "/oauth/", "/graphql", "/webhook/",
    "/user/", "/account/", "/internal/", "/private/", "/config/", "/settings/",
    "/export/", "/upload/", "/download/", "/payment/", "/checkout/", "/token/"
]


@dataclass
class DiscoveredEndpoint:
    url_or_path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source_url: str = ""
    is_interesting: bool = False
    endpoint_type: str = "general"  # api, auth, admin, graphql, webhook, general


@dataclass
class ExtractedJsMetadata:
    js_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    feature_flags: List[str] = field(default_factory=list)
    sensitive_config_keys: List[str] = field(default_factory=list)


class EndpointExtractor:
    """Extracts endpoints, parameters, and metadata from JavaScript and HTML content."""

    # Regex patterns for endpoint extraction in JS/HTML
    ENDPOINT_PATTERNS = [
        # Explicit full or relative API paths in quotes
        r'''(?:"|')((?:https?://[^"'\s]+|/(?:api|v[0-9]|admin|auth|login|graphql|oauth|webhook)[^"'\s]*))(?:"|')''',
        # General relative paths starting with /
        r'''(?:"|')(/[a-zA-Z0-9_\-\./]+(?:\?[a-zA-Z0-9_&=%\-]*)?)(?:"|')''',
        # Fetch/Axios calls: fetch("/api/...", { method: "POST" })
        r'''(?:fetch|axios|ajax|\$.get|\$.post)\s*\(\s*["']([^"']+)["'](?:\s*,\s*\{[^}]*method\s*:\s*["']([A-Z]+)["'])?''',
    ]

    # Source map patterns
    SOURCEMAP_PATTERNS = [
        r'''//[#@]\s*sourceMappingURL=([^\s'"]+\.map)''',
        r'''/\*#\s*sourceMappingURL=([^\s'"]+\.map)\s*\*\/''',
        r'''["']([^"']+\.js\.map(?:\?[^"']*)?)["']'''
    ]

    # Feature flag patterns
    FEATURE_FLAG_PATTERNS = [
        r'''(?:flags?|featureFlags?|features?)\s*:\s*\{([^}]+)\}''',
        r'''isFeatureEnabled\s*\(\s*["']([^"']+)["']\s*\)''',
        r'''enableFeature\s*\(\s*["']([^"']+)["']\s*\)'''
    ]

    # Potential config object keys
    CONFIG_KEY_PATTERNS = [
        r'''(?:config|environment|env|settings)\s*:\s*\{([^}]+)\}''',
        r'''(?:REACT_APP_|NEXT_PUBLIC_|VUE_APP_|ANGULAR_APP_)[A-Z0-9_]+'''
    ]

    def __init__(self, scope_manager: Optional[ScopeManager] = None):
        self.scope_manager = scope_manager

    def extract_from_js(self, js_content: str, base_url: str) -> ExtractedJsMetadata:
        """Extract endpoints, source maps, feature flags, and configs from a JS file."""
        metadata = ExtractedJsMetadata(js_url=base_url)
        if not js_content:
            return metadata

        # 1. Source maps
        for pattern in self.SOURCEMAP_PATTERNS:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                sm = match.group(1).strip()
                if not sm.startswith("http"):
                    sm = urljoin(base_url, sm)
                if sm not in metadata.source_maps:
                    metadata.source_maps.append(sm)

        # 2. Endpoints & Methods
        extracted_endpoints: Dict[str, DiscoveredEndpoint] = {}

        # Fetch/axios with method
        for match in re.finditer(self.ENDPOINT_PATTERNS[2], js_content, re.IGNORECASE):
            path = match.group(1).strip()
            method = (match.group(2) or "GET").upper()
            self._process_candidate_endpoint(path, method, base_url, extracted_endpoints)

        # General quoted paths
        for p in self.ENDPOINT_PATTERNS[:2]:
            for match in re.finditer(p, js_content):
                path = match.group(1).strip()
                self._process_candidate_endpoint(path, "GET", base_url, extracted_endpoints)

        metadata.endpoints = list(extracted_endpoints.values())

        # 3. Feature flags
        for p in self.FEATURE_FLAG_PATTERNS:
            for match in re.finditer(p, js_content):
                val = match.group(1).strip()[:100]
                if val and val not in metadata.feature_flags:
                    metadata.feature_flags.append(val)

        # 4. Sensitive config identifiers
        for p in self.CONFIG_KEY_PATTERNS:
            for match in re.finditer(p, js_content):
                val = match.group(0).strip()[:80]
                if val and val not in metadata.sensitive_config_keys:
                    metadata.sensitive_config_keys.append(val)

        return metadata

    def _process_candidate_endpoint(
        self,
        candidate: str,
        method: str,
        base_url: str,
        collection: Dict[str, DiscoveredEndpoint]
    ):
        """Filter and classify candidate endpoint path or URL."""
        if not candidate or len(candidate) < 2:
            return

        # Skip common static assets like images, fonts, css, etc.
        skip_extensions = (
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
            '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3'
        )
        clean_path = candidate.split('?')[0].lower()
        if any(clean_path.endswith(ext) for ext in skip_extensions):
            return

        # If it's a full URL, validate scope
        if candidate.startswith("http://") or candidate.startswith("https://"):
            if self.scope_manager and not self.scope_manager.is_url_in_scope(candidate):
                return
            full_url = candidate
        elif candidate.startswith("/"):
            # Relative path - resolve against base_url
            full_url = urljoin(base_url, candidate)
            if self.scope_manager and not self.scope_manager.is_url_in_scope(full_url):
                return
        else:
            return

        if full_url in collection:
            return

        # Parse query params
        parsed = urlparse(full_url)
        params = list(parse_qs(parsed.query).keys())

        # Check path parameters like /user/:id or /order/{orderId}
        path_params = re.findall(r'[:{]([a-zA-Z0-9_]+)[}]?', parsed.path)
        for p in path_params:
            if p not in params:
                params.append(p)

        # Determine endpoint category & interest
        is_interesting = False
        lower_path = parsed.path.lower()
        endpoint_type = "general"

        if "/api/" in lower_path or "/v1/" in lower_path or "/v2/" in lower_path:
            endpoint_type = "api"
            is_interesting = True
        elif any(k in lower_path for k in ["/auth", "/login", "/oauth", "/signin", "/token"]):
            endpoint_type = "auth"
            is_interesting = True
        elif "/admin" in lower_path or "/internal" in lower_path:
            endpoint_type = "admin"
            is_interesting = True
        elif "graphql" in lower_path:
            endpoint_type = "graphql"
            is_interesting = True
        elif "webhook" in lower_path:
            endpoint_type = "webhook"
            is_interesting = True
        elif any(k in lower_path for k in INTERESTING_KEYWORDS):
            is_interesting = True

        collection[full_url] = DiscoveredEndpoint(
            url_or_path=full_url,
            method=method,
            parameters=params,
            source_url=base_url,
            is_interesting=is_interesting,
            endpoint_type=endpoint_type
        )
