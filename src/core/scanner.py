"""
NightCrawler v5.0 - Scope-Aware, Rate-Limited Core Scanner
Async, concurrent JS file scanner with strict scope validation, 5 RPS rate limiting,
verified TLS certificates, masked reporting, and endpoint discovery.
"""

import asyncio
import aiohttp
import re
import ssl
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import time
import hashlib

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from jsbeautifier import beautify

from src.patterns.secrets import ALL_PATTERNS, SecretPattern, PatternValidator, TOTAL_PATTERNS
from src.integrations.tools import (
    SubfinderIntegration, KatanaIntegration, GauIntegration,
    WaybackurlsIntegration, SubJSIntegration, HakrawlerIntegration,
    GetJSIntegration, JSLuiceIntegration, find_tool, get_all_tool_paths
)
from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.http_client import NightCrawlerHttpClient
from src.core.endpoints import EndpointExtractor, DiscoveredEndpoint, ExtractedJsMetadata
from src.output.html_report import mask_secret

console = Console()


@dataclass
class Finding:
    """Represents a secret finding with validation status and masked reporting"""
    url: str
    pattern_name: str
    category: str
    matched_value: str
    confidence: int
    validated: bool = True
    line_number: Optional[int] = None
    context: Optional[str] = None
    # KeyHacks validation fields
    keyhacks_status: str = "NOT_CHECKED"  # VALID, INVALID, UNKNOWN, ERROR, NOT_CHECKED
    keyhacks_message: str = ""
    keyhacks_command: str = ""
    
    def severity(self) -> str:
        """Get severity based on confidence"""
        if self.confidence >= 90:
            return "CRITICAL"
        elif self.confidence >= 75:
            return "HIGH"
        elif self.confidence >= 60:
            return "MEDIUM"
        else:
            return "LOW"
    
    def is_keyhacks_valid(self) -> bool:
        """Check if KeyHacks validation confirmed the secret is valid"""
        return self.keyhacks_status == "VALID"


@dataclass
class ScanResult:
    """Aggregated scan results including endpoints and reconnaissance metadata"""
    target: str
    total_urls_scanned: int = 0
    total_js_files: int = 0
    total_findings: int = 0
    total_validated: int = 0
    keyhacks_valid: int = 0  # Count of secrets confirmed VALID by KeyHacks
    keyhacks_invalid: int = 0  # Count of secrets confirmed INVALID
    subdomains_found: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    discovered_endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    feature_flags: List[str] = field(default_factory=list)
    sensitive_config_keys: List[str] = field(default_factory=list)


class NightCrawlerScanner:
    """Main scanner class for NightCrawler v5.0 with strict scope and rate limiting"""
    
    def __init__(
        self,
        concurrency: int = 1,
        timeout: int = 30,
        depth: int = 1,
        use_external_tools: bool = True,
        custom_patterns: Optional[str] = None,
        verbose: bool = False,
        validate: bool = True,
        # Scope, headers, rate-limiting, and feature controls
        scope_manager: Optional[ScopeManager] = None,
        rate_limiter: Optional[GlobalRateLimiter] = None,
        header_manager: Optional[HeaderManager] = None,
        max_requests_per_second: float = 5.0,
        verify_tls: bool = True,
        strict_scope: bool = True,
        javascript_extraction: bool = True,
        endpoint_discovery: bool = True,
        secret_detection: bool = True,
        validate_keys: bool = False
    ):
        self.concurrency = max(1, concurrency)
        self.timeout_seconds = timeout
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.depth = depth
        self.use_external_tools = use_external_tools
        self.verbose = verbose
        self.validate = validate
        
        # Scope, headers, rate limiting
        self.scope_manager = scope_manager or ScopeManager(enabled=strict_scope)
        self.max_requests_per_second = max_requests_per_second
        self.rate_limiter = rate_limiter or GlobalRateLimiter(max_requests_per_second=max_requests_per_second)
        self.header_manager = header_manager or HeaderManager()
        self.verify_tls = verify_tls
        self.strict_scope = strict_scope
        self.javascript_extraction = javascript_extraction
        self.endpoint_discovery = endpoint_discovery
        self.secret_detection = secret_detection
        self.validate_keys = validate_keys

        # Centralized HTTP client
        self.http_client = NightCrawlerHttpClient(
            scope_manager=self.scope_manager,
            rate_limiter=self.rate_limiter,
            header_manager=self.header_manager,
            timeout_seconds=timeout,
            verify_tls=verify_tls
        )

        # Endpoint extractor
        self.endpoint_extractor = EndpointExtractor(scope_manager=self.scope_manager)
        
        # Pattern validator
        self.validator = PatternValidator()
        
        # Compile patterns
        self.patterns: List[Tuple[SecretPattern, re.Pattern]] = []
        if self.secret_detection:
            for p in ALL_PATTERNS:
                try:
                    self.patterns.append((p, p.compile()))
                except re.error as e:
                    if self.verbose:
                        console.print(f"[dim][!] Skipping invalid pattern '{p.name}': {e}[/dim]")
        
        # External tools - configured with scope and rate limit controls
        self.subfinder = SubfinderIntegration(scope_manager=self.scope_manager)
        self.katana = KatanaIntegration(
            scope_manager=self.scope_manager,
            header_manager=self.header_manager,
            max_rps=self.max_requests_per_second
        )
        self.gau = GauIntegration(scope_manager=self.scope_manager)
        self.waybackurls = WaybackurlsIntegration(scope_manager=self.scope_manager)
        self.subjs = SubJSIntegration(scope_manager=self.scope_manager, strict_mode=self.strict_scope)
        self.hakrawler = HakrawlerIntegration(scope_manager=self.scope_manager, strict_mode=self.strict_scope)
        self.getjs = GetJSIntegration(scope_manager=self.scope_manager, strict_mode=self.strict_scope)
        self.jsluice = JSLuiceIntegration(scope_manager=self.scope_manager)
        
        # Results
        self.results = ScanResult(target="")
        self.scanned_urls: Set[str] = set()
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]
        self._ua_index = 0
    
    def _get_user_agent(self) -> str:
        """Rotate through user agents"""
        ua = self.user_agents[self._ua_index % len(self.user_agents)]
        self._ua_index += 1
        return ua
    
    def _create_ssl_context(self):
        """Create verified SSL context with no insecure fallback"""
        if self.verify_tls:
            return ssl.create_default_context()
        return False

    async def _fetch_url(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch a URL using centralized rate limiter, scope validator, and TLS verification."""
        clean_url = url.strip()
        if clean_url in self.scanned_urls:
            return None
        
        # Scope validation: Never fetch out-of-scope URLs
        if self.scope_manager and not self.scope_manager.is_url_in_scope(clean_url):
            if self.verbose:
                console.print(f"[dim][Scope] Skipping out-of-scope URL: {clean_url}[/dim]")
            return None
        
        self.scanned_urls.add(clean_url)
        
        try:
            extra_headers = {"User-Agent": self._get_user_agent()}
            status, content, final_url = await self.http_client.get(session, clean_url, extra_headers=extra_headers)
            return content
        except Exception as e:
            if self.verbose:
                console.print(f"[dim][!] Error: {clean_url}: {str(e)[:60]}[/dim]")
            return None
    
    def _extract_js_urls(self, base_url: str, html_content: str) -> List[str]:
        """Extract JavaScript URLs from HTML content with strict scope enforcement"""
        js_urls = []
        
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if '.js' not in match.lower():
                    continue
                    
                skip_libs = ['jquery', 'react', 'angular', 'vue', 'bootstrap', 'lodash']
                if any(lib in match.lower() for lib in skip_libs):
                    continue
                
                # Resolve URL
                resolved = None
                if match.startswith('http'):
                    resolved = match
                elif match.startswith('//'):
                    resolved = 'https:' + match
                elif match.startswith('/'):
                    parsed = urlparse(base_url)
                    resolved = f"{parsed.scheme}://{parsed.netloc}{match}"
                else:
                    resolved = urljoin(base_url, match)

                # Scope enforcement: ONLY keep in-scope JS URLs
                if resolved and self.scope_manager.is_url_in_scope(resolved):
                    js_urls.append(resolved)
        
        # Deduplicate
        seen = set()
        unique = []
        for url in js_urls:
            base = url.split('?')[0]
            if base not in seen:
                seen.add(base)
                unique.append(url)
        
        return unique
    
    def _scan_content(self, url: str, content: str) -> List[Finding]:
        """Scan content for secrets with validation and extract endpoints"""
        findings = []
        if not content:
            return findings

        # Run endpoint discovery and JS metadata extraction if enabled
        if self.endpoint_discovery or self.javascript_extraction:
            meta = self.endpoint_extractor.extract_from_js(content, url)
            if meta.endpoints:
                self.results.discovered_endpoints.extend(meta.endpoints)
            if meta.source_maps:
                self.results.source_maps.extend(meta.source_maps)
            if meta.feature_flags:
                self.results.feature_flags.extend(meta.feature_flags)
            if meta.sensitive_config_keys:
                self.results.sensitive_config_keys.extend(meta.sensitive_config_keys)

        # Skip secret scanning if secret_detection is disabled
        if not self.secret_detection:
            return findings

        # Beautify JS for better matching
        try:
            content = beautify(content)
        except Exception:
            pass
        
        # Split into lines for context
        lines = content.split('\n')
        
        for pattern, compiled in self.patterns:
            try:
                matches = compiled.findall(content)
            except Exception:
                continue
            
            for match in matches:
                if isinstance(match, tuple):
                    match = next((m for m in match if m), '')
                
                if not match or len(match) < 8:
                    continue
                
                is_valid = True
                if self.validate:
                    is_valid = self.validator.validate(pattern, str(match))
                
                if not is_valid:
                    continue
                
                line_num = None
                context = None
                for i, line in enumerate(lines):
                    if str(match) in line:
                        line_num = i + 1
                        context = line.strip()[:150]
                        break
                
                finding = Finding(
                    url=url,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    matched_value=str(match)[:100],
                    confidence=pattern.confidence,
                    validated=is_valid,
                    line_number=line_num,
                    context=context
                )
                findings.append(finding)
        
        return findings
    
    async def _scan_js_url(self, session: aiohttp.ClientSession, url: str) -> List[Finding]:
        """Scan a single JS URL with scope check"""
        if not self.scope_manager.is_url_in_scope(url):
            return []

        content = await self._fetch_url(session, url)
        if content:
            self.results.total_js_files += 1
            return self._scan_content(url, content)
        return []
    
    async def scan_target(self, target: str):
        """Scan a single target domain with strict scope, rate limiting, and TLS verification."""
        start_time = time.time()
        self.results.target = target
        
        # Extract host and check scope
        target_host = self.scope_manager.extract_hostname(target)
        if target_host and not self.scope_manager.is_host_allowed(target_host):
            console.print(f"[bold red][!] TARGET OUT OF SCOPE:[/] {target} is not in authorized domains or is explicitly excluded!")
            console.print("[yellow][!] Aborting scan to respect program boundaries.[/]\n")
            return
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v5.0 - Bug Bounty Reconnaissance[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Target:[/] [yellow]{target}[/]")
        console.print(f"[bold]Scope Enforced:[/] [{'green' if self.scope_manager.enabled else 'yellow'}]{'Yes (Strict)' if self.scope_manager.enabled else 'No'}[/]")
        console.print(f"[bold]Allowed Scope:[/] [cyan]{', '.join(self.scope_manager.allowed_domains) or 'None'}[/]")
        console.print(f"[bold]Excluded Scope:[/] [red]{', '.join(self.scope_manager.excluded_domains) or 'None'}[/]")
        console.print(f"[bold]Rate Limiter:[/] [green]Max {self.max_requests_per_second} requests/second[/]")
        console.print(f"[bold]Concurrency:[/] [cyan]{self.concurrency}[/]")
        console.print(f"[bold]TLS Verification:[/] [{'green' if self.verify_tls else 'red'}]{'Strict (Enabled)' if self.verify_tls else 'Disabled'}[/]")
        console.print(f"[bold]Researcher Header:[/] [{'green' if self.header_manager.is_active() else 'dim'}]{self.header_manager.header_name + ': ' + self.header_manager.get_masked_value() if self.header_manager.is_active() else 'Disabled'}[/]")
        console.print(f"[bold]KeyHacks Auto-Validation:[/] [{'red' if self.validate_keys else 'green'}]{'Enabled (Ethical Auth Only)' if self.validate_keys else 'Disabled (Safe by default)'}[/]")
        console.print()
        
        all_js_urls = set()
        
        # Phase 1: Subdomain Enumeration
        if self.use_external_tools and self.subfinder.is_available():
            subdomains = self.subfinder.enumerate(target_host or target)
            subdomains = self.scope_manager.filter_subdomains(subdomains)
            self.results.subdomains_found = len(subdomains)
        else:
            subdomains = [target_host or target]
            subdomains = self.scope_manager.filter_subdomains(subdomains)
            self.results.subdomains_found = len(subdomains)
        
        # Phase 2: URL Gathering with scope-aware external tools
        if self.use_external_tools and subdomains:
            live_urls = [f"https://{s}" for s in subdomains]
            
            # GAU (archived URLs) - filtered against scope
            if self.gau.is_available():
                archived_js = self.gau.fetch(subdomains)
                all_js_urls.update(self.scope_manager.filter_urls(archived_js))
            
            # Waybackurls (Wayback Machine) - filtered against scope
            if self.waybackurls.is_available():
                wayback_js = self.waybackurls.fetch(subdomains)
                all_js_urls.update(self.scope_manager.filter_urls(wayback_js))
            
            # Katana (live crawling with rate limiting) - filtered against scope
            if self.katana.is_available():
                crawled = self.katana.crawl(live_urls, depth=self.depth)
                js_from_crawl = [u for u in crawled if '.js' in u.lower()]
                all_js_urls.update(self.scope_manager.filter_urls(js_from_crawl))
            
            # Hakrawler
            if self.hakrawler.is_available():
                hakrawler_js = self.hakrawler.crawl(live_urls, depth=self.depth)
                all_js_urls.update(self.scope_manager.filter_urls(hakrawler_js))
            
            # SubJS
            if self.subjs.is_available():
                subjs_urls = self.subjs.fetch(live_urls)
                all_js_urls.update(self.scope_manager.filter_urls(subjs_urls))
            
            # GetJS
            if self.getjs.is_available():
                getjs_urls = self.getjs.extract(live_urls[:20])
                all_js_urls.update(self.scope_manager.filter_urls(getjs_urls))
        
        # Phase 3: Direct page scanning for JS with verified TLS and rate limiter
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=self._create_ssl_context()
        )
        async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
            console.print(f"\n[cyan][*] Fetching pages from {len(subdomains)} in-scope hosts (rate limit: {self.max_requests_per_second} RPS)...[/]")
            
            semaphore = asyncio.Semaphore(self.concurrency)

            async def fetch_page_js(subdomain):
                async with semaphore:
                    url = f"https://{subdomain}"
                    content = await self._fetch_url(session, url)
                    if content:
                        return self._extract_js_urls(url, content)
                    return []
            
            tasks = [fetch_page_js(s) for s in subdomains[:100]]
            results = await asyncio.gather(*tasks)
            
            for js_list in results:
                all_js_urls.update(js_list)
            
            # Deduplicate and scope check
            all_js_urls = self.scope_manager.filter_urls(list(all_js_urls))
            console.print(f"[green][+] Total in-scope JS files to scan: {len(all_js_urls)}[/]\n")
            
            # Phase 4: Scan all JS files with progress
            if all_js_urls:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]🔍 Scanning JS files (rate-limited)...", total=len(all_js_urls))
                    
                    async def scan_with_progress(url):
                        async with semaphore:
                            findings = await self._scan_js_url(session, url)
                            self.results.findings.extend(findings)
                            self.results.total_findings = len(self.results.findings)
                            self.results.total_validated = len([f for f in self.results.findings if f.validated])
                            progress.advance(task)
                            return findings
                    
                    await asyncio.gather(*[scan_with_progress(url) for url in all_js_urls])
            
            self.results.total_urls_scanned = len(self.scanned_urls)
        
        self.results.scan_time = time.time() - start_time
    
    async def scan_urls_from_file(self, file_path: Path):
        """Scan JS URLs from a file with scope enforcement and rate limiting"""
        start_time = time.time()
        
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and '.js' in line.lower()]
        
        urls = self.scope_manager.filter_urls(raw_urls)
        self.results.target = str(file_path)
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v5.0 - URL List Mode[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Source:[/] [yellow]{file_path}[/]")
        console.print(f"[bold]Total URLs in file:[/] [cyan]{len(raw_urls)}[/]")
        console.print(f"[bold]In-Scope URLs:[/] [green]{len(urls)}[/]")
        console.print(f"[bold]Rate Limit:[/] [cyan]{self.max_requests_per_second} RPS[/]")
        console.print()
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=self._create_ssl_context())
        async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]🔍 Scanning (rate-limited)...", total=len(urls))
                semaphore = asyncio.Semaphore(self.concurrency)
                
                async def scan_with_progress(url):
                    async with semaphore:
                        findings = await self._scan_js_url(session, url)
                        self.results.findings.extend(findings)
                        progress.advance(task)
                        return findings
                
                await asyncio.gather(*[scan_with_progress(url) for url in urls])
            
            self.results.total_urls_scanned = len(self.scanned_urls)
            self.results.total_findings = len(self.results.findings)
            self.results.total_validated = len([f for f in self.results.findings if f.validated])
        
        self.results.scan_time = time.time() - start_time
    
    async def scan_targets_from_file(self, file_path: Path):
        """Scan multiple targets from a file, filtering each against scope"""
        with open(file_path, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        valid_targets = [t for t in targets if self.scope_manager.is_host_allowed(self.scope_manager.extract_hostname(t))]
        console.print(f"[bold green][+] Loaded {len(targets)} targets ({len(valid_targets)} in-scope)[/]")
        
        for target in valid_targets:
            await self.scan_target(target)
    
    async def scan_directory(self, directory: Path):
        """Scan local JS files in a directory (offline mode)"""
        start_time = time.time()
        self.results.target = str(directory)
        
        js_files = list(directory.glob('**/*.js'))
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v5.0 - Offline Mode[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Directory:[/] [yellow]{directory}[/]")
        console.print(f"[bold]Files:[/] [cyan]{len(js_files)}[/]")
        console.print()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]📁 Scanning local files...", total=len(js_files))
            
            for js_file in js_files:
                try:
                    content = js_file.read_text(errors='ignore')
                    findings = self._scan_content(str(js_file), content)
                    self.results.findings.extend(findings)
                    self.results.total_js_files += 1
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim][!] Error: {js_file}: {e}[/dim]")
                progress.advance(task)
        
        self.results.total_findings = len(self.results.findings)
        self.results.total_validated = len([f for f in self.results.findings if f.validated])
        self.results.scan_time = time.time() - start_time
    
    def print_summary(self):
        """Print scan summary with masked values"""
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]📊 RECONNAISSANCE SUMMARY[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        
        table = Table(title="[bold cyan]Scan Performance & Scope[/]", border_style="cyan", show_header=True)
        table.add_column("Metric", style="dim", width=28)
        table.add_column("Value", style="green", width=30)
        
        table.add_row("Target", self.results.target[:38])
        table.add_row("Scope Enforced", "Yes" if self.scope_manager.enabled else "No")
        table.add_row("Subdomains Found", str(self.results.subdomains_found))
        table.add_row("HTTP Requests Made", str(self.rate_limiter.total_requests))
        table.add_row("URLs Scanned", str(self.results.total_urls_scanned))
        table.add_row("JS Files Analyzed", str(self.results.total_js_files))
        table.add_row("Endpoints Discovered", str(len(self.results.discovered_endpoints)))
        table.add_row("Total Potential Secrets", str(self.results.total_findings))
        table.add_row("Validated Patterns", f"[bold green]{self.results.total_validated}[/]")
        table.add_row("Scan Duration", f"{self.results.scan_time:.2f}s")
        
        console.print(table)
        
        # Endpoints breakdown
        if self.results.discovered_endpoints:
            console.print(f"\n[bold cyan]🌐 DISCOVERED ENDPOINTS ({len(self.results.discovered_endpoints)} in scope):[/]\n")
            interesting_eps = [e for e in self.results.discovered_endpoints if e.is_interesting]
            sample_eps = interesting_eps[:8] if interesting_eps else self.results.discovered_endpoints[:8]
            for ep in sample_eps:
                tag = f"[{ep.endpoint_type.upper()}]" if ep.endpoint_type != "general" else ""
                console.print(f"  [cyan]{ep.method:<5}[/] [yellow]{tag:<10}[/] {ep.url_or_path}")
            if len(self.results.discovered_endpoints) > 8:
                console.print(f"  [dim]... and {len(self.results.discovered_endpoints) - 8} more endpoints in output report[/]\n")

        # Findings breakdown (Masked!)
        if self.results.findings:
            console.print(f"\n[bold red]🔥 POTENTIAL SECRETS DETECTED ({self.results.total_validated} validated patterns, values masked):[/]\n")
            
            by_severity: Dict[str, List[Finding]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for f in self.results.findings:
                if f.validated:
                    by_severity[f.severity()].append(f)
            
            severity_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                findings = by_severity[severity]
                if findings:
                    console.print(f"[bold {severity_colors[severity]}]━━━ {severity} ({len(findings)}) ━━━[/]")
                    
                    for f in findings[:5]:
                        masked_val = mask_secret(f.matched_value)
                        console.print(f"  [bold cyan]{f.pattern_name}[/] [{severity_colors[severity]}][{f.confidence}%][/]")
                        console.print(f"    [dim]URL:[/] {f.url[:80]}...")
                        console.print(f"    [dim]Masked Value:[/] [yellow]{masked_val}[/]")
                        console.print()
                    
                    if len(findings) > 5:
                        console.print(f"  [dim]... and {len(findings) - 5} more[/]\n")
        else:
            console.print("[dim]No potential secrets detected.[/dim]")
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print("[dim]NightCrawler v5.0 | Scope-Aware Bug Bounty Reconnaissance[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
    
    def export_results(self, output_path: str):
        """Export results to file with masked values and endpoints"""
        import json
        from datetime import datetime
        
        output_path = Path(output_path)
        
        data = {
            "tool": "NightCrawler",
            "version": "5.0",
            "scan_date": datetime.now().isoformat(),
            "target": self.results.target,
            "scan_time": self.results.scan_time,
            "scope": {
                "enforced": self.scope_manager.enabled,
                "allowed": list(self.scope_manager.allowed_domains),
                "excluded": list(self.scope_manager.excluded_domains)
            },
            "stats": {
                "subdomains": self.results.subdomains_found,
                "requests_made": self.rate_limiter.total_requests,
                "urls_scanned": self.results.total_urls_scanned,
                "js_files": self.results.total_js_files,
                "total_findings": self.results.total_findings,
                "validated_findings": self.results.total_validated,
                "total_endpoints": len(self.results.discovered_endpoints)
            },
            "discovered_endpoints": [
                {
                    "url_or_path": e.url_or_path,
                    "method": e.method,
                    "parameters": e.parameters,
                    "endpoint_type": e.endpoint_type,
                    "is_interesting": e.is_interesting,
                    "source": e.source_url
                }
                for e in self.results.discovered_endpoints
            ],
            "findings": [
                {
                    "url": f.url,
                    "pattern": f.pattern_name,
                    "category": f.category,
                    "masked_value": mask_secret(f.matched_value),
                    "confidence": f.confidence,
                    "severity": f.severity(),
                    "validated": f.validated,
                    "line": f.line_number,
                    "context": f.context.replace(f.matched_value, mask_secret(f.matched_value)) if (f.context and f.matched_value in f.context) else f.context
                }
                for f in self.results.findings if f.validated
            ]
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        console.print(f"[green][+] Results exported safely to {output_path}[/]")
