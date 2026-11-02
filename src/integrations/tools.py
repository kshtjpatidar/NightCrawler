"""
NightCrawler v5.0 - External Tool Integrations
Scope-aware, rate-limited recon tools with custom headers and compliance controls.
"""

import subprocess
import shutil
import os
from pathlib import Path
from typing import List, Optional, Dict
from rich.console import Console

from src.core.scope import ScopeManager
from src.core.header_manager import HeaderManager

console = Console()

# Tool configuration
TOOL_CONFIG = {
    "subfinder": {
        "name": "Subfinder",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    },
    "httpx": {
        "name": "Httpx", 
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    },
    "katana": {
        "name": "Katana",
        "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    },
    "gau": {
        "name": "GAU",
        "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest"
    },
    "waybackurls": {
        "name": "Waybackurls",
        "install": "go install -v github.com/tomnomnom/waybackurls@latest"
    },
    "subjs": {
        "name": "SubJS",
        "install": "go install -v github.com/lc/subjs@latest"
    },
    "jsluice": {
        "name": "JSLuice",
        "install": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"
    },
    "hakrawler": {
        "name": "Hakrawler",
        "install": "go install -v github.com/hakluke/hakrawler@latest"
    },
    "getjs": {
        "name": "GetJS",
        "install": "go install -v github.com/003random/getJS@latest"
    }
}


def find_tool(tool_name: str) -> Optional[str]:
    """Find tool in PATH or common locations"""
    path = shutil.which(tool_name)
    if path:
        return path
    
    go_bin = os.path.expanduser(f"~/go/bin/{tool_name}")
    if os.path.exists(go_bin):
        return go_bin
    
    local_bin = f"/usr/local/bin/{tool_name}"
    if os.path.exists(local_bin):
        return local_bin
    
    usr_bin = f"/usr/bin/{tool_name}"
    if os.path.exists(usr_bin):
        return usr_bin
    
    return None


def install_tool(tool_name: str) -> bool:
    """Install a tool using go install"""
    config = TOOL_CONFIG.get(tool_name)
    if not config:
        return False
    
    console.print(f"[cyan][*] Installing {config['name']}...[/]")
    try:
        result = subprocess.run(config["install"], shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green][+] {config['name']} installed![/]")
            return True
        else:
            console.print(f"[red][!] Failed to install {config['name']}: {result.stderr}[/]")
            return False
    except Exception as e:
        console.print(f"[red][!] Error installing {config['name']}: {e}[/]")
        return False


def get_all_tool_paths() -> Dict[str, Optional[str]]:
    """Get paths for all configured tools"""
    paths = {}
    for tool_name in TOOL_CONFIG:
        paths[tool_name] = find_tool(tool_name)
    return paths


class SubfinderIntegration:
    """Wrapper for Subfinder subdomain enumeration with scope enforcement"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None):
        self.tool_path = tool_path or find_tool('subfinder')
        self.scope_manager = scope_manager
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def enumerate(self, domain: str, recursive: bool = True, silent: bool = True) -> List[str]:
        """Run Subfinder with scope validation of results"""
        if not self.is_available():
            console.print("[yellow][!] Subfinder not found. Skipping subdomain enumeration.[/]")
            return [domain] if (not self.scope_manager or self.scope_manager.is_host_allowed(domain)) else []
        
        # Verify target domain itself is in scope
        if self.scope_manager and not self.scope_manager.is_host_allowed(domain):
            console.print(f"[red][!] Target domain '{domain}' is out-of-scope. Aborting subdomain scan.[/]")
            return []

        cmd = [self.tool_path, '-d', domain]
        if recursive:
            cmd.extend(['-all', '-recursive'])
        if silent:
            cmd.append('-silent')
        
        try:
            console.print(f"[cyan][*] Running Subfinder on {domain}...[/]")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            raw_subdomains = []
            if result.returncode == 0:
                raw_subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            
            if not raw_subdomains:
                raw_subdomains = [domain]

            # Strictly filter results against authorized scope
            if self.scope_manager:
                valid_subdomains = self.scope_manager.filter_subdomains(raw_subdomains)
                filtered_out = len(raw_subdomains) - len(valid_subdomains)
                if filtered_out > 0:
                    console.print(f"[yellow][!] Filtered out {filtered_out} out-of-scope subdomains[/]")
                console.print(f"[green][+] Found {len(valid_subdomains)} in-scope subdomains[/]")
                return valid_subdomains
            
            return raw_subdomains
                
        except Exception as e:
            console.print(f"[red][!] Error running Subfinder: {e}[/]")
            return [domain] if (not self.scope_manager or self.scope_manager.is_host_allowed(domain)) else []


class KatanaIntegration:
    """Wrapper for Katana web crawler with strict scope, rate limiting, and custom headers"""
    
    def __init__(
        self,
        tool_path: Optional[str] = None,
        scope_manager: Optional[ScopeManager] = None,
        header_manager: Optional[HeaderManager] = None,
        max_rps: float = 5.0
    ):
        self.tool_path = tool_path or find_tool('katana')
        self.scope_manager = scope_manager
        self.header_manager = header_manager
        self.max_rps = max_rps
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def crawl(self, targets: List[str], depth: int = 2, js_only: bool = True) -> List[str]:
        """Crawl targets with rate limiting, scope filtering, and researcher headers"""
        if not self.is_available():
            console.print("[yellow][!] Katana not found. Skipping deep crawl.[/]")
            return []

        # Filter input targets to in-scope only
        in_scope_targets = self.scope_manager.filter_urls(targets) if self.scope_manager else targets
        if not in_scope_targets:
            console.print("[yellow][!] No in-scope targets for Katana crawl.[/]")
            return []

        # Concurrency 1 and rate limit max 5 req/s (or configured max_rps)
        rate_limit_val = max(1, int(self.max_rps))
        cmd = [self.tool_path, '-d', str(depth), '-c', '1', '-rl', str(rate_limit_val), '-silent']
        
        if js_only:
            cmd.append('-jc')

        # Add researcher header if active
        if self.header_manager and self.header_manager.is_active():
            header_flag = self.header_manager.format_cli_header_flag()
            if header_flag:
                cmd.extend(['-H', header_flag])
        
        try:
            console.print(f"[cyan][*] Running Katana crawler (depth={depth}, rate-limit={rate_limit_val} rps)...[/]")
            result = subprocess.run(cmd, input='\n'.join(in_scope_targets), capture_output=True, text=True)
            
            if result.returncode == 0:
                raw_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                # Strictly filter crawled URLs against scope
                in_scope_urls = self.scope_manager.filter_urls(raw_urls) if self.scope_manager else raw_urls
                console.print(f"[green][+] Katana found {len(in_scope_urls)} in-scope URLs[/]")
                return in_scope_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running Katana: {e}[/]")
            return []


class GauIntegration:
    """Wrapper for GAU (GetAllURLs) with scope filtering"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None):
        self.tool_path = tool_path or find_tool('gau')
        self.scope_manager = scope_manager
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, domains: List[str], threads: int = 2) -> List[str]:
        """Fetch archived URLs from public archives with strict output scope filtering"""
        if not self.is_available():
            console.print("[yellow][!] GAU not found. Skipping archive search.[/]")
            return []

        # Filter target domains
        in_scope_domains = self.scope_manager.filter_subdomains(domains) if self.scope_manager else domains
        if not in_scope_domains:
            return []

        cmd = [self.tool_path, '--threads', str(threads)]
        
        try:
            console.print(f"[cyan][*] Fetching archived URLs with GAU...[/]")
            result = subprocess.run(cmd, input='\n'.join(in_scope_domains), capture_output=True, text=True)
            
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in urls if '.js' in u.lower()]
                # Strictly filter against scope so out-of-scope archive links are rejected
                if self.scope_manager:
                    js_urls = self.scope_manager.filter_urls(js_urls)
                console.print(f"[green][+] GAU found {len(js_urls)} in-scope JS URLs from archives[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running GAU: {e}[/]")
            return []


class WaybackurlsIntegration:
    """Wrapper for Waybackurls with scope filtering"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None):
        self.tool_path = tool_path or find_tool('waybackurls')
        self.scope_manager = scope_manager
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, domains: List[str]) -> List[str]:
        """Fetch Wayback Machine URLs with strict scope filtering"""
        if not self.is_available():
            console.print("[yellow][!] Waybackurls not found. Skipping.[/]")
            return []

        in_scope_domains = self.scope_manager.filter_subdomains(domains) if self.scope_manager else domains
        if not in_scope_domains:
            return []
        
        try:
            console.print(f"[cyan][*] Fetching Wayback URLs...[/]")
            result = subprocess.run([self.tool_path], input='\n'.join(in_scope_domains), capture_output=True, text=True)
            
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in urls if '.js' in u.lower()]
                if self.scope_manager:
                    js_urls = self.scope_manager.filter_urls(js_urls)
                console.print(f"[green][+] Waybackurls found {len(js_urls)} in-scope JS URLs[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running Waybackurls: {e}[/]")
            return []


class SubJSIntegration:
    """Wrapper for SubJS with compliance mode awareness"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None, strict_mode: bool = True):
        self.tool_path = tool_path or find_tool('subjs')
        self.scope_manager = scope_manager
        self.strict_mode = strict_mode
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, urls: List[str]) -> List[str]:
        """Fetch JS files from URLs"""
        if self.strict_mode:
            console.print("[yellow][i] SubJS disabled in strict compliance mode (cannot enforce 5 RPS or custom headers). Using internal HTTP client instead.[/]")
            return []

        if not self.is_available():
            return []
        
        in_scope = self.scope_manager.filter_urls(urls) if self.scope_manager else urls
        if not in_scope:
            return []

        try:
            console.print(f"[cyan][*] Fetching JS with SubJS...[/]")
            result = subprocess.run([self.tool_path], input='\n'.join(in_scope), capture_output=True, text=True)
            
            if result.returncode == 0:
                js_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                if self.scope_manager:
                    js_urls = self.scope_manager.filter_urls(js_urls)
                return js_urls
            return []
        except Exception as e:
            console.print(f"[red][!] Error running SubJS: {e}[/]")
            return []


class HakrawlerIntegration:
    """Wrapper for Hakrawler with compliance mode awareness"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None, strict_mode: bool = True):
        self.tool_path = tool_path or find_tool('hakrawler')
        self.scope_manager = scope_manager
        self.strict_mode = strict_mode
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def crawl(self, urls: List[str], depth: int = 1) -> List[str]:
        """Crawl URLs with compliance checking"""
        if self.strict_mode:
            console.print("[yellow][i] Hakrawler disabled in strict compliance mode (cannot guarantee 5 RPS limit). Using rate-limited Katana / internal crawler instead.[/]")
            return []

        if not self.is_available():
            return []
        
        in_scope = self.scope_manager.filter_urls(urls) if self.scope_manager else urls
        if not in_scope:
            return []

        cmd = [self.tool_path, '-d', str(depth), '-t', '1']
        
        try:
            console.print(f"[cyan][*] Running Hakrawler...[/]")
            result = subprocess.run(cmd, input='\n'.join(in_scope), capture_output=True, text=True)
            
            if result.returncode == 0:
                all_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in all_urls if '.js' in u.lower()]
                if self.scope_manager:
                    js_urls = self.scope_manager.filter_urls(js_urls)
                return js_urls
            return []
        except Exception as e:
            console.print(f"[red][!] Error running Hakrawler: {e}[/]")
            return []


class GetJSIntegration:
    """Wrapper for GetJS with compliance mode awareness"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None, strict_mode: bool = True):
        self.tool_path = tool_path or find_tool('getJS') or find_tool('getjs')
        self.scope_manager = scope_manager
        self.strict_mode = strict_mode
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def extract(self, urls: List[str]) -> List[str]:
        """Extract JS from URLs with compliance checking"""
        if self.strict_mode:
            console.print("[yellow][i] GetJS disabled in strict compliance mode (cannot enforce 5 RPS limit or headers). Using internal HTTP client instead.[/]")
            return []

        if not self.is_available():
            return []
        
        in_scope = self.scope_manager.filter_urls(urls) if self.scope_manager else urls
        if not in_scope:
            return []

        cmd = [self.tool_path, '--complete']
        
        try:
            console.print(f"[cyan][*] Extracting JS with GetJS...[/]")
            result = subprocess.run(cmd, input='\n'.join(in_scope), capture_output=True, text=True)
            
            if result.returncode == 0:
                js_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                if self.scope_manager:
                    js_urls = self.scope_manager.filter_urls(js_urls)
                return js_urls
            return []
        except Exception as e:
            console.print(f"[red][!] Error running GetJS: {e}[/]")
            return []


class JSLuiceIntegration:
    """Wrapper for JSLuice - extracts endpoints and secrets from JS content (offline parser)"""
    
    def __init__(self, tool_path: Optional[str] = None, scope_manager: Optional[ScopeManager] = None):
        self.tool_path = tool_path or find_tool('jsluice')
        self.scope_manager = scope_manager
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def extract_urls(self, js_content: str) -> List[str]:
        """Extract URLs from JS content offline and filter by scope"""
        if not self.is_available() or not js_content:
            return []
        
        cmd = [self.tool_path, 'urls']
        
        try:
            result = subprocess.run(cmd, input=js_content, capture_output=True, text=True)
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                if self.scope_manager:
                    urls = self.scope_manager.filter_urls(urls)
                return urls
            return []
        except:
            return []
    
    def extract_secrets(self, js_content: str) -> List[dict]:
        """Extract secrets from JS content offline"""
        if not self.is_available() or not js_content:
            return []
        
        cmd = [self.tool_path, 'secrets']
        
        try:
            result = subprocess.run(cmd, input=js_content, capture_output=True, text=True)
            if result.returncode == 0:
                import json
                secrets = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            secrets.append(json.loads(line))
                        except:
                            pass
                return secrets
            return []
        except:
            return []
