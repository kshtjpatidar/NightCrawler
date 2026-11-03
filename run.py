#!/usr/bin/env python3
"""
NightCrawler v5.0 - Multi-Program, Policy-Aware Bug Bounty Reconnaissance Interface
Interactive terminal control center for managing programs, policies, scope, authentication,
reconnaissance modules, audit logs, and compliance reporting.
by kshtjpatidar | Keep Learning // Keep Hacking
"""

import os
import sys
import shutil
import subprocess
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "aiohttp", "jsbeautifier", "click", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt

from src.core.program_manager import ProgramManager
from src.core.program_profile import ProgramProfile, PolicyValidator, PolicyParser
from src.core.scope import ScopeManager
from src.core.auth_manager import AuthenticationManager
from src.core.permissions import TestingPermissionManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.audit_logger import AuditLogger

console = Console()

BANNER = """[bold green]
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
[/bold green]"""


def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')


def print_banner(active_prog_name: str = "UXCam", active_rps: float = 5.0):
    clear_screen()
    console.print(BANNER)
    
    info = Text()
    info.append("v5.0 Multi-Program Framework", style="bold green")
    info.append(" │ ", style="dim")
    info.append(f"Program: {active_prog_name}", style="bold magenta")
    info.append(" │ ", style="dim")
    info.append(f"Max {active_rps} RPS", style="bold cyan")
    info.append(" │ ", style="dim")
    info.append("Policy-Aware Scope", style="bold yellow")
    info.append(" │ ", style="dim")
    info.append("Audit Logging Active", style="bold green")
    console.print(Panel(info, border_style="green"))
    console.print("[dim]⚠️  Ethical Bug Bounty Reconnaissance Only • Keep Learning // Keep Hacking[/dim]\n")


def display_main_menu(active_profile: Optional[ProgramProfile]):
    """Display the 14-item interactive control menu"""
    active_title = f"{active_profile.name} ({active_profile.id})" if active_profile else "None (Select/Create a profile)"
    table = Table(
        title=f"[bold cyan]🎯 NightCrawler Control Center — Active Program: [magenta]{active_title}[/][/]",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan"
    )
    table.add_column("Option", style="bold green", width=8, justify="center")
    table.add_column("Management & Recon Operation", style="white", width=42)
    table.add_column("Status / Setting", style="yellow", width=28)

    table.add_row("[1]", "Select program", active_title)
    table.add_row("[2]", "List programs", "View all program profiles")
    table.add_row("[3]", "Create program profile", "Add new program profile")
    table.add_row("[4]", "Import policy", "YAML / JSON / Text import")
    table.add_row("[5]", "Validate program policy", "Run compliance & safety checks")
    scope_status = f"{len(active_profile.scope.allowed_domains)} allowed, {len(active_profile.scope.excluded_domains)} excluded" if active_profile else "No profile active"
    table.add_row("[6]", "View program scope", scope_status)
    auth_status = f"Auth type: {active_profile.authentication.type.upper()}" if active_profile else "No profile active"
    table.add_row("[7]", "Configure authentication", auth_status)
    req_status = f"{active_profile.request_policy.max_rps} RPS (Concurrency: {active_profile.request_policy.concurrency})" if active_profile else "No profile active"
    table.add_row("[8]", "Configure request limits", req_status)
    table.add_row("[9]", "Select reconnaissance modules", "Configure active / passive tools")
    table.add_row("[10]", "Start reconnaissance", "[bold green]🚀 Run Recon Scan[/]")
    table.add_row("[11]", "View reports", "Open generated reports")
    table.add_row("[12]", "View audit logs", "Inspect security audit trail")
    table.add_row("[13]", "Run tests", "Execute automated test suite")
    table.add_row("[14]", "Exit", "[dim]Quit NightCrawler[/]")

    return table


def run_scan_subprocess(target: str, profile_or_cfg):
    """Execute main.py with the active program profile or config"""
    if hasattr(profile_or_cfg, "name") and hasattr(profile_or_cfg, "id"):
        # ProgramProfile
        prog_name = profile_or_cfg.name
        prog_id = profile_or_cfg.id
        fmt = profile_or_cfg.reporting.default_format
        cmd = [
            sys.executable, "main.py",
            "--program", prog_id,
            "-t", target,
            "--mode", "deep",
            "--no-prompt",
            "-o", f"report_{target.replace('.', '_')}.{fmt}"
        ]
        env = dict(os.environ)
        # Populate env with researcher header if set
        hdrs = profile_or_cfg.headers.get("required", {})
        if "X-User-Id" in hdrs:
            val = profile_or_cfg.resolve_headers().get("X-User-Id", "")
            if val:
                env["NIGHTCRAWLER_RESEARCHER_ID"] = val
                env["NIGHTCRAWLER_HEADER_VALUE"] = val
    else:
        # NightCrawlerConfig
        prog_name = getattr(profile_or_cfg, "program_name", "Bug Bounty Recon")
        fmt = getattr(profile_or_cfg, "default_format", "html")
        cmd = [
            sys.executable, "main.py",
            "-t", target,
            "--mode", "deep",
            "--no-prompt",
            "--concurrency", str(profile_or_cfg.concurrency),
            "--max-rps", str(profile_or_cfg.max_requests_per_second),
            "--timeout", str(profile_or_cfg.timeout),
            "--depth", str(profile_or_cfg.depth),
            "--template", profile_or_cfg.default_template,
            "-o", f"report_{target.replace('.', '_')}.{fmt}"
        ]
        for d in profile_or_cfg.allowed_domains:
            cmd.extend(["--allowed-domain", d])
        for ed in profile_or_cfg.excluded_domains:
            cmd.extend(["--excluded-domain", ed])

        env = dict(os.environ)
        if profile_or_cfg.custom_header_enabled and profile_or_cfg.header_value:
            cmd.extend(["--header-name", profile_or_cfg.header_name])
            header_env_key = profile_or_cfg.header_value_env or "NIGHTCRAWLER_RESEARCHER_ID"
            env[header_env_key] = profile_or_cfg.header_value
            env["NIGHTCRAWLER_HEADER_VALUE"] = profile_or_cfg.header_value
        else:
            cmd.append("--disable-header")

        if profile_or_cfg.verify_tls:
            cmd.append("--verify-tls")
        else:
            cmd.append("--no-verify-tls")

        if profile_or_cfg.strict_scope:
            cmd.append("--strict-scope")

        if profile_or_cfg.validate_keys:
            cmd.append("--validate-keys")

    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print(f"[bold cyan]│   🚀  STARTING BUG BOUNTY SCAN: {prog_name[:25]:<26}│[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent, env=env)
        if result.returncode == 0:
            console.print("\n[bold green]✓ Reconnaissance completed successfully![/bold green]")
        else:
            console.print(f"\n[yellow]⚠️  Scan finished with exit code: {result.returncode}[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]✗ Error during execution: {e}[/red]")


def main():
    try:
        pm = ProgramManager()
        # Default profile: UXCam if present, else first available
        active_profile = pm.get_profile("uxcam")
        if not active_profile:
            all_profs = pm.list_profiles()
            if all_profs:
                active_profile = pm.get_profile(all_profs[0]["id"])
            else:
                active_profile = None

        target = active_profile.scope.allowed_domains[0].lstrip("*.") if (active_profile and active_profile.scope.allowed_domains) else ""

        while True:
            banner_name = active_profile.name if active_profile else "No Active Program"
            banner_rps = active_profile.request_policy.max_rps if active_profile else 0.0
            print_banner(banner_name, banner_rps)
            table = display_main_menu(active_profile)
            console.print(table)
            console.print()

            choice = Prompt.ask("[bold white]Select an option [1-14][/bold white]", default="10")

            if choice in ("5", "6", "7", "8", "9", "10", "12") and not active_profile:
                console.print("\n[bold red]❌ No program profile active. Please select [1], create [3], or import [4] a valid program profile first.[/]\n")
                Prompt.ask("Press Enter to continue", default="")
                continue

            if choice == "1":
                # Select program
                profs = pm.list_profiles()
                console.print("\n[bold cyan]Available Programs:[/]")
                for idx, p in enumerate(profs, 1):
                    console.print(f"  [{idx}] {p['id']} - {p['name']} ({p['max_rps']} RPS)")
                p_idx = Prompt.ask("Select program number or enter ID", default="1")
                if p_idx.isdigit() and 1 <= int(p_idx) <= len(profs):
                    selected_id = profs[int(p_idx) - 1]["id"]
                else:
                    selected_id = p_idx.strip().lower()

                loaded = pm.get_profile(selected_id)
                if loaded:
                    active_profile = loaded
                    if active_profile.scope.allowed_domains:
                        target = active_profile.scope.allowed_domains[0].lstrip("*.")
                    console.print(f"[green]✓ Switched to program: {active_profile.name} ({active_profile.id})[/]\n")
                else:
                    console.print(f"[red]❌ Program '{selected_id}' not found.[/]\n")
                time.sleep(1)

            elif choice == "2":
                # List programs
                profs = pm.list_profiles()
                t = Table(title="[bold cyan]All Configured Programs[/]", border_style="cyan")
                t.add_column("ID", style="bold magenta")
                t.add_column("Name", style="white")
                t.add_column("Platform", style="cyan")
                t.add_column("Max RPS", style="yellow")
                t.add_column("Valid", style="green")
                for p in profs:
                    t.add_row(p["id"], p["name"], p["platform"], str(p["max_rps"]), "✓ Yes" if p["valid"] else "✗ No")
                console.print()
                console.print(t)
                console.print()
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "3":
                # Create program profile
                new_id = Prompt.ask("[bold cyan]Enter new program ID (alphanumeric, lowercase)[/]")
                if new_id:
                    new_name = Prompt.ask("[bold cyan]Enter program name[/]", default=new_id.title())
                    domains_str = Prompt.ask("[bold cyan]Enter allowed domains (comma-separated)[/]", default=f"{new_id}.com")
                    max_rps = FloatPrompt.ask("[bold cyan]Enter max requests per second (RPS)[/]", default=5.0)
                    data = {
                        "id": new_id.lower().strip(),
                        "name": new_name,
                        "scope": {"allowed_domains": [d.strip() for d in domains_str.split(",") if d.strip()]},
                        "request_policy": {"max_rps": max_rps}
                    }
                    try:
                        created = pm.create_profile(data, save=True)
                        active_profile = created
                        console.print(f"[green]✓ Created and activated profile '{created.id}'![/]\n")
                    except Exception as e:
                        console.print(f"[red]❌ Error creating profile: {e}[/]\n")
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "4":
                # Import policy
                source = Prompt.ask("[bold cyan]Enter path to YAML, JSON, or policy text file[/]")
                if source:
                    try:
                        imported = pm.import_profile(source)
                        active_profile = imported
                        console.print(f"[green]✓ Imported program profile '{imported.id}' ({imported.name})![/]\n")
                    except Exception as e:
                        console.print(f"[red]❌ Error importing policy: {e}[/]\n")
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "5":
                # Validate program policy
                errors = PolicyValidator.validate(active_profile)
                if errors:
                    console.print(f"\n[bold red]❌ Validation Failed for '{active_profile.id}':[/]")
                    for err in errors:
                        console.print(f"   • [yellow]{err}[/]")
                else:
                    console.print(f"\n[bold green]✓ Program profile '{active_profile.id}' is 100% VALID and compliant with all security policies![/]\n")
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "6":
                # View program scope
                console.print(f"\n[bold cyan]=== Scope for {active_profile.name} ===[/]")
                console.print(f"  Allowed Domains: {', '.join(active_profile.scope.allowed_domains) or 'None'}")
                console.print(f"  Excluded Domains: {', '.join(active_profile.scope.excluded_domains) or 'None'}")
                console.print(f"  Allowed CIDRs: {', '.join(active_profile.scope.allowed_cidrs) or 'None'}")
                console.print(f"  Excluded CIDRs: {', '.join(active_profile.scope.excluded_cidrs) or 'None'}")
                console.print(f"  Excluded Paths: {', '.join(active_profile.scope.excluded_paths) or 'None'}")
                console.print(f"  Third-Party Hosted Exclusions: {', '.join(active_profile.scope.third_party_hosted_exclusions) or 'None'}")
                console.print()
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "7":
                # Configure authentication
                console.print(f"\n[bold cyan]Current Auth Type: {active_profile.authentication.type}[/]")
                new_type = Prompt.ask("Select auth type", choices=["none", "bearer", "api_key", "cookie", "basic"], default=active_profile.authentication.type)
                active_profile.authentication.type = new_type
                if new_type in ("bearer", "api_key"):
                    active_profile.authentication.token_env = Prompt.ask("Token Environment Variable", default=active_profile.authentication.token_env or "PROGRAM_API_TOKEN")
                target_path = pm.base_dir / active_profile.id / "program.yaml"
                active_profile.save_yaml(target_path)
                console.print("[green]✓ Authentication configuration saved.[/]\n")
                time.sleep(1)

            elif choice == "8":
                # Configure request limits
                new_rps = FloatPrompt.ask("[bold cyan]Enter max requests per second[/]", default=active_profile.request_policy.max_rps)
                if active_profile.id == "uxcam" and new_rps > 5.0:
                    console.print("[red]❌ Error: UXCam program policy strictly limits rate to max 5.0 RPS![/]\n")
                elif new_rps <= 0:
                    console.print("[red]❌ Error: Rate must be positive (> 0)![/]\n")
                else:
                    active_profile.request_policy.max_rps = new_rps
                    target_path = pm.base_dir / active_profile.id / "program.yaml"
                    active_profile.save_yaml(target_path)
                    console.print(f"[green]✓ Rate limit set to {new_rps} RPS.[/]\n")
                time.sleep(1)

            elif choice == "9":
                # Select reconnaissance modules
                console.print(f"\n[bold cyan]=== Tool Compatibility & Modules for {active_profile.name} ===[/]")
                tcm = ToolCompatibilityManager(active_profile)
                for tool, info in tcm.get_tool_audit_report().items():
                    st = "[green]Enabled[/]" if info["compatible"] else "[red]Disabled[/]"
                    console.print(f"  • {tool:<18}: {st} ({info['reason']})")
                console.print()
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "10":
                # Start reconnaissance
                console.print(f"\n[bold yellow]Target Hostname for Recon: {target}[/]")
                if Confirm.ask(f"Change target domain? (Current: {target})", default=False):
                    target = Prompt.ask("Enter target domain", default=target)

                # Validate scope
                sm = ScopeManager.from_profile(active_profile)
                host = sm.extract_hostname(target)
                if not sm.is_host_allowed(host):
                    console.print(f"\n[bold red]❌ ERROR: Target '{target}' is OUT OF SCOPE for program '{active_profile.name}'![/]")
                    Prompt.ask("Press Enter to continue", default="")
                    continue

                if Confirm.ask(f"[bold green]Confirm: Start live scan against '{target}' under program '{active_profile.name}'?[/]", default=True):
                    run_scan_subprocess(target, active_profile)
                    Prompt.ask("\nPress Enter to return to menu", default="")

            elif choice == "11":
                # View reports
                reports = list(Path(".").glob("report_*.*"))
                if not reports:
                    console.print("\n[yellow]No reports found in current directory.[/yellow]\n")
                else:
                    console.print("\n[bold cyan]Generated Reports:[/]")
                    for r in reports:
                        console.print(f"  • {r.name} ({r.stat().st_size} bytes)")
                    console.print()
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "12":
                # View audit logs
                al = AuditLogger(program_id=active_profile.id)
                recent = al.read_recent_logs(limit=20)
                if not recent:
                    console.print("\n[yellow]Audit log is currently empty (logs/audit.jsonl).[/yellow]\n")
                else:
                    console.print(f"\n[bold cyan]=== Recent Audit Log Entries ({len(recent)} displayed) ===[/]")
                    for r in recent:
                        st = f"[{r.get('response_status')}]" if r.get('response_status') else ""
                        console.print(f"  [{r.get('timestamp')[:19]}] {r.get('method')} {r.get('url')[:60]} -> {r.get('scope_decision')} {st}")
                    console.print()
                Prompt.ask("Press Enter to continue", default="")

            elif choice == "13":
                # Run tests
                console.print("\n[bold cyan]Running automated test suite...[/]\n")
                subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])
                Prompt.ask("\nPress Enter to continue", default="")

            elif choice == "14" or choice == "0":
                console.print("[yellow]👋 Goodbye! Keep Learning // Keep Hacking[/yellow]")
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")


if __name__ == "__main__":
    main()
