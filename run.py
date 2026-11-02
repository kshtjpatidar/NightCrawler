#!/usr/bin/env python3
"""
NightCrawler v5.0 - Interactive Bug Bounty Reconnaissance Interface
Full interactive configuration menu complying with bug bounty rules.
by CyberTechAjju | Keep Learning // Keep Hacking
"""

import os
import sys
import shutil
import subprocess
import time
from pathlib import Path

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

from src.core.request_config import load_config, NightCrawlerConfig
from src.core.header_manager import HeaderManager

console = Console()

BANNER = """
[bold green]
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
[/bold green]
"""


def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')


def print_banner():
    clear_screen()
    console.print(BANNER)
    
    info = Text()
    info.append("v5.0 Bug Bounty Edition", style="bold green")
    info.append(" │ ", style="dim")
    info.append("Max 5 RPS", style="bold cyan")
    info.append(" │ ", style="dim")
    info.append("Scope Enforced", style="bold yellow")
    info.append(" │ ", style="dim")
    info.append("Verified TLS", style="bold green")
    info.append(" │ ", style="dim")
    info.append("Bugcrowd Reports", style="bold magenta")
    console.print(Panel(info, border_style="green"))
    console.print("[dim]⚠️  Ethical Bug Bounty Reconnaissance Only • Keep Learning // Keep Hacking[/dim]\n")


def display_menu():
    """Display the 12-item interactive configuration menu"""
    table = Table(title="[bold cyan]🎯 NightCrawler Configuration & Control Menu[/]", show_header=True, header_style="bold cyan", border_style="cyan")
    table.add_column("Option", style="bold green", width=8, justify="center")
    table.add_column("Configuration Task", style="white", width=42)
    table.add_column("Status / Current Value", style="yellow", width=28)

    return table


def render_review_panel(cfg: NightCrawlerConfig, target: str):
    """Render full configuration review with sensitive values strictly masked"""
    hm = cfg.get_header_manager()
    hdr_val = hm.get_masked_value() if hm.is_active() else "(disabled)"

    table = Table(title="[bold cyan]📋 Configuration Review (Values Safely Masked)[/]", border_style="green", show_header=True)
    table.add_column("Parameter", style="cyan", width=30)
    table.add_column("Configured Setting", style="white", width=45)

    table.add_row("1. Target Domain", target or "(Not configured)")
    table.add_row("2. Allowed Scope", ", ".join(cfg.allowed_domains) or "None")
    table.add_row("3. Excluded Domains", ", ".join(cfg.excluded_domains) or "None")
    table.add_row("4. Researcher Header", f"{cfg.header_name}: {hdr_val}" if cfg.custom_header_enabled else "Disabled")
    table.add_row("5. Max Requests Per Second", f"{cfg.max_requests_per_second} RPS")
    table.add_row("6. Concurrency", str(cfg.concurrency))
    table.add_row("7. JavaScript Extraction", "Enabled" if cfg.javascript_extraction else "Disabled")
    table.add_row("8. Endpoint Discovery", "Enabled" if cfg.endpoint_discovery else "Disabled")
    table.add_row("9. Secret Detection", "Enabled" if cfg.secret_detection else "Disabled")
    table.add_row("10. Report Template & Format", f"{cfg.default_template.upper()} ({cfg.default_format.upper()})")
    table.add_row("TLS Certificate Verification", "Enabled (Strict)" if cfg.verify_tls else "Disabled")
    table.add_row("KeyHacks Validation", "Disabled (Safe by default)" if not cfg.validate_keys else "Enabled")

    console.print()
    console.print(table)
    console.print()


def run_scan_subprocess(target: str, cfg: NightCrawlerConfig):
    """Execute main.py with the configured parameters"""
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               🚀  STARTING BUG BOUNTY SCAN                  │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")

    cmd = [
        sys.executable, "main.py",
        "-t", target,
        "--mode", "deep",
        "--no-prompt",
        "--concurrency", str(cfg.concurrency),
        "--max-rps", str(cfg.max_requests_per_second),
        "--timeout", str(cfg.timeout),
        "--depth", str(cfg.depth),
        "--template", cfg.default_template,
        "-o", f"report_{target.replace('.', '_')}.{cfg.default_format}"
    ]

    for d in cfg.allowed_domains:
        cmd.extend(["--allowed-domain", d])

    for ed in cfg.excluded_domains:
        cmd.extend(["--excluded-domain", ed])

    if cfg.custom_header_enabled and cfg.header_value:
        cmd.extend(["--header-name", cfg.header_name, "--header-value", cfg.header_value])
    else:
        cmd.append("--disable-header")

    if cfg.verify_tls:
        cmd.append("--verify-tls")
    else:
        cmd.append("--no-verify-tls")

    if cfg.strict_scope:
        cmd.append("--strict-scope")

    if cfg.validate_keys:
        cmd.append("--validate-keys")

    # Safe display command with masked header
    display_cmd = list(cmd)
    if "--header-value" in display_cmd:
        idx = display_cmd.index("--header-value")
        display_cmd[idx + 1] = cfg.get_header_manager().get_masked_value()

    console.print(f"[dim]Command: {' '.join(display_cmd)}[/dim]\n")

    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        if result.returncode == 0:
            console.print("\n[bold green]✓ Reconnaissance completed successfully![/bold green]")
        else:
            console.print("\n[yellow]⚠️  Scan finished with exit code: " + str(result.returncode) + "[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]✗ Error during execution: {e}[/red]")


def main():
    try:
        print_banner()
        cfg = load_config()
        target = "uxcam.com"

        while True:
            hm = cfg.get_header_manager()
            hdr_display = hm.get_masked_value() if hm.is_active() else "Disabled"

            table = display_menu()
            table.add_row("[1]", "Configure target", target)
            table.add_row("[2]", "Configure allowed scope", f"{len(cfg.allowed_domains)} domains: {', '.join(cfg.allowed_domains)[:20]}")
            table.add_row("[3]", "Configure excluded domains", f"{len(cfg.excluded_domains)} domains: {', '.join(cfg.excluded_domains)[:20]}")
            table.add_row("[4]", "Configure researcher header", f"{cfg.header_name}: {hdr_display}")
            table.add_row("[5]", "Configure max requests/sec", f"{cfg.max_requests_per_second} RPS")
            table.add_row("[6]", "Configure concurrency", str(cfg.concurrency))
            table.add_row("[7]", "Toggle JavaScript extraction", "Enabled" if cfg.javascript_extraction else "Disabled")
            table.add_row("[8]", "Toggle endpoint discovery", "Enabled" if cfg.endpoint_discovery else "Disabled")
            table.add_row("[9]", "Toggle secret detection", "Enabled" if cfg.secret_detection else "Disabled")
            table.add_row("[10]", "Configure report format", f"{cfg.default_template.upper()} ({cfg.default_format.upper()})")
            table.add_row("[11]", "Review configuration summary", "[cyan]View Masked Summary[/]")
            table.add_row("[12]", "Start reconnaissance", "[bold green]🚀 Run Recon Scan[/]")
            table.add_row("[0]", "Exit NightCrawler", "[dim]Quit[/]")

            console.print(table)
            console.print()

            choice = Prompt.ask("[bold white]Select an option [0-12][/bold white]", default="12")

            if choice == "1":
                new_target = Prompt.ask("[bold cyan]Enter target domain[/]", default=target)
                if new_target:
                    target = new_target.strip().lower()
                    console.print(f"[green]✓ Target set to: {target}[/]\n")

            elif choice == "2":
                console.print(f"[dim]Current allowed domains: {', '.join(cfg.allowed_domains)}[/dim]")
                domains_in = Prompt.ask("[bold cyan]Enter allowed domains (comma-separated)[/]", default=", ".join(cfg.allowed_domains))
                cfg.allowed_domains = [d.strip().lower() for d in domains_in.split(",") if d.strip()]
                console.print(f"[green]✓ Allowed scope updated: {', '.join(cfg.allowed_domains)}[/]\n")

            elif choice == "3":
                console.print(f"[dim]Current excluded domains: {', '.join(cfg.excluded_domains)}[/dim]")
                domains_in = Prompt.ask("[bold cyan]Enter excluded domains (comma-separated)[/]", default=", ".join(cfg.excluded_domains))
                cfg.excluded_domains = [d.strip().lower() for d in domains_in.split(",") if d.strip()]
                console.print(f"[green]✓ Excluded domains updated: {', '.join(cfg.excluded_domains)}[/]\n")

            elif choice == "4":
                cfg.custom_header_enabled = Confirm.ask("[bold cyan]Enable researcher identification header?[/]", default=cfg.custom_header_enabled)
                if cfg.custom_header_enabled:
                    cfg.header_name = Prompt.ask("Header Name", default=cfg.header_name)
                    new_val = Prompt.ask("Header Value (e.g. researcher email)", default=cfg.header_value or "")
                    if new_val:
                        cfg.header_value = new_val
                    console.print(f"[green]✓ Header configured: {cfg.header_name} (masked: {cfg.get_header_manager().get_masked_value()})[/]\n")
                if Confirm.ask("Save this header configuration to config.yaml?", default=False):
                    cfg.save_to_file()
                    console.print("[green]✓ Configuration saved to config.yaml[/]\n")

            elif choice == "5":
                cfg.max_requests_per_second = FloatPrompt.ask("[bold cyan]Maximum requests per second[/]", default=cfg.max_requests_per_second)
                console.print(f"[green]✓ Rate limit set to {cfg.max_requests_per_second} RPS[/]\n")

            elif choice == "6":
                cfg.concurrency = IntPrompt.ask("[bold cyan]Concurrency workers (1-5 recommended for 5 RPS)[/]", default=cfg.concurrency)
                console.print(f"[green]✓ Concurrency set to {cfg.concurrency}[/]\n")

            elif choice == "7":
                cfg.javascript_extraction = not cfg.javascript_extraction
                console.print(f"[green]✓ JavaScript extraction: {'Enabled' if cfg.javascript_extraction else 'Disabled'}[/]\n")

            elif choice == "8":
                cfg.endpoint_discovery = not cfg.endpoint_discovery
                console.print(f"[green]✓ Endpoint discovery: {'Enabled' if cfg.endpoint_discovery else 'Disabled'}[/]\n")

            elif choice == "9":
                cfg.secret_detection = not cfg.secret_detection
                console.print(f"[green]✓ Secret detection: {'Enabled' if cfg.secret_detection else 'Disabled'}[/]\n")

            elif choice == "10":
                console.print("\nTemplate choices: [1] Bugcrowd  [2] HackerOne  [3] Email")
                t_choice = Prompt.ask("Select template", choices=["1", "2", "3"], default="1")
                cfg.default_template = {"1": "bugcrowd", "2": "hackerone", "3": "email"}[t_choice]

                console.print("\nFormat choices: [1] HTML  [2] JSON")
                f_choice = Prompt.ask("Select format", choices=["1", "2"], default="1")
                cfg.default_format = {"1": "html", "2": "json"}[f_choice]
                console.print(f"[green]✓ Report set to: {cfg.default_template.upper()} ({cfg.default_format.upper()})[/]\n")

            elif choice == "11":
                render_review_panel(cfg, target)
                Prompt.ask("Press Enter to return to menu", default="")

            elif choice == "12":
                render_review_panel(cfg, target)
                # Scope check on target
                scope_mgr = cfg.get_scope_manager()
                host = scope_mgr.extract_hostname(target)
                if host and not scope_mgr.is_host_allowed(host):
                    console.print(f"[bold red]❌ ERROR: Target '{target}' is not in allowed scope or is excluded![/]")
                    console.print("[yellow]Please update the target or configure allowed scope first.[/]\n")
                    Prompt.ask("Press Enter to continue", default="")
                    continue

                if Confirm.ask("[bold green]Confirm: Proceed with live reconnaissance scan?[/]", default=True):
                    run_scan_subprocess(target, cfg)
                    Prompt.ask("\nPress Enter to return to menu", default="")
                else:
                    console.print("[yellow]Scan cancelled by user.[/yellow]\n")

            elif choice == "0":
                console.print("[yellow]👋 Goodbye! Keep Learning // Keep Hacking[/yellow]")
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")


if __name__ == "__main__":
    main()
