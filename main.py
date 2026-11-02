#!/usr/bin/env python3
"""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

NightCrawler v5.0 - Scope-Aware, Rate-Limited Bug Bounty Reconnaissance
by kshtjpatidar | Keep Learning // Keep Hacking

⚠️ ETHICAL USE ONLY - For authorized security testing and bug bounty programs 
"""

import asyncio
import click
import os
import sys
from pathlib import Path
from typing import List

from src.ui.banner import print_banner
from src.core.scanner import NightCrawlerScanner
from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.request_config import load_config, NightCrawlerConfig
from src.output.console import ConsoleOutput
from src.output.html_report import HtmlReportGenerator, ReportConfig, mask_secret
from src.validators.keyhacks import KeyHacksValidator, ValidationStatus


def show_scan_mode_menu():
    """Display scan mode selection menu"""
    click.echo()
    click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg="cyan"))
    click.echo(click.style("│               🎯  SELECT SCAN MODE                          │", fg="cyan"))
    click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[1]", fg="green", bold=True) + click.style(" Main Domain Only", fg="white") + click.style("                                  │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Scan only target domain (respects 5 RPS limit)", dim=True) + click.style("    │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[2]", fg="yellow", bold=True) + click.style(" Include Subdomains", fg="white") + click.style("                                │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Subfinder enumeration (in-scope subdomains only)", dim=True) + click.style("│", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[3]", fg="red", bold=True) + click.style(" Deep Scan (Scope Crawling & Archives)", fg="white") + click.style("          │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Rate-limited Katana + Scope-filtered Archives", dim=True) + click.style("     │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg="cyan"))
    click.echo()


@click.command()
@click.option('-t', '--target', help='Single target domain (e.g., uxcam.com)')
@click.option('-l', '--list', 'target_list', type=click.Path(exists=True), help='File containing list of targets')
@click.option('-u', '--urls', type=click.Path(exists=True), help='File containing JS URLs to scan directly')
@click.option('-o', '--output', type=click.Path(), help='Output file (supports .json, .html)')
@click.option('-c', '--concurrency', default=None, type=int, help='Concurrent workers (default: 1)')
@click.option('-d', '--depth', default=None, type=int, help='Crawl depth (default: 1)')
@click.option('--timeout', default=None, type=int, help='Request timeout in seconds (default: 30)')
@click.option('--offline', type=click.Path(exists=True), help='Scan local JS files in directory')
@click.option('--patterns', type=click.Path(exists=True), help='Custom patterns file (YAML)')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('-q', '--quiet', is_flag=True, help='Only output findings')
@click.option('--config-file', type=click.Path(exists=True), help='Path to custom config.yaml')
# Scan Mode Options
@click.option('--mode', type=click.Choice(['main', 'subdomains', 'deep']), help='Scan mode: main, subdomains, or deep')
@click.option('--no-prompt', is_flag=True, help='Skip interactive prompts')
# Rate Limiting & Scope Controls
@click.option('--max-rps', default=None, type=float, help='Global maximum requests per second (default: 5.0)')
@click.option('--allowed-domain', 'allowed_domains', multiple=True, help='Authorized domain pattern (e.g., uxcam.com, uxc.am)')
@click.option('--excluded-domain', 'excluded_domains', multiple=True, help='Excluded domain pattern (e.g., tara.uxcam.com)')
@click.option('--verify-tls/--no-verify-tls', default=None, help='Verify TLS certificates (default: True)')
@click.option('--strict-scope/--no-strict-scope', default=None, help='Enforce strict scope boundary checks (default: True)')
# Researcher Header Options
@click.option('--header-name', help='Custom researcher header name (e.g., X-User-Id)')
@click.option('--header-value', help='Custom researcher header value (e.g., researcher email)')
@click.option('--enable-header/--disable-header', default=None, help='Enable researcher identification header')
# KeyHacks Validation
@click.option('--validate-keys', is_flag=True, default=False, help='🔑 Auto-validate discovered secrets using KeyHacks (default: False)')
@click.option('--validate-timeout', default=10, help='Timeout for KeyHacks validation requests (default: 10)')
# Report Options
@click.option('--template', type=click.Choice(['bugcrowd', 'hackerone', 'email']), default=None,
              help='Report template format (default: bugcrowd)')
@click.option('--reporter', default=None, help='Reporter name for the report')
@click.option('--reporter-email', default=None, help='Reporter email address')
@click.option('--program', default=None, help='Bug bounty program name')
@click.version_option(version='5.0.0', prog_name='NightCrawler')
def main(target, target_list, urls, output, concurrency, depth, timeout, 
         offline, patterns, verbose, quiet, config_file, mode, no_prompt,
         max_rps, allowed_domains, excluded_domains, verify_tls, strict_scope,
         header_name, header_value, enable_header, validate_keys, validate_timeout,
         template, reporter, reporter_email, program):
    """
    NightCrawler v5.0 - Scope-Aware, Rate-Limited Bug Bounty Reconnaissance
    
    Hunt for exposed secrets, API keys, and hidden endpoints in JavaScript files.
    Complies with bug bounty program rules: strict target scope, max 5 RPS rate limit,
    TLS certificate verification, researcher identification header, and Bugcrowd reporting.
    """
    if not quiet:
        print_banner()

    # Load base configuration from config.yaml and environment
    cfg = load_config(config_file)

    # Merge CLI options onto configuration
    if concurrency is not None:
        cfg.concurrency = concurrency
    if depth is not None:
        cfg.depth = depth
    if timeout is not None:
        cfg.timeout = timeout
    if max_rps is not None:
        cfg.max_requests_per_second = max_rps
    if verify_tls is not None:
        cfg.verify_tls = verify_tls
    if strict_scope is not None:
        cfg.strict_scope = strict_scope
        cfg.scope_enabled = strict_scope
    if allowed_domains:
        cfg.allowed_domains = list(allowed_domains)
    if excluded_domains:
        cfg.excluded_domains = list(excluded_domains)
    if enable_header is not None:
        cfg.custom_header_enabled = enable_header
    if header_name:
        cfg.header_name = header_name
    if header_value:
        cfg.header_value = header_value
    if template:
        cfg.default_template = template
    if reporter:
        cfg.reporter_name = reporter
    if reporter_email:
        cfg.reporter_email = reporter_email
    if program:
        cfg.program_name = program
    if validate_keys:
        cfg.validate_keys = True

    # Validate target presence
    if not any([target, target_list, urls, offline]):
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='red'))
        click.echo(click.style("│  ❌ Error: No target specified                              │", fg='red'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='red'))
        click.echo(click.style("\n[*] Examples:", fg='cyan'))
        click.echo("    nightcrawler -t uxcam.com -o report.html")
        click.echo("    nightcrawler -t uxcam.com --mode subdomains --header-value researcher@example.com")
        click.echo("    nightcrawler --offline ./downloaded_js/ -o report.json")
        return

    # Interactive researcher header setup if not specified
    if not no_prompt and not offline and not cfg.header_value:
        click.echo()
        if click.confirm(click.style("[?] Enable researcher identification header (e.g. X-User-Id)?", fg="cyan"), default=cfg.custom_header_enabled):
            cfg.custom_header_enabled = True
            cfg.header_name = click.prompt(click.style("    Header name", fg="white"), default=cfg.header_name)
            val = click.prompt(click.style("    Header value (e.g. researcher email)", fg="white"), default="")
            if val:
                cfg.header_value = val
                if click.confirm(click.style("    Save this configuration to config.yaml?", fg="cyan"), default=False):
                    cfg.save_to_file()
                    click.echo(click.style("    ✓ Configuration saved to config.yaml", fg="green"))
        else:
            cfg.custom_header_enabled = False

    # Scan mode selection for single target
    use_subdomains = False
    use_archives = False
    
    if target and not no_prompt and not mode and not offline:
        show_scan_mode_menu()
        choice = click.prompt(
            click.style('[?] Select scan mode', fg='cyan'),
            type=click.Choice(['1', '2', '3']),
            default='1'
        )
        if choice == '1':
            mode = 'main'
            click.echo(click.style("\n  ✓ Main Domain Only selected", fg='green'))
        elif choice == '2':
            mode = 'subdomains'
            use_subdomains = True
            click.echo(click.style("\n  ✓ Subdomains mode selected", fg='yellow'))
        else:
            mode = 'deep'
            use_subdomains = True
            use_archives = True
            click.echo(click.style("\n  ✓ Deep Scan mode selected", fg='red'))
    elif mode:
        if mode == 'subdomains':
            use_subdomains = True
        elif mode == 'deep':
            use_subdomains = True
            use_archives = True

    # Scope validation on single target
    scope_mgr = cfg.get_scope_manager()
    if target and scope_mgr.enabled:
        host = scope_mgr.extract_hostname(target)
        if host and not scope_mgr.is_host_allowed(host):
            click.echo(click.style(f"\n[!] ERROR: Target '{target}' is OUT OF SCOPE!", fg='red', bold=True))
            click.echo(click.style(f"    Allowed domains: {', '.join(cfg.allowed_domains)}", fg='yellow'))
            click.echo(click.style(f"    Excluded domains: {', '.join(cfg.excluded_domains)}", fg='yellow'))
            click.echo(click.style("[!] Aborting to ensure bug bounty compliance.\n", fg='red'))
            return

    # Key validation safety check
    if cfg.validate_keys and not quiet:
        keyhacks_validator = KeyHacksValidator(timeout=validate_timeout)
        keyhacks_validator.print_disclaimer()
        if not click.confirm(click.style('[?] Do you confirm you have explicit authorization to validate these secrets?', fg='yellow'), default=False):
            click.echo(click.style("[!] Key validation cancelled. Running passive recon only.", fg='yellow'))
            cfg.validate_keys = False

    # Instantiate managers
    header_mgr = cfg.get_header_manager()
    rate_limiter = cfg.get_rate_limiter()

    # Display configuration summary with sensitive values masked
    if not quiet:
        click.echo()
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
        click.echo(click.style("│               🦇  SCAN CONFIGURATION SUMMARY                │", fg='green'))
        click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
        click.echo(click.style(f"│  Target: {str(target or target_list or urls or offline):<51}│", fg='green'))
        click.echo(click.style(f"│  Mode: {(mode or 'main').upper():<53}│", fg='green'))
        click.echo(click.style(f"│  Allowed Scope: {', '.join(cfg.allowed_domains)[:43]:<44}│", fg='green'))
        click.echo(click.style(f"│  Excluded Scope: {', '.join(cfg.excluded_domains)[:42]:<43}│", fg='green'))
        click.echo(click.style(f"│  Rate Limit: {f'{cfg.max_requests_per_second} requests/second':<47}│", fg='green'))
        click.echo(click.style(f"│  Concurrency: {cfg.concurrency:<46}│", fg='green'))
        click.echo(click.style(f"│  TLS Verification: {'Enabled (Strict)' if cfg.verify_tls else 'Disabled':<41}│", fg='green'))
        hdr_display = f"{cfg.header_name}: {header_mgr.get_masked_value()}" if header_mgr.is_active() else "Disabled"
        click.echo(click.style(f"│  Researcher Header: {hdr_display:<40}│", fg='green'))
        click.echo(click.style(f"│  Key Validation: {'Enabled' if cfg.validate_keys else 'Disabled (Safe by default)':<43}│", fg='green'))
        click.echo(click.style(f"│  Report Template: {cfg.default_template.upper():<42}│", fg='green'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))
        click.echo()

    # Confirmation before scanning in interactive mode
    if not no_prompt and not offline:
        if not click.confirm(click.style("[?] Ready to start reconnaissance?", fg="green"), default=True):
            click.echo(click.style("[!] Reconnaissance cancelled by user.", fg="yellow"))
            return

    # Initialize Scanner
    scanner = NightCrawlerScanner(
        concurrency=cfg.concurrency,
        timeout=cfg.timeout,
        depth=cfg.depth,
        use_external_tools=use_subdomains or use_archives,
        custom_patterns=patterns,
        verbose=verbose,
        validate=True,
        scope_manager=scope_mgr,
        rate_limiter=rate_limiter,
        header_manager=header_mgr,
        max_requests_per_second=cfg.max_requests_per_second,
        verify_tls=cfg.verify_tls,
        strict_scope=cfg.strict_scope,
        javascript_extraction=cfg.javascript_extraction,
        endpoint_discovery=cfg.endpoint_discovery,
        secret_detection=cfg.secret_detection,
        validate_keys=cfg.validate_keys
    )

    try:
        if offline:
            asyncio.run(scanner.scan_directory(Path(offline)))
        elif urls:
            asyncio.run(scanner.scan_urls_from_file(Path(urls)))
        elif target_list:
            asyncio.run(scanner.scan_targets_from_file(Path(target_list)))
        else:
            asyncio.run(scanner.scan_target(target))

        # KeyHacks Validation phase (only if explicitly enabled)
        if cfg.validate_keys and scanner.results.findings:
            click.echo()
            click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='yellow'))
            click.echo(click.style("│               🔑  KEYHACKS VALIDATION                       │", fg='yellow'))
            click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='yellow'))
            keyhacks_validator = KeyHacksValidator(timeout=validate_timeout)
            with click.progressbar(scanner.results.findings, label=click.style('  🔑 Validating', fg='cyan')) as findings:
                for finding in findings:
                    if finding.validated:
                        res = asyncio.run(keyhacks_validator.validate_secret(finding.pattern_name, finding.matched_value))
                        finding.keyhacks_status = res.status.value
                        finding.keyhacks_message = res.message
                        finding.keyhacks_command = res.validation_command or ""
                        if res.status == ValidationStatus.VALID:
                            scanner.results.keyhacks_valid += 1
                        elif res.status == ValidationStatus.INVALID:
                            scanner.results.keyhacks_invalid += 1

        # Report Generation
        default_out = output or f"report_{str(target or 'recon').replace('.', '_')}.{cfg.default_format}"
        output_path = Path(default_out)

        rep_cfg = ReportConfig(
            reporter_name=cfg.reporter_name,
            reporter_email=cfg.reporter_email,
            program_name=cfg.program_name,
            template=cfg.default_template
        )
        report_gen = HtmlReportGenerator(rep_cfg)
        valid_findings = [f for f in scanner.results.findings if f.validated]

        report_gen.generate(
            findings=valid_findings,
            scan_result=scanner.results,
            output_path=str(output_path)
        )

        click.echo()
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
        click.echo(click.style("│               📄  REPORT GENERATED SAFELY                   │", fg='green'))
        click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
        click.echo(click.style(f"│  File: {str(output_path):<53}│", fg='green'))
        click.echo(click.style(f"│  Format / Template: {cfg.default_template.upper():<40}│", fg='green'))
        click.echo(click.style(f"│  In-Scope Endpoints: {len(scanner.results.discovered_endpoints):<39}│", fg='green'))
        click.echo(click.style(f"│  Potential Secrets: {len(valid_findings):<40}│", fg='green'))
        click.echo(click.style(f"│  Values Masked: {'Yes (Zero Secret Leakage)':<44}│", fg='green'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))

        if not quiet:
            scanner.print_summary()

    except KeyboardInterrupt:
        click.echo(click.style("\n[!] Scan interrupted by user.", fg='yellow'))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg='red'))
        if verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
