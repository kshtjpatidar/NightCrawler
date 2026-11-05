#!/usr/bin/env python3
"""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

NightCrawler v5.0 - Multi-Program, Policy-Aware Bug Bounty Reconnaissance Framework
by kshtjpatidar | Keep Learning // Keep Hacking

⚠️ ETHICAL USE ONLY - For authorized security testing and bug bounty programs 
"""

import asyncio
import click
import os
import sys
from pathlib import Path
from typing import List, Optional

from src.ui.banner import print_banner
from src.core.scanner import NightCrawlerScanner
from src.core.scope import ScopeManager
from src.core.rate_limiter import GlobalRateLimiter
from src.core.header_manager import HeaderManager
from src.core.request_config import load_config, NightCrawlerConfig
from src.output.console import ConsoleOutput
from src.output.html_report import HtmlReportGenerator, ReportConfig, mask_secret
from src.validators.keyhacks import KeyHacksValidator, ValidationStatus

# Multi-Program Framework Components
from src.core.program_manager import ProgramManager
from src.core.program_profile import ProgramProfile, PolicyParser, PolicyValidator
from src.core.effective_policy import EffectivePolicy
from src.core.request_policy import RequestPolicyManager
from src.core.auth_manager import AuthenticationManager
from src.core.permissions import TestingPermissionManager
from src.core.tool_compatibility import ToolCompatibilityManager
from src.core.audit_logger import AuditLogger
from src.output.report_manager import ReportManager


def show_scan_mode_menu():
    """Display scan mode selection menu"""
    click.echo()
    click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg="cyan"))
    click.echo(click.style("│               🎯  SELECT SCAN MODE                          │", fg="cyan"))
    click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[1]", fg="green", bold=True) + click.style(" Main Domain Only", fg="white") + click.style("                                  │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Scan only target domain (respects program RPS limit)", dim=True) + click.style("   │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[2]", fg="yellow", bold=True) + click.style(" Include Subdomains", fg="white") + click.style("                                │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Subfinder enumeration (in-scope subdomains only)", dim=True) + click.style("│", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[3]", fg="red", bold=True) + click.style(" Deep Scan (Scope Crawling & Archives)", fg="white") + click.style("          │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Rate-limited Katana + Scope-filtered Archives", dim=True) + click.style("     │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg="cyan"))
    click.echo()


@click.group(invoke_without_command=True)
@click.option('-t', '--target', help='Single target domain or URL (e.g., uxcam.com)')
@click.option('-l', '--list', 'target_list', type=click.Path(exists=True), help='File containing list of targets')
@click.option('-u', '--urls', type=click.Path(exists=True), help='File containing JS URLs to scan directly')
@click.option('-o', '--output', type=click.Path(), help='Output file (supports .json, .html, .md)')
@click.option('-c', '--concurrency', default=None, type=int, help='Concurrent workers')
@click.option('-d', '--depth', default=None, type=int, help='Crawl depth')
@click.option('--timeout', default=None, type=int, help='Request timeout in seconds')
@click.option('--offline', type=click.Path(exists=True), help='Scan local JS files in directory')
@click.option('--patterns', type=click.Path(exists=True), help='Custom patterns file (YAML)')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('-q', '--quiet', is_flag=True, help='Only output findings')
@click.option('--config-file', type=click.Path(exists=True), help='Path to custom config.yaml')
@click.option('--mode', type=click.Choice(['main', 'subdomains', 'deep']), help='Scan mode: main, subdomains, or deep')
@click.option('--no-prompt', is_flag=True, help='Skip interactive prompts')
@click.option('--max-rps', default=None, type=float, help='Global maximum requests per second')
@click.option('--allowed-domain', 'allowed_domains', multiple=True, help='Authorized domain pattern (e.g., uxcam.com, uxc.am)')
@click.option('--excluded-domain', 'excluded_domains', multiple=True, help='Excluded domain pattern (e.g., tara.uxcam.com)')
@click.option('--scope/--no-scope', 'scope_enabled', default=None, help='Enable/disable target scope enforcement')
@click.option('--verify-tls/--no-verify-tls', default=None, help='Verify TLS certificates (default: True)')
@click.option('--strict-scope/--no-strict-scope', default=None, help='Enforce strict scope boundary checks (default: True)')
@click.option('--header-name', help='Custom researcher header name (e.g., X-User-Id)')
@click.option('--header-value', help='Custom researcher header value (prefer setting NIGHTCRAWLER_RESEARCHER_ID env var)')
@click.option('--enable-header/--disable-header', default=None, help='Enable researcher identification header')
@click.option('--validate-keys', is_flag=True, default=False, help='🔑 Auto-validate discovered secrets using KeyHacks (default: False)')
@click.option('--validate-timeout', default=10, help='Timeout for KeyHacks validation requests (default: 10)')
@click.option('--template', type=click.Choice(['bugcrowd', 'hackerone', 'email']), default=None,
              help='Report template format (default: bugcrowd)')
@click.option('--authorized-provider', 'authorized_providers', multiple=True, help='Authorized provider domain (can only narrow or specify when no profile restrictions)')
@click.option('--reporter', default=None, help='Reporter name for the report')
@click.option('--reporter-email', default=None, help='Reporter email address')
@click.option('--program', default=None, help='Bug bounty program profile ID (e.g. uxcam, example-program)')
@click.option('--confirm-review', is_flag=True, default=False,
              help='Acknowledge and confirm manual review of a review-required program profile')
@click.version_option(version='5.0.0', prog_name='NightCrawler')
@click.pass_context
def main(ctx, target, target_list, urls, output, concurrency, depth, timeout, 
         offline, patterns, verbose, quiet, config_file, mode, no_prompt,
         max_rps, allowed_domains, excluded_domains, scope_enabled, verify_tls, strict_scope,
         header_name, header_value, enable_header, validate_keys, validate_timeout,
         template, reporter, reporter_email, program, confirm_review, authorized_providers):
    """
    NightCrawler v5.0 - Multi-Program, Policy-Aware Bug Bounty Reconnaissance Framework
    
    Hunt for exposed secrets, API keys, and hidden endpoints in JavaScript files.
    Complies with bug bounty program rules: strict target scope, rate limits,
    TLS certificate verification, researcher identification header, and structured reporting.
    """
    if ctx.invoked_subcommand is not None:
        return

    if not quiet:
        print_banner()

    # Load program profile or base configuration
    pm = ProgramManager()
    active_profile: Optional[ProgramProfile] = None

    if program:
        try:
            active_profile = pm.get_profile(program)
        except Exception as e:
            click.echo(click.style(f"\n[!] ERROR: Failed to load program profile '{program}': {e}\n", fg='red', bold=True))
            sys.exit(1)
        if not active_profile:
            click.echo(click.style(f"\n[!] ERROR: Program profile '{program}' not found in programs/ directory!", fg='red', bold=True))
            try:
                available = ', '.join([p['id'] for p in pm.list_profiles()])
            except Exception:
                available = 'unknown'
            click.echo(click.style(f"    Available programs: {available}\n", fg='yellow'))
            sys.exit(1)
        errors = PolicyValidator.validate(active_profile)
        if errors:
            click.echo(click.style(f"\n[!] POLICY ERROR: Program profile '{program}' failed validation: {'; '.join(errors)}\n", fg='red', bold=True))
            sys.exit(1)
    else:
        # Check if default program profile exists on disk
        default_program = "uxcam"
        try:
            if pm.profile_exists(default_program):
                active_profile = pm.get_profile(default_program)
                if active_profile:
                    errors = PolicyValidator.validate(active_profile)
                    if errors:
                        click.echo(click.style(
                            f"\n[!] POLICY ERROR: Default program profile '{default_program}' failed validation: {'; '.join(errors)}\n",
                            fg='red', bold=True
                        ))
                        sys.exit(1)
            else:
                active_profile = None
        except Exception as e:
            click.echo(click.style(
                f"\n[!] ERROR: Failed to load default program profile '{default_program}': {e}\n",
                fg='red', bold=True
            ))
            sys.exit(1)

    # Load base fallback configuration
    try:
        cfg = load_config(config_file)
    except (ValueError, TypeError, FileNotFoundError) as cfg_err:
        click.echo(click.style(f"\n[!] CONFIG ERROR: {cfg_err}\n", fg='red', bold=True))
        sys.exit(1)

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
    if scope_enabled is not None:
        cfg.scope_enabled = scope_enabled
    if strict_scope is not None:
        cfg.strict_scope = strict_scope
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
        header_env_key = cfg.header_value_env or "NIGHTCRAWLER_RESEARCHER_ID"
        os.environ[header_env_key] = header_value
        os.environ["NIGHTCRAWLER_HEADER_VALUE"] = header_value
        if not quiet:
            click.echo(click.style(
                f"[dim]Notice: Passed researcher ID registered in environment ({header_env_key}).[/dim]",
                dim=True
            ))
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

    # P0: Validate Rate Limit (Reject non-positive RPS, enforce hard maximum of 5 for UXCam profile)
    if cfg.max_requests_per_second <= 0:
        click.echo(click.style(f"\n[!] ERROR: max-rps must be a positive number (> 0), got {cfg.max_requests_per_second}!\n", fg='red', bold=True))
        sys.exit(1)

    if cfg.is_uxcam_profile() and cfg.max_requests_per_second > 5.0:
        click.echo(click.style(
            f"\n[!] POLICY VIOLATION: UXCam bug bounty policy enforces a strict maximum rate limit of 5 requests per second "
            f"(requested {cfg.max_requests_per_second} RPS)!\n",
            fg='red', bold=True
        ))
        sys.exit(1)

    # P1: Reject insecure TLS configuration when strict mode is enabled
    if cfg.strict_scope and not cfg.verify_tls:
        click.echo(click.style("\n[!] SECURITY VIOLATION: Insecure TLS configuration is prohibited in strict compliance mode!", fg='red', bold=True))
        click.echo(click.style("    TLS certificate verification must remain enabled.\n", fg='yellow'))
        sys.exit(1)

    # Validate report output extension if specified
    if output:
        out_ext = Path(output).suffix.lower()
        if out_ext not in [".html", ".htm", ".json", ".md", ".markdown"]:
            click.echo(click.style(f"\n[!] ERROR: Unsupported report format '{out_ext}'! Supported formats: .html, .json, .md\n", fg='red', bold=True))
            sys.exit(1)

    # Build Authoritative EffectivePolicy
    cli_overrides = {
        "concurrency": concurrency,
        "depth": depth,
        "timeout": timeout,
        "max_rps": max_rps,
        "verify_tls": verify_tls,
        "strict_scope": strict_scope,
        "scope_enabled": scope_enabled,
        "allowed_domains": list(allowed_domains) if allowed_domains else None,
        "excluded_domains": list(excluded_domains) if excluded_domains else None,
        "header_name": header_name,
        "header_value": header_value,
        "template": template,
        "reporter": reporter,
        "reporter_email": reporter_email,
        "validate_keys": validate_keys if validate_keys else None,
        "confirm_review": confirm_review if confirm_review else None,
        "authorized_providers": list(authorized_providers) if authorized_providers else None
    }
    # Filter out None values so EffectivePolicy uses base profile/config values
    cli_overrides = {k: v for k, v in cli_overrides.items() if v is not None}

    try:
        effective_policy = EffectivePolicy.build(
            profile=active_profile,
            config=cfg,
            cli_overrides=cli_overrides
        )
    except ValueError as val_err:
        click.echo(click.style(f"\n[!] POLICY ERROR: {val_err}\n", fg='red', bold=True))
        sys.exit(1)

    # Validate target presence
    if not any([target, target_list, urls, offline]):
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='red'))
        click.echo(click.style("│  ❌ Error: No target specified                              │", fg='red'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='red'))
        click.echo(click.style("\n[*] Examples:", fg='cyan'))
        click.echo("    nightcrawler -t uxcam.com -o report.html")
        click.echo("    nightcrawler --program uxcam -t uxcam.com")
        click.echo("    nightcrawler programs list")
        click.echo("    export NIGHTCRAWLER_RESEARCHER_ID=researcher@example.com && nightcrawler -t uxcam.com --mode subdomains")
        click.echo("    nightcrawler --offline ./downloaded_js/ -o report.json")
        return

    # Interactive researcher header setup if not specified
    if not no_prompt and not offline and not cfg.header_value and not os.getenv("NIGHTCRAWLER_RESEARCHER_ID"):
        click.echo()
        if click.confirm(click.style("[?] Enable researcher identification header (e.g. X-User-Id)?", fg="cyan"), default=cfg.custom_header_enabled):
            cfg.custom_header_enabled = True
            cfg.header_name = click.prompt(click.style("    Header name", fg="white"), default=cfg.header_name)
            val = click.prompt(click.style("    Header value (e.g. researcher email)", fg="white"), default="")
            if val:
                cfg.header_value = val
                os.environ[cfg.header_value_env or "NIGHTCRAWLER_RESEARCHER_ID"] = val
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
    scope_mgr = effective_policy.scope_manager
    if target and scope_mgr.enabled:
        host = scope_mgr.extract_hostname(target)
        if host and not scope_mgr.is_host_allowed(host):
            click.echo(click.style(f"\n[!] ERROR: Target '{target}' is OUT OF SCOPE!", fg='red', bold=True))
            click.echo(click.style(f"    Allowed domains: {', '.join(scope_mgr.allowed_domains)}", fg='yellow'))
            click.echo(click.style(f"    Excluded domains: {', '.join(scope_mgr.excluded_domains)}", fg='yellow'))
            click.echo(click.style("[!] Aborting to ensure bug bounty compliance.\n", fg='red'))
            sys.exit(1)

    # Key validation safety check: close quiet/non-interactive bypass
    if effective_policy.validate_keys:
        if not effective_policy.permission_manager.is_permitted("credential_validation"):
            if not quiet:
                click.echo(click.style("[!] POLICY NOTICE: Credential validation is prohibited by program policy. Disabling validation.", fg='yellow'))
            effective_policy.validate_keys = False
        elif quiet or no_prompt:
            if not quiet:
                click.echo(click.style("[!] SAFETY NOTICE: Interactive confirmation is required for active credential validation. Disabling validation in non-interactive mode.", fg='yellow'))
            effective_policy.validate_keys = False
        else:
            keyhacks_validator = KeyHacksValidator.from_policy(
                effective_policy=effective_policy,
                timeout=validate_timeout
            )
            keyhacks_validator.print_disclaimer()
            if not click.confirm(click.style('[?] Do you confirm you have explicit authorization to validate these secrets?', fg='yellow'), default=False):
                click.echo(click.style("[!] Key validation cancelled. Running passive recon only.", fg='yellow'))
                effective_policy.validate_keys = False

    # Instantiate managers
    header_mgr = cfg.get_header_manager()
    rate_limiter = effective_policy.request_policy_manager.global_limiter

    # Display configuration summary with sensitive values masked
    if not quiet:
        prog_display = f"{effective_policy.program_name} ({effective_policy.program_id})"
        click.echo()
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
        click.echo(click.style("│               🦇  SCAN CONFIGURATION SUMMARY                │", fg='green'))
        click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
        click.echo(click.style(f"│  Active Program: {prog_display[:42]:<43}│", fg='green'))
        click.echo(click.style(f"│  Target: {str(target or target_list or urls or offline)[:50]:<51}│", fg='green'))
        click.echo(click.style(f"│  Mode: {(mode or 'main').upper():<53}│", fg='green'))
        click.echo(click.style(f"│  Allowed Scope: {', '.join(scope_mgr.allowed_domains)[:43]:<44}│", fg='green'))
        click.echo(click.style(f"│  Excluded Scope: {', '.join(scope_mgr.excluded_domains)[:42]:<43}│", fg='green'))
        click.echo(click.style(f"│  Rate Limit: {f'{effective_policy.max_rps} requests/second':<47}│", fg='green'))
        click.echo(click.style(f"│  Concurrency: {effective_policy.concurrency:<46}│", fg='green'))
        click.echo(click.style(f"│  TLS Verification: {'Enabled (Strict)' if effective_policy.verify_tls else 'Disabled':<41}│", fg='green'))
        hdr_display = f"{cfg.header_name}: {header_mgr.get_masked_value()}" if header_mgr.is_active() else "Disabled"
        click.echo(click.style(f"│  Researcher Header: {hdr_display:<40}│", fg='green'))
        click.echo(click.style(f"│  Key Validation: {'Enabled' if effective_policy.validate_keys else 'Disabled (Safe by default)':<43}│", fg='green'))
        click.echo(click.style(f"│  Report Template: {effective_policy.default_template.upper():<42}│", fg='green'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))
        click.echo()

    # Confirmation before scanning in interactive mode
    if not no_prompt and not offline:
        if not click.confirm(click.style("[?] Ready to start reconnaissance?", fg="green"), default=True):
            click.echo(click.style("[!] Reconnaissance cancelled by user.", fg="yellow"))
            return

    # P0 Authentication Ordering: Validate credentials BEFORE constructing scanner or external tool processes
    try:
        if not offline:
            effective_policy.validate_ready_to_scan()
    except ValueError as auth_err:
        click.echo(click.style(f"\n[!] AUTHENTICATION ERROR: {auth_err}\n", fg='red', bold=True))
        sys.exit(1)

    # Initialize Scanner with Authoritative EffectivePolicy
    scanner = NightCrawlerScanner(
        concurrency=effective_policy.concurrency,
        timeout=effective_policy.timeout,
        depth=effective_policy.crawl_depth,
        use_external_tools=use_subdomains or use_archives,
        custom_patterns=patterns,
        verbose=verbose,
        validate=True,
        scope_manager=effective_policy.scope_manager,
        rate_limiter=rate_limiter,
        header_manager=header_mgr,
        max_requests_per_second=effective_policy.max_rps,
        verify_tls=effective_policy.verify_tls,
        strict_scope=effective_policy.strict_scope,
        javascript_extraction=effective_policy.permission_manager.is_permitted("javascript_analysis"),
        endpoint_discovery=effective_policy.permission_manager.is_permitted("endpoint_discovery"),
        secret_detection=effective_policy.permission_manager.is_permitted("secret_detection"),
        validate_keys=effective_policy.validate_keys,
        profile=active_profile,
        auth_manager=effective_policy.auth_manager,
        permission_manager=effective_policy.permission_manager,
        tool_compatibility_manager=effective_policy.tool_compatibility_manager,
        audit_logger=effective_policy.audit_logger,
        request_policy_manager=effective_policy.request_policy_manager,
        effective_policy=effective_policy
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

        # Report Generation
        default_out = output or f"report_{str(target or 'recon').replace('.', '_')}.{effective_policy.default_format}"
        output_path = Path(default_out)

        rep_manager = ReportManager(
            profile=active_profile,
            policy=effective_policy,
            reporter_name=effective_policy.reporter_name
        )
        valid_findings = [f for f in scanner.results.findings if f.validated]

        tools_status = scanner.tool_compatibility_manager.get_tool_audit_report() if scanner.tool_compatibility_manager else {}
        stats = scanner.request_policy_manager.get_statistics() if scanner.request_policy_manager else {}

        rep_manager.generate(
            findings=valid_findings,
            scan_result=scanner.results,
            output_path=str(output_path),
            tools_report=tools_status,
            stats=stats
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


# -------------------------------------------------------------
# Multi-Program CLI Subcommands
# -------------------------------------------------------------

@main.group(name='programs')
def programs_group():
    """Manage multi-program bug bounty profiles (list, show, validate, import, export, create, duplicate)."""
    pass


@programs_group.command(name='list')
def programs_list():
    """List all available bug bounty program profiles."""
    pm = ProgramManager()
    profiles = pm.list_profiles()

    if not profiles:
        click.echo("\nNo program profiles found in programs/ directory.")
        return

    click.echo("\n" + click.style("┌──────────────────────────────────────────────────────────────────────────────┐", fg="cyan"))
    click.echo(click.style("│                       📁  BUG BOUNTY PROGRAM PROFILES                        │", fg="cyan", bold=True))
    click.echo(click.style("├─────────────────┬──────────────────────────────┬──────────┬─────────┬────────┤", fg="cyan"))
    click.echo(click.style("│ Program ID      │ Name                         │ Platform │ Max RPS │ Status │", fg="cyan"))
    click.echo(click.style("├─────────────────┼──────────────────────────────┼──────────┼─────────┼────────┤", fg="cyan"))

    for p in profiles:
        status = click.style("✓ VALID", fg="green") if p["valid"] else click.style("✗ ERR", fg="red")
        if p.get("requires_review"):
            status = click.style("? REVIEW", fg="yellow")
        click.echo(f"│ {p['id']:<15} │ {p['name'][:28]:<28} │ {p['platform'][:8]:<8} │ {p['max_rps']:<7} │ {status} │")

    click.echo(click.style("└─────────────────┴──────────────────────────────┴──────────┴─────────┴────────┘\n", fg="cyan"))


@programs_group.command(name='show')
@click.argument('program_id')
def programs_show(program_id):
    """Show detailed policy and scope configuration for a program profile."""
    pm = ProgramManager()
    profile = pm.get_profile(program_id)
    if not profile:
        click.echo(click.style(f"\n❌ Error: Program profile '{program_id}' not found.\n", fg="red"))
        sys.exit(1)

    click.echo("\n" + click.style(f"=== Program Profile: {profile.name} ({profile.id}) ===", fg="cyan", bold=True))
    click.echo(f"Platform: {profile.platform} | Version: {profile.version}")
    if profile.policy_url:
        click.echo(f"Policy URL: {profile.policy_url}")
    if profile.description:
        click.echo(f"Description: {profile.description}")

    click.echo("\n" + click.style("[Scope Rules]", fg="yellow", bold=True))
    click.echo(f"  Allowed Domains: {', '.join(profile.scope.allowed_domains) or 'None'}")
    click.echo(f"  Excluded Domains: {', '.join(profile.scope.excluded_domains) or 'None'}")
    if profile.scope.allowed_cidrs:
        click.echo(f"  Allowed CIDRs: {', '.join(profile.scope.allowed_cidrs)}")
    if profile.scope.excluded_cidrs:
        click.echo(f"  Excluded CIDRs: {', '.join(profile.scope.excluded_cidrs)}")
    if profile.scope.excluded_paths:
        click.echo(f"  Excluded Paths: {', '.join(profile.scope.excluded_paths)}")
    if profile.scope.third_party_hosted_exclusions:
        click.echo(f"  Third-Party Exclusions: {', '.join(profile.scope.third_party_hosted_exclusions)}")

    click.echo("\n" + click.style("[Request Policy]", fg="yellow", bold=True))
    click.echo(f"  Max RPS: {profile.request_policy.max_rps}")
    click.echo(f"  Concurrency: {profile.request_policy.concurrency}")
    click.echo(f"  Timeout: {profile.request_policy.timeout}s")
    click.echo(f"  Strict Scope: {profile.request_policy.strict_scope}")
    click.echo(f"  Verify TLS: {profile.request_policy.verify_tls}")

    click.echo("\n" + click.style("[Headers & Authentication]", fg="yellow", bold=True))
    req_hdrs = profile.resolve_headers()
    click.echo(f"  Required Headers: {req_hdrs if req_hdrs else 'None'}")
    click.echo(f"  Auth Type: {profile.authentication.type}")

    click.echo("\n" + click.style("[Testing Permissions]", fg="yellow", bold=True))
    tpm = TestingPermissionManager.from_profile(profile)
    for act, perm in tpm.get_effective_permissions().items():
        st = click.style("PERMITTED", fg="green") if perm else click.style("PROHIBITED", fg="red")
        click.echo(f"  - {act:<25}: {st}")

    click.echo("\n" + click.style("[Tool Compatibility]", fg="yellow", bold=True))
    tcm = ToolCompatibilityManager(profile)
    for tool, info in tcm.get_tool_audit_report().items():
        st = click.style("ENABLED", fg="green") if info["compatible"] else click.style("DISABLED", fg="red")
        click.echo(f"  - {tool:<15}: {st} ({info['reason']})")
    click.echo()


@programs_group.command(name='validate')
@click.argument('program_id')
def programs_validate(program_id):
    """Validate a program profile against security policies and schema boundaries."""
    pm = ProgramManager()
    errors = pm.validate_profile(program_id)
    if errors:
        click.echo(click.style(f"\n❌ Validation failed for profile '{program_id}':", fg="red", bold=True))
        for err in errors:
            click.echo(click.style(f"   • {err}", fg="yellow"))
        click.echo()
        sys.exit(1)
    else:
        click.echo(click.style(f"\n✓ Program profile '{program_id}' is VALID and complies with all safety policies.\n", fg="green", bold=True))


@programs_group.command(name='create')
@click.argument('program_id')
@click.option('--name', default=None, help='Program display name')
@click.option('--domains', default='', help='Comma-separated allowed domains')
@click.option('--max-rps', default=5.0, type=float, help='Max requests per second')
def programs_create(program_id, name, domains, max_rps):
    """Create a new program profile template."""
    pm = ProgramManager()
    allowed = [d.strip() for d in domains.split(",") if d.strip()]
    data = {
        "id": program_id,
        "name": name or program_id.title(),
        "scope": {"allowed_domains": allowed},
        "request_policy": {"max_rps": max_rps}
    }
    try:
        profile = pm.create_profile(data, save=True)
        click.echo(click.style(f"\n✓ Created program profile '{profile.id}' at programs/{profile.id}/program.yaml\n", fg="green", bold=True))
    except Exception as e:
        click.echo(click.style(f"\n❌ Error creating profile: {e}\n", fg="red"))
        sys.exit(1)


@programs_group.command(name='import')
@click.argument('source_file')
def programs_import(source_file):
    """Import a program profile from YAML, JSON, or text rules."""
    pm = ProgramManager()
    try:
        profile = pm.import_profile(source_file)
        click.echo(click.style(f"\n✓ Successfully imported program '{profile.id}' ({profile.name}).", fg="green", bold=True))
        if profile.requires_review:
            click.echo(click.style("⚠️  Notice: Profile contains ambiguous rules that require review.", fg="yellow"))
            for n in profile.review_notes:
                click.echo(click.style(f"   - {n}", fg="yellow"))
        click.echo()
    except Exception as e:
        click.echo(click.style(f"\n❌ Error importing profile: {e}\n", fg="red"))
        sys.exit(1)


@programs_group.command(name='export')
@click.argument('program_id')
@click.argument('output_file')
def programs_export(program_id, output_file):
    """Export a program profile to YAML or JSON."""
    pm = ProgramManager()
    try:
        out_path = pm.export_profile(program_id, output_file)
        click.echo(click.style(f"\n✓ Exported profile '{program_id}' to {out_path}\n", fg="green"))
    except Exception as e:
        click.echo(click.style(f"\n❌ Error exporting profile: {e}\n", fg="red"))
        sys.exit(1)


@programs_group.command(name='duplicate')
@click.argument('source_id')
@click.argument('new_id')
def programs_duplicate(source_id, new_id):
    """Duplicate an existing program profile."""
    pm = ProgramManager()
    try:
        new_prof = pm.duplicate_profile(source_id, new_id)
        click.echo(click.style(f"\n✓ Duplicated profile '{source_id}' -> '{new_prof.id}'\n", fg="green"))
    except Exception as e:
        click.echo(click.style(f"\n❌ Error duplicating profile: {e}\n", fg="red"))
        sys.exit(1)


if __name__ == '__main__':
    main()
