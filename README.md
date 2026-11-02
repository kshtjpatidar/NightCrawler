<div align="center">

# 🦇 NightCrawler

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=600&lines=Multi-Program+Recon+Framework;Policy-Aware+Scope+Enforcement;Strict+Rate+Limiting+%26+Audit;Built+for+Bug+Bounty+Hunters" alt="Typing SVG" />

<br>

[![Version](https://img.shields.io/badge/version-5.0-brightgreen.svg?style=for-the-badge)](https://github.com/kshtjpatidar/NightCrawler)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/kshtjpatidar/NightCrawler?style=for-the-badge&logo=github)](https://github.com/kshtjpatidar/NightCrawler)

<br>

**Multi-Program, Policy-Aware Bug Bounty Reconnaissance & Secret Discovery Framework**

*Dynamically adapts scope, rate limits, headers, authentication, and tool capabilities to program policies*

<br>

[📖 Documentation](#-multi-program-framework-architecture) •
[🚀 Quick Start](#-quick-start) •
[🛠️ Installation](#-installation) •
[⚙️ Program Profiles](#-program-profiles) •
[🛡️ Scope & Policies](#-scope-configuration) •
[💻 CLI & Menu](#-usage--cli-commands)

</div>

---

## 🎬 Framework Overview

```
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

┌────────────────────────────────────────────────────────────────────────────────────────┐
│ v5.0 │ Multi-Program │ Policy-Aware Scope │ Strict Rate Limits │ Safe Harbor Reporting │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

NightCrawler v5.0 is a modular bug bounty reconnaissance framework. Rather than permanently hardcoding targets, NightCrawler automatically loads **program profiles** containing policy rules: allowed domains, wildcard subdomains, IP ranges, CIDR blocks, path exclusions, third-party hosted service exclusions, strict request limits, required headers, authentication tokens, and authorized testing permissions.

---

## 🏛️ Multi-Program Framework Architecture

```mermaid
flowchart TD
    Profile[Program Profile YAML/JSON] --> PM[ProgramManager]
    PM --> PolicyVal[PolicyValidator]
    PolicyVal --> CLI[CLI Options & Overrides]
    CLI --> EffPol[EffectivePolicy\n(Single Authoritative Source of Truth)]
    
    EffPol --> SM[ScopeManager\n(Exact & Wildcard Domains, CIDRs, Paths)]
    EffPol --> RPM[RequestPolicyManager\n(Global & Per-Host Rate Limits)]
    EffPol --> AM[AuthenticationManager\n(Headers, Bearer, Cookies, Isolation)]
    EffPol --> TPM[TestingPermissionManager\n(Safety Ceilings)]
    EffPol --> TCM[ToolCompatibilityManager\n(Capability Matrix)]
    
    SM & RPM & AM --> Client[NightCrawlerHttpClient\n(Hop-by-Hop Redirect Checks & Token Pacing)]
    Client --> Audit[AuditLogger\n(Structured JSONL Logs with Redaction)]
    Client --> Engine[NightCrawlerScanner]
    TPM & TCM --> Engine
    Engine --> RepM[ReportManager\n(HTML, JSON, Markdown with Lifecycle Classification)]
```

### Core Architecture Components

| Component | Responsibility |
|-----------|----------------|
| **`ProgramManager`** | Discovers, loads, validates, duplicates, imports, and exports program profiles in `programs/`. |
| **`ProgramProfile`** | Typed data model encapsulating scope, rate limits, headers, authentication, testing permissions, and reporting options. |
| **`PolicyParser`** | Parses policies from YAML, JSON, or text rules, expanding environment variables (`${VAR}`) and flagging ambiguous rules for review. |
| **`PolicyValidator`** | Enforces fail-closed validation: rejects non-positive/NaN rates, verifies CIDR/IP syntax, and permanently blocks destructive or DoS actions. |
| **`ScopeManager`** | Suffix-boundary domain matching, wildcard support, IP/CIDR checking, path allowlists/exclusions, port/protocol checks, and third-party SaaS exclusions. |
| **`RequestPolicyManager`** | Coordinates global rate limiting, per-host limits, concurrency semaphores, retry/redirect accounting, and exponential backoff. |
| **`AuthenticationManager`** | Securely injects Bearer tokens, API keys, cookies, or basic auth. Prevents forwarding credentials to out-of-scope hosts or on redirects. |
| **`TestingPermissionManager`** | Evaluates active/passive testing permissions. Enforces global safety ceilings (destructive actions and DoS are impossible to enable). |
| **`ToolCompatibilityManager`** | Inspects tool capabilities (Katana, Subfinder, GAU, Waybackurls, JSLuice, etc.) and auto-disables incompatible tools in strict mode. |
| **`AuditLogger`** | Writes structured audit trails (`logs/audit.jsonl`) recording every request, policy check, and scope decision with sensitive parameters redacted. |
| **`ReportManager`** | Generates Bugcrowd, HTML, JSON, and Markdown reports classifying findings as `DISCOVERED`, `PATTERN_MATCHED`, or `INDEPENDENTLY_VERIFIED`. |

---

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/kshtjpatidar/NightCrawler.git
cd NightCrawler

# Install Python dependencies
pip3 install -r requirements.txt

# Run interactive menu (Program Selection & Management)
python3 run.py
```

---

## 🛠️ Installation

### 1. Requirements
- Python 3.8+
- Go 1.19+ (optional, for external recon integrations)

```bash
pip3 install -r requirements.txt
```

### 2. External Tools (Optional)
NightCrawler works standalone using its built-in async HTTP crawler and regex engine. External tools are automatically evaluated by the `ToolCompatibilityManager`:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest
```

---

## 📁 Program Profiles

Program profiles are stored in the `programs/` directory:

```
programs/
├── uxcam/
│   └── program.yaml        # Dedicated UXCam Bug Bounty profile (Max 5 RPS, X-User-Id)
└── example-program/
    └── program.yaml        # Demonstration profile with CIDR, IP & path exclusions
```

### Example Profile (`programs/example-program/program.yaml`)

```yaml
id: example-program
name: "Example Security Program"
version: "1.0.0"
platform: "HackerOne"
policy_url: "https://hackerone.com/example"
description: "Demonstration profile for multi-program reconnaissance testing."

scope:
  enabled: true
  allowed_domains:
    - "example.com"
    - "*.example.com"
  excluded_domains:
    - "out-of-scope.example.com"
    - "*.out-of-scope.example.com"
  allowed_ips:
    - "192.168.1.100"
  allowed_cidrs:
    - "10.0.0.0/24"
  excluded_ips:
    - "10.0.0.254"
  excluded_cidrs:
    - "10.0.0.128/25"
  allowed_paths: []
  excluded_paths:
    - "/logout"
    - "/delete-account"
    - "/admin/destroy"
  allowed_protocols:
    - "http"
    - "https"
  allowed_ports:
    - 80
    - 443
    - 8443
  third_party_hosted_exclusions:
    - "support.example.com"

request_policy:
  max_rps: 10.0
  concurrency: 2
  timeout: 25
  max_retries: 2
  crawl_depth: 2
  burst: 2
  verify_tls: true
  strict_scope: true
  per_host_rps: 5.0

headers:
  required:
    X-Bug-Bounty: "${RESEARCHER_NAME}"
  optional:
    X-Security-Scan: "NightCrawler-v5"

authentication:
  type: "bearer"
  token_env: "EXAMPLE_API_TOKEN"
  header_name: "Authorization"
  header_prefix: "Bearer "

testing_permissions:
  passive_recon: true
  active_recon: true
  endpoint_discovery: true
  javascript_analysis: true
  secret_detection: true
  credential_validation: false
  fuzzing: false
  injection_testing: false
  destructive_testing: false
  denial_of_service: false
  social_engineering: false

tool_restrictions:
  allowed_tools:
    - "subfinder"
    - "httpx"
    - "gau"
    - "waybackurls"
    - "jsluice"
  disabled_tools:
    - "katana"
    - "hakrawler"

reporting:
  default_template: "hackerone"
  default_format: "html"
  program_name: "Example Security Program"
```

---

## 🛡️ Scope Configuration

NightCrawler's `ScopeManager` enforces comprehensive boundaries:

- **Exact Hostname Matching**: An entry like `example.com` matches **only** the bare apex hostname `example.com`. It does **not** match subdomains unless explicitly paired with a wildcard.
- **Wildcard Subdomains**: An entry like `*.example.com` matches all subdomains (e.g., `app.example.com`, `api.v1.example.com`). It does **not** match the bare apex unless `example.com` is also listed.
- **Suffix-Boundary Lookalike Protection**: Strict DNS label checks ensure that lookalike domains (`evil-example.com`, `notexample.com`, `example.com.attacker.com`) are mathematically impossible to match.
- **Exclusions Override Inclusions**: Excluded domains (e.g., `tara.uxcam.com`) reject both the host and all its subdomains (`*.tara.uxcam.com`), even if a parent wildcard was allowed.
- **IP & CIDR Ranges**: Validates targets against allowed CIDRs (`10.0.0.0/24`) while respecting excluded subnets (`10.0.0.128/25`) and specific IPs (`10.0.0.254`).
- **Path Restrictions**: Prohibits scanning dangerous or state-changing paths (e.g. `/logout`, `/delete-account`).
- **Third-Party Hosted Services**: First-party subdomains hosted on external SaaS (e.g. Zendesk on `help.uxcam.com`, Medium on `blog.uxcam.com`) are explicitly excluded.
- **Fail-Closed Principle**: If scope is ambiguous, the asset is skipped. Exclusions always override inclusions.

---

## 🔄 Migration Guide (From UXCam-Only Configuration)

NightCrawler v5.0 transitions from a hardcoded single-target engine to a multi-program framework:

1. **Dedicated Program Profiles**: Target policies now reside in `programs/<program_id>/program.yaml`. The UXCam program is preserved in `programs/uxcam/program.yaml`.
2. **Backwards Compatibility**: Existing `config.yaml` files continue to load as fallback defaults. If you have customized `config.yaml`, NightCrawler merges its parameters into an active `custom-target` profile without data loss.
3. **Automatic Backup**: Backups of legacy configuration files are preserved before any programmatic overwrite.
4. **Selecting Profiles**: Simply pass `--program <id>` or select option `[1]` in `python3 run.py`:
   ```bash
   python3 main.py --program uxcam -t uxcam.com
   ```
5. **Exact vs. Wildcard Upgrades**: When migrating domain lists, specify both `domain.com` (for apex) and `*.domain.com` (for subdomains) to ensure comprehensive reconnaissance coverage.

---

## ⏱️ Request Policies & Rate Limiting

- **Strictest Limit Wins**: The engine calculates the minimum between the program's policy limit and operator CLI overrides.
- **Per-Attempt Token Consumption**: Every initial request, retry, and redirect hop consumes a token from the shared bucket.
- **Per-Host Pacing**: Optional `per_host_rps` prevents overwhelming single servers even when total concurrency is higher.
- **Exponential Backoff**: Automatic backoff with jitter on HTTP 429 and transient 5xx errors.
- **Sanity Checks**: Non-positive, zero, NaN, and Infinity rates are immediately rejected.
- **UXCam Hard Limit**: UXCam profile enforces a hard maximum ceiling of 5.0 RPS.

---

## 🔑 Authentication & Credential Isolation

- **Secure Environment Resolution**: Credentials like tokens and researcher IDs are loaded via `${ENV_VAR}` syntax.
- **Credential Boundary Protection**: Program headers, Bearer tokens, API keys, and cookies are dispatched **exclusively** to authorized in-scope destinations.
- **Redirect Protection**: If an in-scope request is redirected to an out-of-scope destination or third-party service, credentials are automatically stripped.
- **Session File Security**: Session files must possess `0600` permissions (owner read/write only); group/world readable files are rejected with a security error.
- **Zero Process Table Leakage**: Tokens are passed to subprocesses via environment variables, avoiding command-line argument exposure in `ps aux`.

---

## ⚙️ Testing Permissions & Safety Ceilings

Every reconnaissance module checks authorization before execution:

- `passive_recon`: Ingestion from archives, DNS APIs, and AST parsing.
- `active_recon`: Outbound HTTP crawling and endpoint fetching.
- `endpoint_discovery`: Regex/AST route extraction.
- `secret_detection`: Passive pattern matching.
- `credential_validation`: Active testing against live APIs (**disabled by default**; requires both profile permission and explicit CLI authorization).
- `destructive_testing`: **Permanently prohibited** (cannot be enabled by policy).
- `denial_of_service`: **Permanently prohibited** (cannot be enabled by policy).

---

## 💻 Usage & CLI Commands

### 1. Profile Management Commands

```bash
# List all configured program profiles
python3 main.py programs list

# Show detailed policy and scope for a profile
python3 main.py programs show uxcam
python3 main.py programs show example-program

# Validate a profile against safety boundaries
python3 main.py programs validate uxcam

# Create a new program profile
python3 main.py programs create my-program --name "My Bounty" --domains "myprogram.com" --max-rps 5.0

# Import policy from YAML, JSON, or unstructured rules text
python3 main.py programs import /path/to/rules.yaml

# Export a profile to JSON or YAML
python3 main.py programs export uxcam ./uxcam_backup.json

# Duplicate a profile
python3 main.py programs duplicate uxcam uxcam-staging
```

### 2. Reconnaissance Scan Commands

```bash
# Run reconnaissance using a specific program profile
python3 main.py --program uxcam -t uxcam.com -o report.html

# Run with environment-passed researcher header
export NIGHTCRAWLER_RESEARCHER_ID="researcher@example.com"
python3 main.py --program uxcam -t uxcam.com

# Deep scan with passive archives and AST extraction
python3 main.py --program uxcam -t uxcam.com --mode deep -o report.json

# Export report in Markdown format
python3 main.py --program uxcam -t uxcam.com -o report.md

# Scan list of targets
python3 main.py --program uxcam -l targets.txt -o report.html
```

---

## 🎮 Interactive Menu

Launch the full interactive control center:

```bash
python3 run.py
```

**Control Center Options:**
```
[1]  Select program                 → Switch active bug bounty program profile
[2]  List programs                  → View summary table of all loaded profiles
[3]  Create program profile         → Interactive profile creator
[4]  Import policy                  → Import from YAML, JSON, or policy text
[5]  Validate program policy        → Verify compliance against safety rules
[6]  View program scope             → Inspect domains, CIDRs, and exclusions
[7]  Configure authentication       → Configure Bearer tokens, API keys, or cookies
[8]  Configure request limits       → Adjust RPS and concurrency
[9]  Select reconnaissance modules  → Inspect tool compatibility matrix
[10] Start reconnaissance           → Run live scan with confirmation prompt
[11] View reports                   → Browse generated HTML, JSON, and Markdown reports
[12] View audit logs                → Review recent security audit trail
[13] Run tests                      → Run the automated test suite
[14] Exit                           → Quit
```

---

## 📊 Reports & Finding Lifecycle

NightCrawler reports clearly classify findings across their lifecycle to distinguish passive observations from confirmed vulnerabilities:

- **`DISCOVERED`**: Endpoint or asset URL found during crawling or archive parsing.
- **`PATTERN_MATCHED`**: String matched syntax, format, and entropy checks offline.
- **`MANUALLY_REVIEWED`**: Finding triaged by security analyst.
- **`INDEPENDENTLY_VERIFIED`**: Credential confirmed valid via authorized active validation.

Supported formats:
- **Bugcrowd VRT HTML**: Ready-to-submit bug bounty report format.
- **JSON**: Machine-readable format with `pattern_validation` and `credential_verification` separation.
- **Markdown (`.md`)**: GitHub-flavored report format for developer documentation.

*All sensitive secrets and researcher header tokens are strictly masked in all reports.*

---

## 🧪 Automated Testing

NightCrawler includes a test suite covering program profiles, scope matching, rate limits, credential isolation, tool compatibility, and audit logging:

```bash
python3 -m pytest tests/ -v
```

```
============================== 59 passed in 3.92s ==============================
```

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE ONLY  ⚠️                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED security testing only:                 ║
║  ✅ Bug Bounty Programs (with explicit scope and policy authorization)       ║
║  ✅ Authorized Penetration Testing                                            ║
║  ✅ Red Team Engagements (with signed rules of engagement)                    ║
║                                                                              ║
║  ❌ Unauthorized scanning, credential usage, or DoS is strictly ILLEGAL.      ║
║  The author is NOT responsible for misuse of this tool.                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 👨‍💻 Author

<div align="center">

**kshtjpatidar**  
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/kshtjpatidar)

*Keep Learning // Keep Hacking* 🦇

</div>
