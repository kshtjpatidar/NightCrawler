<div align="center">

# 🦇 NightCrawler

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=600&lines=Advanced+JS+Secret+Scanner;KeyHacks+Auto-Validation;Red+Team+Level+Tool;Built+for+Bug+Bounty+Hunters" alt="Typing SVG" />

<br>

[![Version](https://img.shields.io/badge/version-5.0-brightgreen.svg?style=for-the-badge)](https://github.com/kshtjpatidar/NightCrawler)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/kshtjpatidar/NightCrawler?style=for-the-badge&logo=github)](https://github.com/kshtjpatidar/NightCrawler)

<br>

**Hunt for secrets, API keys, and hidden endpoints in JavaScript files**

*Auto-validate discovered secrets using 75+ KeyHacks validators*

<br>

[📖 Documentation](#-usage) •
[🚀 Quick Start](#-quick-start) •
[🛠️ Installation](#-installation) •
[⚙️ Configuration](#-configuration)

</div>

---

## 🎬 Demo

```
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

┌─────────────────────────────────────────────────────────────┐
│ v5.0 │ Scope-Aware │ Max 5 RPS │ Bugcrowd VRT │ kshtjpatidar │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🛡️ Scope & Compliance
- **Strict Scope Enforcement**
- Domain & subdomain boundary validation
- Apex & subdomain exclusions (`tara.uxcam.com`, `connect.uxcam.com`)
- Lookalike domain rejection (`eviluxcam.com`)
- Strict URL scheme validation (`http`/`https` only)
- Hop-by-hop redirect verification
- Out-of-scope leak prevention across all modules

</td>
<td width="50%">

### ⏱️ Global Rate Limiting & TLS
- **Shared Token-Bucket Rate Limiter**
- Max 5 RPS limit shared across all async workers
- Token consumed on every HTTP attempt & retry
- Separate token consumed on every redirect hop
- Full TLS certificate verification (`verify_tls: true`)
- Rejection of insecure fallback in strict mode
- Uncoordinated external tools disabled in strict mode

</td>
</tr>
<tr>
<td width="50%">

### 🔍 Secret Detection
- **200+ Regex Patterns**
- AWS, Azure, GCP keys
- API tokens & secrets
- Passive discovery preserved
- **Automatic validation disabled by default**
- Sensitive values masked in logs & reports

</td>
<td width="50%">

### 🏷️ Researcher Identification
- **Configurable Header (`X-User-Id`)**
- Program policy compliant
- Configured via CLI, YAML, or ENV
- Passed via subprocess environment (`ps aux` safe)
- Dispatched only to authorized in-scope hosts
- Values masked in console and reports

</td>
</tr>
<tr>
<td width="50%">

### 🌐 Tool Integrations
- **Strict-Aware Integration Wrappers**
- Subfinder, Httpx, GAU, Waybackurls
- JSLuice AST analysis
- Out-of-scope domain filtering on ingestion
- Uncoordinated tools disabled in strict mode

</td>
<td width="50%">

### 📊 Reports
- **Bugcrowd VRT Default Template**
- HackerOne & Email templates also supported
- Structured findings: Preconditions, Steps, Impact
- Masked secret credentials (`AKIA***`)
- Masked researcher headers
- HTML and JSON export formats

</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
# Clone and enter directory
git clone https://github.com/kshtjpatidar/NightCrawler.git
cd NightCrawler

# Install dependencies
pip3 install -r requirements.txt

# Run interactive mode
python3 run.py
```

That's it! The interactive mode will guide you through everything. 🎉

---

## 🛠️ Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/kshtjpatidar/NightCrawler.git
cd NightCrawler
```

### Step 2: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

Required packages:
- `aiohttp` - Async HTTP client
- `rich` - Beautiful terminal UI
- `jsbeautifier` - JS beautification
- `click` - CLI framework

### Step 3: Install External Tools (Optional but Recommended)

<details>
<summary><b>📦 One-liner Install (All Tools)</b></summary>

```bash
# Install Go first (if not installed)
# https://golang.org/doc/install

# Install all tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
go install -v github.com/lc/gau/v2/cmd/gau@latest && \
go install -v github.com/tomnomnom/waybackurls@latest && \
go install -v github.com/lc/subjs@latest && \
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
go install -v github.com/hakluke/hakrawler@latest && \
go install -v github.com/003random/getJS@latest && \
go install -v github.com/tomnomnom/anew@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

</details>

<details>
<summary><b>📦 Individual Tool Installation</b></summary>

| Tool | Purpose | Install Command |
|------|---------|-----------------|
| **Subfinder** | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **Httpx** | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **Katana** | Web crawler | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **GAU** | Archive URLs | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| **Waybackurls** | Wayback Machine | `go install -v github.com/tomnomnom/waybackurls@latest` |
| **SubJS** | JS file fetcher | `go install -v github.com/lc/subjs@latest` |
| **JSLuice** | JS extractor | `go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| **Hakrawler** | Crawler | `go install -v github.com/hakluke/hakrawler@latest` |
| **GetJS** | JS extractor | `go install -v github.com/003random/getJS@latest` |
| **Anew** | Unique lines | `go install -v github.com/tomnomnom/anew@latest` |

</details>

### Step 4: Verify Installation

```bash
python3 run.py
```

The tool will show you which tools are found:

```
                          Tool Status                          
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool       ┃  Status  ┃ Path                                ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Subfinder  │ ✓ Found  │ /usr/bin/subfinder                  │
│ Httpx      │ ✓ Found  │ /usr/bin/httpx                      │
│ Katana     │ ✓ Found  │ ~/go/bin/katana                     │
│ GAU        │ ✓ Found  │ ~/go/bin/gau                        │
│ Waybackurls│ ✓ Found  │ ~/go/bin/waybackurls                │
└────────────┴──────────┴─────────────────────────────────────┘
```

---

## 📖 Usage

### 🎮 Interactive Mode (Recommended)

```bash
python3 run.py
```

**Flow:**
```
1. 🔍 Dependency Check     → Auto-checks all tools
2. 🎯 Enter Target         → example.com
3. ⚙️ Scan Mode            → [1] Main  [2] Subdomains  [3] Deep
4. 🛡️ Scope Enforcement   → Allowed/excluded domains configured
5. 🏷️ Researcher Header    → [y/n] e.g. X-User-Id: researcher@example.com
6. ⏱️ Rate Limiting        → Enforces max 5 RPS
7. 🔒 TLS Verification     → Strict certificate validation
8. 🔑 Validate Keys?       → [y/n] (Default: No / passive discovery)
9. 📄 Generate Report?     → [y/n]
10. 📋 Report Format       → [1] BugCrowd (default)  [2] HackerOne  [3] Email
11. ✍️ Your Name            → Hunter
12. 🚀 Start Scan!
```

### 💻 Command Line Mode

```bash
# Basic Bug Bounty Scan (UXCam Profile: Scope-enforced, 5 RPS, Researcher Header)
python3 main.py -t uxcam.com -o report.html

# Pass researcher ID securely via environment variable
export NIGHTCRAWLER_RESEARCHER_ID="researcher@example.com"
python3 main.py -t uxcam.com -o report.html

# Custom scope domains and explicit exclusions
python3 main.py -t uxcam.com \
  --scope-domains uxcam.com,uxc.am \
  --excluded-domains tara.uxcam.com,connect.uxcam.com \
  -o report.html

# Deep scan (rate-limited, passive archive extraction, strict scope)
python3 main.py -t uxcam.com --mode deep -o report.html

# Automated execution (no interactive prompts)
python3 main.py -t uxcam.com -o report.html --no-prompt
```

### 📋 All CLI Options

```
Usage: main.py [OPTIONS]

Options:
  -t, --target TEXT                  Target domain
  -l, --list PATH                    File with list of targets
  -u, --urls PATH                    File with JS URLs to scan
  -o, --output PATH                  Output file (.json or .html)
  -c, --concurrency INTEGER          Concurrent requests [default: 1]
  -d, --depth INTEGER                Crawl depth [default: 1]
  --timeout INTEGER                  Request timeout [default: 30]
  --max-rps FLOAT                    Max requests per second [default: 5.0]
  --scope-domains TEXT               Comma-separated allowed domains
  --excluded-domains TEXT            Comma-separated excluded domains
  --no-strict-scope                  Allow requests outside strict scope
  --no-verify-tls                    Disable TLS verification (blocked in strict mode)
  --header-name TEXT                 Custom researcher HTTP header name
  --header-value TEXT                Custom researcher HTTP header value
  --header-env TEXT                  Env var for header value [default: NIGHTCRAWLER_RESEARCHER_ID]
  --disable-header                   Disable researcher identification header
  --mode [main|subdomains|deep]      Scan mode [default: main]
  --validate-keys                    Auto-validate secrets against live APIs (disabled by default)
  --validate-timeout INTEGER         Validation timeout [default: 10]
  --template [bugcrowd|hackerone|email]  Report format [default: bugcrowd]
  --reporter TEXT                    Reporter name
  --program TEXT                     Bug bounty program name
  --no-prompt                        Skip interactive prompts
  -v, --verbose                      Verbose output
  -q, --quiet                        Only output findings
  --version                          Show version
  --help                             Show help
```

---

## ⚙️ Configuration

### config.yaml

```yaml
# Scope-aware, rate-limited recon for authorized bug bounty targets
scope:
  enabled: true
  allowed_domains:
    - uxcam.com
    - uxc.am

  excluded_domains:
    - tara.uxcam.com
    - connect.uxcam.com

researcher:
  custom_header_enabled: true
  header_name: X-User-Id
  header_value_env: NIGHTCRAWLER_RESEARCHER_ID

scan:
  concurrency: 1
  timeout: 30
  depth: 1
  max_requests_per_second: 5
  strict_scope: true
  verify_tls: true

features:
  javascript_extraction: true
  endpoint_discovery: true
  secret_detection: true
  validate_keys: false
  external_secret_validation: false

report:
  default_template: bugcrowd
  default_format: html
```

---

## 🔒 Security & Bug Bounty Compliance Architecture

NightCrawler v5.0 includes architecture designed specifically for bug bounty rules of engagement:

| Policy Requirement | Implementation Details |
|--------------------|------------------------|
| **Global Rate Limiting** | Centralized token-bucket rate limiter enforcing max 5 requests/sec across all concurrent asynchronous workers. A token is consumed before every initial request, retry, and redirect hop. |
| **Strict Scope Enforcement** | Subdomain and apex boundary parsing with exclusion matching. Prevents lookalike domain bypasses (`eviluxcam.com`). Enforced before any network request and on tool output. |
| **TLS Certificate Verification** | Standard SSL verification with zero silent insecure fallback. Insecure TLS (`verify_tls: false`) is strictly prohibited in strict compliance mode. |
| **Researcher Identification** | `X-User-Id` header sent **exclusively** to authorized in-scope targets. Passed via environment variables to subprocesses to prevent `ps aux` command-line disclosure. Masked in console logs and reports. |
| **KeyHacks Safety** | Automatic active credential validation against third-party APIs is **disabled by default**. Passive regex discovery is preserved, and credential values are masked in generated reports. |
| **Tool Orchestration** | External CLI crawlers that cannot guarantee rate limit coordination or header isolation (e.g. Katana, Hakrawler, SubJS, GetJS) are automatically disabled in strict compliance mode. Passive recon tools (Subfinder, GAU, Waybackurls, JSLuice) are strictly filtered against the scope manager on ingestion. |

---

## 📁 Project Structure

```
NightCrawler/
├── 📄 run.py                     # Interactive mode entry (subprocess env isolation)
├── 📄 main.py                    # CLI mode entry with strict compliance validation
├── 📄 requirements.txt           # Python dependencies
├── 📄 config.yaml                # Scope, rate limit, researcher header & report config
├── 📁 src/
│   ├── 📁 core/
│   │   ├── scanner.py            # Main scanning logic & scope orchestration
│   │   ├── scope.py              # ScopeManager (boundary, exclusion, lookalike checks)
│   │   ├── rate_limiter.py       # GlobalRateLimiter (token bucket, retry/redirect aware)
│   │   ├── header_manager.py     # HeaderManager (X-User-Id, env vars, masking)
│   │   └── http_client.py        # NightCrawlerHttpClient (strict TLS & rate limited)
│   ├── 📁 patterns/
│   │   └── secrets.py            # 200+ regex patterns for passive secret detection
│   ├── 📁 validators/
│   │   └── keyhacks.py           # KeyHacks validator (safe/passive by default)
│   ├── 📁 integrations/
│   │   └── tools.py              # External tool wrappers with strict mode compliance
│   ├── 📁 output/
│   │   ├── html_report.py        # Report generator (Bugcrowd VRT, masked secrets)
│   │   └── console.py            # Console output with credential masking
│   └── 📁 ui/
│       └── banner.py             # UI components
└── 📁 tests/                     # 31 automated security & compliance tests
```

---

## 📊 Scan Modes

| Mode | Description | Tools Used |
|------|-------------|------------|
| **Main** | Fast scan on main domain only | Katana, Internal patterns |
| **Subdomains** | Enumerate + scan all subdomains | Subfinder, Httpx, Katana |
| **Deep** | Full recon with archives | All tools: Subfinder, Httpx, Katana, GAU, Waybackurls, SubJS, etc. |

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE ONLY  ⚠️                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED security testing only:                ║
║                                                                              ║
║  ✅ Bug Bounty Programs (with explicit permission)                           ║
║  ✅ Authorized Penetration Testing                                           ║
║  ✅ Security Assessments (with signed authorization)                         ║
║                                                                              ║
║  ❌ Unauthorized access is ILLEGAL                                           ║
║  ❌ Using validated keys without permission is a CRIME                       ║
║                                                                              ║
║  The author is NOT responsible for any misuse of this tool.                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🤝 Contributing

Contributions are welcome! 

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file.

---

## 👨‍💻 Author

<div align="center">

**kshtjpatidar**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/kshtjpatidar)

*Keep Learning // Keep Hacking* 🦇

</div>

---

<div align="center">

**If you find this tool useful, please ⭐ star the repository!**

Made with ❤️ for the Bug Bounty Community

</div>
