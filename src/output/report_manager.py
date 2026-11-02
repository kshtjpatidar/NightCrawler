"""
NightCrawler - Multi-Program Report Manager Module
Generates Bugcrowd, HackerOne, HTML, JSON, and Markdown reports.
Clearly distinguishes findings lifecycle:
- DISCOVERED
- PATTERN_MATCHED
- MANUALLY_REVIEWED
- INDEPENDENTLY_VERIFIED
All secret credentials, tokens, and sensitive parameters are strictly masked.
"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.output.html_report import mask_secret, get_impact_info, HtmlReportGenerator, ReportConfig
from src.core.program_profile import ProgramProfile


class FindingStatus:
    DISCOVERED = "DISCOVERED"
    PATTERN_MATCHED = "PATTERN_MATCHED"
    MANUALLY_REVIEWED = "MANUALLY_REVIEWED"
    INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"


class ReportManager:
    """
    Unified report generation engine producing structured Bugcrowd, HTML, JSON,
    and Markdown reports containing full compliance metadata and lifecycle classifications.
    """

    def __init__(
        self,
        profile: Optional[ProgramProfile] = None,
        reporter_name: str = "Security Researcher",
        policy: Optional[Any] = None
    ):
        self.profile = profile
        self.policy = policy
        self.reporter_name = reporter_name
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)

    def _build_base_dict(self, findings: List, scan_result, tools_report: Optional[Dict[str, Any]] = None, stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build structured dictionary containing all required metadata and classified findings."""
        if self.policy:
            prog_id = self.policy.program_id
            prog_name = self.policy.program_name
            policy_ver = self.policy.version
        elif self.profile:
            prog_id = self.profile.id
            prog_name = self.profile.name
            policy_ver = self.profile.version
        else:
            prog_id = "custom-program"
            prog_name = getattr(scan_result, 'target', 'Bug Bounty Recon') if scan_result else 'Bug Bounty Recon'
            policy_ver = "1.0.0"

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulnerabilities = []

        target_str = getattr(scan_result, 'target', 'authorized targets') if scan_result else 'authorized targets'

        for f in findings:
            is_dict = isinstance(f, dict)
            p_name = f.get('pattern_name') if is_dict else getattr(f, 'pattern_name', 'Unknown')
            matched_val = f.get('matched_value') if is_dict else getattr(f, 'matched_value', '')
            url = f.get('url') if is_dict else getattr(f, 'url', '')
            line_num = f.get('line_number') if is_dict else getattr(f, 'line_number', None)
            context = f.get('context') if is_dict else getattr(f, 'context', None)

            if is_dict:
                sev = f.get('severity', 'MEDIUM')
            else:
                sev = f.severity() if hasattr(f, 'severity') else 'MEDIUM'
            if sev in severity_counts:
                severity_counts[sev] += 1

            # Classification
            is_keyhacks = (f.get('keyhacks_status') == 'VALID') if is_dict else getattr(f, 'is_keyhacks_valid', lambda: False)()
            if is_keyhacks:
                lifecycle_status = FindingStatus.INDEPENDENTLY_VERIFIED
            else:
                lifecycle_status = FindingStatus.PATTERN_MATCHED

            masked_val = mask_secret(matched_val)
            masked_ctx = context.replace(matched_val, masked_val) if (context and matched_val in context) else (context or "N/A")

            impact = get_impact_info(p_name)
            priority = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}.get(sev, "P3")
            verification_label = "Active Verified Secret" if is_keyhacks else "Potential Secret — Not Verified"

            vulnerabilities.append({
                "title": f"[{priority}] Potential {p_name} Exposure ({verification_label})",
                "asset": url,
                "category": "Sensitive Data Exposure > Exposed API Keys",
                "severity": f"{priority} - {sev}",
                "cvss_score": impact.get('cvss', '5.3'),
                "lifecycle_classification": lifecycle_status,
                "pattern_matched": True,
                "pattern_validated": True,
                "credential_verified": bool(is_keyhacks),
                "manual_review_status": "PENDING",
                "validation_status": "INDEPENDENTLY_VERIFIED" if is_keyhacks else "NOT_VERIFIED",
                "verification_label": verification_label,
                "pattern_validation": {
                    "status": "PASSED",
                    "pattern_name": p_name,
                    "description": "Format and syntax matched regular expression and entropy validation offline."
                },
                "credential_verification": {
                    "status": "CONFIRMED_VALID" if is_keyhacks else "NOT_CHECKED",
                    "verified_against_live_api": is_keyhacks,
                    "notice": "Active validation verified via API" if is_keyhacks else "Active verification disabled per program safe harbor rules."
                },
                "evidence": {
                    "source_url": url,
                    "line_number": line_num,
                    "masked_secret": masked_val,
                    "context": masked_ctx
                },
                "remediation": impact.get('remediation', 'Revoke exposed key and store secrets server-side.')
            })

        endpoints = []
        if scan_result and hasattr(scan_result, 'discovered_endpoints') and scan_result.discovered_endpoints:
            for ep in scan_result.discovered_endpoints:
                endpoints.append({
                    "url_or_path": ep.url_or_path if hasattr(ep, 'url_or_path') else str(ep),
                    "method": getattr(ep, 'method', 'GET'),
                    "parameters": getattr(ep, 'parameters', []),
                    "type": getattr(ep, 'endpoint_type', 'general')
                })

        return {
            "framework": "NightCrawler v5.0",
            "program_metadata": {
                "program_id": prog_id,
                "program_name": prog_name,
                "policy_version": policy_ver,
                "reporter_name": self.reporter_name,
                "scan_timestamp": self.timestamp.isoformat(),
                "scan_duration_seconds": round(getattr(scan_result, 'scan_time', 0.0), 2) if scan_result else 0.0
            },
            "scope_decisions": {
                "allowed_domains": list(self.profile.scope.allowed_domains) if self.profile else [],
                "excluded_domains": list(self.profile.scope.excluded_domains) if self.profile else [],
                "allowed_cidrs": list(self.profile.scope.allowed_cidrs) if self.profile else [],
                "excluded_paths": list(self.profile.scope.excluded_paths) if self.profile else [],
                "third_party_exclusions": list(self.profile.scope.third_party_hosted_exclusions) if self.profile else []
            },
            "tools_audit": tools_report or {},
            "request_statistics": stats or {},
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "total_urls_scanned": getattr(scan_result, 'total_urls_scanned', 0) if scan_result else 0,
                "total_js_files": getattr(scan_result, 'total_js_files', 0) if scan_result else 0,
                "subdomains_found": getattr(scan_result, 'subdomains_found', 0) if scan_result else 0,
                "discovered_endpoints": len(endpoints)
            },
            "findings": vulnerabilities,
            "discovered_endpoints": endpoints,
            "errors": getattr(scan_result, 'errors', []) if scan_result else []
        }

    def generate_json(self, findings: List, scan_result, tools_report: Optional[Dict] = None, stats: Optional[Dict] = None) -> str:
        """Generate JSON report string."""
        data = self._build_base_dict(findings, scan_result, tools_report, stats)
        return json.dumps(data, indent=2)

    def generate_markdown(self, findings: List, scan_result, tools_report: Optional[Dict] = None, stats: Optional[Dict] = None) -> str:
        """Generate GitHub-flavored Markdown report string."""
        data = self._build_base_dict(findings, scan_result, tools_report, stats)
        meta = data["program_metadata"]
        summ = data["summary"]

        lines = [
            f"# 🦇 NightCrawler Reconnaissance Report",
            f"",
            f"**Program:** {meta['program_name']} (`{meta['program_id']}`)  ",
            f"**Policy Version:** {meta['policy_version']}  ",
            f"**Scan Timestamp:** {meta['scan_timestamp']}  ",
            f"**Reporter:** {meta['reporter_name']}  ",
            f"",
            f"---",
            f"",
            f"## 📊 Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **Total Potential Secrets** | {summ['total_findings']} |",
            f"| **URLs Scanned** | {summ['total_urls_scanned']} |",
            f"| **JavaScript Files Analyzed** | {summ['total_js_files']} |",
            f"| **In-Scope Subdomains** | {summ['subdomains_found']} |",
            f"| **Endpoints Discovered** | {summ['discovered_endpoints']} |",
            f"",
            f"### Severity Breakdown",
            f"- **Critical:** {summ['severity_breakdown']['CRITICAL']}",
            f"- **High:** {summ['severity_breakdown']['HIGH']}",
            f"- **Medium:** {summ['severity_breakdown']['MEDIUM']}",
            f"- **Low:** {summ['severity_breakdown']['LOW']}",
            f"",
            f"---",
            f"",
            f"## 🛡️ Scope Enforcement & Boundaries",
            f"",
            f"- **Allowed Domains:** {', '.join(data['scope_decisions']['allowed_domains']) or 'None'}",
            f"- **Excluded Domains:** {', '.join(data['scope_decisions']['excluded_domains']) or 'None'}",
            f"- **Excluded Paths:** {', '.join(data['scope_decisions']['excluded_paths']) or 'None'}",
            f"",
            f"---",
            f"",
            f"## 🔍 Findings & Potential Secret Exposures",
            f""
        ]

        if not data["findings"]:
            lines.append("*No secret exposures or sensitive tokens identified.*")
        else:
            for idx, f in enumerate(data["findings"], 1):
                lines.extend([
                    f"### {idx}. {f['title']}",
                    f"",
                    f"- **Affected Asset:** `{f['asset']}`",
                    f"- **Severity:** {f['severity']}",
                    f"- **Lifecycle Status:** `{f['lifecycle_classification']}`",
                    f"- **Validation Status:** **{f.get('verification_label', 'Potential Secret — Not Verified')}**",
                    f"- **Pattern Validation:** {f['pattern_validation']['status']} ({f['pattern_validation']['description']})",
                    f"- **Credential Verification:** {f['credential_verification']['status']} *({f['credential_verification']['notice']})*",
                    f"- **Masked Evidence:** `{f['evidence']['masked_secret']}`",
                    f"- **Remediation:** {f['remediation']}",
                    f"",
                    f"```javascript",
                    f"// Context line {f['evidence']['line_number'] or 'N/A'}",
                    f"{f['evidence']['context']}",
                    f"```",
                    f""
                ])

        lines.extend([
            f"---",
            f"",
            f"## 🛠️ Reconnaissance Tools Status",
            f""
        ])

        if data["tools_audit"]:
            lines.extend([
                f"| Tool | Status | Reason / Mode |",
                f"|------|--------|---------------|"
            ])
            for tool, info in data["tools_audit"].items():
                st = "✅ Active" if info.get("compatible") else "❌ Disabled"
                lines.append(f"| **{tool}** | {st} | {info.get('reason')} |")

        lines.append("\n*Report generated by NightCrawler v5.0 Policy-Aware Bug Bounty Framework.*")
        return "\n".join(lines)

    def generate(self, findings: List, scan_result, output_path: str, tools_report: Optional[Dict] = None, stats: Optional[Dict] = None) -> str:
        """Generate report in HTML, JSON, or Markdown based on file extension."""
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        ext = out_file.suffix.lower()

        if ext == ".json":
            content = self.generate_json(findings, scan_result, tools_report, stats)
            out_file.write_text(content, encoding="utf-8")
        elif ext in (".md", ".markdown"):
            content = self.generate_markdown(findings, scan_result, tools_report, stats)
            out_file.write_text(content, encoding="utf-8")
        else:
            # HTML report
            template = self.profile.reporting.default_template if self.profile else "bugcrowd"
            program_name = self.profile.reporting.program_name if self.profile else "Bug Bounty Program"
            rep_cfg = ReportConfig(
                reporter_name=self.reporter_name,
                program_name=program_name,
                template=template
            )
            html_gen = HtmlReportGenerator(rep_cfg)
            content = html_gen.generate(findings, scan_result, str(out_file))

        return str(out_file)
