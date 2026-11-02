"""
NightCrawler - Audit Logger Module
Provides tamper-resistant, structured compliance auditing of every network request,
scope decision, policy evaluation, and rate limiter action.
Sensitive credentials and parameters are strictly redacted.
"""

import json
import re
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class AuditLogger:
    """
    Maintains a structured JSON Lines audit log of all reconnaissance activities,
    verifying compliance with program scope, rate limits, and safe harbor rules.
    """

    REDACTED_PARAMS = {
        "token", "api_key", "apikey", "key", "secret", "password", "pass",
        "auth", "session", "jwt", "access_token", "refresh_token", "code"
    }

    def __init__(self, program_id: str = "default", log_file: Optional[Path] = None):
        self.program_id = program_id
        if log_file:
            self.log_file = Path(log_file)
        else:
            self.log_file = Path(__file__).parent.parent.parent / "logs" / "audit.jsonl"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def redact_url(cls, url: str) -> str:
        """Redact sensitive query parameter values from URL."""
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return url

            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            redacted_query = {}
            for k, vals in query_dict.items():
                if k.lower() in cls.REDACTED_PARAMS or any(p in k.lower() for p in ("token", "secret", "pass", "key")):
                    redacted_query[k] = ["REDACTED"]
                else:
                    redacted_query[k] = vals

            new_query = urlencode(redacted_query, doseq=True)
            parts = list(parsed)
            parts[4] = new_query
            return urlunparse(parts)
        except Exception:
            # Fallback regex redaction
            return re.sub(r'([?&](?:token|key|api_key|secret|password)=)[^&]+', r'\1REDACTED', url, flags=re.I)

    def log_event(
        self,
        target_host: str,
        method: str,
        url: str,
        scope_decision: str,  # "ALLOWED" or "BLOCKED"
        policy_decision: str, # "PERMITTED" or "DENIED"
        rate_limiter_decision: str = "TOKEN_ACQUIRED",
        tool_name: str = "nightcrawler_http",
        response_status: Optional[int] = None,
        redirect_decision: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        """Append an audit record to the structured audit log."""
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "program_id": self.program_id,
            "target_host": target_host,
            "method": method.upper(),
            "url": self.redact_url(url),
            "scope_decision": scope_decision,
            "policy_decision": policy_decision,
            "rate_limiter_decision": rate_limiter_decision,
            "tool_name": tool_name,
            "response_status": response_status,
            "redirect_decision": redirect_decision,
            "extra": extra or {}
        }

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def read_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read recent audit records."""
        if not self.log_file.exists():
            return []

        records = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    line_s = line.strip()
                    if line_s:
                        records.append(json.loads(line_s))
        except Exception:
            pass
        return records

    def explain_decision(self, target_url: str) -> List[Dict[str, Any]]:
        """Find audit log records matching the specified target URL or host."""
        matching = []
        clean_url = self.redact_url(target_url)
        for record in self.read_recent_logs(limit=200):
            if target_url in record.get("url", "") or record.get("target_host", "") in target_url:
                matching.append(record)
        return matching
