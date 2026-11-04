"""
NightCrawler v3.0 - KeyHacks Auto-Validator
Automatically validate discovered secrets using API calls
Based on: https://github.com/streaak/keyhacks

⚠️ ETHICAL USE ONLY ⚠️
This tool is designed for:
- Bug Bounty Programs (with explicit permission)
- Authorized Security Assessments
- Penetration Testing (with signed authorization)

DO NOT use this tool for unauthorized access or malicious purposes.
The author is not responsible for any misuse of this tool.

by kshtjpatidar | Keep Learning // Keep Hacking
"""

import subprocess
import asyncio
import aiohttp
import json
import re
from typing import Dict, Optional, Tuple, List, Any, Set
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from rich.console import Console

from src.core.http_client import _in_concurrency_scope, PolicyAwareResolver
from src.core.audit_logger import AuditLogger
from src.output.html_report import mask_secret

console = Console()


class KeyHacksPolicyError(ValueError):
    """Raised when mandatory policy dependencies are missing or violated in KeyHacksValidator."""
    pass


class ValidationSideEffect(str, Enum):
    """Classification of validator side effects."""
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class ValidationStatus(Enum):
    """Validation result status"""
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    PARTIAL = "PARTIAL"  # Some permissions work


@dataclass
class ValidationResult:
    """Result of secret validation"""
    status: ValidationStatus
    message: str
    permissions: Optional[List[str]] = None
    raw_response: Optional[str] = None
    validation_command: Optional[str] = None


# ============================================
# KEYHACKS VALIDATION DATABASE
# 50+ API validation commands
# ============================================

KEYHACKS_VALIDATORS = {
    # ==========================================
    # CLOUD PROVIDERS
    # ==========================================
    
    "AWS Access Key": {
        "type": "command",
        "command": "AWS_ACCESS_KEY_ID={key} AWS_SECRET_ACCESS_KEY={secret} aws sts get-caller-identity --output json 2>/dev/null",
        "success_indicators": ["Account", "UserId", "Arn"],
        "failure_indicators": ["InvalidClientTokenId", "SignatureDoesNotMatch"],
        "requires_pair": True,
        "pair_pattern": "AWS Secret Key",
        "description": "Validates AWS credentials by calling STS GetCallerIdentity",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "aws"
    },
    
    "Google API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key}",
        "success_indicators": ["audience", "scope", "expires_in"],
        "failure_indicators": ["invalid_token", "Invalid Value"],
        "alt_validation": {
            "url": "https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}",
            "success_indicators": ["results", "status"],
            "failure_indicators": ["REQUEST_DENIED", "InvalidKeyMapError"]
        },
        "description": "Validates Google API key using OAuth tokeninfo or Maps API",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "google"
    },
    
    "Firebase Key": {
        "type": "http",
        "method": "POST",
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}",
        "headers": {"Content-Type": "application/json"},
        "body": "{}",
        "success_indicators": ["idToken", "refreshToken", "kind"],
        "failure_indicators": ["API_KEY_INVALID", "INVALID_API_KEY"],
        "description": "Validates Firebase API key by attempting anonymous signup",
        "side_effect": ValidationSideEffect.STATE_CHANGING,
        "provider": "firebase"
    },
    
    # ==========================================
    # PAYMENT PROCESSORS
    # ==========================================
    
    "Stripe Live Secret Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.stripe.com/v1/charges",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["data", "object", "has_more"],
        "failure_indicators": ["Invalid API Key", "api_key_expired"],
        "description": "Validates Stripe key by listing charges",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "stripe"
    },
    
    "Stripe Test Secret Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.stripe.com/v1/charges",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["data", "object"],
        "failure_indicators": ["Invalid API Key"],
        "description": "Validates Stripe test key (less critical but still validates)",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "stripe"
    },
    
    "PayPal Braintree Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.braintreegateway.com/merchants/{merchant_id}",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["merchant", "id"],
        "failure_indicators": ["Unauthorized", "Invalid"],
        "description": "Validates Braintree/PayPal token"
    },
    
    "Square Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://connect.squareup.com/v2/locations",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["locations"],
        "failure_indicators": ["UNAUTHORIZED", "AUTHENTICATION_ERROR"],
        "description": "Validates Square API token by listing locations"
    },
    
    "Razorpay API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.razorpay.com/v1/payments",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["entity", "count", "items"],
        "failure_indicators": ["BAD_REQUEST_ERROR", "Unauthorized"],
        "description": "Validates Razorpay API key and secret"
    },
    
    # ==========================================
    # SOURCE CONTROL & CI/CD
    # ==========================================
    
    "GitHub PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://api.github.com/user",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/vnd.github+json"},
        "success_indicators": ["login", "id", "email"],
        "failure_indicators": ["Bad credentials", "Requires authentication"],
        "permission_check": {
            "url": "https://api.github.com/rate_limit",
            "headers": {"Authorization": "Bearer {key}"},
            "scope_header": "X-OAuth-Scopes"
        },
        "description": "Validates GitHub token and checks scopes",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "github"
    },
    
    "GitHub Personal Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.github.com/user",
        "headers": {"Authorization": "token {key}"},
        "success_indicators": ["login", "id"],
        "failure_indicators": ["Bad credentials"],
        "description": "Validates GitHub classic PAT",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "github"
    },
    
    "GitLab PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://gitlab.com/api/v4/user",
        "headers": {"PRIVATE-TOKEN": "{key}"},
        "success_indicators": ["id", "username", "email"],
        "failure_indicators": ["401 Unauthorized"],
        "description": "Validates GitLab personal access token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "gitlab"
    },
    
    "CircleCI Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://circleci.com/api/v1.1/me?circle-token={key}",
        "success_indicators": ["name", "login", "id"],
        "failure_indicators": ["Permission denied", "Must provide API token"],
        "description": "Validates CircleCI API token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "circleci"
    },
    
    "Travis CI API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.travis-ci.com/user",
        "headers": {"Travis-API-Version": "3", "Authorization": "token {key}"},
        "success_indicators": ["@type", "id", "login"],
        "failure_indicators": ["access denied", "insufficient_access"],
        "description": "Validates Travis CI API token"
    },
    
    "NPM Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://registry.npmjs.org/-/npm/v1/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["name", "email"],
        "failure_indicators": ["Unauthorized", "invalid token"],
        "description": "Validates NPM access token"
    },
    
    # ==========================================
    # MESSAGING & COMMUNICATION
    # ==========================================
    
    "Slack Bot Token": {
        "type": "http",
        "method": "POST",
        "url": "https://slack.com/api/auth.test",
        "headers": {"Authorization": "Bearer {key}", "Content-Type": "application/json"},
        "success_indicators": ["ok", "user", "team"],
        "failure_indicators": ["invalid_auth", "not_authed"],
        "description": "Validates Slack bot token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "slack"
    },
    
    "Slack User Token": {
        "type": "http",
        "method": "POST",
        "url": "https://slack.com/api/auth.test",
        "data": {"token": "{key}"},
        "success_indicators": ["ok", "user_id"],
        "failure_indicators": ["invalid_auth"],
        "description": "Validates Slack user token (xoxp)",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "slack"
    },
    
    "Slack Webhook": {
        "type": "http",
        "method": "POST",
        "url": "{key}",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text":""}',
        "success_indicators": ["missing_text_or_fallback_or_attachments"],
        "failure_indicators": ["invalid_payload", "channel_not_found", "Webhook URL"],
        "description": "Validates Slack webhook by sending empty message",
        "side_effect": ValidationSideEffect.STATE_CHANGING,
        "provider": "slack"
    },
    
    "Discord Webhook": {
        "type": "http",
        "method": "GET",
        "url": "{key}",
        "success_indicators": ["id", "token", "name", "channel_id"],
        "failure_indicators": ["Unknown Webhook", "Invalid Webhook Token"],
        "description": "Validates Discord webhook by GET request",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "discord"
    },
    
    "Discord Bot Token": {
        "type": "http",
        "method": "GET",
        "url": "https://discord.com/api/v10/users/@me",
        "headers": {"Authorization": "Bot {key}"},
        "success_indicators": ["id", "username", "discriminator"],
        "failure_indicators": ["401: Unauthorized", "Invalid Token"],
        "description": "Validates Discord bot token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "discord"
    },
    
    "Telegram Bot Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.telegram.org/bot{key}/getMe",
        "success_indicators": ["ok", "result", "username"],
        "failure_indicators": ["Not Found", "Unauthorized"],
        "description": "Validates Telegram bot token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "telegram"
    },
    
    "Twilio Account SID": {
        "type": "http",
        "method": "GET",
        "url": "https://api.twilio.com/2010-04-01/Accounts/{key}.json",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "pair_pattern": "Twilio Auth Token",
        "success_indicators": ["account_sid", "status", "friendly_name"],
        "failure_indicators": ["Authenticate", "invalid username"],
        "description": "Validates Twilio Account SID and Auth Token",
        "side_effect": ValidationSideEffect.READ_ONLY,
        "provider": "twilio"
    },
    
    # ==========================================
    # EMAIL SERVICES
    # ==========================================
    
    "SendGrid API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.sendgrid.com/v3/scopes",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["scopes"],
        "failure_indicators": ["authorization required", "The provided authorization"],
        "description": "Validates SendGrid API key and lists scopes"
    },
    
    "MailGun API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.mailgun.net/v3/domains",
        "auth": "basic",
        "auth_user": "api",
        "auth_pass": "{key}",
        "success_indicators": ["items", "total_count"],
        "failure_indicators": ["Forbidden", "Unauthorized"],
        "description": "Validates Mailgun API key"
    },
    
    "MailChimp API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{dc}.api.mailchimp.com/3.0/",
        "auth": "basic",
        "auth_user": "anystring",
        "auth_pass": "{key}",
        "extract_dc": True,  # Extract datacenter from key (last part after -)
        "success_indicators": ["account_id", "account_name"],
        "failure_indicators": ["API Key Invalid", "Wrong"],
        "description": "Validates MailChimp API key"
    },
    
    # ==========================================
    # CLOUD INFRASTRUCTURE
    # ==========================================
    
    "Heroku API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.heroku.com/apps",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/vnd.heroku+json; version=3"},
        "success_indicators": ["id", "name", "web_url"],
        "failure_indicators": ["Invalid credentials", "Unauthorized"],
        "description": "Validates Heroku API key"
    },
    
    "DigitalOcean Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.digitalocean.com/v2/account",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["account", "email", "uuid"],
        "failure_indicators": ["Unable to authenticate", "unauthorized"],
        "description": "Validates DigitalOcean API token"
    },
    
    "Cloudflare API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.cloudflare.com/client/v4/user/tokens/verify",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["success", "result"],
        "failure_indicators": ["Invalid API Token", "Authentication error"],
        "description": "Validates Cloudflare API token"
    },
    
    "Vercel Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.vercel.com/v2/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["Invalid token", "FORBIDDEN"],
        "description": "Validates Vercel deployment token"
    },
    
    "Netlify Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.netlify.com/api/v1/sites",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "name", "url"],
        "failure_indicators": ["Invalid access token", "Unauthorized"],
        "description": "Validates Netlify access token"
    },
    
    # ==========================================
    # MONITORING & ANALYTICS
    # ==========================================
    
    "Datadog API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.datadoghq.com/api/v1/validate",
        "headers": {"DD-API-KEY": "{key}"},
        "success_indicators": ["valid"],
        "failure_indicators": ["Forbidden", "Invalid API key"],
        "description": "Validates Datadog API key"
    },
    
    "New Relic API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.newrelic.com/v2/applications.json",
        "headers": {"X-Api-Key": "{key}"},
        "success_indicators": ["applications"],
        "failure_indicators": ["Invalid API key", "Unauthorized"],
        "description": "Validates New Relic API key"
    },
    
    "Sentry Auth Token": {
        "type": "http",
        "method": "GET",
        "url": "https://sentry.io/api/0/",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["version", "user"],
        "failure_indicators": ["Invalid token", "Unauthorized"],
        "description": "Validates Sentry auth token"
    },
    
    "PagerDuty API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.pagerduty.com/users?limit=1",
        "headers": {"Authorization": "Token token={key}"},
        "success_indicators": ["users", "offset"],
        "failure_indicators": ["Invalid credentials", "Unauthorized Access"],
        "description": "Validates PagerDuty API key"
    },
    
    # ==========================================
    # SOCIAL & MARKETING
    # ==========================================
    
    "Facebook Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://graph.facebook.com/v18.0/me?access_token={key}",
        "success_indicators": ["id", "name"],
        "failure_indicators": ["Invalid OAuth access token", "OAuthException"],
        "description": "Validates Facebook access token"
    },
    
    "Twitter Bearer Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.twitter.com/2/tweets/search/recent?query=test",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "meta"],
        "failure_indicators": ["Unauthorized", "Invalid Token"],
        "description": "Validates Twitter/X Bearer token"
    },
    
    "Instagram Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://graph.instagram.com/me?fields=id,username&access_token={key}",
        "success_indicators": ["id", "username"],
        "failure_indicators": ["Invalid OAuth", "OAuthException"],
        "description": "Validates Instagram Graph API token"
    },
    
    "LinkedIn Client Secret": {
        "type": "http",
        "method": "GET",
        "url": "https://api.linkedin.com/v2/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "localizedFirstName"],
        "failure_indicators": ["Unauthorized", "Invalid access token"],
        "description": "Validates LinkedIn access token"
    },
    
    # ==========================================
    # SECURITY & RECON
    # ==========================================
    
    "Shodan API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.shodan.io/api-info?key={key}",
        "success_indicators": ["query_credits", "scan_credits", "plan"],
        "failure_indicators": ["Invalid API key", "Access denied"],
        "description": "Validates Shodan API key"
    },
    
    "VirusTotal API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.virustotal.com/api/v3/users/{key}",
        "headers": {"x-apikey": "{key}"},
        "success_indicators": ["data", "id"],
        "failure_indicators": ["NotFoundError", "ForbiddenError"],
        "description": "Validates VirusTotal API key"
    },
    
    "Censys API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://search.censys.io/api/v1/account",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["email", "quota"],
        "failure_indicators": ["Unauthorized"],
        "description": "Validates Censys API credentials"
    },
    
    # ==========================================
    # MISC SERVICES
    # ==========================================
    
    "OpenAI API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.openai.com/v1/models",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "object"],
        "failure_indicators": ["invalid_api_key", "Incorrect API key"],
        "description": "Validates OpenAI API key"
    },
    
    "Algolia API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{app_id}-dsn.algolia.net/1/keys/{key}",
        "headers": {"X-Algolia-Application-Id": "{app_id}", "X-Algolia-API-Key": "{key}"},
        "success_indicators": ["acl", "validity"],
        "failure_indicators": ["Invalid API key", "IndexNotFoundException"],
        "description": "Validates Algolia API key"
    },
    
    "Mapbox API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.mapbox.com/tokens/v2?access_token={key}",
        "success_indicators": ["token", "scopes"],
        "failure_indicators": ["Not Authorized", "Invalid token"],
        "description": "Validates Mapbox access token"
    },
    
    "HubSpot API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.hubapi.com/crm/v3/objects/contacts?limit=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["results", "paging"],
        "failure_indicators": ["INVALID_AUTHENTICATION", "Invalid API key"],
        "description": "Validates HubSpot API key"
    },
    
    "Asana Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://app.asana.com/api/1.0/users/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "gid", "name"],
        "failure_indicators": ["Not Authorized", "Invalid token"],
        "description": "Validates Asana personal access token"
    },
    
    "Zendesk API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{subdomain}.zendesk.com/api/v2/users/me.json",
        "auth": "basic",
        "auth_user": "{email}/token",
        "auth_pass": "{key}",
        "success_indicators": ["user", "id"],
        "failure_indicators": ["Couldn't authenticate", "Invalid credentials"],
        "description": "Validates Zendesk API token (requires subdomain)"
    },
    
    "Grafana Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://grafana.com/api/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "name", "login"],
        "failure_indicators": ["Unauthorized", "invalid API key"],
        "description": "Validates Grafana Cloud access token"
    },
    
    "Spotify Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.spotify.com/v1/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "display_name"],
        "failure_indicators": ["Invalid access token", "token expired"],
        "description": "Validates Spotify access token"
    },
    
    "YouTube API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true&key={key}",
        "success_indicators": ["kind", "items"],
        "failure_indicators": ["API key not valid", "keyInvalid"],
        "description": "Validates YouTube Data API key"
    },
    
    # ==========================================
    # SECRETS NINJA - ADDITIONAL VALIDATORS
    # ==========================================
    
    "Notion API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.notion.com/v1/users/me",
        "headers": {"Authorization": "Bearer {key}", "Notion-Version": "2022-06-28"},
        "success_indicators": ["object", "id", "type"],
        "failure_indicators": ["unauthorized", "invalid_token"],
        "description": "Validates Notion integration token"
    },
    
    "Figma Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.figma.com/v1/me",
        "headers": {"X-Figma-Token": "{key}"},
        "success_indicators": ["id", "email", "handle"],
        "failure_indicators": ["Invalid token", "Not authorized"],
        "description": "Validates Figma personal access token"
    },
    
    "Airtable PAT": {
        "type": "http",
        "method": "GET",
        "url": "https://api.airtable.com/v0/meta/whoami",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "email", "scopes"],
        "failure_indicators": ["AUTHENTICATION_REQUIRED", "INVALID_PERMISSIONS_OR_MODEL"],
        "description": "Validates Airtable personal access token"
    },
    
    "Linear API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.linear.app/graphql",
        "headers": {"Authorization": "{key}", "Content-Type": "application/json"},
        "body": '{"query":"{ viewer { id email } }"}',
        "success_indicators": ["data", "viewer", "email"],
        "failure_indicators": ["AUTHENTICATION_ERROR", "UNAUTHENTICATED"],
        "description": "Validates Linear API key using GraphQL"
    },
    
    "Jira API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.atlassian.net/rest/api/3/myself",
        "auth": "basic",
        "auth_user": "{email}",
        "auth_pass": "{key}",
        "success_indicators": ["accountId", "emailAddress", "displayName"],
        "failure_indicators": ["Unauthorized", "Basic authentication"],
        "description": "Validates Jira/Atlassian API token (requires domain and email)"
    },
    
    "Confluence API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.atlassian.net/wiki/rest/api/user/current",
        "auth": "basic",
        "auth_user": "{email}",
        "auth_pass": "{key}",
        "success_indicators": ["type", "username", "accountId"],
        "failure_indicators": ["Unauthorized", "authentication required"],
        "description": "Validates Confluence API token"
    },
    
    "Anthropic API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.anthropic.com/v1/messages",
        "headers": {"x-api-key": "{key}", "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        "body": '{"model":"claude-3-sonnet-20240229","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}',
        "success_indicators": ["content", "model", "id"],
        "failure_indicators": ["invalid_api_key", "authentication_error"],
        "description": "Validates Anthropic/Claude API key",
        "side_effect": ValidationSideEffect.STATE_CHANGING,
        "provider": "anthropic"
    },
    
    "Supabase API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{project_ref}.supabase.co/rest/v1/",
        "headers": {"apikey": "{key}", "Authorization": "Bearer {key}"},
        "success_indicators": ["swagger", "info"],
        "failure_indicators": ["Invalid API key", "JWT"],
        "description": "Validates Supabase anon/service key"
    },
    
    "PlanetScale API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.planetscale.com/v1/organizations",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["data", "type"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates PlanetScale API token"
    },
    
    "Clerk API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.clerk.com/v1/users?limit=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["data", "total_count"],
        "failure_indicators": ["authorization_invalid", "Unauthorized"],
        "description": "Validates Clerk secret key"
    },
    
    "Auth0 Management Token": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.auth0.com/api/v2/users?per_page=1",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["user_id", "email"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates Auth0 Management API token"
    },
    
    "Plaid API Key": {
        "type": "http",
        "method": "POST",
        "url": "https://sandbox.plaid.com/institutions/get",
        "headers": {"Content-Type": "application/json"},
        "body": '{"client_id":"{client_id}","secret":"{key}","count":1,"offset":0,"country_codes":["US"]}',
        "success_indicators": ["institutions", "total"],
        "failure_indicators": ["INVALID_API_KEYS", "UNAUTHORIZED"],
        "description": "Validates Plaid API secret"
    },
    
    "Loom API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.loom.com/v1/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["id", "email"],
        "failure_indicators": ["Unauthorized", "invalid_token"],
        "description": "Validates Loom API token"
    },
    
    "Postman API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.getpostman.com/me",
        "headers": {"X-Api-Key": "{key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["AuthenticationError", "Invalid API Key"],
        "description": "Validates Postman API key"
    },
    
    "Mixpanel API Secret": {
        "type": "http",
        "method": "GET",
        "url": "https://mixpanel.com/api/2.0/engage",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "success_indicators": ["results", "page"],
        "failure_indicators": ["Invalid secret", "Unauthorized"],
        "description": "Validates Mixpanel API secret"
    },
    
    "Amplitude API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://amplitude.com/api/2/export?start=20200101T00&end=20200101T01",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "{secret}",
        "requires_pair": True,
        "success_indicators": ["events", "data"],
        "failure_indicators": ["Unauthorized", "Invalid credentials"],
        "description": "Validates Amplitude API key and secret"
    },
    
    "Segment Write Key": {
        "type": "http",
        "method": "POST",
        "url": "https://api.segment.io/v1/track",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "",
        "body": '{"userId":"test","event":"test"}',
        "headers": {"Content-Type": "application/json"},
        "success_indicators": ["success"],
        "failure_indicators": ["Invalid write key", "Unauthorized"],
        "description": "Validates Segment write key",
        "side_effect": ValidationSideEffect.STATE_CHANGING,
        "provider": "segment"
    },
    
    "LaunchDarkly API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://app.launchdarkly.com/api/v2/projects",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["items", "_links"],
        "failure_indicators": ["Unauthorized", "invalid api key"],
        "description": "Validates LaunchDarkly API access token"
    },
    
    "Intercom Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.intercom.io/me",
        "headers": {"Authorization": "Bearer {key}", "Accept": "application/json"},
        "success_indicators": ["type", "id", "email"],
        "failure_indicators": ["unauthorized", "Invalid token"],
        "description": "Validates Intercom access token"
    },
    
    "Freshdesk API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{domain}.freshdesk.com/api/v2/tickets?per_page=1",
        "auth": "basic",
        "auth_user": "{key}",
        "auth_pass": "X",
        "success_indicators": ["id", "subject"],
        "failure_indicators": ["authentication required", "invalid credentials"],
        "description": "Validates Freshdesk API key"
    },
    
    "Dropbox Access Token": {
        "type": "http",
        "method": "POST",
        "url": "https://api.dropboxapi.com/2/users/get_current_account",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["account_id", "email"],
        "failure_indicators": ["Invalid access token", "expired_access_token"],
        "description": "Validates Dropbox access token"
    },
    
    "Box Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.box.com/2.0/users/me",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["type", "id", "login"],
        "failure_indicators": ["Unauthorized", "expired_token"],
        "description": "Validates Box access token"
    },
    
    "Monday API Token": {
        "type": "http",
        "method": "POST",
        "url": "https://api.monday.com/v2",
        "headers": {"Authorization": "{key}", "Content-Type": "application/json"},
        "body": '{"query":"{ me { id name email } }"}',
        "success_indicators": ["data", "me", "email"],
        "failure_indicators": ["Not Authenticated", "invalid_token"],
        "description": "Validates Monday.com API token"
    },
    
    "ClickUp API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.clickup.com/api/v2/user",
        "headers": {"Authorization": "{key}"},
        "success_indicators": ["user", "id", "email"],
        "failure_indicators": ["OAUTH_017", "Unauthorized"],
        "description": "Validates ClickUp personal API token"
    },
    
    "Trello API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.trello.com/1/members/me?key={key}&token={token}",
        "success_indicators": ["id", "username", "email"],
        "failure_indicators": ["invalid key", "unauthorized"],
        "description": "Validates Trello API key and token"
    },
    
    "Bitly Access Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api-ssl.bitly.com/v4/user",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["login", "name"],
        "failure_indicators": ["FORBIDDEN", "INVALID_ACCESS_TOKEN"],
        "description": "Validates Bitly access token"
    },
    
    "RapidAPI Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.geoapify.com/v1/ipinfo?apiKey={key}",
        "success_indicators": ["ip", "country"],
        "failure_indicators": ["Invalid API Key", "Unauthorized"],
        "description": "Validates RapidAPI key (via Geoapify)"
    },
    
    "Cohere API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.cohere.ai/v1/models",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["models"],
        "failure_indicators": ["invalid api token", "Unauthorized"],
        "description": "Validates Cohere AI API key"
    },
    
    "Replicate API Token": {
        "type": "http",
        "method": "GET",
        "url": "https://api.replicate.com/v1/account",
        "headers": {"Authorization": "Token {key}"},
        "success_indicators": ["type", "username"],
        "failure_indicators": ["Unauthorized", "Invalid token"],
        "description": "Validates Replicate API token"
    },
    
    "Pinecone API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://api.pinecone.io/indexes",
        "headers": {"Api-Key": "{key}"},
        "success_indicators": ["indexes"],
        "failure_indicators": ["Unauthorized", "Invalid API key"],
        "description": "Validates Pinecone API key"
    },
    
    "Weaviate API Key": {
        "type": "http",
        "method": "GET",
        "url": "https://{cluster}.weaviate.network/v1/schema",
        "headers": {"Authorization": "Bearer {key}"},
        "success_indicators": ["classes"],
        "failure_indicators": ["Unauthorized", "invalid api key"],
        "description": "Validates Weaviate Cloud API key"
    },
}

_PROVIDER_MAP = {
    "PayPal Braintree Token": ("braintree", ValidationSideEffect.READ_ONLY),
    "Square Access Token": ("square", ValidationSideEffect.READ_ONLY),
    "Razorpay API Key": ("razorpay", ValidationSideEffect.READ_ONLY),
    "Travis CI API Token": ("travis", ValidationSideEffect.READ_ONLY),
    "NPM Access Token": ("npm", ValidationSideEffect.READ_ONLY),
    "SendGrid API Key": ("sendgrid", ValidationSideEffect.READ_ONLY),
    "MailGun API Key": ("mailgun", ValidationSideEffect.READ_ONLY),
    "MailChimp API Key": ("mailchimp", ValidationSideEffect.READ_ONLY),
    "Heroku API Key": ("heroku", ValidationSideEffect.READ_ONLY),
    "DigitalOcean Token": ("digitalocean", ValidationSideEffect.READ_ONLY),
    "Cloudflare API Key": ("cloudflare", ValidationSideEffect.READ_ONLY),
    "Vercel Token": ("vercel", ValidationSideEffect.READ_ONLY),
    "Netlify Token": ("netlify", ValidationSideEffect.READ_ONLY),
    "Datadog API Key": ("datadog", ValidationSideEffect.READ_ONLY),
    "New Relic API Key": ("newrelic", ValidationSideEffect.READ_ONLY),
    "Sentry Auth Token": ("sentry", ValidationSideEffect.READ_ONLY),
    "PagerDuty API Key": ("pagerduty", ValidationSideEffect.READ_ONLY),
    "Facebook Access Token": ("facebook", ValidationSideEffect.READ_ONLY),
    "Twitter Bearer Token": ("twitter", ValidationSideEffect.READ_ONLY),
    "Instagram Access Token": ("instagram", ValidationSideEffect.READ_ONLY),
    "LinkedIn Client Secret": ("linkedin", ValidationSideEffect.READ_ONLY),
    "Shodan API Key": ("shodan", ValidationSideEffect.READ_ONLY),
    "VirusTotal API Key": ("virustotal", ValidationSideEffect.READ_ONLY),
    "Censys API Key": ("censys", ValidationSideEffect.READ_ONLY),
    "OpenAI API Key": ("openai", ValidationSideEffect.READ_ONLY),
    "Algolia API Key": ("algolia", ValidationSideEffect.READ_ONLY),
    "Mapbox API Key": ("mapbox", ValidationSideEffect.READ_ONLY),
    "HubSpot API Key": ("hubspot", ValidationSideEffect.READ_ONLY),
    "Asana Access Token": ("asana", ValidationSideEffect.READ_ONLY),
    "Zendesk API Token": ("zendesk", ValidationSideEffect.READ_ONLY),
    "Grafana Access Token": ("grafana", ValidationSideEffect.READ_ONLY),
    "Spotify Access Token": ("spotify", ValidationSideEffect.READ_ONLY),
    "YouTube API Key": ("google", ValidationSideEffect.READ_ONLY),
    "Notion API Token": ("notion", ValidationSideEffect.READ_ONLY),
    "Figma Access Token": ("figma", ValidationSideEffect.READ_ONLY),
    "Airtable PAT": ("airtable", ValidationSideEffect.READ_ONLY),
    "Linear API Key": ("linear", ValidationSideEffect.READ_ONLY),
    "Jira API Token": ("atlassian", ValidationSideEffect.READ_ONLY),
    "Confluence API Token": ("atlassian", ValidationSideEffect.READ_ONLY),
    "Supabase API Key": ("supabase", ValidationSideEffect.READ_ONLY),
    "PlanetScale API Token": ("planetscale", ValidationSideEffect.READ_ONLY),
    "Clerk API Key": ("clerk", ValidationSideEffect.READ_ONLY),
    "Auth0 Management Token": ("auth0", ValidationSideEffect.READ_ONLY),
    "Plaid API Key": ("plaid", ValidationSideEffect.READ_ONLY),
    "Loom API Token": ("loom", ValidationSideEffect.READ_ONLY),
    "Postman API Key": ("postman", ValidationSideEffect.READ_ONLY),
    "Mixpanel API Secret": ("mixpanel", ValidationSideEffect.READ_ONLY),
    "Amplitude API Key": ("amplitude", ValidationSideEffect.READ_ONLY),
    "LaunchDarkly API Key": ("launchdarkly", ValidationSideEffect.READ_ONLY),
    "Intercom Access Token": ("intercom", ValidationSideEffect.READ_ONLY),
    "Freshdesk API Key": ("freshdesk", ValidationSideEffect.READ_ONLY),
    "Dropbox Access Token": ("dropbox", ValidationSideEffect.READ_ONLY),
    "Box Access Token": ("box", ValidationSideEffect.READ_ONLY),
    "Monday API Token": ("monday", ValidationSideEffect.READ_ONLY),
    "ClickUp API Token": ("clickup", ValidationSideEffect.READ_ONLY),
    "Trello API Key": ("trello", ValidationSideEffect.READ_ONLY),
    "Bitly Access Token": ("bitly", ValidationSideEffect.READ_ONLY),
    "RapidAPI Key": ("rapidapi", ValidationSideEffect.READ_ONLY),
    "Cohere API Key": ("cohere", ValidationSideEffect.READ_ONLY),
    "Replicate API Token": ("replicate", ValidationSideEffect.READ_ONLY),
    "Pinecone API Key": ("pinecone", ValidationSideEffect.READ_ONLY),
    "Weaviate API Key": ("weaviate", ValidationSideEffect.READ_ONLY),
}

for _vname, (_prov, _se) in _PROVIDER_MAP.items():
    if _vname in KEYHACKS_VALIDATORS:
        KEYHACKS_VALIDATORS[_vname].setdefault("provider", _prov)
        KEYHACKS_VALIDATORS[_vname].setdefault("side_effect", _se)

# Any validator still missing side_effect or provider defaults to UNKNOWN for fail-closed security
for _v in KEYHACKS_VALIDATORS.values():
    _v.setdefault("side_effect", ValidationSideEffect.UNKNOWN)
    _v.setdefault("provider", "unknown")


class KeyHacksValidator:
    """
    Validates discovered secrets using KeyHacks methodology
    
    ⚠️ WARNING: This tool is for AUTHORIZED security testing only.
    Ensure you have explicit permission before validating any secrets.
    """
    
    DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE WARNING  ⚠️                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This validation feature is for AUTHORIZED security testing only:           ║
║                                                                              ║
║  ✅ Bug Bounty Programs (with explicit scope permission)                     ║
║  ✅ Authorized Penetration Testing                                           ║
║  ✅ Security Assessments (with signed authorization)                         ║
║                                                                              ║
║  ❌ Unauthorized access to systems is ILLEGAL                                ║
║  ❌ Using validated keys without permission is a CRIME                       ║
║                                                                              ║
║  🔒 I am just a tool. Always verify findings manually.                       ║
║  🔒 Confirm authorization before reporting or using validated secrets.      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def __init__(
        self,
        effective_policy: Optional[Any] = None,
        http_client: Optional[Any] = None,
        request_policy_manager: Optional[Any] = None,
        scope_manager: Optional[Any] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        allow_state_changing: bool = False,
        authorized_providers: Optional[Set[str]] = None
    ):
        # Support legacy positional signatures, e.g. KeyHacksValidator(timeout=10, verify_ssl=True)
        if isinstance(effective_policy, (int, float)):
            timeout = int(effective_policy)
            effective_policy = None

        if effective_policy is not None:
            self.effective_policy = effective_policy
            self.scope_manager = scope_manager or getattr(effective_policy, "scope_manager", None)
            self.request_policy_manager = request_policy_manager or getattr(effective_policy, "request_policy_manager", None)
            self.http_client = http_client or getattr(effective_policy, "http_client", None)
            policy_tls = getattr(effective_policy, "verify_tls", None)
            self.verify_ssl = policy_tls if policy_tls is not None else verify_ssl
            policy_providers = getattr(effective_policy, "authorized_providers", None)
            self.authorized_providers = set(authorized_providers) if authorized_providers is not None else (set(policy_providers) if policy_providers else set())
            policy_state_changing = getattr(effective_policy, "allow_state_changing", False)
            self.allow_state_changing = allow_state_changing or policy_state_changing
        else:
            self.effective_policy = None
            self.scope_manager = scope_manager
            self.request_policy_manager = request_policy_manager
            self.http_client = http_client
            self.verify_ssl = verify_ssl
            self.allow_state_changing = allow_state_changing
            self.authorized_providers = set(authorized_providers) if authorized_providers is not None else set()

        if self.http_client is not None and self.authorized_providers:
            if getattr(self.http_client, "authorized_providers", None) is not None:
                self.http_client.authorized_providers.update(self.authorized_providers)
            else:
                self.http_client.authorized_providers = set(self.authorized_providers)

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.validated_count = 0
        self.valid_secrets = []

    @classmethod
    def from_policy(
        cls,
        effective_policy: Any,
        timeout: int = 10,
        allow_state_changing: bool = False,
        authorized_providers: Optional[Set[str]] = None
    ) -> "KeyHacksValidator":
        """Construct a KeyHacksValidator wired with all mandatory policy dependencies from an EffectivePolicy."""
        policy_tls = getattr(effective_policy, "verify_tls", None)
        verify_ssl = policy_tls if policy_tls is not None else True
        policy_state_changing = getattr(effective_policy, "allow_state_changing", False)
        policy_providers = getattr(effective_policy, "authorized_providers", None)
        providers = set(authorized_providers) if authorized_providers is not None else (set(policy_providers) if policy_providers else set())
        
        http_client = getattr(effective_policy, "http_client", None)
        if http_client is None:
            from src.core.http_client import NightCrawlerHttpClient
            http_client = NightCrawlerHttpClient(effective_policy=effective_policy)
            effective_policy.http_client = http_client

        return cls(
            effective_policy=effective_policy,
            http_client=http_client,
            request_policy_manager=getattr(effective_policy, "request_policy_manager", None),
            scope_manager=getattr(effective_policy, "scope_manager", None),
            timeout=timeout,
            verify_ssl=verify_ssl,
            allow_state_changing=allow_state_changing or policy_state_changing,
            authorized_providers=providers
        )

    @classmethod
    def redact_url(cls, url: str, secret: Optional[str] = None) -> str:
        """Redact query credentials, webhook paths, and embedded secrets in URLs."""
        clean = AuditLogger.redact_url(url)
        if secret:
            from urllib.parse import quote, quote_plus
            clean = clean.replace(secret, "[REDACTED]")
            clean = clean.replace(quote(secret), "[REDACTED]")
            clean = clean.replace(quote_plus(secret), "[REDACTED]")
            try:
                clean = re.sub(re.escape(secret), "[REDACTED]", clean, flags=re.IGNORECASE)
            except Exception:
                pass
        return clean

    @classmethod
    def redact_text(cls, text: Optional[str], secret: Optional[str] = None) -> str:
        """Scrub secret credentials, tokens, and authorization headers from text."""
        if not text:
            return ""
        clean = str(text)
        if secret:
            from urllib.parse import quote, quote_plus
            clean = clean.replace(secret, "[REDACTED]")
            clean = clean.replace(quote(secret), "[REDACTED]")
            clean = clean.replace(quote_plus(secret), "[REDACTED]")
            try:
                clean = re.sub(re.escape(secret), "[REDACTED]", clean, flags=re.IGNORECASE)
            except Exception:
                pass

        # Redact bearer tokens and authorization headers
        clean = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{8,}', r'\1[REDACTED]', clean)
        clean = re.sub(r'(?i)(token\s+)[A-Za-z0-9_\-\.]{8,}', r'\1[REDACTED]', clean)
        clean = re.sub(r'(?i)(bot\s+)[A-Za-z0-9_\-\.]{8,}', r'\1[REDACTED]', clean)
        clean = re.sub(r'(?i)(Basic\s+)[A-Za-z0-9+/=]{8,}', r'\1[REDACTED]', clean)

        # Redact common query string secrets
        clean = re.sub(r'([?&](?:access_token|key|api_key|apiKey|secret|password|circle-token|token)=)[^&\s\'"]+', r'\1[REDACTED]', clean, flags=re.I)

        # Redact webhook path tokens
        clean = re.sub(r'(hooks\.slack\.com/services/T[^/]+/B[^/]+/)[^/\s?#\'"]+', r'\1[REDACTED]', clean)
        clean = re.sub(r'(discord\.com/api/webhooks/\d+/)[^/\s?#\'"]+', r'\1[REDACTED]', clean)
        clean = re.sub(r'(api\.telegram\.org/bot)[^/\s?#\'"]+', r'\1[REDACTED]', clean)

        return clean

    @classmethod
    def build_sanitized_command(
        cls,
        validator: Dict,
        secret: str,
        extra_params: Optional[Dict] = None,
        url: Optional[str] = None,
        method: Optional[str] = None
    ) -> str:
        """
        Build a sanitized reproducible validation command (e.g. curl or CLI)
        with all secret tokens, API keys, passwords, and webhook paths strictly redacted.
        """
        v_type = validator.get("type", "http")
        if v_type == "command":
            raw_cmd = validator.get("command", "")
            cmd_safe = raw_cmd.replace("{key}", "[REDACTED]").replace("{secret}", "[REDACTED]")
            if extra_params:
                safe_params = {k: ("[REDACTED]" if any(s in k.lower() for s in ("key", "secret", "token", "pass")) else v) for k, v in extra_params.items()}
                try:
                    cmd_safe = cmd_safe.format(**safe_params)
                except Exception:
                    pass
            return cls.redact_text(cmd_safe, secret)

        # HTTP curl command
        req_method = (method or validator.get("method", "GET")).upper()
        if not url:
            raw_url = validator.get("url", "")
            try:
                url = raw_url.format(key=secret, **(extra_params or {}))
            except Exception:
                url = raw_url

        clean_url = cls.redact_url(url, secret)
        parts = ["curl", f"-X {req_method}"]

        # Headers
        if "headers" in validator:
            for h_k, h_v in validator["headers"].items():
                h_k_lower = h_k.lower()
                if h_k_lower in ("authorization", "proxy-authorization", "private-token", "api-key", "x-api-key") or any(s in h_k_lower for s in ("token", "secret", "key", "auth")):
                    if "bearer " in h_v.lower():
                        val_sanitized = "Bearer [REDACTED]"
                    elif "token " in h_v.lower():
                        val_sanitized = "token [REDACTED]"
                    elif "bot " in h_v.lower():
                        val_sanitized = "Bot [REDACTED]"
                    else:
                        val_sanitized = "[REDACTED]"
                else:
                    try:
                        val_sanitized = h_v.format(key=secret, **(extra_params or {}))
                    except Exception:
                        val_sanitized = h_v
                    val_sanitized = cls.redact_text(val_sanitized, secret)
                parts.append(f"-H '{h_k}: {val_sanitized}'")

        # Basic Auth
        if validator.get("auth") == "basic":
            parts.append("-u '[REDACTED]:[REDACTED]'")

        # Body / Data
        if "body" in validator:
            raw_body = validator["body"]
            body_clean = raw_body.replace("{key}", "[REDACTED]").replace("{secret}", "[REDACTED]")
            body_clean = cls.redact_text(body_clean, secret)
            parts.append(f"-d '{body_clean}'")
        elif "data" in validator:
            parts.append("-d '[REDACTED]'")

        parts.append(f"'{clean_url}'")
        cmd_str = " ".join(parts)
        return cls.redact_text(cmd_str, secret)

    @classmethod
    def extract_provider_from_url(cls, url: str) -> str:
        """Infer provider identifier from destination host."""
        if not url:
            return "unknown"
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return host or "unknown"

    def is_provider_authorized(self, validator: Dict, url: str) -> bool:
        """Verify if external third-party provider is explicitly authorized."""
        if not self.authorized_providers:
            return False
        if "*" in self.authorized_providers or "all" in self.authorized_providers:
            return True
        provider = (validator.get("provider") or self.extract_provider_from_url(url)).lower()
        if self.http_client is not None and hasattr(self.http_client, "is_provider_authorized"):
            return self.http_client.is_provider_authorized(provider, url)
        from src.core.http_client import NightCrawlerHttpClient
        client = NightCrawlerHttpClient(authorized_providers=self.authorized_providers)
        return client.is_provider_authorized(provider, url)

    def validate_policy_dependencies(self, connector: Optional[aiohttp.TCPConnector] = None) -> None:
        """
        Validate all mandatory policy dependencies are present, identical to EffectivePolicy,
        and configured strictly before any network activity.
        Fails closed with KeyHacksPolicyError if any dependency is missing, mismatched, or violated.
        """
        if self.scope_manager is None:
            raise KeyHacksPolicyError("ScopeManager is missing: active HTTP validation requires an authorized ScopeManager.")
        if self.request_policy_manager is None:
            raise KeyHacksPolicyError("RequestPolicyManager is missing: active HTTP validation requires a RequestPolicyManager.")
        if self.http_client is None:
            raise KeyHacksPolicyError("HttpClient is missing: active HTTP validation requires NightCrawlerHttpClient.")

        resolver = self.http_client.get_resolver() if hasattr(self.http_client, "get_resolver") else None
        if resolver is None:
            raise KeyHacksPolicyError("DNS Resolver is missing: active HTTP validation requires a PolicyAwareResolver.")
        if not hasattr(self.request_policy_manager, "global_limiter") or self.request_policy_manager.global_limiter is None:
            raise KeyHacksPolicyError("RateLimiter is missing: active HTTP validation requires a GlobalRateLimiter.")

        # Strict identity enforcement against EffectivePolicy
        if self.effective_policy is not None:
            if self.scope_manager is not self.effective_policy.scope_manager:
                raise KeyHacksPolicyError("Mismatched ScopeManager: KeyHacksValidator ScopeManager is not identical to EffectivePolicy.scope_manager")
            if self.request_policy_manager is not self.effective_policy.request_policy_manager:
                raise KeyHacksPolicyError("Mismatched RequestPolicyManager: KeyHacksValidator RequestPolicyManager is not identical to EffectivePolicy.request_policy_manager")
            if hasattr(self.effective_policy, "http_client") and self.effective_policy.http_client is not None and self.http_client is not self.effective_policy.http_client:
                raise KeyHacksPolicyError("Mismatched HttpClient: KeyHacksValidator HttpClient is not identical to EffectivePolicy.http_client")

        # Strict identity enforcement between HttpClient and managers
        if self.http_client.scope_manager is not self.scope_manager:
            raise KeyHacksPolicyError("Mismatched ScopeManager: HttpClient ScopeManager is not identical to KeyHacksValidator ScopeManager")
        if self.http_client.rate_limiter is not self.request_policy_manager.global_limiter:
            raise KeyHacksPolicyError("Mismatched RateLimiter: HttpClient rate_limiter is not identical to RequestPolicyManager.global_limiter")
        if not isinstance(resolver, PolicyAwareResolver) or getattr(resolver, "http_client", None) is not self.http_client:
            raise KeyHacksPolicyError("Mismatched Resolver: Resolver is not an authorized PolicyAwareResolver bound to this HttpClient")

        # Connector Resolver validation
        if connector is not None:
            from unittest.mock import Mock
            conn_resolver = getattr(connector, "_resolver", None)
            if not isinstance(connector, Mock) and not isinstance(conn_resolver, Mock):
                if conn_resolver is not resolver:
                    raise KeyHacksPolicyError("Mismatched Connector Resolver: TCPConnector does not use the authorized PolicyAwareResolver")
            elif hasattr(connector, "_resolver") and conn_resolver is not resolver and not isinstance(conn_resolver, Mock):
                raise KeyHacksPolicyError("Mismatched Connector Resolver: TCPConnector does not use the authorized PolicyAwareResolver")

        # TLS Configuration verification
        if not self.verify_ssl:
            if self.effective_policy and getattr(self.effective_policy, "strict_scope", True):
                raise KeyHacksPolicyError("Insecure TLS verification is prohibited under strict policy compliance")
        if hasattr(self.http_client, "verify_tls") and self.http_client.verify_tls != self.verify_ssl:
            raise KeyHacksPolicyError("Conflicting TLS configuration between HttpClient and KeyHacksValidator")

    def print_disclaimer(self):
        """Print ethical use disclaimer"""
        console.print(self.DISCLAIMER, style="bold yellow")
    
    def get_validator(self, pattern_name: str) -> Optional[Dict]:
        """Get validation config for a pattern"""
        # Try exact match
        if pattern_name in KEYHACKS_VALIDATORS:
            return KEYHACKS_VALIDATORS[pattern_name]
        
        # Try partial match
        for key in KEYHACKS_VALIDATORS:
            if key.lower() in pattern_name.lower() or pattern_name.lower() in key.lower():
                return KEYHACKS_VALIDATORS[key]
        
        return None
    
    async def validate_http(self, validator: Dict, secret: str, extra_params: Dict = None) -> ValidationResult:
        """Validate secret using HTTP request under shared concurrency, scope, DNS, and rate-limiting policy"""
        try:
            url = validator["url"].format(key=secret, **(extra_params or {}))
            method = validator.get("method", "GET").upper()
            sanitized_cmd = self.build_sanitized_command(validator, secret, extra_params, url, method)

            # Check side effects before touching network or dependency validation
            side_effect = validator.get("side_effect")
            if side_effect is None:
                if method in ("GET", "HEAD"):
                    side_effect = ValidationSideEffect.READ_ONLY
                else:
                    side_effect = ValidationSideEffect.UNKNOWN
            side_effect_str = side_effect.value if isinstance(side_effect, ValidationSideEffect) else str(side_effect).lower()
            if side_effect_str == "unknown":
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    message=f"Validation operation for '{validator.get('description', 'secret')}' has unknown side effects and is blocked.",
                    validation_command=sanitized_cmd
                )
            if side_effect_str == "destructive":
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    message=f"Destructive validation for '{validator.get('description', 'secret')}' is prohibited.",
                    validation_command=sanitized_cmd
                )
            if side_effect_str == "state_changing" and not self.allow_state_changing:
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    message=f"State-changing validation for '{validator.get('description', 'secret')}' is disabled by default. Requires explicit authorization.",
                    validation_command=sanitized_cmd
                )

            # Phase 2: Fail-closed dependency validation before any network activity
            self.validate_policy_dependencies()

            # Phase 3.A: Scope & External Provider authorization check
            is_in_scope = self.scope_manager.is_url_in_scope(url)
            provider = validator.get("provider") or self.extract_provider_from_url(url)
            if not is_in_scope:
                if not self.is_provider_authorized(validator, url):
                    return ValidationResult(
                        status=ValidationStatus.ERROR,
                        message=f"Target validation URL is out of scope (external provider '{provider}' is not authorized)",
                        validation_command=sanitized_cmd
                    )

            # Phase 3.C: Shared Concurrency Semaphore enforcement
            sem = self.request_policy_manager.get_semaphore()
            if not _in_concurrency_scope.get():
                async with sem:
                    token = _in_concurrency_scope.set(True)
                    try:
                        return await self._do_validate_http(validator, secret, extra_params, url, method, sanitized_cmd=sanitized_cmd, provider=provider)
                    finally:
                        _in_concurrency_scope.reset(token)
            else:
                return await self._do_validate_http(validator, secret, extra_params, url, method, sanitized_cmd=sanitized_cmd, provider=provider)

        except asyncio.TimeoutError:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Request timed out",
                validation_command=sanitized_cmd if 'sanitized_cmd' in locals() else None
            )
        except KeyHacksPolicyError:
            raise
        except Exception as e:
            safe_err = self.redact_text(str(e), secret)
            return ValidationResult(
                status=ValidationStatus.ERROR,
                message=f"Validation error: {safe_err[:100]}",
                validation_command=sanitized_cmd if 'sanitized_cmd' in locals() else None
            )

    async def _do_validate_http(
        self,
        validator: Dict,
        secret: str,
        extra_params: Optional[Dict],
        url: str,
        method: str,
        sanitized_cmd: Optional[str] = None,
        provider: Optional[str] = None
    ) -> ValidationResult:
        cmd = sanitized_cmd or self.build_sanitized_command(validator, secret, extra_params, url, method)
        headers = {}
        
        # Build headers
        if "headers" in validator:
            for k, v in validator["headers"].items():
                headers[k] = v.format(key=secret, **(extra_params or {}))
        
        # Build auth
        auth = None
        if validator.get("auth") == "basic":
            auth_user = validator.get("auth_user", "").format(key=secret, **(extra_params or {}))
            auth_pass = validator.get("auth_pass", "").format(key=secret, **(extra_params or {}))
            auth = aiohttp.BasicAuth(auth_user, auth_pass)
        
        # Build body
        body = None
        if "body" in validator:
            raw_body = validator["body"]
            try:
                body = raw_body.format(key=secret, **(extra_params or {}))
            except (IndexError, KeyError, ValueError):
                body = raw_body.replace("{key}", secret)
                if extra_params:
                    for ep_k, ep_v in extra_params.items():
                        body = body.replace(f"{{{ep_k}}}", str(ep_v))
        
        # Build data
        data = None
        if "data" in validator:
            data = {k: v.format(key=secret) for k, v in validator["data"].items()}

        payload = body or data

        # Always construct session using policy-aware resolver to pin validated DNS answers & enforce IP safety
        # and unified SSL settings to prevent connector-vs-request conflicts
        resolver = self.http_client.get_resolver()
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=self.http_client.ssl_context)
        self.validate_policy_dependencies(connector=connector)

        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            status, content, final_url = await self.http_client.request(
                session=session,
                method=method,
                url=url,
                extra_headers=headers,
                data=payload,
                auth=auth,
                authorized_provider=provider
            )

        if status is None:
            return ValidationResult(
                status=ValidationStatus.ERROR,
                message="HTTP request blocked by policy or network safety controls",
                validation_command=cmd
            )

        if status in (301, 302, 303, 307, 308) and not content:
            return ValidationResult(
                status=ValidationStatus.ERROR,
                message="Redirect was blocked by scope or security policy",
                validation_command=cmd
            )

        return self._analyze_response(validator, content or "", status, final_url or url, secret=secret, sanitized_cmd=cmd)
    
    def _analyze_response(
        self,
        validator: Dict,
        response: str,
        status_code: int,
        url: str,
        secret: Optional[str] = None,
        sanitized_cmd: Optional[str] = None
    ) -> ValidationResult:
        """Analyze HTTP response to determine validity with strict secret redaction."""
        response_lower = response.lower()
        cmd = sanitized_cmd or self.build_sanitized_command(validator, secret or "", url=url)
        clean_resp = self.redact_text(response[:500], secret) if response else None
        
        # Check for success indicators
        success_count = 0
        for indicator in validator.get("success_indicators", []):
            if indicator.lower() in response_lower:
                success_count += 1
        
        # Check for failure indicators
        failure_count = 0
        for indicator in validator.get("failure_indicators", []):
            if indicator.lower() in response_lower:
                failure_count += 1
        
        # Determine status
        if failure_count > 0:
            return ValidationResult(
                status=ValidationStatus.INVALID,
                message=f"Key appears to be invalid (HTTP {status_code})",
                raw_response=clean_resp,
                validation_command=cmd
            )
        elif success_count >= 2 or (success_count > 0 and status_code == 200):
            return ValidationResult(
                status=ValidationStatus.VALID,
                message=f"✅ KEY IS VALID! (HTTP {status_code}, {success_count} success indicators)",
                raw_response=clean_resp,
                validation_command=cmd
            )
        elif status_code == 429:
            return ValidationResult(
                status=ValidationStatus.RATE_LIMITED,
                message="Rate limited - try manual validation",
                raw_response=clean_resp,
                validation_command=cmd
            )
        elif status_code in [401, 403]:
            return ValidationResult(
                status=ValidationStatus.INVALID,
                message=f"Authentication failed (HTTP {status_code})",
                raw_response=clean_resp,
                validation_command=cmd
            )
        else:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message=f"Unclear result (HTTP {status_code}) - verify manually",
                raw_response=clean_resp,
                validation_command=cmd
            )
    
    async def validate_secret(self, pattern_name: str, secret_value: str, extra_params: Dict = None) -> ValidationResult:
        """
        Validate a discovered secret
        
        Args:
            pattern_name: The type of secret (e.g., "GitHub PAT")
            secret_value: The actual secret value
            extra_params: Additional parameters needed for validation
        
        Returns:
            ValidationResult with status and details
        """
        validator = self.get_validator(pattern_name)
        
        if not validator:
            return ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message=f"No validator available for {pattern_name}. Manual verification required.",
                validation_command="N/A - Check KeyHacks for manual validation"
            )
        
        # Check if requires pair (like AWS key + secret)
        if validator.get("requires_pair"):
            if not extra_params or "secret" not in extra_params:
                sanitized_cmd = self.build_sanitized_command(validator, secret_value, extra_params)
                return ValidationResult(
                    status=ValidationStatus.UNKNOWN,
                    message=f"Requires paired secret ({validator.get('pair_pattern', 'secret')}). Cannot validate alone.",
                    validation_command=sanitized_cmd
                )
        
        # Validate based on type
        if validator.get("type") == "http":
            try:
                result = await self.validate_http(validator, secret_value, extra_params)
            except KeyHacksPolicyError as pe:
                sanitized_cmd = self.build_sanitized_command(validator, secret_value, extra_params)
                result = ValidationResult(
                    status=ValidationStatus.ERROR,
                    message=f"Policy dependency missing: {pe}",
                    validation_command=sanitized_cmd
                )
        elif validator.get("type") == "command":
            sanitized_cmd = self.build_sanitized_command(validator, secret_value, extra_params)
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Command-based validation not auto-run for safety. Use manual command.",
                validation_command=sanitized_cmd
            )
        else:
            result = ValidationResult(
                status=ValidationStatus.UNKNOWN,
                message="Unknown validator type"
            )
        
        # Track valid secrets
        if result.status == ValidationStatus.VALID:
            self.validated_count += 1
            self.valid_secrets.append({
                "pattern": pattern_name,
                "value": mask_secret(secret_value),
                "message": self.redact_text(result.message, secret_value)
            })
        
        return result
    
    def get_manual_verification_note(self) -> str:
        """Get manual verification note for reports"""
        return """
┌─────────────────────────────────────────────────────────────────────────────┐
│                        📋 MANUAL VERIFICATION REQUIRED                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  This tool provides AUTOMATED validation which may have false positives    │
│  or false negatives. Before reporting:                                     │
│                                                                             │
│  1. ✅ Verify the secret is actually valid using the provided commands     │
│  2. ✅ Confirm the secret belongs to the target organization               │
│  3. ✅ Check if the secret has any actual permissions/access               │
│  4. ✅ Document the exact steps to reproduce                               │
│  5. ✅ Ensure you have authorization to test                               │
│                                                                             │
│  💡 Use the curl commands provided to manually verify each finding.        │
│                                                                             │
│  ⚠️  I am just a tool. The final verification is YOUR responsibility.      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
"""


# Convenience function for quick validation
async def validate_key(
    pattern_name: str,
    secret_value: str,
    effective_policy: Optional[Any] = None,
    **kwargs
) -> ValidationResult:
    """Quick validation of a single key under policy controls"""
    if effective_policy is not None:
        validator = KeyHacksValidator.from_policy(effective_policy, **kwargs)
    else:
        validator = KeyHacksValidator(**kwargs)
    return await validator.validate_secret(pattern_name, secret_value)
