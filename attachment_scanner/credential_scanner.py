# credential_scanner.py
# Universal Credential Exposure Scanner
#
# Runs on ALL file types after type-specific analysis.
# Extracts raw text from file bytes (UTF-8 → UTF-16 → Latin-1 cascade),
# then applies a regex pattern battery covering:
#
#   - Cloud provider API keys   (AWS, GCP, Azure)
#   - Developer tokens          (GitHub, GitLab, npm, PyPI)
#   - AI/ML service keys        (OpenAI, Anthropic, Hugging Face)
#   - Payment keys              (Stripe, PayPal, Braintree)
#   - Generic secrets           (Bearer tokens, Basic Auth, JWT)
#   - PEM private keys          (RSA, EC, DSA, OpenSSH, PGP)
#   - Email:password pairs
#   - Database connection strings
#   - .env / config file patterns
#   - Base64-decoded credential blobs
#
# Returns deduplicated findings with redacted values and context.

import re
import base64
import binascii

# ── Pattern definitions ───────────────────────────────────────────────────────
# Each entry: (rule_id, description, pattern, risk_tier, why_flagged)

_PATTERNS = [
    # ── AWS ──
    (
        "aws_access_key",
        "AWS Access Key ID",
        r"(?<![A-Z0-9])(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "Critical",
        "AWS Access Key IDs grant API access to cloud resources — exposure enables full account takeover",
    ),
    (
        "aws_secret_key",
        "AWS Secret Access Key",
        r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]",
        "Critical",
        "AWS Secret Key combined with Access Key ID allows full AWS API access",
    ),
    # ── GitHub ──
    (
        "github_pat_classic",
        "GitHub Personal Access Token (classic)",
        r"ghp_[A-Za-z0-9]{36,}",
        "Critical",
        "GitHub PATs grant read/write access to repositories and user data",
    ),
    (
        "github_oauth",
        "GitHub OAuth Token",
        r"gho_[A-Za-z0-9]{36,}",
        "Critical",
        "GitHub OAuth tokens grant API access on behalf of a user",
    ),
    (
        "github_app_token",
        "GitHub App Token",
        r"(ghs_|ghr_)[A-Za-z0-9]{36,}",
        "Critical",
        "GitHub App installation/refresh tokens enable repository and org operations",
    ),
    (
        "github_fine_grained",
        "GitHub Fine-Grained PAT",
        r"github_pat_[A-Za-z0-9_]{82,}",
        "Critical",
        "GitHub fine-grained PATs provide scoped access to specific repositories",
    ),
    # ── GitLab ──
    (
        "gitlab_pat",
        "GitLab Personal Access Token",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        "Critical",
        "GitLab PATs provide API access to projects, groups, and user data",
    ),
    # ── OpenAI / AI services ──
    (
        "openai_key",
        "OpenAI API Key",
        r"sk-[A-Za-z0-9]{32,}(?:-[A-Za-z0-9]{32,})?",
        "Critical",
        "OpenAI API keys grant access to GPT models and incur billing charges",
    ),
    (
        "anthropic_key",
        "Anthropic API Key",
        r"sk-ant-[A-Za-z0-9\-_]{40,}",
        "Critical",
        "Anthropic API keys grant access to Claude models and incur billing charges",
    ),
    (
        "huggingface_token",
        "Hugging Face API Token",
        r"hf_[A-Za-z0-9]{32,}",
        "High",
        "Hugging Face tokens allow model downloads, dataset access, and inference API calls",
    ),
    # ── Stripe / Payment ──
    (
        "stripe_live_key",
        "Stripe Live Secret Key",
        r"sk_live_[A-Za-z0-9]{24,}",
        "Critical",
        "Stripe live secret keys allow charges, refunds, and full account access",
    ),
    (
        "stripe_restricted",
        "Stripe Restricted Key",
        r"rk_live_[A-Za-z0-9]{24,}",
        "Critical",
        "Stripe restricted keys still carry payment operation privileges",
    ),
    (
        "stripe_test_key",
        "Stripe Test Secret Key",
        r"sk_test_[A-Za-z0-9]{24,}",
        "High",
        "Stripe test keys reveal account structure and test payment data",
    ),
    # ── Generic Bearer / Authorization ──
    (
        "bearer_token",
        "Bearer Authorization Token",
        r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)",
        "High",
        "Bearer tokens directly authenticate HTTP API requests — exposure grants access to any service accepting this token",
    ),
    (
        "basic_auth_header",
        "HTTP Basic Auth Header",
        r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/]{10,}={0,2})",
        "High",
        "Basic Auth headers contain base64-encoded username:password credentials",
    ),
    # ── PEM Private Keys ──
    (
        "pem_private_key",
        "PEM Private Key Block",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "Critical",
        "PEM private keys are cryptographic secrets — exposure enables identity impersonation, certificate forgery, or SSH login",
    ),
    (
        "pem_certificate_key",
        "PEM Certificate with Private Key",
        r"-----BEGIN CERTIFICATE-----[\s\S]{100,}-----BEGIN (RSA )?PRIVATE KEY-----",
        "Critical",
        "Certificate + private key bundle allows TLS impersonation and MITM attacks",
    ),
    # ── JWT ──
    (
        "jwt_token",
        "JSON Web Token (JWT)",
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}(?=[^A-Za-z0-9\-_]|$)",
        "High",
        "JWTs encode authentication claims — a valid JWT can be replayed to impersonate the token's subject",
    ),
    # ── Email:password pairs ──
    (
        "email_password_pair",
        "Email:Password credential pair",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:(?=[^\s])([A-Za-z0-9!@#$%^&*()\-_+=\[\]{}|\\;,.<>?/~`]{6,64})(?=[\s\"',]|$)",
        "Critical",
        "Email:password pairs are ready-to-use credentials — directly exploitable for account takeover",
    ),
    # ── Database connection strings ──
    (
        "db_connection_string",
        "Database connection string with credentials",
        r"(?i)(jdbc|mongodb(\+srv)?|redis|postgresql|postgres|mysql|sqlserver|mssql|oracle):\/\/[^:@\s]{1,64}:[^@\s]{1,64}@[^\s\"']{1,200}",
        "Critical",
        "Connection strings with embedded credentials grant direct database access",
    ),
    # ── Generic password in config ──
    (
        "env_password",
        "Password/secret in configuration",
        r"(?i)(password|passwd|secret|api_key|apikey|api_secret|auth_token|access_token|client_secret)\s*[=:]\s*['\"]?(?!.*?(test|demo|sample|example|placeholder|your[-_]|<|>|\{|\}|xxxx))[A-Za-z0-9!@#$%^&*()\-_+=]{8,}['\"]?",
        "High",
        "Configuration-embedded passwords are frequently committed to repositories or sent in documents inadvertently",
    ),
    # ── npm / PyPI tokens ──
    (
        "npm_token",
        "npm Automation / Read-Write Token",
        r"npm_[A-Za-z0-9]{36,}",
        "Critical",
        "npm tokens can publish packages — supply-chain attack vector if leaked",
    ),
    (
        "pypi_token",
        "PyPI API Token",
        r"pypi-[A-Za-z0-9\-_]{80,}",
        "Critical",
        "PyPI tokens can publish Python packages — supply-chain attack vector",
    ),
    # ── Slack ──
    (
        "slack_bot_token",
        "Slack Bot Token",
        r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}",
        "High",
        "Slack bot tokens allow reading messages and posting on behalf of the bot",
    ),
    (
        "slack_user_token",
        "Slack User Token",
        r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}",
        "Critical",
        "Slack user tokens grant full workspace access on behalf of the user",
    ),
    # ── Google Cloud ──
    (
        "gcp_service_account",
        "GCP Service Account Key (JSON)",
        r'"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"',
        "Critical",
        "GCP service account JSON keys grant API access to all configured Google Cloud services",
    ),
    # ── Azure ──
    (
        "azure_connection_string",
        "Azure Storage / Service Bus Connection String",
        r"DefaultEndpointsProtocol=https;AccountName=[^;]{1,64};AccountKey=[A-Za-z0-9+/=]{80,}",
        "Critical",
        "Azure connection strings grant full access to Storage accounts or Service Bus namespaces",
    ),
    # ── SSH private key (OpenSSH format) ──
    (
        "ssh_private_key",
        "SSH Private Key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "Critical",
        "OpenSSH private keys allow passwordless authentication to any server that has the matching public key authorized",
    ),
    # ── Twilio ──
    (
        "twilio_account_sid",
        "Twilio Account SID + Auth Token pattern",
        r"SK[a-f0-9]{32}",
        "High",
        "Twilio API keys allow sending SMS/calls and accessing call logs",
    ),
    # ── SendGrid ──
    (
        "sendgrid_key",
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "High",
        "SendGrid keys allow sending bulk emails and accessing contact lists",
    ),
    # ── Partial password patterns ──
    (
        "hardcoded_password_var",
        "Hardcoded password variable",
        r"(?i)(const|var|let|string|password|pwd)\s+\w*[Pp]ass(?:word)?\w*\s*[=:]\s*['\"][^'\"]{4,}['\"]",
        "High",
        "Hardcoded password in source code / config — should use environment variables or secret managers",
    ),
]

# Compiled patterns
_COMPILED = [
    (rule_id, desc, re.compile(pattern, re.MULTILINE), risk, why)
    for rule_id, desc, pattern, risk, why in _PATTERNS
]


# ── Text extraction ───────────────────────────────────────────────────────────

def _extract_text(file_bytes: bytes) -> str:
    """
    Extract printable text from raw file bytes.
    Tries UTF-8, then UTF-16, then Latin-1 (always succeeds).
    Also attempts to find base64-encoded blobs and decode them.
    """
    # Primary: UTF-8
    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    # Supplement: UTF-16 (common in some Office internals)
    try:
        text_16 = file_bytes.decode("utf-16", errors="replace")
        if len(text_16) > 10:
            text = text + "\n" + text_16
    except Exception:
        pass

    # Supplement: Latin-1 fallback
    try:
        text_latin = file_bytes.decode("latin-1", errors="replace")
        text = text + "\n" + text_latin
    except Exception:
        pass

    return text


def _decode_base64_blobs(text: str) -> str:
    """Find long base64 strings and append their decoded form for scanning."""
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    extras = []
    for match in b64_pattern.finditer(text):
        blob = match.group(0)
        try:
            # Correct padding without over-padding valid strings
            padding_needed = (4 - len(blob) % 4) % 4
            decoded = base64.b64decode(blob + "=" * padding_needed).decode("utf-8", errors="replace")
            if decoded.isprintable() and len(decoded) > 10:
                extras.append(decoded)
        except Exception:
            pass
    return "\n".join(extras)


def _redact(value: str, keep_chars: int = 6) -> str:
    """Redact a secret value, keeping only the first N chars visible."""
    if len(value) <= keep_chars:
        return "*" * len(value)
    return value[:keep_chars] + "****"


def _get_context(text: str, start: int, window: int = 50) -> str:
    """Extract surrounding context around a match position."""
    ctx_start = max(0, start - window)
    ctx_end   = min(len(text), start + window)
    return text[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")


# ── Main entry point ──────────────────────────────────────────────────────────

def scan(file_bytes: bytes) -> list:
    """
    Scan file bytes for credential exposure patterns.
    Runs on ALL file types.
    Returns a flat list of finding dicts.
    """
    findings  = []
    seen_keys = set()  # Deduplicate: (rule_id, redacted_value)

    # Extract all text layers
    text = _extract_text(file_bytes)
    # Also scan base64-decoded content
    decoded_extras = _decode_base64_blobs(text)
    full_text = text + "\n" + decoded_extras

    for rule_id, description, compiled_re, risk_tier, why_flagged in _COMPILED:
        matches = list(compiled_re.finditer(full_text))
        if not matches:
            continue

        for match in matches[:5]:  # Max 5 findings per rule to avoid noise
            matched_val = match.group(0)

            # Redact the secret portion for the finding
            redacted = _redact(matched_val)

            dedup_key = (rule_id, redacted[:20])
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            context = _get_context(full_text, match.start())

            findings.append({
                "stage":       "Credential Exposure Scanner",
                "rule":        rule_id,
                "description": description,
                "detail":      f"Value (redacted): {redacted} — matched at offset {match.start()}",
                "risk_tier":   risk_tier,
                "category":    "credential_exposure",
                "context":     context,
                "why_flagged": why_flagged,
            })

    # Summarize grouped credential types if multiple found
    if len(findings) > 1:
        types_found = list({f["description"] for f in findings})
        for f in findings:
            f["co_occurring_types"] = types_found

    return findings
