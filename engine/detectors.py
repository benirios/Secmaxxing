import re
import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class Finding:
    id: str
    tier: int
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    file: str
    line: Optional[int]
    title: str
    description: str
    remediation: str
    auto_fixable: bool = False
    destructive_fixable: bool = False
    context: str = ""


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ── Regex patterns ──────────────────────────────────────────────────────────

SECRETS_PATTERNS = [
    ("S003a", re.compile(r'sk-[a-zA-Z0-9]{20,}'), "CRITICAL",
     "OpenAI API key exposed",
     "OpenAI secret key hardcoded in source",
     "Move to environment variable + rotate key"),
    ("S003b", re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL",
     "AWS access key exposed",
     "AWS access key ID hardcoded in source",
     "Move to environment variable + rotate key"),
    ("S003c", re.compile(r'ghp_[a-zA-Z0-9]{36}'), "CRITICAL",
     "GitHub token exposed",
     "GitHub personal access token hardcoded",
     "Move to environment variable + revoke token"),
    ("S003d", re.compile(r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+'), "CRITICAL",
     "Slack bot token exposed",
     "Slack bot token hardcoded in source",
     "Move to environment variable + revoke token"),
    ("S003e", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "CRITICAL",
     "Google API key exposed",
     "Google API key hardcoded in source",
     "Move to environment variable"),
    ("S003f", re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), "CRITICAL",
     "Hardcoded password",
     "Password value hardcoded in source",
     "Move to environment variable"),
    ("S003g", re.compile(r'(?:secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), "HIGH",
     "Hardcoded secret/token",
     "Secret or token hardcoded in source",
     "Move to environment variable"),
    ("S004a", re.compile(r'NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASS|PRIVATE)[A-Z_]*\s*='), "CRITICAL",
     "NEXT_PUBLIC_ exposes secret",
     "Secret exposed to browser via NEXT_PUBLIC_ prefix",
     "Rename variable; remove NEXT_PUBLIC_ prefix"),
    ("S005", re.compile(r'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE'), "CRITICAL",
     "Supabase service role key exposed to client",
     "Service role key is admin-level and must never reach the browser",
     "Rename to server-only env var immediately"),
    ("S006a", re.compile(r'//.*(?:password|secret|token|key)\s*[=:]\s*\S{8,}', re.IGNORECASE), "HIGH",
     "Secret in comment",
     "Credential or key value left in code comment",
     "Remove comment; use env var reference"),
]

INJECTION_PATTERNS = [
    ("S010", re.compile(r'(?:query|execute|raw)\s*\(\s*["\'\`][^"\'`]*["\'\`]\s*\+'), "CRITICAL",
     "SQL injection via string concat",
     "User-controlled data concatenated into SQL string",
     "Use parameterized queries or ORM methods"),
    ("S011", re.compile(r'(?:query|execute|raw)\s*\(`[^`]*\$\{'), "CRITICAL",
     "SQL injection via template literal",
     "Template literal used to build SQL — enables injection",
     "Use parameterized queries with $1/$2 placeholders"),
    ("S016a", re.compile(r'(?:exec|spawn|execSync|spawnSync)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)'), "CRITICAL",
     "Command injection via exec/spawn",
     "User input passed directly to shell command",
     "Validate and sanitize input; use execFile with arg array"),
    ("S017a", re.compile(r'(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)'), "HIGH",
     "Path traversal via readFile",
     "User-controlled path passed to file read operation",
     "Sanitize with path.resolve() + check against allowed base dir"),
    ("S021", re.compile(r'(?:redirect|res\.redirect|router\.push)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)'), "HIGH",
     "Open redirect with user input",
     "Redirect URL sourced from user input enables phishing",
     "Validate redirect target against allowlist"),
    ("S032", re.compile(r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|request\.)'), "HIGH",
     "Prototype pollution risk",
     "Object.assign with empty object and user input enables prototype pollution",
     "Use explicit property mapping instead of spreading request body"),
    ("S016b", re.compile(r'subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*(?:request\.|input\(|argv)'), "CRITICAL",
     "Command injection via subprocess",
     "User input passed directly to shell subprocess",
     "Use subprocess with list args; never shell=True with user input"),
]

XSS_PATTERNS = [
    ("S012", re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{'), "HIGH",
     "dangerouslySetInnerHTML without sanitization",
     "Raw HTML injected into DOM — XSS if content is user-controlled",
     "Wrap value with DOMPurify.sanitize() or use a safe renderer"),
    ("S013", re.compile(r'\.innerHTML\s*=(?!.*DOMPurify)'), "HIGH",
     "innerHTML assignment",
     "Direct innerHTML assignment enables XSS if value includes user input",
     "Use textContent for text; DOMPurify.sanitize() for HTML"),
    ("S014", re.compile(r'\beval\s*\('), "CRITICAL",
     "eval() usage",
     "eval() executes arbitrary code — critical XSS and RCE vector",
     "Replace with JSON.parse() for data; avoid dynamic code eval"),
    ("S014b", re.compile(r'\bnew\s+Function\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)'), "CRITICAL",
     "new Function() with user input",
     "Dynamic function construction from user input — RCE vector",
     "Never pass user input to new Function()"),
    ("S015", re.compile(r'document\.write\s*\('), "HIGH",
     "document.write() usage",
     "document.write blocks parsing and enables XSS",
     "Replace with safe DOM manipulation methods"),
    ("S013b", re.compile(r'\.outerHTML\s*='), "HIGH",
     "outerHTML assignment",
     "Direct outerHTML assignment enables XSS",
     "Use safe DOM methods or DOMPurify.sanitize()"),
    ("S036", re.compile(r'console\.(?:log|info|warn|error)\s*\([^)]*(?:password|token|secret|user|session|cookie|auth)', re.IGNORECASE), "MEDIUM",
     "Sensitive data in console log",
     "Credentials or session data logged — leaks in log aggregators",
     "Remove log or redact sensitive fields"),
]

AUTH_PATTERNS = [
    ("S018", re.compile(r'\.auth\.getSession\s*\(\s*\)'), "CRITICAL",
     "Supabase getSession() on server",
     "getSession() trusts client-supplied JWT without server verification",
     "Replace with supabase.auth.getUser() on all server-side code"),
    ("S031", re.compile(r'(?:app\.post|router\.post|app\.put|router\.put)\s*\([^)]*auth'), "MEDIUM",
     "Verify CSRF protection on mutation route",
     "POST/PUT route with auth — verify CSRF token validation present",
     "Add CSRF middleware or use SameSite=Strict cookies"),
    ("S030a", re.compile(r'(?:app\.post|router\.post)\s*\([^)]*(?:login|signin|auth|token)'), "HIGH",
     "Verify rate limiting on auth route",
     "Login/auth endpoint — verify rate limiting middleware is present",
     "Add rate limiting middleware (e.g. express-rate-limit)"),
    ("S033", re.compile(r'(?:upload|multer|formidable|busboy)(?![\s\S]{0,200}(?:mimetype|fileFilter|allowedTypes))'), "HIGH",
     "File upload without type validation",
     "File upload handler lacks MIME type or extension filtering",
     "Add fileFilter to validate MIME type and extension allowlist"),
]

CONFIG_PATTERNS = [
    ("S020", re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)'), "MEDIUM",
     "Insecure HTTP URL",
     "Non-localhost HTTP URL in source — should be HTTPS",
     "Replace with https://"),
    ("S019a", re.compile(r'(?:Set-Cookie|cookie\s*\(|cookies\.set)[^;}\n]*(?!\bhttpOnly\s*:\s*true)'), "HIGH",
     "Cookie possibly missing httpOnly flag",
     "Cookie set without httpOnly:true enables XSS token theft",
     "Add httpOnly: true to cookie options"),
]


def scan_line_patterns(lines: list[str], file_path: str, patterns: list, tier: int,
                       auto_fixable: bool = False, destructive_fixable: bool = False) -> list[Finding]:
    findings = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        for rule_id, pattern, severity, title, description, remediation in patterns:
            if pattern.search(line):
                findings.append(Finding(
                    id=rule_id,
                    tier=tier,
                    severity=severity,
                    file=file_path,
                    line=lineno,
                    title=title,
                    description=description,
                    remediation=remediation,
                    auto_fixable=auto_fixable,
                    destructive_fixable=destructive_fixable,
                    context=line.rstrip(),
                ))
    return findings


def scan_secrets(lines: list[str], file_path: str) -> list[Finding]:
    return scan_line_patterns(lines, file_path, SECRETS_PATTERNS, tier=1,
                              auto_fixable=False, destructive_fixable=True)


def scan_injection(lines: list[str], file_path: str) -> list[Finding]:
    return scan_line_patterns(lines, file_path, INJECTION_PATTERNS, tier=2,
                              auto_fixable=False, destructive_fixable=True)


def scan_xss(lines: list[str], file_path: str) -> list[Finding]:
    return scan_line_patterns(lines, file_path, XSS_PATTERNS, tier=2,
                              auto_fixable=False, destructive_fixable=True)


def scan_auth(lines: list[str], file_path: str) -> list[Finding]:
    return scan_line_patterns(lines, file_path, AUTH_PATTERNS, tier=2,
                              auto_fixable=False, destructive_fixable=False)


def scan_config(lines: list[str], file_path: str) -> list[Finding]:
    return scan_line_patterns(lines, file_path, CONFIG_PATTERNS, tier=1,
                              auto_fixable=True, destructive_fixable=False)


def scan_env_vars(lines: list[str], file_path: str) -> list[Finding]:
    """Scan .env files for NEXT_PUBLIC_ secret exposure."""
    findings = []
    secret_keywords = re.compile(r'SECRET|KEY|TOKEN|PASS|PRIVATE|CREDENTIAL', re.IGNORECASE)
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith('#') or '=' not in stripped:
            continue
        var_name = stripped.split('=')[0]
        if var_name.startswith('NEXT_PUBLIC_') and secret_keywords.search(var_name):
            findings.append(Finding(
                id="S004a",
                tier=1,
                severity="CRITICAL",
                file=file_path,
                line=lineno,
                title="NEXT_PUBLIC_ exposes secret",
                description=f"Variable '{var_name}' is exposed to the browser via NEXT_PUBLIC_ prefix",
                remediation="Remove NEXT_PUBLIC_ prefix; access server-side only",
                auto_fixable=False,
                destructive_fixable=True,
                context=line.rstrip(),
            ))
    return findings


def scan_sql_migrations(lines: list[str], file_path: str) -> list[Finding]:
    """Check SQL/migration files for tables missing RLS."""
    findings = []
    content = "\n".join(lines)
    create_tables = re.findall(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)', content, re.IGNORECASE)
    rls_enables = re.findall(r'ENABLE\s+ROW\s+LEVEL\s+SECURITY', content, re.IGNORECASE)

    if create_tables and not rls_enables:
        for table in create_tables:
            findings.append(Finding(
                id="S039",
                tier=3,
                severity="CRITICAL",
                file=file_path,
                line=None,
                title=f"RLS not enabled on table {table}",
                description=f"Table '{table}' created without enabling Row Level Security",
                remediation=f"Add: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; + policy",
                auto_fixable=False,
                destructive_fixable=False,
                context=f"Table: {table}",
            ))
    return findings
