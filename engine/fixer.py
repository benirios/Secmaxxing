import os
import re
import subprocess
from pathlib import Path
from engine.detectors import Finding


# ── Guardrails — enforced at runtime ────────────────────────────────────────

NEVER_TOUCH_NAMES = {
    ".env.example",
    "package.json",       # scripts section sacred
    "vercel.json",
    "netlify.toml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitignore",         # only additive changes allowed (handled separately)
}

NEVER_TOUCH_PATTERNS = [
    re.compile(r'migrations?/', re.IGNORECASE),
    re.compile(r'\.migration\.[tj]s$', re.IGNORECASE),
    re.compile(r'__tests__/'),
    re.compile(r'\.test\.[tj]sx?$'),
    re.compile(r'\.spec\.[tj]sx?$'),
    re.compile(r'\.test\.py$'),
    re.compile(r'(?:^|/)test_[^/]+\.py$'),    # test_*.py anywhere
    re.compile(r'(?:^|/)tests?/'),             # /test/ or /tests/ anywhere
    re.compile(r'(?:^|/)__tests__/'),
    re.compile(r'middleware\.[tj]s$', re.IGNORECASE),
    re.compile(r'/auth/(?:middleware|guard|protect)\.[tj]sx?$', re.IGNORECASE),
    re.compile(r'prisma/schema\.prisma$'),
    re.compile(r'supabase/migrations/'),
    re.compile(r'\.spec\.py$'),
]


def is_protected(file_path: str) -> bool:
    name = Path(file_path).name
    if name in NEVER_TOUCH_NAMES:
        return True
    normalized = file_path.replace("\\", "/")
    return any(p.search(normalized) for p in NEVER_TOUCH_PATTERNS)


def guard(file_path: str, operation: str = "modify") -> None:
    """Raise if file is protected. Call before any write/delete."""
    if is_protected(file_path):
        raise PermissionError(
            f"[guardrail] Blocked: cannot {operation} protected file: {file_path}"
        )


# ── Audit-safe fixes ────────────────────────────────────────────────────────

def fix_gitignore(target_path: str) -> list[str]:
    """Add missing .env patterns to .gitignore."""
    gitignore_path = os.path.join(target_path, ".gitignore")
    required = [".env", ".env.local", ".env.*.local", "*.pem", "*.key"]
    changed = []

    if not os.path.exists(gitignore_path):
        with open(gitignore_path, "w") as f:
            f.write("\n".join(required) + "\n")
        changed.append(f"Created .gitignore with: {', '.join(required)}")
        return changed

    with open(gitignore_path, "r") as f:
        content = f.read()

    missing = [p for p in required if p not in content]
    if missing:
        with open(gitignore_path, "a") as f:
            f.write("\n# Added by secmaxxing audit\n")
            for p in missing:
                f.write(p + "\n")
        changed.append(f".gitignore: added {', '.join(missing)}")

    return changed


def fix_env_example(target_path: str) -> list[str]:
    """Create .env.example if missing, populated from .env keys."""
    example_path = os.path.join(target_path, ".env.example")
    if os.path.exists(example_path):
        return []

    env_path = os.path.join(target_path, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()
        example_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                example_lines.append(line)
            elif '=' in stripped:
                key = stripped.split('=')[0]
                example_lines.append(f"{key}=\n")
        with open(example_path, "w") as f:
            f.writelines(example_lines)
        return [f"Created .env.example from .env keys (values redacted)"]
    else:
        with open(example_path, "w") as f:
            f.write("# Add all required environment variables here (no values)\n")
        return ["Created empty .env.example"]


def fix_http_urls(file_path: str) -> list[str]:
    """Replace http:// with https:// in non-logic config/constants files."""
    safe_exts = {".json", ".toml", ".yaml", ".yml", ".env", ".env.example"}
    if Path(file_path).suffix.lower() not in safe_exts:
        return []
    guard(file_path, "modify")

    http_pattern = re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)')
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    new_content, count = http_pattern.subn("https://", content)
    if count > 0:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return [f"{file_path}: replaced {count} http:// → https://"]
    return []


def fix_csp_stub(target_path: str) -> list[str]:
    """Add Content-Security-Policy stub to next.config.js if missing."""
    config_files = ["next.config.js", "next.config.mjs", "next.config.ts"]
    changed = []

    for config_file in config_files:
        config_path = os.path.join(target_path, config_file)
        if not os.path.exists(config_path):
            continue
        try:
            guard(config_path, "modify")
        except PermissionError as e:
            changed.append(f"SKIP (guardrail): {e}")
            continue

        with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if "Content-Security-Policy" in content or "contentSecurityPolicy" in content:
            continue

        csp_comment = """
// TODO(secmaxxing): Add Content-Security-Policy header
// headers: async () => [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }]
"""
        with open(config_path, "a") as f:
            f.write(csp_comment)
        changed.append(f"{config_file}: added CSP TODO comment")

    return changed


# ── Destructive fixes ────────────────────────────────────────────────────────

def fix_git_untrack_env(target_path: str, findings: list[Finding]) -> list[str]:
    """Run git rm --cached on tracked .env files."""
    changed = []
    env_findings = [f for f in findings if f.id == "S002"]

    for finding in env_findings:
        file_path = finding.file
        try:
            result = subprocess.run(
                ["git", "rm", "--cached", file_path],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                changed.append(f"git rm --cached {file_path} — file removed from tracking")
            else:
                changed.append(f"WARN: git rm --cached {file_path} failed: {result.stderr.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            changed.append(f"WARN: Could not run git rm --cached {file_path}: {e}")

    return changed


def fix_eval_usage(file_path: str, lines: list[str]) -> list[str]:
    """Replace bare eval() with JSON.parse() where clearly safe."""
    guard(file_path, "modify")
    changed = []
    eval_json = re.compile(r'\beval\s*\(\s*([^)]+)\s*\)')
    new_lines = []
    modified = False

    for i, line in enumerate(lines):
        match = eval_json.search(line)
        if match:
            arg = match.group(1).strip()
            # Only auto-replace if arg looks like a JSON string variable (not code)
            if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', arg):
                new_line = line[:match.start()] + f"JSON.parse({arg})" + line[match.end():]
                new_lines.append(new_line)
                changed.append(f"{file_path}:{i+1}: eval({arg}) → JSON.parse({arg})")
                modified = True
                continue
        new_lines.append(line)

    if modified:
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return changed


def fix_getSession(file_path: str, lines: list[str]) -> list[str]:
    """Replace supabase.auth.getSession() with supabase.auth.getUser() on server files."""
    server_indicators = ["/api/", "route.ts", "route.js", "server.", "actions.", "middleware."]
    if not any(ind in file_path for ind in server_indicators):
        return []
    guard(file_path, "modify")

    changed = []
    pattern = re.compile(r'\.auth\.getSession\s*\(\s*\)')
    new_lines = []
    modified = False

    for i, line in enumerate(lines):
        new_line = pattern.sub(".auth.getUser()", line)
        if new_line != line:
            new_lines.append(new_line)
            changed.append(f"{file_path}:{i+1}: getSession() → getUser()")
            modified = True
        else:
            new_lines.append(line)

    if modified:
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return changed


def apply_audit_fixes(target_path: str, findings: list[Finding]) -> list[str]:
    """Apply all auto_fixable fixes. Returns list of change descriptions."""
    all_changes = []

    all_changes += fix_gitignore(target_path)
    all_changes += fix_env_example(target_path)
    all_changes += fix_csp_stub(target_path)

    # Per-file fixes
    http_findings = [f for f in findings if f.id == "S020" and f.auto_fixable]
    seen_files = set()
    for finding in http_findings:
        fp = os.path.join(target_path, finding.file) if not os.path.isabs(finding.file) else finding.file
        if fp not in seen_files and os.path.exists(fp):
            all_changes += fix_http_urls(fp)
            seen_files.add(fp)

    return all_changes


def apply_destructive_fixes(target_path: str, findings: list[Finding]) -> list[str]:
    """Apply destructive fixes. Returns list of change descriptions."""
    all_changes = []

    # git rm --cached .env
    all_changes += fix_git_untrack_env(target_path, findings)

    # Per-file destructive fixes
    from engine.file_analyzer import ALL_TEXT_EXTS
    processed = set()

    for finding in findings:
        fp = os.path.join(target_path, finding.file) if not os.path.isabs(finding.file) else finding.file
        if fp in processed or not os.path.exists(fp):
            continue

        # Hard guardrail check before any destructive write
        if is_protected(fp):
            all_changes.append(f"SKIP (guardrail): {fp} is protected — fix manually")
            processed.add(fp)
            continue

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue

        if finding.id == "S014":
            try:
                all_changes += fix_eval_usage(fp, lines)
            except PermissionError as e:
                all_changes.append(f"SKIP (guardrail): {e}")

        if finding.id == "S018":
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    fresh_lines = f.readlines()
                all_changes += fix_getSession(fp, fresh_lines)
            except (OSError, PermissionError) as e:
                all_changes.append(f"SKIP (guardrail): {e}")

        processed.add(fp)

    return all_changes
