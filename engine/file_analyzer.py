import os
from pathlib import Path
from engine.detectors import (
    Finding,
    scan_secrets,
    scan_injection,
    scan_xss,
    scan_auth,
    scan_config,
    scan_env_vars,
    scan_sql_migrations,
)

JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
PY_EXTS = {".py"}
SQL_EXTS = {".sql"}
CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".env", ".env.local",
               ".env.production", ".env.development", ".env.staging"}
DOC_EXTS = {".md", ".mdx", ".txt"}
ALL_TEXT_EXTS = JS_TS_EXTS | PY_EXTS | SQL_EXTS | CONFIG_EXTS | DOC_EXTS | {
    ".sh", ".bash", ".zsh"
}

# Skip secrets scan on generated/report files to reduce false positives
SKIP_SECRETS_NAMES = {"sec-report.md", "PLAN.md", "README.md", "CHANGELOG.md"}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist", ".next", "venv", ".venv",
    "build", "coverage", ".turbo", ".cache", "out", ".output",
}


class FileAnalyzer:
    def analyze(self, file_path: str, rel_base: str = "") -> list[Finding]:
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext not in ALL_TEXT_EXTS:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return []

        display_path = os.path.relpath(file_path, rel_base) if rel_base else file_path
        findings: list[Finding] = []

        # Secrets scan — skip doc/report files to avoid false positives from examples
        if path.name not in SKIP_SECRETS_NAMES and ext not in DOC_EXTS:
            findings += scan_secrets(lines, display_path)

        # Config-specific scans
        if ext in CONFIG_EXTS or path.name.startswith(".env"):
            findings += scan_env_vars(lines, display_path)
            findings += scan_config(lines, display_path)

        # JS/TS — full suite
        if ext in JS_TS_EXTS:
            findings += scan_injection(lines, display_path)
            findings += scan_xss(lines, display_path)
            findings += scan_auth(lines, display_path)
            findings += scan_config(lines, display_path)

        # Python
        if ext in PY_EXTS:
            findings += scan_injection(lines, display_path)
            findings += scan_config(lines, display_path)

        # SQL / migration files
        if ext in SQL_EXTS:
            findings += scan_sql_migrations(lines, display_path)

        return findings
