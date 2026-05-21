import os
import subprocess
from pathlib import Path
from engine.detectors import Finding
from engine.file_analyzer import FileAnalyzer, SKIP_DIRS


class ProjectAnalyzer:
    def __init__(self, target_path: str):
        self.target_path = str(Path(target_path).resolve())
        self.file_analyzer = FileAnalyzer()

    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []

        # File-level scan
        target = Path(self.target_path)
        if target.is_file():
            findings += self.file_analyzer.analyze(str(target), rel_base=str(target.parent))
            return findings

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for file_name in files:
                file_path = os.path.join(root, file_name)
                findings += self.file_analyzer.analyze(file_path, rel_base=self.target_path)

        # Project-level checks
        findings += self._check_gitignore()
        findings += self._check_git_tracked_env()
        findings += self._check_env_example()
        findings += self._check_npm_audit()
        findings += self._check_lockfile()

        return findings

    # ── Project-level checks ─────────────────────────────────────────────────

    def _check_gitignore(self) -> list[Finding]:
        gitignore_path = os.path.join(self.target_path, ".gitignore")
        if not os.path.exists(gitignore_path):
            return [Finding(
                id="S001",
                tier=1,
                severity="CRITICAL",
                file=".gitignore",
                line=None,
                title=".gitignore missing entirely",
                description="No .gitignore found — .env and other secrets may be committed",
                remediation="Create .gitignore with .env* entry",
                auto_fixable=True,
                destructive_fixable=False,
                context="File not found",
            )]

        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        findings = []
        env_patterns = [".env", ".env.local", ".env.*.local", "*.pem", "*.key", "*.p12", "*.pfx"]
        missing = []
        for pattern in env_patterns:
            if pattern not in content:
                missing.append(pattern)

        if ".env" in missing:
            findings.append(Finding(
                id="S001",
                tier=1,
                severity="CRITICAL",
                file=".gitignore",
                line=None,
                title=".env not in .gitignore",
                description=".env files not excluded from version control — secrets may be committed",
                remediation="Add .env* to .gitignore",
                auto_fixable=True,
                destructive_fixable=False,
                context=f"Missing patterns: {', '.join(missing)}",
            ))
        elif missing:
            findings.append(Finding(
                id="S001b",
                tier=1,
                severity="LOW",
                file=".gitignore",
                line=None,
                title=".gitignore missing some secret file patterns",
                description=f"Patterns not in .gitignore: {', '.join(missing)}",
                remediation=f"Add to .gitignore: {' '.join(missing)}",
                auto_fixable=True,
                destructive_fixable=False,
                context=f"Missing: {', '.join(missing)}",
            ))
        return findings

    def _check_git_tracked_env(self) -> list[Finding]:
        try:
            result = subprocess.run(
                ["git", "ls-files", ".env", ".env.local", ".env.production", ".env.development"],
                cwd=self.target_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            tracked = [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        findings = []
        for tracked_file in tracked:
            findings.append(Finding(
                id="S002",
                tier=1,
                severity="CRITICAL",
                file=tracked_file,
                line=None,
                title=f"{tracked_file} committed to git",
                description=f"{tracked_file} is tracked by git — secrets may be in history",
                remediation="Run: git rm --cached " + tracked_file + " && add to .gitignore",
                auto_fixable=False,
                destructive_fixable=True,
                context=f"git ls-files found: {tracked_file}",
            ))
        return findings

    def _check_env_example(self) -> list[Finding]:
        example_path = os.path.join(self.target_path, ".env.example")
        if not os.path.exists(example_path):
            return [Finding(
                id="S038",
                tier=3,
                severity="LOW",
                file=".env.example",
                line=None,
                title=".env.example missing",
                description="No .env.example file to document required env vars",
                remediation="Create .env.example with all required variable names (no values)",
                auto_fixable=True,
                destructive_fixable=False,
                context="File not found",
            )]
        return []

    def _check_npm_audit(self) -> list[Finding]:
        pkg_path = os.path.join(self.target_path, "package.json")
        if not os.path.exists(pkg_path):
            return []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=self.target_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            import json
            data = json.loads(result.stdout)
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            critical = vulns.get("critical", 0)
            high = vulns.get("high", 0)
            total = sum(vulns.values()) if vulns else 0

            if total > 0:
                severity = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"
                return [Finding(
                    id="S035",
                    tier=3,
                    severity=severity,
                    file="package.json",
                    line=None,
                    title=f"npm audit: {total} vulnerabilities ({critical} critical, {high} high)",
                    description=f"Dependencies contain known CVEs: {critical} critical, {high} high, {total} total",
                    remediation="Run: npm audit fix — review breaking changes manually",
                    auto_fixable=False,
                    destructive_fixable=False,
                    context=str(vulns),
                )]
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        return []

    def _check_lockfile(self) -> list[Finding]:
        pkg_path = os.path.join(self.target_path, "package.json")
        if not os.path.exists(pkg_path):
            return []

        has_lock = any(
            os.path.exists(os.path.join(self.target_path, f))
            for f in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]
        )
        if not has_lock:
            return [Finding(
                id="S035b",
                tier=3,
                severity="MEDIUM",
                file="package.json",
                line=None,
                title="No package lockfile",
                description="No lockfile found — dependency versions not pinned",
                remediation="Run npm install to generate package-lock.json",
                auto_fixable=False,
                destructive_fixable=False,
                context="Missing: package-lock.json / yarn.lock / pnpm-lock.yaml",
            )]
        return []
