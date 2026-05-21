import subprocess
import sys
import os
from pathlib import Path


BRANCH_NAME = "secmaxxing-audit"


def _run(cmd: list[str], cwd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check, timeout=30)


def assert_git_repo(cwd: str) -> bool:
    try:
        result = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def has_remote(cwd: str) -> bool:
    try:
        result = _run(["git", "remote"], cwd=cwd, check=False)
        return bool(result.stdout.strip())
    except FileNotFoundError:
        return False


def current_branch(cwd: str) -> str:
    try:
        result = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def branch_exists(cwd: str, branch: str) -> bool:
    result = _run(["git", "branch", "--list", branch], cwd=cwd, check=False)
    return bool(result.stdout.strip())


def has_uncommitted_changes(cwd: str) -> bool:
    result = _run(["git", "status", "--porcelain"], cwd=cwd, check=False)
    return bool(result.stdout.strip())


def prepare_destructive(cwd: str, no_remote: bool = False) -> bool:
    """
    Ensures we are on (or switch to) secmaxxing-audit branch with all
    current work committed. Returns True if safe to proceed.
    """
    if not assert_git_repo(cwd):
        print("\n[secmaxxing] ERROR: Not a git repository.")
        print("  Destructive mode requires git to create a safety checkpoint branch.")
        print("  Options:")
        print("    1. Run: git init && git add -A && git commit -m 'initial'")
        print("    2. Re-run with --no-remote flag to skip remote check (still needs git)")
        return False

    if not no_remote and not has_remote(cwd):
        print("\n[secmaxxing] WARNING: No git remote found.")
        print("  Destructive mode is safer with a remote (push to recover if needed).")
        print("  Options:")
        print("    1. Add a remote: git remote add origin <url>")
        print("    2. Re-run with --no-remote flag to proceed without remote (YOUR RISK)")
        return False

    # Commit any uncommitted changes first
    if has_uncommitted_changes(cwd):
        print(f"\n[secmaxxing] Committing current work before destructive changes...")
        _run(["git", "add", "-A"], cwd=cwd)
        _run(["git", "commit", "-m", "chore(secmaxxing): checkpoint before destructive security fixes"], cwd=cwd)
        print("  ✓ Work committed")

    # Switch to or create secmaxxing-audit branch
    if branch_exists(cwd, BRANCH_NAME):
        print(f"[secmaxxing] Branch '{BRANCH_NAME}' exists — switching to it...")
        _run(["git", "checkout", BRANCH_NAME], cwd=cwd)
    else:
        print(f"[secmaxxing] Creating branch '{BRANCH_NAME}'...")
        _run(["git", "checkout", "-b", BRANCH_NAME], cwd=cwd)

    print(f"  ✓ On branch '{BRANCH_NAME}'. Proceeding with destructive fixes.\n")
    return True


def commit_fixes(cwd: str, message: str = "fix(security): apply secmaxxing destructive fixes"):
    if has_uncommitted_changes(cwd):
        _run(["git", "add", "-A"], cwd=cwd)
        result = _run(["git", "commit", "-m", message], cwd=cwd, check=False)
        if result.returncode == 0:
            print(f"\n[secmaxxing] ✓ Fixes committed to '{BRANCH_NAME}'")
            print("  To push: git push origin " + BRANCH_NAME)
        else:
            print(f"\n[secmaxxing] git commit failed: {result.stderr}")
