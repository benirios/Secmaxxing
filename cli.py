#!/usr/bin/env python3
"""
secmaxxing — security audit and hardening CLI

Usage:
  secmaxxing review [path]       Scan project, write sec-report.md
  secmaxxing audit [path]        Apply safe fixes (no deletions, no logic changes)
  secmaxxing destructive [path]  Apply heavy fixes (branch checkpoint required)
    --no-remote                  Skip remote check (proceed without git remote)
"""

import sys
import os
from pathlib import Path

SKILL_DIR = Path(__file__).parent
sys.path.insert(0, str(SKILL_DIR))

VALID_COMMANDS = ["review", "audit", "destructive"]


def parse_args() -> tuple[str, str, bool]:
    args = sys.argv[1:]
    if not args or args[0] not in VALID_COMMANDS:
        print(__doc__)
        sys.exit(1)

    command = args[0]
    remaining = [a for a in args[1:] if not a.startswith("--")]
    flags = [a for a in args[1:] if a.startswith("--")]

    target = str(Path(remaining[0]).resolve()) if remaining else str(Path(".").resolve())
    no_remote = "--no-remote" in flags

    return command, target, no_remote


def run_review(target: str):
    from engine.project_analyzer import ProjectAnalyzer
    from engine.report_generator import generate_report

    print(f"[secmaxxing review] Scanning: {target}")
    print("  Running security checks...")

    analyzer = ProjectAnalyzer(target)
    findings = analyzer.analyze()

    output_path = os.path.join(target, "sec-report.md")
    generate_report(findings, target, output_path)

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = sum(counts.values())
    print(f"\n[secmaxxing review] Done — {total} findings:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        if n:
            print(f"  {sev}: {n}")
    print(f"\n  Report written → {output_path}")


def run_audit(target: str):
    from engine.project_analyzer import ProjectAnalyzer
    from engine.fixer import apply_audit_fixes
    from engine.report_generator import generate_report

    print(f"[secmaxxing audit] Target: {target}")
    print("  Scanning for issues...")

    analyzer = ProjectAnalyzer(target)
    findings = analyzer.analyze()

    print("  Applying safe fixes...")
    changes = apply_audit_fixes(target, findings)

    if changes:
        print(f"\n  {len(changes)} changes applied:")
        for c in changes:
            print(f"    ✓ {c}")
    else:
        print("  No safe auto-fixes needed.")

    # Regenerate report post-fix
    output_path = os.path.join(target, "sec-report.md")
    generate_report(findings, target, output_path)
    print(f"\n  Report updated → {output_path}")


def run_destructive(target: str, no_remote: bool):
    from engine.git_guard import prepare_destructive, commit_fixes
    from engine.project_analyzer import ProjectAnalyzer
    from engine.fixer import apply_audit_fixes, apply_destructive_fixes
    from engine.report_generator import generate_report

    print(f"[secmaxxing destructive] Target: {target}")
    print()
    print("  ⚠️  DESTRUCTIVE MODE — This will:")
    print("    • Commit all current work to branch 'secmaxxing-audit'")
    print("    • Remove tracked .env files from git")
    print("    • Refactor unsafe code patterns (getSession, eval, etc.)")
    print()

    if not no_remote:
        confirm = input("  Type CONFIRM to proceed (or Ctrl+C to abort): ").strip()
        if confirm != "CONFIRM":
            print("  Aborted.")
            sys.exit(0)

    if not prepare_destructive(target, no_remote=no_remote):
        sys.exit(1)

    print("  Scanning for issues...")
    analyzer = ProjectAnalyzer(target)
    findings = analyzer.analyze()

    print("  Applying audit-safe fixes first...")
    audit_changes = apply_audit_fixes(target, findings)

    print("  Applying destructive fixes...")
    destructive_changes = apply_destructive_fixes(target, findings)

    all_changes = audit_changes + destructive_changes

    if all_changes:
        print(f"\n  {len(all_changes)} changes applied:")
        for c in all_changes:
            print(f"    ✓ {c}")
        commit_fixes(target)
    else:
        print("  No changes needed.")

    output_path = os.path.join(target, "sec-report.md")
    generate_report(findings, target, output_path)
    print(f"\n  Report written → {output_path}")
    print("\n  ⚠️  REMINDER: Review changes before merging. Push when ready:")
    print("    git push origin secmaxxing-audit")


def main():
    command, target, no_remote = parse_args()

    if not Path(target).exists():
        print(f"Error: path not found: {target}")
        sys.exit(1)

    if command == "review":
        run_review(target)
    elif command == "audit":
        run_audit(target)
    elif command == "destructive":
        run_destructive(target, no_remote)


if __name__ == "__main__":
    main()
