from datetime import datetime
from pathlib import Path
from engine.detectors import Finding, SEVERITY_ORDER


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}


def generate_report(findings: list[Finding], target_path: str, output_path: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    project_name = Path(target_path).name

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line or 0))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = sum(counts.values())

    lines = [
        f"# Security Report — {project_name} — {now}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
        f"| 🟠 HIGH     | {counts['HIGH']} |",
        f"| 🟡 MEDIUM   | {counts['MEDIUM']} |",
        f"| 🔵 LOW      | {counts['LOW']} |",
        f"| **Total**   | **{total}** |",
        "",
    ]

    if total == 0:
        lines += ["## ✅ No security issues found.", ""]
    else:
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            tier_findings = [f for f in sorted_findings if f.severity == severity]
            if not tier_findings:
                continue

            emoji = SEVERITY_EMOJI[severity]
            lines += [f"## {emoji} {severity}", ""]

            for f in tier_findings:
                loc = f"{f.file}:{f.line}" if f.line else f.file
                lines += [
                    f"### [{f.id}] {f.title}",
                    f"- **Location:** `{loc}`",
                    f"- **Description:** {f.description}",
                    f"- **Remediation:** {f.remediation}",
                ]
                if f.context and f.context.strip():
                    ctx = f.context.strip()[:200]
                    lines += [f"- **Context:**", f"  ```", f"  {ctx}", f"  ```"]
                fix_tags = []
                if f.auto_fixable:
                    fix_tags.append("`secmaxxing audit`")
                if f.destructive_fixable:
                    fix_tags.append("`secmaxxing destructive`")
                if fix_tags:
                    lines += [f"- **Auto-fix:** {' / '.join(fix_tags)}"]
                lines += [""]

    # Checklists
    audit_fixable = [f for f in sorted_findings if f.auto_fixable]
    destructive_fixable = [f for f in sorted_findings if f.destructive_fixable]

    if audit_fixable:
        lines += ["---", "", "## Checklist — Safe fixes (`secmaxxing audit`)", ""]
        for f in audit_fixable:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"- [ ] [{f.id}] {f.title} — `{loc}`")
        lines.append("")

    if destructive_fixable:
        lines += ["---", "", "## Checklist — Destructive fixes (`secmaxxing destructive`)", ""]
        lines += [
            "> ⚠️  These changes modify logic or delete files. "
            "All uncommitted work will be committed to `secmaxxing-audit` branch first.",
            "",
        ]
        for f in destructive_fixable:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"- [ ] [{f.id}] {f.title} — `{loc}`")
        lines.append("")

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return content
