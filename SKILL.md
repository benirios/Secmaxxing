---
name: Secmaxxing
description: Security audit and hardening engine — scan, fix, and harden codebases
allowed-tools: Bash, Read, Edit, Write
---

# Secmaxxing

Security-first code auditing skill. Three escalating modes:

- `secmaxxing review` — full scan, zero writes, produces `sec-report.md`
- `secmaxxing audit` — safe fixes only (gitignore, headers, cookie flags, TODOs)
- `secmaxxing destructive` — heavy fixes (parameterized queries, sanitization, git rm); commits to `secmaxxing-audit` branch first

## Trigger

When user runs `/secmaxxing [review|audit|destructive] [path]`:

1. Determine target path (default: current working directory)
2. Run:

```bash
python3 ~/.claude/skills/secmaxxing/cli.py $ARGUMENTS
```

3. If `review`: summarize `sec-report.md` findings by severity tier
4. If `audit`: list every file changed and what was fixed
5. If `destructive`: confirm git safety steps completed, list all changes made

## Notes

- Always read `sec-report.md` after `review` and surface CRITICAL/HIGH findings immediately
- `destructive` mode requires git repo; warn user if none found
- Never push to remote — user controls that
