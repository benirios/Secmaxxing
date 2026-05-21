![alt text](https://github.com/benirios/Secmaxxing/blob/main/smaxxing.png "Logo Title Text 1")

> "Ran it on a project I'd been shipping for months. Found a tracked `.env` with live keys and a `getSession()` auth hole on every server route. Fixed in one command."

> "Finally a security tool that doesn't require a PhD to read the output. Just tells you what's broken and how to fix it."

> "Covers the stuff that actually gets you hacked — not just linting rules dressed up as security."

A Claude Code skill that audits your codebase for real security vulnerabilities — from `.env` in git to SQL injection and XSS — and fixes what it can, safely.

---

## Why I Built This

Most security tools are built for enterprise security teams. Long XML reports, SAST dashboards, 200-line configs. I'm a solo developer. I need to know: **is my app going to get hacked?**

So I built Secmaxxing. It scans for the vulnerabilities that actually show up in real breaches — hardcoded secrets, injection flaws, auth bypasses, exposed credentials. Three modes: read-only scan, safe fixes, and heavy fixes with a git checkpoint.

The system does the boring work. You just review what it finds.

---

## How It Works

Three commands. Each one does exactly one thing.

### 1. Review

```
/secmaxxing review
```

Scans every file in your project. Writes a `sec-report.md` with every finding sorted by severity — CRITICAL first. Zero writes to your code. Run this first, always.

### 2. Audit

```
/secmaxxing audit
```

Applies safe, non-breaking fixes automatically:
- Adds `.env*`, `*.pem`, `*.key` to `.gitignore` if missing
- Creates `.env.example` from your `.env` keys (values redacted)
- Replaces `http://` with `https://` in config files
- Adds `Content-Security-Policy` stub to `next.config.js`
- Adds `httpOnly` / `secure` flag TODOs to cookie setters

No file deletions. No logic changes. Safe to run on any branch.

### 3. Destructive

```
/secmaxxing destructive
```

Heavy fixes. Before touching anything, it:
1. Asserts you're in a git repo with a remote
2. Commits all uncommitted work
3. Creates (or switches to) a `secmaxxing-audit` branch

Then applies:
- `git rm --cached` on tracked `.env` files
- `eval()` → `JSON.parse()` where safe
- `getSession()` → `getUser()` in Supabase server files
- Inline fix comments for patterns that need manual review

You push when you're ready. It never touches the remote.

---

## Getting Started

```bash
npx secmaxxing
```

Clones the skill into `~/.claude/skills/secmaxxing`. Restart Claude Code, then:

```
/secmaxxing review
/secmaxxing audit
/secmaxxing destructive
```

**Requires:** Python 3.8+, git

---

## What It Covers

39 security checks across 3 tiers.

### 🔴 Tier 1 — Critical (Secrets & Config)

| ID | Check | Auto-fix |
|----|-------|----------|
| S001 | `.env` not in `.gitignore` | `audit` |
| S002 | `.env` committed to git | `destructive` |
| S003a | OpenAI API key hardcoded (`sk-...`) | `destructive` |
| S003b | AWS access key hardcoded (`AKIA...`) | `destructive` |
| S003c | GitHub token hardcoded (`ghp_...`) | `destructive` |
| S003d | Slack bot token hardcoded (`xoxb-...`) | `destructive` |
| S003e | Google API key hardcoded (`AIza...`) | `destructive` |
| S003f | Password hardcoded in source | `destructive` |
| S003g | Secret/token hardcoded in source | `destructive` |
| S004a | `NEXT_PUBLIC_` exposing secret to browser | `destructive` |
| S005 | Supabase service role key as `NEXT_PUBLIC_` | `destructive` |
| S006a | Credentials left in code comments | manual |
| S019a | Cookie missing `httpOnly: true` | `audit` |
| S019b | Cookie missing `secure: true` | `audit` |
| S020 | Non-localhost `http://` URL in config | `audit` |
| S034 | Missing `Content-Security-Policy` header | `audit` |
| S038 | `.env.example` missing | `audit` |

### 🟠 Tier 2 — High (Injection & Auth)

| ID | Check | Auto-fix |
|----|-------|----------|
| S010 | SQL injection via string concatenation | `destructive` |
| S011 | SQL injection via template literal | `destructive` |
| S010py | SQL injection via `%` formatting (Python) | `destructive` |
| S012 | `dangerouslySetInnerHTML` without sanitization | `destructive` |
| S013 | `innerHTML` assignment | `destructive` |
| S013b | `outerHTML` assignment | `destructive` |
| S014 | `eval()` usage | `destructive` |
| S014b | `new Function()` with user input | `destructive` |
| S015 | `document.write()` usage | `destructive` |
| S016a | Command injection via `exec`/`spawn` (JS) | `destructive` |
| S016b | Command injection via `subprocess` (Python) | `destructive` |
| S017a | Path traversal via `readFile` (JS) | `destructive` |
| S017b | Path traversal via `open()` (Python) | `destructive` |
| S018 | Supabase `getSession()` on server — use `getUser()` | `destructive` |
| S021 | Open redirect with user-controlled URL | manual |
| S030a | No rate limiting on auth routes | manual |
| S032 | Prototype pollution via `Object.assign` | `destructive` |
| S033 | File upload without MIME type validation | manual |
| S036 | Sensitive data in `console.log` | `destructive` |

### 🟡 Tier 3 — Medium (Structural)

| ID | Check | Auto-fix |
|----|-------|----------|
| S031 | Missing CSRF protection on mutation routes | manual |
| S035 | npm audit vulnerabilities | manual |
| S035b | No package lockfile | manual |
| S035c | Wildcard `*` dependency version | `destructive` |
| S035d | `latest` dependency version | manual |
| S037a | Possible IDOR — no ownership check | manual |
| S039 | RLS not enabled on Supabase table | manual |

---

## Commands

| Command | What it does |
|---------|-------------|
| `/secmaxxing review [path]` | Full scan → `sec-report.md`. Zero writes. |
| `/secmaxxing audit [path]` | Safe auto-fixes. No deletions, no logic changes. |
| `/secmaxxing destructive [path]` | Heavy fixes. Git branch checkpoint first. |

`path` defaults to current working directory.

**Destructive flags:**

| Flag | What it does |
|------|-------------|
| `--no-remote` | Skip git remote check (proceed without remote — your risk) |

---

## Guardrails

Secmaxxing will **never** touch:

- `.env.example`
- Migration files (`prisma/`, `supabase/migrations/`, `.migration.ts`)
- Test files (`*.test.ts`, `*.spec.py`, `test_*.py`, `__tests__/`)
- Auth middleware (`middleware.ts`)
- `package.json`, `vercel.json`, `Dockerfile`, `docker-compose.yml`
- `prisma/schema.prisma`

These are flagged in `sec-report.md` with manual remediation instructions. They are never auto-modified.

---

## Why It Works

Three things most security scans get wrong:

**1. False positives kill trust.** Secmaxxing skips documentation and report files when scanning for secrets. It won't flag `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE` inside a README example.

**2. Findings without fixes are noise.** Every finding includes a remediation instruction. Auto-fixable findings are tagged with which command fixes them. The report ends with two checklists: safe fixes and destructive fixes.

**3. Destructive tools need checkpoints.** The `destructive` command refuses to run without a git repo. It commits your work, creates a branch, then applies changes. If anything goes wrong, `git checkout main` puts you back.

---

## Report Format

`sec-report.md` is written to your project root after every scan.

```
# Security Report — myapp — 2026-05-21 10:35

## Summary
| Severity | Count |
| CRITICAL |   4   |
| HIGH     |   7   |
| MEDIUM   |   2   |
| LOW      |   1   |

## 🔴 CRITICAL
### [S002] .env committed to git
- Location: `.env`
- Description: ...
- Remediation: git rm --cached .env && add to .gitignore
- Auto-fix: `secmaxxing destructive`

...

## Checklist — Safe fixes (`secmaxxing audit`)
- [ ] [S001] .env not in .gitignore — `.gitignore`

## Checklist — Destructive fixes (`secmaxxing destructive`)
- [ ] [S002] .env committed to git — `.env`
```

---

## Troubleshooting

**Skill not showing up after install?** Restart Claude Code.

**Python not found?** Secmaxxing requires Python 3.8+. Check: `python3 --version`

**Destructive mode aborted — no remote?** Either add a remote (`git remote add origin <url>`) or run with `--no-remote` flag to skip the check at your own risk.

**False positive on a finding?** Open an issue on [GitHub](https://github.com/benirios/Secmaxxing/issues). Include the file type and the matched line.

**Re-install / update:**
```bash
npx secmaxxing
```
The installer is idempotent — if the skill is already installed, it runs `git pull` instead.

---

## License

MIT — see [LICENSE](LICENSE) for details.
