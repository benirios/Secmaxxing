# PLAN.md — Secmaxxing Skill

Security audit skill modeled after cleanmaxxing. Three-tier command system: scan-only → safe fixes → destructive fixes.

---

## Target Path

```
~/.claude/skills/secmaxxing/
```

---

## File Structure

```
secmaxxing/
├── SKILL.md                    ← Claude entry point (triggers on /secmaxxing)
├── secmaxxing.md               ← Security knowledge base + review rules
├── guardrails.md               ← What NEVER to touch (mirrors cleanmaxxing pattern)
├── cli.py                      ← CLI dispatcher: review | audit | destructive
├── engine/
│   ├── __init__.py
│   ├── detectors.py            ← Regex + AST detectors per vulnerability class
│   ├── file_analyzer.py        ← Per-file scanner, maps ext → detector set
│   ├── project_analyzer.py     ← Walks project dirs, skips node_modules/.git
│   ├── report_generator.py     ← Builds sec-report.md from findings
│   └── git_guard.py            ← Branch safety logic for destructive mode
├── rules/
│   ├── secrets-exposure.csv    ← Hardcoded creds, NEXT_PUBLIC_ leaks, .env in git
│   ├── injection-rules.csv     ← SQL injection, command injection, path traversal
│   ├── xss-rules.csv           ← dangerouslySetInnerHTML, innerHTML, eval, document.write
│   ├── auth-rules.csv          ← getSession() misuse, missing auth guards, IDOR patterns
│   ├── config-rules.csv        ← .gitignore gaps, missing security headers, HTTP refs
│   └── dependency-rules.csv    ← Known bad patterns, npm audit triggers
└── prompts/
    └── rule-engine.md          ← LLM prompt for AI-assisted deeper analysis
```

---

## Commands

### `secmaxxing review`

Read-only. Scans entire project. Produces `sec-report.md`.

**Behavior:**
- Walk all files (skip: `node_modules`, `.git`, `__pycache__`, `dist`, `.next`, `venv`)
- Run all detector tiers (T1 → T2 → T3) on every file
- Check project-level concerns (`.gitignore`, `package.json`, git history for secrets)
- Write `sec-report.md` in project root
- Zero file modifications

**sec-report.md structure:**
```
# Security Report — <project> — <date>

## Summary
| Tier | Count | Severity |
...

## Findings

### CRITICAL
- [ ] finding · file:line · description · remediation hint

### HIGH
...

### MEDIUM
...

### LOW / INFO
...

## Checklist (audit-safe)
Auto-generated list of T1+T2 fixes safe for `secmaxxing audit`

## Checklist (destructive)
Auto-generated list of T2+T3 fixes requiring `secmaxxing destructive`
```

---

### `secmaxxing audit`

Safe changes only. No file deletion. No logic rewrites.

**Allowed actions:**
- Add `.env`, `.env.local`, `*.pem`, `*.key` to `.gitignore` if missing
- Add `NEXT_PUBLIC_` variable check warnings as inline comments
- Add missing `X-Content-Type-Options`, `X-Frame-Options` headers to config files
- Replace `http://` with `https://` in config/constants (non-logic files)
- Add `httpOnly: true`, `secure: true` to cookie configs
- Flag `getSession()` calls with TODO comments (does not change logic)
- Add missing `Content-Security-Policy` stub in next.config.js if absent

**Does NOT:**
- Delete files
- Refactor auth flows
- Change business logic
- Touch database schemas or migrations

---

### `secmaxxing destructive`

Heavy changes. Requires branch safety protocol.

**Git safety protocol (enforced before any change):**
1. Check if in a git repo
   - If not: warn user, ask for confirmation to proceed without git safety, abort by default
2. Check if GitHub remote exists
   - If not: warn user, require explicit `--no-remote` confirmation or provide remote URL
3. Commit all uncommitted changes to branch `secmaxxing-audit`
   - If branch exists: commit to it
   - If not: create it from current HEAD
4. Only then apply destructive changes

**Allowed actions (beyond audit):**
- Delete committed `.env` files accidentally tracked by git (`git rm --cached`)
- Remove hardcoded credential strings and replace with `process.env.VAR_NAME` + `.env.example` stub
- Refactor SQL string concatenation → parameterized queries
- Replace `dangerouslySetInnerHTML` with sanitized alternatives (DOMPurify wrapper)
- Remove `eval()` calls where replaceable with `JSON.parse` or `Function` alternatives
- Add Supabase RLS policy stubs to migration files (adds comment block, does not auto-run)
- Wrap unguarded API routes with auth check stubs

**Does NOT (ever):**
- Delete source files that contain active business logic
- Modify test files
- Change database migrations that are already applied
- Push to remote (user must do this manually)

---

## Security Check Catalog

### Tier 1 — Critical / Always Flag

| ID | Check | Detection Method |
|----|-------|-----------------|
| S001 | `.env` not in `.gitignore` | File read: parse `.gitignore`, check for `.env` pattern |
| S002 | `.env` committed to git | `git ls-files .env*` |
| S003 | Hardcoded API keys / secrets | Regex: `(sk-\|AKIA\|ghp_\|xoxb-\|Bearer\s+[A-Za-z0-9]{20,})` |
| S004 | `NEXT_PUBLIC_` exposing non-public secrets | Regex on `.env*`: flag `NEXT_PUBLIC_` + key names containing `SECRET\|KEY\|TOKEN\|PASS` |
| S005 | Service role key as `NEXT_PUBLIC_*` | Regex: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE` |
| S006 | Passwords/tokens in source comments | Regex: `(password|secret|token)\s*[=:]\s*["\'][^"\']{8,}` |

### Tier 2 — High

| ID | Check | Detection Method |
|----|-------|-----------------|
| S010 | SQL injection: string concatenation in query | Regex: `(query|execute|raw)\s*\(.*\+.*\)` / AST |
| S011 | SQL injection: template literals in query | Regex: `(query|execute|raw)\s*\(\`.*\$\{` |
| S012 | XSS: `dangerouslySetInnerHTML` | Regex: `dangerouslySetInnerHTML` without sanitization wrapper |
| S013 | XSS: `innerHTML` assignment | Regex: `\.innerHTML\s*=` |
| S014 | XSS: `eval()` usage | Regex: `\beval\s*\(` |
| S015 | XSS: `document.write()` | Regex: `document\.write\s*\(` |
| S016 | Command injection: `exec`/`spawn` with user input | Regex: `(exec|spawn|execSync)\s*\(.*req\.(body\|query\|params)` |
| S017 | Path traversal: `readFile` with user input | Regex: `readFile.*req\.(body\|query\|params)` |
| S018 | `getSession()` instead of `getUser()` (Supabase) | Regex: `\.auth\.getSession\(\)` in server files |
| S019 | Missing `httpOnly` on cookies | Regex: `cookie\(` without `httpOnly: true` nearby |
| S020 | HTTP (non-HTTPS) URLs in config | Regex: `http://` in config/constants files (not localhost) |
| S021 | Open redirect: unvalidated redirect URLs | Regex: `redirect\(.*req\.(body\|query\|params)` |

### Tier 3 — Medium / Structural

| ID | Check | Detection Method |
|----|-------|-----------------|
| S030 | No rate limiting on auth routes | Pattern match: auth route handlers without rate-limit middleware |
| S031 | Missing CSRF protection | Check for CSRF middleware in route handlers |
| S032 | Prototype pollution: `Object.assign({}, req.body)` | Regex: `Object\.assign\(\s*\{\}` with req input |
| S033 | Insecure file upload: no type validation | Pattern: file upload handlers without MIME check |
| S034 | Missing `Content-Security-Policy` header | Check `next.config.js` / server middleware |
| S035 | Dependency vulnerabilities | Trigger: `npm audit --json` parse (if npm available) |
| S036 | `console.log` with sensitive object spread | Regex: `console\.log\(.*user\|.*token\|.*password` |
| S037 | IDOR: no ownership check before DB write | Pattern: update/delete routes without user_id WHERE clause |
| S038 | Missing `.env.example` | File existence check |
| S039 | RLS disabled on Supabase tables | Parse migration files for `alter table ... enable row level security` |

---

## Engine Architecture

```
cli.py
  └── parse args (review | audit | destructive)
        └── ProjectAnalyzer.analyze(target)
              ├── walk files → FileAnalyzer.analyze(file)
              │     ├── detect language/ext
              │     └── run matching detectors → [Finding]
              ├── ProjectLevelChecks.run()  ← gitignore, git history, npm audit
              └── ReportGenerator.build(findings) → sec-report.md

destructive mode only:
  GitGuard.prepare()
    ├── assert git repo
    ├── assert remote (or --no-remote)
    ├── git add -A && git commit → secmaxxing-audit branch
    └── yield control to Fixer.apply(findings)
```

### Finding schema

```python
@dataclass
class Finding:
    id: str           # S001
    tier: int         # 1 | 2 | 3
    severity: str     # CRITICAL | HIGH | MEDIUM | LOW
    file: str         # relative path
    line: int | None
    title: str
    description: str
    remediation: str
    auto_fixable: bool          # safe for `audit`
    destructive_fixable: bool   # requires `destructive`
```

---

## Implementation Steps

### Phase 1 — Skeleton

1. Create `~/.claude/skills/secmaxxing/` directory
2. Write `SKILL.md` (Claude trigger, slash command: `/secmaxxing`)
3. Write `cli.py` with three command stubs (review/audit/destructive)
4. Write `engine/__init__.py`

### Phase 2 — Tier 1 Detectors

5. Write `engine/detectors.py` — implement S001–S006 (secrets/config)
6. Write `engine/file_analyzer.py` — file walker + extension-to-detector mapping
7. Write `engine/project_analyzer.py` — dir walker (skip list matches cleanmaxxing)
8. Write `engine/report_generator.py` — markdown report builder
9. Create `rules/secrets-exposure.csv` + `rules/config-rules.csv`
10. Wire `cli.py review` → full pipeline → `sec-report.md`
11. Smoke test on this project

### Phase 3 — Tier 2 Detectors

12. Extend `detectors.py` — S010–S021 (injection, XSS, auth)
13. Create `rules/injection-rules.csv`, `rules/xss-rules.csv`, `rules/auth-rules.csv`
14. Add `auto_fixable` flags to Tier 1+2 findings

### Phase 4 — Tier 3 Detectors

15. Extend `detectors.py` — S030–S039 (structural, deps)
16. Create `rules/dependency-rules.csv`
17. Add `npm audit` integration (graceful skip if npm unavailable)

### Phase 5 — Audit Mode

18. Write `engine/fixer.py` — audit-safe fixes (gitignore, headers, cookie flags)
19. Wire `cli.py audit` → run review → filter `auto_fixable=True` → apply fixes

### Phase 6 — Destructive Mode + Git Guard

20. Write `engine/git_guard.py` — git repo check, remote check, branch create/commit logic
21. Write destructive fixers (parameterized queries, innerHTML sanitization, `git rm --cached`)
22. Wire `cli.py destructive` → git_guard → fixer → report diff

### Phase 7 — SKILL.md + Prompts

23. Write `secmaxxing.md` — full security knowledge base (mirrors cleanmaxxing.md depth)
24. Write `guardrails.md` — never-touch list
25. Write `prompts/rule-engine.md` — LLM prompt for AI-assisted analysis pass
26. Register skill in `~/.claude/CLAUDE.md`

---

## CSV Rule Schema (example: `injection-rules.csv`)

```csv
id,pattern,language,severity,title,description,remediation,auto_fixable,destructive_fixable
S010,"(query|execute|raw)\s*\(.*\+.*\)",js|ts|py,CRITICAL,SQL Injection via string concat,User input concatenated into SQL query,Use parameterized queries or ORM methods,false,true
```

---

## Guardrails (never touch)

Same as cleanmaxxing plus security-specific additions:
- Never delete `.env.example`
- Never delete migration files
- Never modify applied database migrations
- Never auto-push to remote
- Never delete auth middleware — flag it instead
- Never remove security headers that already exist

---

## Key Design Decisions

**Why Python CLI (not pure LLM)?**
Regex + AST detectors are deterministic. LLM pass is additive (prompts/rule-engine.md), not primary. Cleanmaxxing uses same pattern.

**Why three tiers?**
Mirrors cleanmaxxing's audit/fix/destructive split. Prevents accidental logic breakage. Matches user's mental model of risk escalation.

**Why branch-first on destructive?**
Security fixes in wrong hands can break apps. Git checkpoint before heavy changes is the correct pattern. Non-negotiable.

**Severity vs Tier:**
- Tier = when it runs (T1 always, T2 injection/xss, T3 structural)
- Severity = how bad it is (CRITICAL/HIGH/MEDIUM/LOW)
- A T3 check can still be CRITICAL (e.g., RLS disabled)
