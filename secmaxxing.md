---
description: Security knowledge base — rules, patterns, and remediation guidance
---

# Secmaxxing Security Knowledge Base

## Philosophy

Security is not an add-on. Every codebase has attack surface. The goal of secmaxxing is:
> Find every path an attacker could exploit, eliminate it cheaply, document what can't be auto-fixed.

Priority order:
1. Secrets never leave the server
2. User input never reaches a query/command/file path unparameterized
3. HTML output is always sanitized
4. Auth always runs server-side with verified tokens
5. Dependencies are pinned and audited

---

## Tier 1 — CRITICAL / Secrets & Config

### S001 — .env not in .gitignore

**Risk:** Any developer clone, public repo, or CI log exposes all secrets.

**Detection:** Parse `.gitignore`; check `.env` and `.env*` patterns are present.

**Fix:** Add to `.gitignore`:
```
.env
.env.local
.env.*.local
*.pem
*.key
```

---

### S002 — .env committed to git

**Risk:** Even after deletion, `.env` values live in git history permanently. Rotate all keys.

**Detection:** `git ls-files .env*`

**Fix:**
```bash
git rm --cached .env
echo ".env" >> .gitignore
git commit -m "fix: remove .env from tracking"
# Then ROTATE ALL KEYS in the .env file
```

---

### S003 — Hardcoded credentials

**Risk:** Any key hardcoded in source reaches every developer machine, CI runner, and Docker image layer.

**Patterns to detect:**
- `sk-...` (OpenAI)
- `AKIA...` (AWS)
- `ghp_...` (GitHub)
- `xoxb-...` (Slack)
- `AIza...` (Google)
- `password = "..."`, `secret = "..."`

**Fix:** Move to `.env`, access via `process.env.VAR_NAME`, rotate the exposed key.

---

### S004/S005 — NEXT_PUBLIC_ secret exposure

**Risk:** Any variable prefixed `NEXT_PUBLIC_` is bundled into the browser JavaScript. Service role keys, signing secrets, or private API keys exposed this way give attackers full backend access.

**Detection:** Scan `.env*` files for `NEXT_PUBLIC_` vars containing `SECRET|KEY|TOKEN|PASS|PRIVATE`.

**Fix:** Remove `NEXT_PUBLIC_` prefix. Access in server components, route handlers, or server actions only.

```ts
// BAD — reaches browser
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=...

// GOOD — server only
SUPABASE_SERVICE_ROLE_KEY=...
```

---

## Tier 2 — HIGH / Injection & XSS

### S010/S011 — SQL Injection

**Risk:** Attacker can read, modify, or delete any database row; in some configs, execute OS commands.

**Patterns:**
```ts
// BAD — string concat
const res = await db.query("SELECT * FROM users WHERE id = " + userId)

// BAD — template literal
const res = await db.query(`SELECT * FROM users WHERE id = ${userId}`)

// GOOD — parameterized
const res = await db.query("SELECT * FROM users WHERE id = $1", [userId])
```

For ORMs (Prisma, Drizzle, Supabase):
```ts
// GOOD — ORM handles parameterization
const user = await prisma.user.findUnique({ where: { id: userId } })
```

---

### S012/S013 — XSS via innerHTML / dangerouslySetInnerHTML

**Risk:** If any user-supplied string reaches innerHTML or dangerouslySetInnerHTML without sanitization, attacker injects `<script>` to steal sessions.

```tsx
// BAD
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// GOOD — sanitize first
import DOMPurify from 'dompurify'
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />

// BEST — use textContent for non-HTML
element.textContent = userInput
```

---

### S014 — eval()

**Risk:** Executes arbitrary JavaScript. If attacker controls input, this is RCE in Node.js.

```ts
// BAD
const data = eval(userInput)

// GOOD — parse JSON safely
const data = JSON.parse(userInput)  // throws on invalid JSON — wrap in try/catch
```

---

### S016 — Command Injection

**Risk:** Attacker appends `;rm -rf /` or similar to shell commands.

```ts
// BAD
exec(`convert ${req.body.filename} output.png`)

// GOOD — use execFile with explicit args array
import { execFile } from 'child_process'
execFile('convert', [req.body.filename, 'output.png'])

// NEVER do shell=True with user input (Python)
subprocess.run(f"convert {filename}", shell=True)  # BAD
subprocess.run(["convert", filename])  # GOOD
```

---

### S017 — Path Traversal

**Risk:** Attacker uses `../../etc/passwd` to read arbitrary files.

```ts
// BAD
const file = fs.readFileSync(req.query.path)

// GOOD — resolve and validate against base dir
import path from 'path'
const BASE = path.resolve('./uploads')
const resolved = path.resolve(BASE, req.query.path)
if (!resolved.startsWith(BASE)) throw new Error('Invalid path')
const file = fs.readFileSync(resolved)
```

---

### S018 — Supabase getSession() on server

**Risk:** `getSession()` reads the JWT from the cookie and trusts it without server verification. An attacker with a tampered cookie can impersonate any user.

```ts
// BAD — server component / route handler
const { data: { session } } = await supabase.auth.getSession()

// GOOD — always use getUser() on server
const { data: { user }, error } = await supabase.auth.getUser()
if (error || !user) return redirect('/login')
```

---

### S021 — Open Redirect

**Risk:** Attacker sends phishing link: `https://yourapp.com/login?next=https://evil.com`

```ts
// BAD
res.redirect(req.query.next)

// GOOD — validate against allowlist
const ALLOWED = ['/', '/dashboard', '/profile']
const next = ALLOWED.includes(req.query.next) ? req.query.next : '/'
res.redirect(next)
```

---

## Tier 3 — MEDIUM / Structural

### S030 — No rate limiting on auth routes

Brute-force protection: add rate limiting to `/login`, `/signup`, `/api/auth/*`.

```ts
import rateLimit from 'express-rate-limit'
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 })
app.post('/login', loginLimiter, handler)
```

---

### S033 — Insecure file uploads

Validate MIME type + extension server-side. Never trust `Content-Type` header alone.

```ts
const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'application/pdf']
if (!ALLOWED_MIMES.includes(file.mimetype)) throw new Error('File type not allowed')
```

---

### S034 — Missing Content-Security-Policy

Add to `next.config.js`:
```js
headers: async () => [{
  source: '/(.*)',
  headers: [{
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  }]
}]
```

---

### S035 — Dependency vulnerabilities

Run `npm audit` regularly. Fix critical/high issues immediately.
- `npm audit fix` for safe fixes
- `npm audit fix --force` only after reviewing breaking changes

---

### S039 — Supabase RLS not enabled

Every table needs RLS or an attacker with the anon key can read all rows.

```sql
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users see own rows"
ON your_table FOR SELECT
USING (auth.uid() = user_id);
```

---

## Security Checklist (pre-deploy)

- [ ] `.env` in `.gitignore`
- [ ] No `.env` in `git ls-files`
- [ ] No hardcoded secrets in source
- [ ] No `NEXT_PUBLIC_` on private vars
- [ ] All SQL queries parameterized
- [ ] All HTML output sanitized
- [ ] No `eval()` with user input
- [ ] `getUser()` not `getSession()` on server
- [ ] Rate limiting on auth routes
- [ ] File uploads validate MIME type
- [ ] CSP header configured
- [ ] `npm audit` passes (no critical/high)
- [ ] RLS enabled on all Supabase tables
- [ ] Cookies have `httpOnly: true, secure: true`
