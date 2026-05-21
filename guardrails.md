## Non-Negotiable Preservation Rules

Never delete, rename, or modify:
- `.env.example` — reference file for required vars
- Migration files (Prisma, Supabase, SQL) that are already applied
- Test files and test suites
- Auth middleware (flag issues, never remove)
- `package.json` scripts section
- Deployment config files (vercel.json, netlify.toml, Dockerfile)
- README and setup docs
- `.gitignore` itself — only ADD to it, never remove entries

Before modifying any file, classify it as:
1. Safe to auto-fix (config, constants, non-logic)
2. Needs destructive mode (logic, queries, render)
3. Never touch (migrations, tests, auth core)

Only audit mode touches category 1.
Only destructive mode touches category 2.
Category 3 is always flagged in report only.
