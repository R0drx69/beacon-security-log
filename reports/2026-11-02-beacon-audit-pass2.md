# 🛰️ Beacon — Security Audit, Pass 2 (Nov 2, 2026)

- **Target:** Beacon (LinkedIn growth SaaS — profile audit, AI content generation, autonomous commenting via a Chrome extension, Stripe payments)
- **Type:** Code review + regression of the previous pass against the author's own live instance (real production)
- **Scope:** everything covered in the [Oct 30 pass](./2026-10-30-beacon-audit.md) (re-verified) **plus** all code added since then: the email ecosystem (`email.js` rewrite, scheduled reminder job), `forgot-password`/`reset-password` (server + pages), account deletion (`handleDeleteAccount`), `db-sqlite.js` (the real database engine), `apps/extension/content-script.js` (not in Pass 1's scope), and the move from two Stripe tiers (`content`/`engage`) to a single plan
- **Methodology:** full manual source review + targeted pattern-grep across the whole tree; every new finding fixed and verified (syntax + deployed to the real instance) before closing it
- **Author:** R0drx69

---

## 📊 Summary

| # | Finding | Severity | Status |
|---|----------|-----------|--------|
| 12 | No `.gitignore` in the project — latent risk of committing `.env` with real credentials | 🟠 Medium | ✅ Fixed |
| 13 | Non-constant-time comparison + no rate-limit on one-time tokens (password reset, email verification) | 🟡 Low | ✅ Fixed |
| 14 | No rate-limit on `/api/billing/checkout` | 🟡 Low | ✅ Fixed |

Findings #1-11 from the previous pass were re-verified against the current code: **all 11 are still fixed, none regressed** (detail in the regression section below).

---

## 🟠 Finding 12 — No `.gitignore` anywhere in the project

**Where:** project root (`C:\Users\rodri\Desktop\beacon\beacon\`) and every subfolder — no `.gitignore` existed at any level.

**Problem:**
The real project isn't under version control yet (no `.git` folder), so today there's no repository for `.env` to leak through. But the author does actively use git for a related purpose (this very security log), and the pattern of "spin up a repo once it's time to share/back up the code" already proved real once: it's exactly what happened with `RESEND_API_KEY.txt`, which sat in plaintext with zero protection until it was found and flagged for manual deletion.

If `git init` is ever run in this project (to back it up, open a PR, or share it) followed by a `git add -A` without a `.gitignore` already in place, **`.env` would be committed as-is** — and `.env` currently holds real credentials for Stripe (`STRIPE_SECRET_KEY`), Anthropic, Google OAuth, LinkedIn OAuth, and Resend. Unlike `RESEND_API_KEY.txt` (a single key), this would expose all five at once.

**Fix:** a `.gitignore` at the project root, covering `.env`/`.env.local` (in any folder), the plaintext Resend key file in case it ever reappears, the local SQLite database (real user data once in use), and the usual build artifacts (`node_modules/`, logs, OS files).

```gitignore
# Real secrets — never commit
.env
.env.local
**/.env
**/.env.local
*RESEND_API_KEY*

# Local database (holds real user data once in use)
apps/web/data/*.sqlite3
apps/web/data/*.sqlite3-shm
apps/web/data/*.sqlite3-wal
apps/web/data/db.json
apps/web/data/db.json.migrated-backup

node_modules/
*.log
.DS_Store
Thumbs.db
```

---

## 🟡 Finding 13 — Non-constant-time comparison + no rate-limit on one-time tokens

**Where:** `server.js` — `handleResetPassword()` and `handleVerifyEmail()`.

**Problem:**
Two issues, same root cause as finding #8 from the previous pass (non-constant-time comparison of the extension token), applied here to more sensitive tokens — the password-reset one in particular gates a real credential change, not just a read:

1. **Non-constant-time comparison:** `Object.values(data.users).find(u => u.passwordResetToken === token)` — a plain `===` on a secret leaks timing proportional to how many characters match before the first difference. The token is 192 bits of random hex (`crypto.randomBytes(24)`), so this is defense-in-depth, not a practical attack on its own — same caveat already noted for finding #8.
2. **`handleResetPassword` had no rate-limit at all**, unlike `handleForgotPassword` (5/hour), `handleLogin` (15/15min), and `handleDeleteAccount` (10/15min per account). With 192 bits of entropy, rate-limiting isn't what makes brute-force infeasible here either — but it left this route inconsistent with every other route handling a one-time secret.

**Fix:** a shared `constantTimeTokenMatch(candidates, token, field)` helper (uses `crypto.timingSafeEqual`, checking length first, same pattern `userFromExtensionToken` already used), applied in both `handleResetPassword` and `handleVerifyEmail`. New rate-limit on `handleResetPassword`, 10/hour per IP — generous enough not to block a legitimate retry, but present.

```js
function constantTimeTokenMatch(candidates, token, field) {
  if (!token) return null;
  const tokenBuf = Buffer.from(token);
  return (
    candidates.find((item) => {
      const stored = item[field];
      return !!stored && stored.length === token.length && crypto.timingSafeEqual(Buffer.from(stored), tokenBuf);
    }) || null
  );
}
```

---

## 🟡 Finding 14 — No rate-limit on `/api/billing/checkout`

**Where:** `server.js` — `handleBillingCheckout()`.

**Problem:** any authenticated account (or a session stolen via XSS/a shared device) could call this endpoint in a loop with no cap, each call creating a real Stripe Checkout Session. No money moves until someone actually completes payment on Stripe's own page, so the practical damage is API/dashboard noise rather than direct financial risk — but it was the only authenticated route in the whole file with no limit at all.

**Fix:** a 20/hour per-user rate-limit, matching the pattern used by every other authenticated route in the file.

---

## ✅ Regression check on the previous pass (Oct 30, 2026) — no new findings, all 11 hold

Each one re-verified against the current code:

| # | Original finding | Status now |
|---|---|---|
| 1 | Account takeover via OAuth without checking `email_verified` | ✅ the `profile.email_verified !== false` check is still present in `linkedin-oauth.js` and `google-oauth.js` |
| 2 | Rate-limit bypass via spoofed `X-Forwarded-For` | ✅ `clientIp()` still ignores the header unless `TRUST_PROXY=1` |
| 3 | Prompt injection in the autonomous comment pipeline | ✅ `isSafeAutonomousComment()` intact in `comment-picker.js`, same rules (no URL/@handle/phone, <600 chars) |
| 4 | No HTTP hardening headers | ✅ CSP/X-Frame-Options/nosniff/Referrer-Policy still applied to every response |
| 5 | Path traversal — prefix bypass in `serveStatic()` | ✅ the separator-aware check is still there |
| 6 | Stripe webhook replay | ✅ the 5-minute timestamp tolerance is still active |
| 7 | Session cookie missing the `Secure` flag | ✅ `Secure` conditional on `isHttps(req)` is still in `auth.js` |
| 8 | Non-constant-time comparison of the extension token | ✅ `userFromExtensionToken` still uses `crypto.timingSafeEqual` |
| 9 | Defensive XSS in `audit.html` | ✅ `item.score` still goes through `escapeHtml()` |
| 10 | IDOR in `/api/extension/report` | ✅ the `plan.userId === user.id` / `c.userId === user.id` check is still present |
| 11 | `DEV_FORCE_PRO` active in the real environment | ✅ confirmed `DEV_FORCE_PRO=0` in the real `.env` as of this pass |

---

## ✅ New code reviewed, no security findings

- **Email ecosystem** (`email.js` rewrite, scheduled `checkStalePlansAndRemind` job): inserts no user-controlled content into HTML without escaping; the Stripe triggers (welcome, cancellation notice) use data that already passed webhook signature verification, not direct caller input.
- **`forgot-password` / `reset-password`** (routes + pages): 192-bit token, expires in 1h, invalidates every active session on password change, and returns a generic response that doesn't confirm whether an email exists — same pattern already established for email verification. The two minor gaps found here are findings #13 above.
- **Account deletion** (`handleDeleteAccount`): re-prompts for the password with its own per-account rate-limit; deletes only the correct user's sessions, audits, plans, and comments.
- **`db-sqlite.js`**: every query uses `.prepare()` with `?` placeholders — zero SQL built by string concatenation, no injection surface.
- **`apps/extension/content-script.js`** (in this audit's scope for the first time): no `innerHTML`/`insertAdjacentHTML`/`outerHTML` anywhere — same clean pattern already verified in `popup.js` and `background.js` during Pass 1.
- **Move to a single Stripe plan** (Nov 1, 2026): specifically reviewed for dangling references after removing the `content`/`engage` split — none found; the `isEngageTier()` helper was left with zero callers after the change and was deleted rather than kept as a dead alias.
- **CORS:** no `Access-Control-Allow-*` headers are set anywhere — correct by default for a same-origin app; nothing to change.
- **OAuth flow (`state` CSRF protection):** `state` is still 128-bit random, single-use (deleted on consumption), and time-limited — unchanged since Pass 1, no new findings.

## 🧩 Lessons / takeaways from this pass

- A Pass 1 finding (a token without constant-time comparison) is a pattern, not a one-off — it resurfaces the moment the project adds a second route with a one-time token. Worth generalizing into a shared helper the first time it shows up, not the third.
- The missing `.gitignore` wasn't exploitable today (no local git repo yet), but it's exactly the kind of thing worth fixing *before* it's needed rather than after a rushed `git add -A` — the same instinct that led to creating this very security log in its own repo.
- A product refactor (collapsing two Stripe tiers into one) is also a good moment to sweep dead code: a helper that loses every caller in the same change is easy to leave "just in case," and easier to remove while the context for why it's no longer needed is still fresh.
