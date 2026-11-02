# 🛰️ Beacon — Security Audit Log

**Ongoing security audit of a self-built SaaS in production, with an AI-assisted workflow.**

---

## Executive summary

This repository documents the real pentesting / security code-review process on **Beacon**, a self-built LinkedIn growth SaaS (AI-driven profile audit, content generation, autonomous commenting via a Chrome extension, Stripe subscriptions). This is not a lab or a CTF: it is a genuine audit of a real application with real users and real payments, carried out as the product is built and evolves.

As of the latest pass, **14 findings identified, 14 fixed and verified** (4 High severity, 5 Medium, 5 Low) across two independent audit passes, with full regression confirmed between them.

| | |
|---|---|
| 👤 **Author** | R0drx69 (Rodrigo Cuevas Veloso) |
| 🎯 **Target** | Beacon — `apps/web` (Node.js backend), `packages/engine` (AI content generation), `apps/extension` (MV3 Chrome extension) |
| 🧱 **Stack** | Node.js (native `http`, no framework), SQLite (`node:sqlite`), OAuth 2.0 (LinkedIn/Google/Facebook), Stripe, Anthropic API |
| 🔁 **Format** | Living log — each testing pass is appended as a new entry; history is never rewritten |
| 📅 **Passes completed** | [Oct 30, 2026](./reports/2026-10-30-beacon-audit.md) (10 findings) · [Nov 2, 2026](./reports/2026-11-02-beacon-audit-pass2.md) (3 findings + full regression) |

---

## Methodology

Each pass combines manual code review with an AI agent (Claude) operating with real shell access to the source code and the production instance (the author's own machine), under the author's explicit direction at every step:

1. **Directed code review** — full reading of the relevant source (not surface-level grepping), focused on authentication/authorization surfaces, secrets handling, and any point where untrusted third-party content reaches an LLM or gets rendered in the browser.
2. **Active, not theoretical, verification** — every finding is confirmed with a real test before being considered valid: `curl` against the live instance, targeted unit tests, or Playwright for the client — never "this could be exploitable" left unverified.
3. **Fix + re-verification** — every fix is deployed to the real instance (byte-for-byte verified after deploy) and the same attack scenario is re-tested to confirm it no longer works.
4. **Cross-pass regression** — every new pass starts by re-verifying, one by one, that the previous pass's findings are still fixed before looking for new ones. No finding is considered permanently closed without re-checking it once the surrounding code changes.

Severity across this log follows an impact × exploitability logic:

| Severity | Criterion |
|---|---|
| 🔴 **High** | Account compromise, authentication/authorization bypass, or an unauthorized action with direct impact on a user's data or funds |
| 🟠 **Medium** | Weakens a real defense (rate-limiting, hardening headers, webhook integrity) without being a direct compromise on its own |
| 🟡 **Low** | Defense in depth — practical risk is low or nil given context (high entropy, reduced surface), but the fix is free and keeps the codebase consistent |

---

## Consolidated findings

| # | Finding | Severity | Pass | Status |
|---|----------|:---:|:---:|---|
| 1 | Account takeover via OAuth without checking `email_verified` | 🔴 High | Oct 30 | ✅ Fixed |
| 2 | Rate-limit bypass via spoofed `X-Forwarded-For` | 🔴 High | Oct 30 | ✅ Fixed |
| 3 | Prompt injection in the autonomous LinkedIn comment pipeline | 🔴 High | Oct 30 | ✅ Fixed |
| 10 | IDOR in `/api/extension/report` | 🔴 High | Oct 30 | ✅ Fixed |
| 4 | No HTTP hardening headers (CSP, X-Frame-Options...) | 🟠 Medium | Oct 30 | ✅ Fixed |
| 5 | Path traversal — classic prefix bypass in `serveStatic()` | 🟠 Medium | Oct 30 | ✅ Fixed |
| 6 | Stripe webhook replay | 🟠 Medium | Oct 30 | ✅ Fixed |
| 11 | Dev flag left active in production — granted the paid plan for free | 🟠 Medium¹ | Oct 30 | ✅ Fixed |
| 12 | No `.gitignore` — latent risk of committing `.env` with real credentials | 🟠 Medium | Nov 2 | ✅ Fixed |
| 7 | Session cookie missing the `Secure` flag | 🟡 Low | Oct 30 | ✅ Fixed |
| 8 | Non-constant-time comparison of the extension token | 🟡 Low | Oct 30 | ✅ Fixed |
| 9 | Defensive XSS in `audit.html` (unescaped score) | 🟡 Low | Oct 30 | ✅ Fixed |
| 13 | One-time tokens without constant-time comparison or rate-limiting | 🟡 Low | Nov 2 | ✅ Fixed |
| 14 | No rate-limit on `/api/billing/checkout` | 🟡 Low | Nov 2 | ✅ Fixed |

**14/14 fixed and verified.** All 11 findings from the first pass were re-confirmed intact — no regression — during the second.

¹ *Classified as a business/monetization risk rather than an intrusion vulnerability — see the original report for detail.*

Full technical detail, before/after code, and reproduction steps for every finding:
- 📄 [`reports/2026-10-30-beacon-audit.md`](./reports/2026-10-30-beacon-audit.md) — first pass (10 findings)
- 📄 [`reports/2026-11-02-beacon-audit-pass2.md`](./reports/2026-11-02-beacon-audit-pass2.md) — second pass: full regression + 3 new findings

---

## Current security posture

As of the latest pass (Nov 2, 2026): OAuth authentication with email verification, IP-based rate-limiting that trusts real socket addresses rather than spoofable headers, two-layer defense against prompt injection in the autonomous comment pipeline (model-level instruction + mechanical technical barrier), HTTP hardening headers on every response, signature and freshness verification on the Stripe webhook, constant-time comparison on every secret checked against user input, owner-based authorization verified on every route that touches data by id, and no development credentials active in the real environment.

---

## 📁 Structure

```
reports/
  2026-10-30-beacon-audit.md         # first full pass (10 findings)
  2026-11-02-beacon-audit-pass2.md   # second pass: regression + 3 new findings
```

Each new testing pass (manual, automated, or prompted by a new feature) is added as a new file under `reports/`, named `YYYY-MM-DD-beacon-<topic>.md`, and the summary above is updated to reflect it.

---

## ⚠️ Scope and disclaimer

Everything documented in this repository is about **my own application**, audited in my own environment, with my own test data. It contains no real credentials, API keys, or real user data — only findings, relevant code (with the project's original comments and variable names), and reproduction steps verified against my own instance.

> 📫 Contact: [LinkedIn](https://www.linkedin.com/in/rodrigocuevasveloso/) · [pentesting-portfolio](https://github.com/R0drx69/pentesting-portfolio)
