# Vguard — Canonical customer-facing checks (2026-06-22)

The Stage-1 **main URL-scan report** and the **Vibe Score** are based on EXACTLY
the 23 checks below. This supersedes the old "~75 detectors" framing: the other
detectors still run, but they are **internal-only** — they never appear in the
customer report and never affect the score.

Single source of truth in code: [`api/_lib/canonical-checks.ts`](../api/_lib/canonical-checks.ts)
(`CANONICAL_CHECKS`, `canonicalCheckForFinding`, `isCustomerFacingFinding`).

## How the partition works

```
detectors (scanner.ts) ──▶ findings[]
                              │
       isCustomerFacingFinding│  ← canonical-checks.ts (the seam)
              ┌───────────────┴───────────────┐
       canonical (23)                    excluded / internal
              │                                │
   enrich → scoring engine → report      dropped (never scored, never shown)
```

The seam is at the **scanner-pipeline boundary**, not inside the scoring engine.
The engine stays a pure, general-purpose scorer (Stage 2/3 still use it for
deeper, consent-gated findings), and every existing engine/calibration unit test
stays valid. Excluded detectors are dropped from `findings[]` before the engine
ever sees them, so they contribute **zero** to the score and are absent from the
UI.

## The 23 canonical checks

| #  | Check | Emitted id(s) | Risk bucket |
|----|-------|---------------|-------------|
| 1  | HTTPS/TLS reachability | `tls-https`, `tls-http*` | transport |
| 2  | Exposed secrets in JS | `secret-<provider>-<file>`, `secrets-clean` | data |
| 3  | Supabase service-role key exposure | `secret-supabase-service-role-<file>` | data (golden) |
| 4  | TLS version (1.0/1.1) | `tls-old-version` | transport |
| 5  | Weak ciphers | `tls-weak-cipher` | transport |
| 6  | Certificate expiry | `tls-cert-expired`, `tls-cert-near-expiry` | transport |
| 7  | Mixed content | `mixed-content` | transport |
| 8  | HTTP→HTTPS redirect | `tls-no-http-redirect` | transport |
| 9  | Cookie/session hardening | `cookie-<name>` | posture |
| 10 | CSRF token on POST forms | `html-form-no-csrf` | access |
| 11 | Sensitive path exposure | `path-<slug>`, `paths-admin*`, `paths-openapi-spec-public`, `paths-graphql-introspection` | data/access |
| 12 | robots.txt sensitive-path analysis | `paths-robots-disclosure` | recon |
| 13 | sitemap.xml internal URL leak | `paths-sitemap-internal` | recon |
| 14 | TRACE method enabled | `methods-trace-enabled` | access |
| 15 | Supabase Storage exposure | `paths-supabase-storage-public-listing`, `paths-supabase-storage-info` | data |
| 16 | Firebase Realtime DB exposure | `paths-firebase-rtdb` | data |
| 17 | Firebase Storage exposure | `paths-firebase-storage-public` | data |
| 18 | S3 ListBucket exposure | `paths-s3-listbucket` | data |
| 19 | Brute Force / Login Rate-Limit | `auth-rate-limit-needs-consent` (Stage-1 passive) · `auth-rate-limit-missing` / `auth-rate-limit-ok` (Stage-3 active) | access |
| 20 | Open Redirect | `paths-open-redirect` | exploit |
| 21 | Reflected XSS | `paths-reflected-xss` | exploit |
| 22 | SQL Injection | `paths-sqli-error` | exploit |
| 23 | Subdomain takeover risk | `dns-cname-takeover-hint` | exploit |

### #19 — Brute Force / Login Rate-Limit (safe & defensive, two-stage)

**Stage 1 is passive only.** It DETECTS login/signup/password-reset surfaces
(passive GET discovery + HTML signals) and emits the informational finding
`auth-rate-limit-needs-consent`:
> "Brute-force protection check requires domain ownership verification or
> explicit consent."

It **never** sends active login attempts to a URL the user hasn't proven they
own — avoiding legal risk, WAF blocks, abuse reports, and being misclassified as
an attack tool.

**The active 5-request test runs only in Stage 3** (ownership-verified) —
`probeAuthRateLimit` in [`api/_lib/deep-scanner.ts`](../api/_lib/deep-scanner.ts).
Hard safety rules, enforced in code:

- **Never** runs on an arbitrary pasted URL — only after ownership verification,
  and only against the endpoints passively detected in Stage 1.
- **Max 5 requests** (`RATE_LIMIT_BURST = 5`).
- **Clearly-invalid credentials only** — a random throwaway address on the
  reserved `.invalid` TLD + a dummy password. Never a real credential.
- **No password lists · no real usernames · no credential stuffing.**
- A clear, attributable **`V-Guards-Scanner/1.0` User-Agent** (never stealthy).
- The user's approval is **logged for audit** (`stage3_active_auth_test` event in
  `scan-deep.ts`: domain, verify method, endpoint count, ownership_verified).

It looks only for protection signals (`429`, `Retry-After`, rate-limit headers,
account lockout, CAPTCHA/throttle) and emits `auth-rate-limit-missing` (warn) or
`auth-rate-limit-ok`.

## Excluded from the main checklist + scoring (internal-only)

These detectors **still run** (some are required internally — see below) but are
removed from the customer report, the score, and the "what we scan" copy:

CORS · Server/version disclosure · Framework fingerprinting · Dependency CVE
matching · DMARC · DKIM · SPF · CAA · DNSSEC · CSP weakness analyzer · Hardcoded
localhost · Source map exposure · Inline event handler · Reverse tabnabbing ·
Generic Security Headers (standalone) · HSTS strength (standalone) · Inline
scripts (standalone) · SRI missing (standalone) · Supabase Edge Functions
discovery (standalone) · Auth signup endpoint probing (standalone) · AI/LLM
endpoint detection (standalone) · SSRF (as a customer finding) · URL
normalization + scheme · WAF detection · JS-AST heuristics (DOM-sink, runtime
codegen, template-URL fetch, hardcoded-creds) · auth-enum / auth-weak /
auth-disclosure surfaces · soft-404 catch-all · platform-shared-subdomain.

### Why some excluded detectors are kept (internal)

- **SSRF / private-host guard** — `runScan` blocks `localhost`, `127.x`, `10.x`,
  `172.16-31.x`, `192.168.x`, `169.254.x`, `*.local` before any fetch. This is a
  safety protection for the scanner itself and must never be relaxed. The
  out-of-band `paths-ssrf-confirmed` finding is excluded from the customer report
  per spec, but the input-safety guard stays.
- **Framework / version detection** — feeds content-aware severity + the attack
  surface map, not shown as a standalone finding.
- **Supabase project / anon-key / edge / signup discovery** — feeds checks #3
  (service-role) and #19 (rate-limit). Discovery findings are not shown
  standalone.
- **WAF detection** — still grants the small score bonus (`engineCtx.wafPresent`)
  and populates `attackSurface.wafVendor` + the WAF-block error UI, but is no
  longer pushed as a finding.

## Stage gating (unchanged)

Deep runtime checks, authenticated checks, aggressive XSS/SQLi/path-traversal,
RLS/IDOR, and AI canaries remain **Stage 2/3 only**, gated behind user
action / consent / domain-ownership verification. The 23 canonical checks are
the Stage-1 passive + safe-active set.
