# CSRF Decision Engine

Module: [`api/_lib/csrf-decision-engine.ts`](../api/_lib/csrf-decision-engine.ts)
Wired into the scan in [`api/_lib/scanner.ts`](../api/_lib/scanner.ts) (the `=== CSRF Decision Engine (PASSIVE) ===` block).

## Why

Absence of a **visible** HTML CSRF token is **not** proof of a vulnerability. Modern apps defend
with SameSite cookies, Origin/Referer validation, framework middleware, custom CSRF headers,
SPA/API auth, or double-submit cookies — none visible to a passive HTML scan. So this engine looks
at **context** before ever creating a warning-level CSRF finding.

**Passive scans are hard-capped at `low`.** Medium/High/Critical are reserved for a future
active/deep-scan mode (verified site ownership / explicitly enabled deep testing) that actively
proves protection is missing. No domain whitelists or brand exceptions — decisions are
evidence-based only.

## Evidence collected (passive)

For each POST/PUT/PATCH/DELETE form: request target (method, action, same-origin, form-vs-API);
visible token (hidden input / field / meta tag + whether JS uses it); custom CSRF header signals in
inline JS (`X-CSRF-Token`, `X-CSRFToken`, `X-XSRF-Token`, `XSRF-TOKEN`, `X-Requested-With`);
cookie evidence (SameSite Strict/Lax/None/missing, Secure, HttpOnly — with attention to
auth/session cookies: `session`, `sid`, `auth`, `token`, `jwt`, `laravel_session`, `csrftoken`,
`XSRF-TOKEN`, `ASP.NET_SessionId`, `JSESSIONID`, `connect.sid`, `PHPSESSID`, `django_session`);
double-submit patterns (`XSRF-TOKEN` cookie + `X-XSRF-Token` header, `csrftoken` + `X-CSRFToken`);
framework hints (Django, Laravel, Rails, ASP.NET, Angular, Spring, Express); and endpoint
sensitivity by conservative keyword classification (unclear → `unknown`, never auto-dangerous).

## Decision matrix

| Decision | When | Finding ID | Severity · Confidence | Risk category → Score |
|----------|------|-----------|-----------------------|-----------------------|
| **no_issue** | visible token · OR meta token used by JS · OR CSRF-header evidence · OR double-submit pattern · OR (auth cookie SameSite=Strict/Lax **and** endpoint public/non-sensitive) | *(none)* | — | no finding |
| **info** | no visible token but some alt-protection evidence · OR endpoint public · OR sensitivity unknown & unverified · OR framework hint but incomplete · OR undeterminable | `csrf-protection-not-visible-info` | info · possible | `recon` → **0** |
| **low** | endpoint sensitive/account-related **AND** no visible token **AND** no CSRF header **AND** no double-submit **AND** no strong SameSite on auth cookie **AND** unverified | `csrf-sensitive-action-no-passive-protection-low` | warn · possible | `posture` → **small, capped ≤5** (reconciles to effectiveSeverity `low` → info bucket, never inflates warn count) |
| **medium** | *(active only)* missing/bogus token accepted · OR Origin/Referer ignored · impact limited/unconfirmed | `csrf-active-bypass-accepted-medium` | warn · likely | `exploit` → scores |
| **high** | *(active only)* sensitive state-changing action accepted without CSRF, or confirmed non-high-impact state change | `csrf-state-change-confirmed-high` | critical · likely/verified | `exploit` → scores |
| **critical** | *(active only)* confirmed forged cross-site request performs a high-impact state change (password/email/admin/financial/permission/destructive) | `csrf-critical-state-change-confirmed` | critical · verified | `exploit` → scores |

Framework evidence **reduces suspicion** (can push a case to `info`) but never **suppresses** a
`low` when a sensitive endpoint has no token/header/double-submit/SameSite evidence.

## Existing visibility-only heuristic

`html-form-no-csrf` (in the scanner block just above the engine) is **unchanged**: `info` severity,
`recon` risk category, **zero** score/grade/warning-count impact. The engine runs **alongside** it
and adds the `low` risk signal only. The old id is never reused for a risk finding.

## Scoring wiring

Routing lives in [`api/_lib/scoring-policy.ts`](../api/_lib/scoring-policy.ts) `mapToRiskCategory`,
using predicates in [`api/_lib/finding-ids.ts`](../api/_lib/finding-ids.ts):

- `isCsrfPassiveRiskId` → `posture` (small, clamped)
- `isCsrfVerifiedRiskId` → `exploit` (active/verified only)
- both checked **before** the blanket `isCsrfId → recon`, so `html-form-no-csrf` and
  `csrf-protection-not-visible-info` still route to `recon` (zero).

## UI levels

1. **Token not visible** → informational / manual review (`html-form-no-csrf`, `…-info`).
2. **Sensitive action may lack protection** → low / passive / unverified (`…-low`).
3. **CSRF bypass verified** → real vulnerability, active verification only (medium/high/critical).
