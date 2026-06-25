# Scoring V6 — Risk-Based Model (2026-06-13)

> Supersedes [SCORING-V5-IMPLEMENTATION.md](SCORING-V5-IMPLEMENTATION.md). Spec authored by Royi 2026-06-13; this doc records the implemented model.

> **🟦 2026-06-22 — canonical 23-check partition.** The engine is unchanged and
> still classifies any finding it is given. But the **Stage-1 main scan now
> filters findings to the 23 canonical customer-facing checks BEFORE the engine
> runs** (`isCustomerFacingFinding` in `api/_lib/canonical-checks.ts`). So the
> excluded posture/recon examples below — **CSP, HSTS, SPF/DKIM/DMARC, SRI,
> CAA/DNSSEC, dependency/server CVEs, CORS, source maps, WAF, framework/server
> fingerprinting** — no longer reach the engine in the main report and contribute
> nothing to the live score. They remain documented here as the engine's general
> classification behavior (still exercised by the unit tests and by Stage 2/3).
> The posture finding that survives into the canonical set is essentially
> **cookie flags**; transport breaks (#1/#4–#8) score as before. Rate limiting is
> now emitted by a real detector (`auth-rate-limit-missing`, canonical #19), so
> the "no detector emits them yet" note below is partly outdated for rate-limit.
> See [CANONICAL-CHECKS.md](CANONICAL-CHECKS.md).

> **🟦 2026-06-22 — display-score normalization (cosmetic only).** The engine and
> `rawScore`/`vibeScore`/`scoreBreakdown` are **never** changed. A separate,
> display-only layer ([`api/_lib/display-score.ts`](../api/_lib/display-score.ts))
> adds two fields to the response: **`displayScore`** (what the UI renders) and
> **`scoreAdjustedForDisplay`**. Rule: a clean **96–99 with no critical finding**
> shows as a premium **100**; everything ≤95 is shown verbatim, and any critical
> finding blocks the bump (rule 11). `vibeScore` stays in the API, logs, tests,
> and the `scoreBreakdown` card; findings/severities/order/recommendations are
> untouched, so a "100" never hides a vulnerability. Tests:
> `api/__tests__/display-score.test.ts`.

## Core objective

The score measures **real-world security risk**: the likelihood of data exposure, unauthorized access, account compromise, system compromise, and business impact.

It does **not** primarily reflect fingerprinting, technology detection, security-header presence, or recon findings. A site with no real exploitable risk can earn an A even with missing hardening controls; a site with verified critical findings can never earn an A or B regardless of hardening quality.

## The formula

```
per-finding penalty = base(riskCategory, golden-kind?, tier)
                      × confidence  (verified 1.0 / likely 0.6 / possible 0.2)
                      × businessImpact (public 0.7 / userData 1.0 / financial 1.3 / adminInternal 1.6)

score = 100 − Σ decayed penalties (+ WAF bonus)
        → grade-cap rule  (verified {IDOR, RLS, SQLi, .env, DB dump, service-role, RCE} ⇒ max 79 / C)
        → perfect-score gate (100 requires literally zero deductions)
```

## Four risk categories (weights = penalty magnitudes, not divided budgets)

| Category | Weight | Examples | Golden base | Regular base (crit/high/med/low) |
|---|---|---|---|---|
| `data` — Data & secret exposure | 40% | .env, .git, DB dumps, AWS/OpenAI/Anthropic/Stripe keys, service-role, public S3/Firebase/Supabase buckets, secrets in responses, PII | **70** | 32 / 24 / 12 / 5 |
| `access` — Access control & authorization | 30% | IDOR, RLS bypass, anonymous write, admin APIs, unauthenticated sensitive APIs, weak JWT, missing rate limiting* | **60** | 28 / 20 / 10 / 4 |
| `exploit` — Exploitable vulnerabilities | 25% | XSS (possible & verified), SQLi, SSRF, path traversal, command injection/RCE, prompt injection, CSRF*, broken TLS | **65** | 26 / 18 / 9 / 4 |
| `posture` — Security posture & hardening | 5% | CSP, HSTS, TLS config, cookie flags, SPF/DKIM/DMARC, SRI, dependency/server CVEs, WAF | — | 12 / 4 / 2.5 / 1.5 |
| `recon` — visibility only | 0% | robots/sitemap, framework/WAF detection, GraphQL/Swagger/health endpoints, server headers, public client identifiers, console errors | — | always 0 |

- A budget model (`weight×100` points per category) was deliberately rejected: a single verified `.env` must reach F on its own, which a 40-point budget cannot do. Weights express through the penalty tables plus the **posture clamp**.
- **Posture clamp:** all *unverified* posture findings together deduct at most **5 points** (the literal 5% weight). A *verified* posture finding (critical CVE match) penalizes via the table outside the clamp.
- Diminishing returns inside each category: each additional finding costs ×0.6 of the previous (DECAY_FACTOR).
- The non-golden tier comes from the surviving `riskClass`: critical-exploit→crit, high-impact-misconfig→high, medium-weakness→med, low-hardening→low.

*Rate limiting / credential stuffing / lockout / CSRF / RCE: the engine scores these kinds (`isRateLimitId`, `isCsrfId`, `isRceId` predicates exist) but **no detector emits them yet** — see "Detector gaps".

## Confidence system (the single biggest V6 change)

| Level | Multiplier | Meaning |
|---|---|---|
| `verified` | 100% | Exploitation / direct-observation evidence: Stage-3 confirmations, traversal returning real file content, SSRF out-of-band, browser-executed XSS, detector-confirmed real secret |
| `likely` | 60% | Strong signal short of exploitation: Stage-2 runtime observation, SQL error signature, unverified detector-critical |
| `possible` | 20% | Detection only: reflected canary, pattern match, heuristic, hardening observations |

Hard rules implemented in `verifiedImpactPredicate` / `classifyConfidence`:
- Detection alone is NOT verification.
- **Reflected input is NOT verified XSS** — `paths-reflected-xss` is *Possible XSS* (browser execution required; only `aggressive-xss`/`xss-executed` ids verify).
- A secret *pattern* is NOT verified secret exposure (the AST heuristic never verifies; detector-confirmed secrets do).
- An SQL error signature is *suspected* SQLi → `likely`, not verified.
- Legacy vocabulary `confirmed|likely|informational` renamed to `verified|likely|possible` (`normalizeConfidence()` shim accepts old spellings).

## Business impact (context awareness)

Derived from observable signals only (`deriveBusinessImpact` in finding-traits.ts) — no brand/domain lists:
- `adminInternal` ×1.6 — service-role keys, admin routes with data, auth/data findings on sensitive routes
- `financial` ×1.3 — payment-grade secrets (`sk_live_`, `AKIA`), billing surfaces, PII
- `userData` ×1.0 — data exposure / auth bypass default
- `public` ×0.7 — hardening, info disclosure, public content

**Floor rule:** for verified golden findings the multiplier is floored at 1.0 — business context can never rescue a verified critical.

## Golden Findings

Major security failures: RLS bypass, IDOR, SQLi, .env exposed, DB dump exposed, service-role exposed, AWS creds exposed, **Verified** XSS, SSRF, path traversal, secrets in responses, anonymous write, public S3/Firebase with sensitive data, RCE.

- A finding **is** golden only when its kind matches (`isGoldenKindId` + secrets category) **and** it has `verifiedImpact` (and is not a public client identifier).
- The golden *kind* drives the penalty base even when unverified — confidence scales it (likely SQLi = 65×0.6 = 39 → D).
- Enriched findings carry `isGoldenFinding: true` for UI.

## Score-cap rule

Any verified finding among **IDOR, RLS bypass, SQLi, .env, DB dump, service-role key, RCE** caps the score at **79 (max grade C)** until fixed — surfaced in `scoreBreakdown.hardCap`. It is an upper bound; the penalties drive these cases to F anyway. The no-HTTPS hard cap (49) survives from V5 and wins when lower.

## WAF policy

WAF present → **+2 bonus** (via `ctx.wafPresent` or the `meta-waf-detected` finding), only when no verified impact exists. WAF absent → **no penalty, ever**. Cloudflare + exposed `.env` is still F (test-locked).

## Grade scale & perfect score

| Score | Grade | | Tier |
|---|---|---|---|
| 90–100 | A | 90–94 | excellent |
| 80–89 | B | 95–99 | outstanding |
| 70–79 | C | 100 | exceptional |
| 60–69 | D | | |
| 0–59 | F | | |

- **`A+` was removed** from the `Grade` type; the A band is qualified by `ScoreBreakdown.scoreTier` instead (shown on the gauge).
- D/F boundary moved: V5 D was 50–69 / F <50; V6 D is 60–69 / F <60.
- **Perfect-score gate:** any non-zero deduction ⇒ max 99. 100 requires literally zero deductions (recon/ok findings don't deduct, so a clean site with robots.txt + a framework still earns 100).

## Worked calibration anchors (all test-locked)

| Scenario | Result |
|---|---|
| Enterprise site: missing CSP/HSTS + cookie flags + framework recon (+ WAF) | ~95–97 · A |
| Verified `.env` exposed | ≤30 · F (cap rule also binds) |
| One Possible XSS (reflected canary), nothing else | ~96 · A |
| Likely SQLi (error signature), nothing else | ~61 · D |
| Verified XSS (browser-executed) | ~35 · F |
| Supabase **anon** key in bundle | 100 · A (recon) |
| Verified SQLi + leaked `sk_live` + weak posture | 0 · F |
| 30 hardening findings | ≥95 · A (posture clamp) |
| 2 runtime auth tokens in localStorage | ~77 · C |

Live smoke anchors: `apple.com`, `paloaltonetworks.com`, `example.com` must stay A (≥90); the calibration fixtures (`calibration-fixtures.json`) replay 8 real professional sites and must all stay ≥80.

## What changed vs V5 (delta)

**Deleted:** `BAND_CEILING` (worst-severity caps), `CLASS_BASE`/`CLASS_DAMAGE`/`SEVERITY_PENALTY` scoring tables, `CATEGORY_CAP`/`DEFAULT_CATEGORY_CAP` per-19-category swing caps, the global 10-point hardening cap (`CAPS`), `BAND_THRESHOLDS`, `gradeForScore`'s `isClean` param, grade `A+`.

**Survives:** the `finding-ids.ts` contract (extended), `verifiedImpactPredicate` as the single verified gate (XSS/SQLi rules tightened), `classifyRiskClass` 5-bucket riskClass (still drives `effectiveSeverity` + `uiGroup` — zero UI grouping changes), `severityCounts`, the no-HTTPS hard cap, `applyEngine` signature (all 5 endpoints unchanged).

**New:** `RiskCategory`/`BusinessImpact`/`ScoreTier` types, `mapToRiskCategory`/`isGoldenFinding`/`gradeCapApplies`/`normalizeConfidence` in scoring-policy, `deriveBusinessImpact` in finding-traits, `ScoreBreakdown.riskCategories` + `wafBonus` + `scoreTier`, `ScoringContext.wafPresent`, golden/recon/cap predicates in finding-ids, the 4-bucket scorecard in `ScanForm`'s breakdown card, gauge tier label.

**Bug fixes shipped alongside:** `extractTraits` matched `paths-xss-reflected` by raw token and missed the real emitted `paths-reflected-xss` (now uses `isActiveProbeHitId`); localStorage auth tokens derived `impactType: hardening` via the cookies-category fallback (now `credentialExposure`).

## Detector gaps (engine-ready, no emitter yet)

Rate limiting (login/reset/OTP/MFA), credential-stuffing exposure, weak account lockout, weak JWT (Stage-2 decode is planned), CSRF, RCE, and S3/Firebase bucket *content* sensitivity classification (today "public bucket" is conservatively treated as data exposure when the detector emits critical). Predicates exist; building detectors is out of scope of V6.

## Files

- `api/_lib/scoring-policy.ts` — all tables + mapping functions (single source of truth)
- `api/_lib/scoring-engine.ts` — classification, penalties, aggregation, caps, breakdown
- `api/_lib/finding-ids.ts` — golden/cap/recon/XSS-split predicates
- `api/_lib/finding-traits.ts` — `deriveBusinessImpact` + impact-type fixes
- `src/lib/scanner-types.ts` — `Grade` (no A+), `Confidence` vocab, `RiskCategory`, `BusinessImpact`, `ScoreBreakdown` extensions
- Tests: `api/__tests__/scoring-v6.test.ts` (new), `scoring-engine.test.ts` / `scoring-v5.test.ts` / `calibration.test.ts` (updated) — **183/183 passing**
