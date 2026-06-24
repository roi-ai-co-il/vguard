# V-Guards Scoring Brain v5 — Implementation Report

> ⚠️ **SUPERSEDED by [SCORING-V6-IMPLEMENTATION.md](SCORING-V6-IMPLEMENTATION.md) (2026-06-13).** Kept as calibration history; the band-ceiling/category-cap model described here was replaced by the V6 risk-category model.

> Date: 2026-06-07. Companion to [`SCANNER-BRAIN-AUDIT.md`](SCANNER-BRAIN-AUDIT.md).
> Status: **implemented, type-checked, and tested** — `124/124` tests pass
> (90 pre-existing + 34 new), `tsc` clean on both `tsconfig.api.json` and
> `tsconfig.app.json`, deploy verifier `0 fail`, and `runScan` smoke-tested
> end-to-end against `example.com`. Not yet deployed to prod (Royi runs the
> deploy gate).

---

## 1. Executive Summary

The scoring brain was rebuilt around a **shared finding-ID contract** and a
**professional, evidence-based exposure model**, without brand whitelists, score
floors, or fake telemetry/ML.

The audit's root cause was *vocabulary drift*: detectors emit ids like
`secret-stripe-<file>`, `path--env`, `paths-reflected-xss`,
`headers-cors-wildcard`, `auth-rls-leak`, while the scoring policy gated on
*different* strings (`secrets-…`, `paths-env`, `paths-xss-reflected`,
`cors-credentials-wildcard`, `stage3-…`). The verified-impact gate therefore
almost never fired, so real secret leaks / `.env` exposures / reflected XSS /
confirmed RLS breaches collapsed to "medium" (≈79/C), while missing
CSP/HSTS/X-Frame-Options were *over*-scored as medium (also ≈79/C).

What changed:

1. **One shared contract** (`finding-ids.ts`) maps every emitted id — real **and**
   legacy spelling — to its security meaning. Detectors and the engine now speak
   the same language; they can't drift again.
2. **Structured, professional traits** (`finding-traits.ts`) attach
   `verifiedImpact`, `exploitability`, `impactType`, `evidenceKind`,
   `evidenceStrength`, `attackPrerequisite`, `remoteReachable`,
   `publicInternetExposure`, `activeProbeConfirmed` to every finding.
3. **One scoring engine is the single source of truth.** Stage 3 and the Stage 2
   bookmarklet path now route through `applyEngine` instead of a legacy linear
   formula / no engine at all.
4. **Verified-impact gate trusts detector severity** (the detector saw the
   unredacted body) instead of re-running secret regexes on the *redacted*
   evidence — a second bug that made the old gate impossible to pass.
5. **Target profiling + coverage/confidence** (`target-profile.ts`) and
   **adaptive intensity + self-explaining score** (`scan-orchestrator-policy.ts`)
   are computed from observable signals and surfaced separately from the score.

Net effect: real risk drops the score to the critical band (≤49/F); hardening-only
gaps land in B (80s); coverage limits lower *confidence*, not the *score*; and a
famous brand earns nothing it didn't demonstrate.

---

## 2. Files Changed

### New files
| File | Purpose |
|---|---|
| `api/_lib/finding-ids.ts` | **Single source of truth** mapping emitted ids → meaning. ~25 predicates (`isRealProviderSecretId`, `isSensitiveFileId`, `isActiveProbeHitId`, `isStage3ConfirmationId`, `isCorsId`, `isBrokenTlsId`, `isBaselineHardeningHeaderId`, `isAdvancedHardeningHeaderId`, `isPublicClientIdentifier`, …). Each matches the real emit **and** the legacy spelling. |
| `api/_lib/finding-traits.ts` | `deriveFindingTraits(finding, ctx)` → the professional dimension set. Delegates `verifiedImpact` to the one gate so engine + traits never disagree. |
| `api/_lib/target-profile.ts` | `deriveTargetProfile(signals)` + `computeCoverage(signals, hasVerifiedImpact)` — observable-only target classification and coverage/confidence (kept separate from the score). |
| `api/_lib/scan-orchestrator-policy.ts` | `decideScanIntensity(...)` (concise/standard/expanded/deep + next-step) and `buildScoreExplanation(...)` (riskDrivers / positiveSignals / coverageLimitations / whyNotHigher / whyNotLower). |
| `api/__tests__/scoring-v5.test.ts` | 34 regression tests A–N using the **real emitted ids**. |

### Edited files
| File | Change |
|---|---|
| `src/lib/scanner-types.ts` | Added `Exploitability`, `AttackPrerequisite`, `ImpactType`, `EvidenceKind`, `EvidenceStrength`, `TargetProfile`, `ScanConfidence`, `ScanIntensity`. Added the 9 trait fields to `Finding` (all optional). Added `riskDrivers`/`positiveSignals`/`coverageLimitations`/`whyNotHigher`/`whyNotLower`/`recommendedNextStep`/`scanIntensityUsed`/`targetProfile` to `ScoreBreakdown`; `targetProfile`/`scanConfidence`/`coverageScore`/`scanIntensityUsed` to `ScanResult`. |
| `api/_lib/scoring-policy.ts` | `verifiedImpactPredicate` **rewritten** to use `finding-ids` (fires on real ids; trusts detector `critical` instead of re-checking redacted evidence). `isPublicClientIdentifier`/`isAdvancedHardeningHeader` delegate to the contract. `gradeForScore` thresholds aligned to v5 bands (C = 70–79). |
| `api/_lib/scoring-engine.ts` | `defenseInDepthOnly` now recognises baseline hardening headers via the contract (fixes CSP/HSTS/XFO mis-scoring). CORS classification uses `isCorsId`. Each enriched finding gets the professional trait set via `deriveFindingTraits`. |
| `api/scan-deep.ts` | Stage 3 now runs `applyEngine(..., stage:3)` over the Stage1+Stage3 union (was `100 − crit*20 − warn*7 − info*2`). Returns engine `vibeScore`/`grade`/`severityCounts`/`scoreBreakdown`. |
| `api/stage2-results.ts` | Bookmarklet path now runs `applyEngine(..., stage:2)` so it ships `riskClass`/`confidence`/`verifiedImpact`/`vibeScore` like the Playwright path. |
| `api/_lib/scanner.ts` | Builds `TargetSignals` from observable scan data, computes `targetProfile`, `coverage`, intensity decision, and the self-explaining score; surfaces them on `ScanResult` + `scoreBreakdown`. |

The Stage-2 **Playwright** path (`scan-browser-assisted.ts`) already routed
through `applyEngine(stage:2)` — left as-is.

---

## 3. New Scoring Architecture

`Risk ≈ Severity × Exploitability × Verified-Impact × Exposure × Confidence`,
realised as deterministic "Smart Scoring" (no ML, no telemetry).

- **Severity** — reconciled 5-tier `effectiveSeverity` (critical/high/medium/low/info)
  derived from the engine `riskClass`, not the raw detector label.
- **Exploitability** — `none | theoretical | plausible | easy | confirmed`
  (`finding-traits.deriveExploitability`): active-probe/Stage-3 = confirmed;
  verified exposures = easy; CORS/weak-CSP/open-redirect/auth-enum = plausible;
  missing hardening = theoretical.
- **Verified impact** — the strict gate (`verifiedImpactPredicate`). `true` only
  for real secret leaks, sensitive-file exposures, public data stores, broken
  transport, active-probe hits, dangerous CORS+creds, and Stage-3 confirmations.
  Drives `impactType` (`credentialExposure` / `dataExposure` / `codeExecution` /
  `authBypass` / `transportBreak` / `abusePath` / `supplyChain` / `infoDisclosure`
  / `hardening` / `none`).
- **Exposure context** — `routeContext` (sensitive/public/unknown) plus
  `attackPrerequisite`, `remoteReachable`, `publicInternetExposure`.
- **Confidence** — `CONFIDENCE_MULT` down-weights unconfirmed findings
  (confirmed ×1.0, likely ×0.7, informational ×0.45), mirrored by
  `evidenceStrength` (`weak/moderate/strong/confirmed`).
- **Coverage score (0–100) + scanConfidence (low/medium/high)** — **separate**
  from the security score. Anchored at 100 for a fully passively-visible target;
  each unverifiable surface (auth area, API behaviour, RLS/rules, WAF block)
  subtracts. A static site → high coverage; an app with login+Supabase → lower
  coverage; a famous brand → no change.
- **Adaptive intensity** — `concise/standard/expanded/deep` chosen from the
  preliminary score + profile + verified-impact + ownership, with a concrete
  `recommendedNextStep`.
- **Target profile** — observable classification (static / small-business /
  vibe-coded / SPA / SaaS-login / e-commerce / API-heavy / enterprise /
  WAF-limited / unknown). Signals: framework, app shell, login/API/checkout/admin
  surface, Supabase/Firebase/S3, vibe-builder traces, third-party scripts, CDN/WAF,
  shared-platform, subdomain count. **No brand/domain names anywhere.**

The aggregate math (band ceiling, per-category swing caps, diminishing returns,
confidence multipliers, no-HTTPS hard cap) is unchanged — it was already sound;
the fix made the right inputs reach it.

---

## 4. Old vs New Behaviour

Verified by unit tests (`scoring-v5.test.ts`) and the `example.com` smoke run.

| Scenario | Before | After |
|---|---|---|
| Dell-like professional site (HTTPS, no secrets, minor headers) | clustered ~79/C from header mis-scoring | low-hardening → **80s/B**; coverage/confidence shown separately; no fake criticals |
| Apple-like (limited passive coverage) | ~79/C or inflated | score reflects only what was found; **confidence**, not score, reflects coverage; no brand boost |
| Small biz missing CSP/HSTS/XFO **only** | **79/C** (mis-scored medium) | **B (~80s)**, all three `low-hardening` (test D) |
| Vibe app, public anon key only | risked medium | **informational, no damage** (test E) |
| Vibe app, real provider secret (Stripe/OpenAI/AWS/Anthropic/service-role) | **79/C** | **critical-exploit, ≤49/F** (test F) |
| Exposed `.env` with real secret | **79/C** | **critical-exploit, ≤49/F** (test G) |
| Stage 3 confirmed RLS public data exposure | **80/B** (linear formula) | **critical-exploit, ≤49/F** via engine (test J) |
| Dangerous CORS wildcard **+ credentials** | medium (id mismatch) | **verified impact, ≤49** (test K) |
| CORS wildcard only (no creds) | varied | **informational, no damage** (test K) |
| Many low hardening issues | could drag toward C | **capped, ≥80, never F**; a real medium keeps it < 90 (test L) |

---

## 5. Score Semantics (v5 bands)

| Band | Meaning |
|---|---|
| **95–100** | Excellent posture within scan coverage. No meaningful weaknesses; few/no hardening gaps. |
| **90–94** | Strong. Only minor hardening/informational issues. |
| **80–89 (B)** | Good, with fixable hardening gaps. Normal for professional sites with minor gaps. |
| **70–79 (C)** | Needs attention. At least one real weakness or several meaningful issues. |
| **50–69 (D)** | Risky. Strong evidence of exploitable/sensitive issues (unconfirmed high-impact). |
| **0–49 (F)** | Critical. **Verified** serious impact: real secret leak, public data leak, broken auth, confirmed exploit, broken transport, or a dangerous Stage-3 result. |

90+ is allowed but **earned** by absence of meaningful findings + reasonable
coverage — never by brand, WAF, or scanner blind-spots. A+ requires a perfectly
clean 100.

Mechanism: `BAND_CEILING` = critical 49 / high 70 / medium 79 / low 89 / info 100;
the worst severity present caps the achievable score, so a verified critical can't
be diluted by a clean rest, and a hardening-only site can't be dragged below B.

---

## 6. Adaptive Scan Behaviour

`decideScanIntensity(score, profile, hasVerifiedImpact, ownershipVerified)`:

- **Stops early (concise)** — score 90–100 **and** a non-app profile (static /
  small-business). Returns "no deeper scan needed unless the site changes." Does
  not invent findings to avoid 90+.
- **Standard** — 80–89, or 90–100 on an app profile (recommends Stage 2/3 to raise
  backend confidence).
- **Expanded** — 65–79 (real weakness present; review + consider browser-assisted
  for app/auth/data-store surfaces).
- **Deep** — verified impact **or** score < 65. Recommends Stage 3 if ownership is
  verified, else "verify ownership to unlock Stage 3," and prioritises confirmed
  findings.
- **WAF/blocked/enterprise** — `wafLimitedTarget` → "coverage limited," recommend
  **Stage 2** (runs on the user's own origin, bypassing the edge). Confidence is
  lowered; the score is **neither inflated** ("looks professional") **nor
  deflated** ("we got blocked").

**Honesty note (what is and isn't wired):** the Stage-1 detector set already runs
to completion on every scan (bundle/path budgets are fixed for the Vercel 10s
limit), so "intensity" governs the **recommendation, report tone, and escalation
path** — it does not yet trigger additional Stage-1 fetches in the same request.
True multi-pass re-fetching would change `runScan`'s control flow and was left out
to avoid destabilising the live single-pass scanner; the policy module is the hook
that the product (and Stage 2/3 endpoints) use to escalate. This is called out so
the report doesn't overclaim.

---

## 7. Tests Added (`api/__tests__/scoring-v5.test.ts`, 34 cases, all green)

- **A/B/C** — professional site, hardening gaps only → ≥85, no critical; a real
  weakness drops it normally (no brand protection exists).
- **D** — `headers-content-security-policy` + `-strict-transport-security` +
  `-x-frame-options` (warn) → all `low-hardening`, ≥80, grade A/B.
- **E** — `secret-supabase-anon-*` with anon-key evidence → informational, ≥85.
- **F** — `secret-stripe/openai/aws/anthropic/supabase-service-role-*` →
  critical-exploit, `verifiedImpact`, `impactType: credentialExposure`, ≤49, F.
- **G/H** — `path--env` critical → F; `path--env-spa-shell-200` (info) and
  `path--env-exposed-needs-review` (warn) → not critical, not F.
- **I** — `paths-reflected-xss` → verified impact, critical-exploit, ≤49.
- **J** — `auth-rls-leak` (stage 3) → critical-exploit, ≤49, F.
- **K** — `headers-cors-wildcard` info → informational; critical (+creds) → ≤49.
- **L** — 8 hardening gaps → capped, ≥80, never F; one real medium → < 90 but ≥ 50.
- **M/N** — `decideScanIntensity`: verified impact → deep+escalate; high+static →
  concise; WAF-limited → Stage 2.
- **Target profile + coverage** — Supabase app → vibeCodedApp + coverage < 80;
  static → coverage 100/high; WAF block → confidence low (score untouched).
- **Gate parity** — `deriveFindingTraits().verifiedImpact` table over 10 real ids.

Full suite: `# tests 124 / # pass 124 / # fail 0`. The 90 pre-existing tests
still pass (backward compatibility preserved by matching legacy ids too).

---

## 8. Safety / Honesty Checks

- ✅ **No brand whitelist** — profiling is 100% observable signals; no domain/brand
  names anywhere in the codebase.
- ✅ **No fake score floor** — the only hard cap is *downward* (no-HTTPS → 49).
- ✅ **No "large company = secure"** — enterprise profile grants zero score bonus;
  it only changes copy + lowers confidence when coverage is partial.
- ✅ **No "blocked scan = secure"** — `wafLimitedTarget` lowers confidence and
  recommends Stage 2; it neither inflates nor deflates the score.
- ✅ **Public anon keys / client IDs are not secrets** (test E, gate parity test).
- ✅ **Real secrets are critical** (test F).
- ✅ **Stage-3 confirmed issues are critical** and routed through the engine (test J).
- ✅ **Hardening gaps are never critical** (tests D, L).
- ✅ **One scoring engine is the source of truth** — Stage 1, Stage 2 (both paths),
  and Stage 3 all call `applyEngine`; the legacy linear formula in `scan-deep.ts`
  is gone; `risk-scorer.ts` only populates back-compat numeric fields.

---

## 9. Remaining Risks / TODOs

Honest limits of passive scanning and of this change:

1. **Single-pass Stage 1.** Adaptive intensity is advisory (see §6) — a low score
   does not yet trigger extra in-request fetches. A future change could let
   `runScan` widen bundle/path coverage when early signals look risky, within the
   time budget.
2. **`risk-scorer.ts` still exists** as a deprecated back-compat shim
   (`riskScore`/`riskBand`/`aggregateRisk`). It no longer decides the grade, but
   collapsing it fully into the engine is a follow-up.
3. **Detector-set impact flags.** The gate now trusts detector `critical` severity
   + the shared id contract. The cleaner long-term form (the detector emits an
   explicit `verifiedImpact`/`evidenceKind` at the push site) is not done — the id
   contract is the bridge until then.
4. **Coverage heuristics are deterministic estimates**, not measurements. They
   express "how much relevant surface a passive scan can see," which is inherently
   approximate; they should be calibrated against real scans over time.
5. **Passive scanning cannot confirm backend authorization** (RLS, IDOR, mass
   assignment, auth bypass) without Stage 3 — correctly reflected by lowered
   coverage on app profiles and the Stage-2/3 recommendations, not by guessing.
6. **`tls-no-http-redirect`** currently classifies as a medium-weakness (transport
   gap), which can cap an otherwise-clean site at 79/C (observed on `example.com`).
   This is defensible (no HTTPS redirect is a real downgrade surface) but is a
   calibration point worth reviewing with real-world data.

---

---

## 11. v5.1 calibration — "deduct vs cap" (clean sites approach 100; risky sites worked harder)

Per Royi's directive: a big professional site (Apple/NVIDIA/Dell-style) with **no
real weaknesses** must not be dragged to 80/90 for a few missing hardening
controls — it should be able to **approach 100**; and the *less* safe a site
looks, the *harder* the brain should work.

The conceptual change (how Palo Alto / CrowdStrike separate posture hygiene from a
confirmed exposure):

- **A hardening / defense-in-depth gap DEDUCTS points but NEVER caps the grade.**
  Previously `low-hardening` imposed an 89 ceiling, so a clean site missing one
  optional header was stuck at B. Now hardening gaps only subtract (small,
  decayed, category-capped). (`scoring-engine.ts` ceiling loop now skips
  `effectiveSeverity === 'low'` and any hardening-only finding.)
- **Only a REAL WEAKNESS (medium-weakness and up, non-hardening) or a VERIFIED
  IMPACT caps the grade.** Real weakness → 79/70 ceiling; verified exploit → ≤49.
- **Catch-all refined** (`classifyRiskClass`): a leftover `warn` is a real
  weakness only if it carries a weakness signal (configuration flaw, sensitive
  data, or a sensitive-route browser surface). Otherwise it's a hardening gap.
  This stopped honest hygiene findings (`tls-no-http-redirect`,
  `methods-trace-enabled`, `email-no-dmarc`) from being mislabelled "medium" and
  capping the grade at 79.
- **Adaptive intensity ties in:** clean/high → `concise`/`standard`; real weakness
  → `expanded`; verified impact or < 65 → `deep` + escalate to Stage 2/3.

Verified calibration curve (synthetic, via `applyEngine`):

| Input | Score / grade | Intensity |
|---|---|---|
| Perfectly clean (ok only) | **100 / A+** | standard |
| Clean + 2 optional headers missing | **98 / A** | standard |
| Missing CSP + HSTS + X-Frame-Options only | **97 / A** | standard |
| 10 hardening gaps, no real weakness | **94 / A** | standard |
| Real medium weakness (non-auth cookie no Secure) | **79 / C** | expanded |
| Auth cookie missing HttpOnly (high) | **70 / C** | expanded |
| Dangerous CORS + credentials | **49 / F** | deep |
| Real Stripe key leak | **49 / F** | deep |
| Exposed `.env` (real secret) | **49 / F** | deep |
| Confirmed reflected XSS | **49 / F** | deep |
| Stage 3 confirmed RLS public data | **49 / F** | deep |
| Vibe app: 2 real issues + hardening | **44 / F** | deep |
| `example.com` (live) | **93 / A** | — |

Discrimination is preserved entirely through **real weaknesses** (which cap),
exactly as the model intends — not by punishing hygiene.

---

## 12. v5.2 — detectors self-declare impact (architecture hardening)

Closes the last architecture gap from §9.3: the verified-impact gate no longer
depends *solely* on id-string matching.

- `verifiedImpactPredicate` now honours `finding.verifiedImpact === true` FIRST.
- Detectors that saw the **unredacted** evidence self-declare it:
  - `scanner.ts` — real provider-secret patterns (`critical` only) + Supabase
    service-role JWT + path-probe-with-real-secret set `verifiedImpact: true`.
  - `deep-scanner.ts` — every Stage-3 finding (all are confirmed probe hits) is
    marked `verifiedImpact: true` + `evidenceKind: 'ownershipVerifiedDeepScan'`
    at the return.
- The id contract (`finding-ids.ts`) remains as the fallback for everything else,
  so nothing regresses. New test: a detector-declared impact on an **unknown id**
  still scores critical-exploit (proves the gate is no longer id-coupled).

Deployed to production (`v-guards.com`) 2026-06-07. Live check: `example.com`
→ 93/A, profile `staticMarketingSite`, confidence high, intensity `concise`.

---

## 13. v5.3 — catch-all/soft-404 fix ("Apple got 46") + adaptive probe depth

**Incident:** apple.com scored **46/F** on production while scoring 89–91/A
locally. Root cause: when Apple's Akamai WAF soft-blocks Vercel's datacenter IP,
it returns HTTP **200** (a challenge page) for *every* path — so the path prober
read ~31 non-existent files as "exposed", the `paths` category maxed its penalty
cap, and the score collapsed to F. A pure WAF artefact, not a real finding.

**Fix (catch-all detection, `scanner.ts`):** before path probing, fetch a
guaranteed-nonexistent canary (`/vguard-nonexistent-canary-…`). If it returns 200
and isn't the SPA shell, the origin is a catch-all → every 200 from a real probe
is the soft-404 page, so exposure findings are suppressed (only a body that
actually contains a real secret is kept), and ONE honest info finding explains it
(`paths-catch-all-200`) with a Stage-2 recommendation. Normal sites (real 404 for
the canary) are unaffected.

**Adaptive probe depth (the deferred "work harder"):** `decideProbeExpansion`
(pure, tested) + an additive `EXTENDED_PATHS_TO_PROBE` set. The baseline probe set
ALWAYS runs (consistent detection for everyone); the extended set (more `.env`
variants, `.git/credentials`, `.vscode/sftp.json`, DB dumps, `.npmrc`,
`/api/admin`, …) runs only when early signals flag risk (backend / login / app
shell / a secret already found). Probes are parallel, so the extra depth costs
no meaningful wall-clock. `scanIntensityUsed` and `coverageLimitations` reflect
when the deeper pass ran.

Deployed to `v-guards.com` 2026-06-07. Live re-verify: apple.com 89/B,
www.apple.com 91/A, example.com 93/A; failure path (`unreachable`) returns clean
`ok:false`. Tests: 127/127.

> Pre-existing note (not introduced here): `vercel deploy` prints a non-fatal
> `TS2339` advisory on `api/scan.ts:69` (failure-branch union narrowing). The
> @vercel/node builder transpiles via esbuild regardless; the function runs
> correctly (verified live on both success and failure paths) and
> `tsc -p tsconfig.api.json` is clean. Worth a separate tidy-up, not a blocker.

---

## 14. v5.4 — "Apple got 43" root cause: Stage-2 false-positives over-punished

The user re-scanned apple.com in the live UI and saw **43/Critical**. Diagnosed in
a real browser (chrome-devtools MCP): the UI auto-runs Stage 2 and merges it
client-side, and two Stage-2 findings were wrongly scored High on a clean
professional site:

1. **"3 first-party API calls returned 2xx without auth" → High (−22).** The
   evidence was `globalheader.umd.js`, `globalheader.css`, and a public `flyouts`
   JSON. Two bugs: (a) `isApiCall` matched the `/v1/` in a versioned *static
   asset* path, so JS/CSS were counted as "API calls"; (b) a plain unauth GET of
   public content was scored as a High weakness.
2. **"1 sensitive cookie valid for >30 days" (`dssid2`) → High (−14).** `dssid2`
   is a tracking cookie; it was flagged "auth-shaped" because the `authCookie`
   trait tested the finding's OWN description prose ("Auth-shaped cookies…"),
   not the actual cookie name.

Fixes:

- `authCookie` now tests **evidence only** (the real cookie name/value), never
  the description copy. A genuine `session=`/`auth_token=` cookie still matches.
- `stage2-unauth-api-calls` → classified **low-hardening** (an audit item, never
  caps the grade).
- High-impact-misconfig now requires an actual exploit surface
  (`exploitable` || real `sensitiveData`) — merely *observing* a cookie or API
  call at runtime is no longer "High".
- Detector (`scan-browser-assisted.ts`): static assets (script/stylesheet/
  image/font + js/css content-types) are never "API calls"; bare `/v1/`,`/v2/`
  GETs are no longer "interesting unauth" (only `/api/`,`/graphql`,`/trpc` or
  state-changing methods).
- Global **defense-in-depth cap** (`HARDENING_TOTAL_CAP = 10`) applied by
  *scaling* each hardening category proportionally, so the scorecard still sums
  exactly to the final deduction (honest breakdown, no hidden subtraction).

Result, verified live in the browser: **apple.com 43/Critical → 90/Healthy**,
breakdown all Low hardening, 0 likely-risks, 0 highs. Tests: 131/131.

---

## 15. v5.5 — cookie flags are hardening, not High (Palo Alto 70→90)

Palo Alto Networks scored 70/C, dragged down by **Cookies (4 Highs) −14** +
"a High issue limits the grade". Same class as Apple: cookie hygiene treated as a
near-exploit on a clean professional site.

Decision (Royi's consistent direction across Apple + Palo Alto): **a cookie
missing HttpOnly/Secure/SameSite is DEFENSE-IN-DEPTH** — only exploitable in
combination with another vuln (XSS for HttpOnly, MITM for Secure). It must
deduct as hardening and **never cap the grade**. Only verified impact lowers the
band.

Changes (`scoring-engine.ts`):

- Removed `(cat === 'cookies' && authCookie)` from `sensitiveData` — a cookie
  *existing* is not data exposure.
- Removed the `cookies && authCookie → high-impact-misconfig` branch and the
  defense-in-depth `cookies → medium` sub-branch. Cookie findings now fall to:
  `warn → low-hardening`, `info → informational`.
- The ONE genuinely-active cookie misconfiguration — `SameSite=None` without
  `Secure` (detector `critical`) — still lands at **medium-weakness** (caps 79),
  because it actively sends the cookie cross-site insecurely.

Preserved: real secrets / `.env` / SQLi / RLS still → critical-exploit ≤49/F
(danger detection unchanged — verified by smoke + tests).

Verified live in the browser: **paloaltonetworks.com 70/C → 90/A**,
**apple.com 43/F → 90/A**; both all-Low, 0 likely-risks, breakdown sums honestly.
Tests: 131/131.

---

## 16. v5.6 — THE ROOT CAUSE (stop the per-site whack-a-mole)

Apple, then Palo Alto, each got dragged to C/F by a DIFFERENT unconfirmed finding
(unauth-api, then cookies; next would have been JWT/auth surfaces). Patching each
finding type is whack-a-mole. The real disease:

**The classifier's DEFAULT for an unconfirmed finding was to promote it to
medium/high — and medium/high CAP the grade (79/70).** The catch-all was "any
`warn` → medium-weakness", plus weak signals (`runtimeConfirmed`, `authImpact`,
auth-named cookie) pushed things to high. So every site trips *some* unconfirmed
finding into a capping tier, and it's a different one each time.

**The fix — one invariant, in one place (`classifyRiskClass`):** ONLY three
things may cap the grade; everything else defaults to hardening (deducts, never
caps):

1. **Verified impact** → critical-exploit (≤49/F) — the strict gate.
2. **Real exposure** short of verified — an active-probe hit, or real
   data/token/bucket OBSERVED at runtime (e.g. auth token in localStorage) → high.
3. **An explicit, short allowlist of genuine unconfirmed weaknesses** —
   account enumeration, CVE-matched deps, mixed content, source-maps leaking
   internal paths, a sensitive path 200 needing review, SameSite=None+insecure
   → medium.

Everything else — missing headers, cookie flags, weak CSP, JWT hygiene, DNS/email,
SRI, DOM-sink heuristics, unauth public GETs, info disclosure — **defaults to
low-hardening and can never cap.** New/unanticipated detectors default to safe, so
no future finding can surprise-cap a clean site. The consistent rule: *anything
that needs ANOTHER vulnerability to be exploitable (cookies, weak CSP, missing
headers) is hardening; only things that are DIRECTLY a problem cap.*

Verified calibration spectrum (engine smoke):

| Input | Score |
|---|---|
| clean | 100/A+ |
| professional: missing headers + cookies + unauth-api + JWT hygiene | 90/A |
| weak CSP (unsafe-inline) | 99/A (hardening) |
| account enumeration | 93/A (deduct, non-stable cat) |
| mixed content / CVE dep | 79/C |
| auth token in localStorage | 70/C |
| dangerous CORS+creds / real secret / confirmed RLS | 49/F |

Verified live in the browser: **apple.com 90/A, 0 likely risks**; Palo Alto 90/A
(v5.5). 131/131 tests. This is the systemic fix — not another per-site patch.

**Bottom line:** the philosophy the audit found correct is now actually executing.
Real, verified risk drives the score into the critical band; hardening-only gaps
sit in B; coverage limits move *confidence*, not the *score*; and nothing is
granted to a brand, a WAF, or a scanner blind-spot. All changes are deterministic,
transparent, and covered by tests.
