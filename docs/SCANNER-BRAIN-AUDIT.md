# V-Guards Scanner Brain Audit

> Scope: code as it exists on branch `main` (HEAD `d568197`) at `ROI-AI/vguard/`.
> Every claim is cited to a file/line that was read directly. This document
> separates **"what it does today"** from **"what it was designed to do."**
> No brand whitelists, no score floors, no invented behavior.
>
> Generated 2026-06-07 from a full end-to-end read of `api/_lib/scanner.ts`,
> `scoring-engine.ts`, `scoring-policy.ts`, `risk-scorer.ts`, `deep-scanner.ts`,
> `scan-deep.ts`, `scan-browser-assisted.ts`, `stage2-results.ts`,
> `stage2-worker/index.ts`, `js-ast.ts`, `attack-surface.ts`, `verify.ts`,
> `scan.ts`, `scan-stream.ts`, and `src/lib/scanner-types.ts`.

---

## 1. Executive Summary

V-Guards thinks in two layers:

1. **Detectors** (`api/_lib/scanner.ts`, ~3,992 lines) fetch the site and `push`
   raw `Finding` objects, each with a string `id`, a 4-tier `severity`
   (`critical|warn|info|ok`), and a `category`.
2. **A scoring engine** (`api/_lib/scoring-engine.ts` + `api/_lib/scoring-policy.ts`)
   re-classifies every finding into a 5-tier risk class, decides whether it has
   *verified impact*, then computes a 0–100 `vibeScore` + letter grade using a
   band-ceiling + diminishing-returns + per-category-cap model that mirrors
   SSL Labs / Mozilla Observatory / CVSS.

**The core problem:** the two layers were written at different times and
**drifted on naming.** The engine's "is this a real exploit?" gate
(`verifiedImpactPredicate`) and its hardening-vs-weakness classifier both match
findings by **`id` prefix strings** — and those strings (`secrets-*`,
`paths-env`, `paths-xss-reflected`, `headers-csp-missing`,
`cors-credentials-wildcard`) **do not match the IDs the scanner actually emits**
(`secret-*`, `path--env`, `paths-reflected-xss`, `headers-content-security-policy`,
`headers-cors-wildcard`).

The consequence is a calibration inversion:

- **Confirmed dangerous findings are under-weighted.** A leaked Stripe
  `sk_live_`, an OpenAI key, even a Supabase **service-role** key in the client
  bundle, and a real secret-bearing `.env` exposure all fall through the gate and
  are scored as a **medium-weakness** → the site can still score **79/C**, never
  the intended **F (≤49)**.
- **Ordinary hardening gaps are over-weighted.** Missing CSP / HSTS /
  X-Frame-Options don't match the "defense-in-depth" list, so they're scored as
  **medium** instead of **low** → a clean professional site missing only those
  lands at **79/C** instead of the intended **89/B**.
- **Stage 3 (the verified deep scan) ignores the engine entirely** and uses a
  crude legacy linear formula, so a *confirmed* public-data RLS breach scores
  ~**80/B**.

The design is sound. The wiring between detector IDs and the policy is broken.

---

## 2. Full Request Flow

```
User pastes URL in ScanForm.tsx
   │  POST /api/scan  or  POST /api/scan-stream (NDJSON live phases)
   ▼
api/scan.ts handler  ──audit log──►  runScan(url)   [api/_lib/scanner.ts:1844]
   │
   ├─ normalize URL, reject private hosts  (isPrivateHost, scanner.ts:419)
   ├─ fire parallel probes: DNS, TLS, OPTIONS, Firebase RTDB, robots,
   │   signup, open-redirect, http→https, reflected-XSS, SQLi, SSRF/OAST,
   │   CT-subdomains
   ├─ fetch homepage (SCANNER_UA, 4s); on 403/406/429/451 → detectWafVendor
   │   + one STEALTH_HEADERS retry; else return blocked_by_waf / blocked_by_target
   ├─ fetch ≤4 JS bundles (≤2 MB each) → SECRET_PATTERNS, JWT decode,
   │   source-map probe, npm-CVE match, AST (js-ast.ts)
   ├─ probe ~31 paths (.env/.git/backup/admin/...), 2.5s each, 8 KB body
   ├─ analyze headers / CSP / HSTS / CORS / cookies / mixed-content / SRI /
   │   HTML hygiene / methods / TLS / DNS / email / deps
   ├─ assemble findings:Finding[]
   ▼
SCORING  [scanner.ts ~3850]
   ├─ classifyRouteContext(pathname)          [risk-scorer.ts:28]   (sensitive/public/unknown)
   ├─ applyRisk(findings, ctx)                [risk-scorer.ts:170]  (DEPRECATED: sets riskScore only)
   ├─ ctx = defaultContext({pathname,isHttps,stage:1})  [scoring-engine.ts:616]
   ├─ applyEngine(findings, ctx)              [scoring-engine.ts:580]  ◄── REAL SCORE
   │     extractTraits → classifyRiskClass → classifyConfidence
   │     → computeFindingRisk → runScoringEngine (band ceiling, caps, decay)
   └─ computeAggregateRisk(findings)          [risk-scorer.ts:196]  (legacy, side number)
   ▼
ScanResult { vibeScore, grade, totals, severityCounts, scoreBreakdown,
             findings[], attackSurface, meta, detected, stage:1 }
   ▼
ScanForm.tsx renders gauge + grouped findings (by uiGroup) + per-finding fixPrompt
```

Stage 2 (`/api/scan-browser-assisted` → Railway Playwright worker, or bookmarklet
→ `/api/stage2-collect` → `/api/stage2-results`) and Stage 3 (`/api/verify` →
`/api/scan-deep`) are separate endpoints described in §3.

---

## 3. Stage-by-Stage Breakdown

### Stage 1 — Passive Scan (`api/_lib/scanner.ts`, live)

| Property | Value |
|---|---|
| Nature | Passive fetch + a handful of **active canary probes** (XSS/SQLi/open-redirect/SSRF) |
| Evidence | Response headers, HTML, JS bundle text, source maps, DNS/TLS handshakes, probe responses (redacted) |
| Scoring | `applyEngine(..., stage:1)` — the real band-ceiling engine |
| SSRF guard | `isPrivateHost` blocks `localhost`, `0.0.0.0`, `127.*`, `10.*`, `192.168.*`, `172.16–31.*`, `169.254.*`, `*.local` (scanner.ts:419) |
| Limits | `MAX_BUNDLES=4`, `MAX_BUNDLE_SIZE=2MB`, `FETCH_TIMEOUT_MS=4000`, `PROBE_TIMEOUT_MS=2500` (scanner.ts:17–20) |

The active probes are the only Stage-1 findings that carry true confirmation:
`paths-reflected-xss` (critical), `paths-sqli-error` (critical),
`paths-open-redirect` (warn), `paths-ssrf-confirmed` (critical) —
scanner.ts:2948–3023.

**False-positive suppression (mature, correct):** `isSpaShellBody` (path probes
returning the SPA index), `detectSharedPlatform` (suppresses apex DNS findings on
`*.vercel.app` etc.), `isPublicClientIdentifier` (anon keys, `pk_live_`, GA IDs),
`evidenceContainsRealSecret` (gates `critical` on actual body content), AST RHS
suppression in `js-ast.ts`.

**False negatives:** anon keys are intentionally not findings; secrets only
detected in the first 4 bundles / 2 MB; path list is fixed (~31).

### Stage 2 — Browser-Assisted (`api/scan-browser-assisted.ts`, `stage2-worker/index.ts`, live)

- **Two transports:** server-side Playwright worker on Railway (full fidelity),
  or a bookmarklet that POSTs **key-names only** to `/api/stage2-collect`
  (1-hour TTL in `vs_stage2_collections`).
- **The worker runs zero security logic** — it only *collects* (cookies w/
  attributes, storage keys, window globals, network requests, JWT shapes,
  response-body samples, console errors). All analysis is server-side in
  `analyzeBrowserScan` (scan-browser-assisted.ts) / `analyzeStage2`
  (stage2-results.ts).
- **Findings** (all `stage2-*`): cookie flags (`stage2-cookie-not-httponly` warn,
  `stage2-cookie-samesite-none-insecure` critical, `-prefix-violations`,
  `-insecure`, `-long-lived`), `stage2-localstorage-auth-tokens` (warn), JWT
  family (`stage2-jwt-alg-none` critical, `-no-exp`, `-very-long-exp`,
  `-sensitive-claims`), response-body family (`stage2-secret-in-response`
  critical, `-pii-in-response`, `-internal-url-leak`, `-stack-trace-in-response`),
  `stage2-unauth-api-calls` (warn, guarded by `isWellKnownPublicEndpoint`),
  `stage2-mixed-content-runtime`, `stage2-console-errors` (guarded by a
  23-pattern `HARMLESS_CONSOLE_NOISE` bank), `stage2-clean` (ok).
- **Scoring asymmetry (bug):** the Playwright path re-scores through
  `applyEngine(..., stage:2)`; the **bookmarklet path does not** — its findings
  keep raw `severity`, get no `riskClass`/`uiGroup`/`confidence`, and produce no
  `vibeScore`.
- `extractTraits` treats any `stage2-`/`stage3-`/`deep-` id as
  `runtimeConfirmed=true` (scoring-engine.ts:57–59), so Stage-2 sensitive
  findings can reach `high-impact-misconfig`.

### Stage 3 — Verified Deep Scan (`api/scan-deep.ts`, `api/_lib/deep-scanner.ts`, live)

- **Ownership gate is strict** (scan-deep.ts:100–116): file challenge
  (`/.well-known/Vguard-verify.txt`), DNS TXT (`_Vguard-verify`), or Vercel token
  (`/api/verify-vercel-token`). On failure → HTTP 403, deep scan never runs.
  30-day TTL in `vs_verified_domains`.
- **Probes are real, not stubbed** (deep-scanner.ts): `probeSupabaseRls` (anon
  SELECT vs 26 tables) → `auth-rls-leak` (critical); `probeAuthenticatedRls`
  (≥50 rows w/ user JWT) → `auth-idor-rls` (critical); `probeSupabaseStorageWrite`
  (OPTIONS preflight) → `paths-supabase-storage-anon-write` (critical);
  `probeAggressiveXss` → `paths-aggressive-xss` (critical); `probePathTraversal`
  → `paths-traversal` (critical); `probeMcpRag` → `ai-mcp-rag-leak` (critical);
  `probeAiInjection` → `ai-prompt-injection` (critical).
- **Two real problems:**
  1. **It never calls `applyEngine`.** It re-counts raw severities and uses the
     legacy linear formula `vibeScore = 100 − crit*20 − warn*7 − info*2`
     (scan-deep.ts:160–163). The band ceiling, confidence weighting, and
     verified-impact gate are bypassed for the stage that produces the *most*
     confirmed exploits. One confirmed RLS breach alone → `100−20 = 80/B`.
  2. The merged result spreads `...stage1` (keeping Stage 1's engine-derived
     `grade`, `severityCounts`, `scoreBreakdown`) but overwrites `vibeScore` with
     the linear number — so `grade` and `vibeScore` are computed by two different
     systems and can disagree.
- **OAST** (`api/_lib/oast.ts`) and `buildAttackSurface` exist but are **not
  wired into the deep scanner** (OAST is only used by the Stage-1 SSRF probe).

---

## 4. Full Check Inventory

Severities below are **as the detector emits them** (the engine later reconciles
them — see §5). "Verified gate?" = whether the engine's
`verifiedImpactPredicate` currently recognizes the emitted id.
**❌ = id mismatch, gate never fires** (the central bug).

### Stage 1 — Headers / CSP / Transport
| Emitted ID | Tests | Sev | Verified gate? | Notes |
|---|---|---|---|---|
| `headers-<header-name>` (e.g. `headers-content-security-policy`, `headers-strict-transport-security`, `headers-x-frame-options`, `headers-x-content-type-options`, `headers-referrer-policy`, `headers-permissions-policy`, `headers-cross-origin-opener-policy`, `-embedder-`, `-resource-`) | header missing | warn (CSP/HSTS/XFO) / info (rest) | n/a (hardening) | **CSP/HSTS/XFO ❌ don't match `defenseInDepthOnly` list → mis-scored as medium.** COOP/COEP/CORP/referrer/permissions ✅ match via `ADVANCED_HARDENING_TOKENS` → correctly low |
| `headers-csp-weak` | CSP present but unsafe-inline / unsafe-eval / wildcard / missing frame-ancestors/base-uri/form-action | warn/info | n/a | ✅ id matches policy |
| `headers-hsts-weak` | short max-age / no includeSubDomains | warn/info | n/a | — |
| `headers-cors-wildcard` | `ACAO:*` (critical iff `+Allow-Credentials:true`) | critical/info | ❌ (policy expects `cors-credentials-wildcard`) | falls to medium |
| `tls-old-version`, `tls-weak-cipher`, `tls-cert-expired` | TLS1.0/1.1, RC4/3DES, expired cert | critical/warn | ✅ ids match | correctly critical |
| `tls-cert-near-expiry`, `tls-no-http-redirect` | <14d, no http→https | warn | partial | — |
| `tls-https`, `tls-http` | HTTPS present/absent | ok | `!httpsActive` → hardCap 49 | — |

### Stage 1 — Secrets / Source maps
| Emitted ID | Tests | Sev | Verified gate? |
|---|---|---|---|
| `secret-<provider>-<file>` (anthropic, openai, google, github, stripe, slack, resend, aws) | provider key regex in bundle | critical (most) | **❌ policy expects `secrets-<provider>` → real key leaks scored as medium** |
| `secret-supabase-service-role-<file>` | decoded JWT `role:service_role` | critical | **❌ policy expects `secrets-supabase-service-role` → worst-case leak scored as medium** |
| `secrets-clean` | none found | ok | — |
| `sourcemaps-exposed-with-secrets` | .map w/ real secret | critical | ✅ matches |
| `sourcemaps-exposed-with-internal-paths` / `sourcemaps-exposed` | .map w/ paths / bare | warn / info | n/a (correctly low) |

### Stage 1 — Paths / Cloud storage
| Emitted ID | Tests | Sev | Verified gate? |
|---|---|---|---|
| `path-<slug>` / `path-<slug>-exposed-needs-review` / `-spa-shell-200` / `-empty-200` (.env, .git, backup.sql, .aws/credentials, admin, etc.) | file/route reachable | critical→downgraded to warn unless `evidenceContainsRealSecret` | **❌ policy expects `paths-env`/`paths-git`/… → even a real secret-bearing `.env` (kept critical) scored as medium** |
| `paths-firebase-rtdb` | `/.json` 200 w/ data | critical | partial (policy gate uses `paths-firebase-rtdb-root`) |
| `paths-supabase-storage-public-listing` / `-info`, `paths-s3-listbucket` / `-references` | public listing | warn/info/critical | partial |
| `paths-reflected-xss` | reflected canary | critical | **❌ policy expects `paths-xss-reflected` (word order) → confirmed XSS scored as medium** |
| `paths-sqli-error` | SQL error on `'` | critical | ✅ matches `paths-sqli` |
| `paths-ssrf-confirmed` | OAST hit | critical | ✅ matches `paths-ssrf` |
| `paths-open-redirect` | Location canary | warn | ✅ matches → **promoted to critical-exploit (over-weighted, see §9)** |
| `paths-admin-unauth-data` | admin route returns data unauth | critical | ✅ (id matches) |
| `paths-robots-disclosure`, `paths-sitemap-internal`, `paths-openapi-spec-public`, `paths-graphql*` | info disclosure | info/warn | n/a |

### Stage 1 — Cookies / HTML / Methods / DNS / Email / Deps / AI
| Emitted ID | Sev | Verified gate? |
|---|---|---|
| `cookie-<name>` (missing Secure/HttpOnly/SameSite) | warn/info | ❌ policy expects `cookies-no-secure`/`cookies-no-samesite` → not classified as defense-in-depth |
| `html-inline-xss-surface`, `html-target-blank-no-rel`, `html-form-no-csrf` | warn/info | n/a |
| `integrity-no-sri`, `mixed-content` | warn/critical | mixed-content ✅ via category branch |
| `methods-trace-enabled`, `methods-options-disclosure` | warn/info | n/a |
| `dns-no-dnssec`, `dns-no-caa`, `dns-cname-takeover-hint` | info | n/a (suppressed on shared platforms) |
| `email-no-dmarc`/`-no-spf` (warn), `email-dmarc-monitor`/`-spf-soft-fail`/`-no-dkim` (info) | warn/info | n/a |
| `deps-npm-<pkg>` (19 CVE patterns), `deps-server-cve-<id>` (server-header CVEs) | info→critical | ✅ (policy checks `deps-npm-`, `deps-server-cve-`) |
| `ai-endpoint-detected`, `meta-trpc-detected`, `auth-signup-endpoint-found`, `auth-edge-fn-*`, `auth-weak-jwt`, `auth-enum-surface`, `auth-disclosure-leak` | info/warn/critical | partial |
| `js-ast-runtime-codegen`, `js-ast-dom-sink`, `js-ast-hardcoded-creds`, `js-ast-template-url-fetch` | warn/info | `js-ast-hardcoded-creds` explicitly forced out of "verified secret" lane (scoring-engine.ts:92) ✅ |
| `meta-waf-detected`, `meta-localhost-leak`, `platform-shared-subdomain`, `headers-server-disclosure`, `headers-x-powered-by` | info/ok | `meta` → always informational |

### Stage 2 (browser-assisted) — `stage2-*`
Cookie flags (`stage2-cookie-not-httponly`, `-samesite-none-insecure` critical,
`-prefix-violations`, `-insecure`, `-long-lived`), `stage2-localstorage-auth-tokens`,
JWT family (`stage2-jwt-alg-none` critical, `-no-exp`, `-very-long-exp`,
`-sensitive-claims`), response-body family (`stage2-secret-in-response` critical,
`-pii-in-response`, `-internal-url-leak`, `-stack-trace-in-response`),
`stage2-unauth-api-calls`, `stage2-mixed-content-runtime`, `stage2-console-errors`,
`stage2-external-apis`, `stage2-firebase-config-global`, `stage2-auth-enum-surface`,
`stage2-clean`. Re-scored via engine on Playwright path only.

### Stage 3 (deep) — confirmed exploits
`auth-rls-leak`, `auth-idor-rls`, `paths-supabase-storage-anon-write`,
`paths-aggressive-xss`, `paths-traversal`, `ai-mcp-rag-leak`, `ai-prompt-injection`
— all critical. **❌ none match the policy's `stage3-*` gate** (scoring-policy.ts:488–500),
and moot anyway because Stage 3 doesn't call the engine.

---

## 5. Scoring Engine Breakdown

All constants live in `scoring-policy.ts`; the math lives in `runScoringEngine`
(scoring-engine.ts:433).

**Pipeline per finding:**
1. `extractTraits` (scoring-engine.ts:50) derives ~13 boolean traits (exploitable,
   secretPattern, sensitiveData, authImpact, defenseInDepthOnly, runtimeConfirmed,
   knownPublicAsset, **verifiedImpact**, …).
2. `classifyRiskClass` (214) → one of `critical-exploit | high-impact-misconfig |
   medium-weakness | low-hardening | informational`.
3. `classifyConfidence` (292) → `confirmed (×1.0) | likely (×0.7) |
   informational (×0.45)` (`CONFIDENCE_MULT`).
4. `effectiveSeverity` = `RISKCLASS_TO_EFFECTIVE[riskClass]`; this — not the
   detector severity — drives the badge and the score.

**Aggregate score (`runScoringEngine`):**
- Base = **100**.
- Per-finding penalty = `SEVERITY_PENALTY[effective] × CONFIDENCE_MULT[confidence]`,
  where `SEVERITY_PENALTY = {critical:45, high:22, medium:10, low:3, info:0}`.
- Penalties grouped **by category**, summed with **diminishing returns**
  `DECAY_FACTOR=0.6` (`diminishingSum`, 342): sorted desc, each next ×0.6.
- Each category penalty capped by `CATEGORY_CAP` (headers 22, cookies 14, html 12,
  …; default 30) — **unless that category carries a reconciled `critical`**, in
  which case the cap is lifted (`hasRealRisk`, 469).
- `rawScore = 100 − Σ category penalties`.
- **Band ceiling** = `BAND_CEILING[worstSeverity]` =
  `{critical:49, high:70, medium:79, low:89, info:100}` — the worst severity
  present caps the max achievable score (SSL Labs mechanic). **Only "stable"
  categories or confirmed findings may set the ceiling** (`STABLE_CEILING_CATS`,
  407 — headers/cookies/tls/secrets/… but not flaky active probes unless
  verified), so the same site grades consistently run-to-run.
- **Hard cap:** no HTTPS → cap 49 (the only hard cap).
- `finalScore = round(min(rawScore, bandCeiling, hardCap))`.
- Grade: `gradeForScore` — ≥90 A (A+ only if clean & =100), ≥80 B, ≥65 C,
  ≥50 D, else F.

**How each requested factor is handled:**
- **Base** = 100 (top grade is *earned*, not default — A+ requires a perfectly
  clean 100).
- **Severity** → via `effectiveSeverity` → `SEVERITY_PENALTY` and `BAND_CEILING`.
- **Confidence** → `CONFIDENCE_MULT` multiplies the penalty (passive/heuristic
  dents 45–55% less than confirmed).
- **Confirmed impact** → `verifiedImpact` trait promotes to `critical-exploit`
  (penalty 45, ceiling 49) and adds `+0.6` to per-finding risk
  (computeFindingRisk:329).
- **Duplicates / similar** → diminishing returns within a category (2nd similar
  finding counts ×0.6, 3rd ×0.36…) + per-category caps.
- **Diminishing/caps** → `DECAY_FACTOR` + `CATEGORY_CAP`/`DEFAULT_CATEGORY_CAP`.
- **Critical gating** → a confirmed critical lifts its category cap and sets a 49
  ceiling, so it can never be diluted by caps.
- **Why legit sites aren't crushed** → `high` caps at 70 and `low` at 89 (so one
  missing hardening header → B, not F); shared-platform DNS suppression;
  advanced-header findings down-weighted to `informational` confidence.
- **Why weak sites can't get 90+** → *intended via* the band ceiling: any
  `critical`/`high` present caps below 90. **This is exactly the mechanism the
  ID-mismatch bug defeats** (§7/§9): dangerous findings are demoted to `medium`,
  so the ceiling lands at 79 instead of 49.

**Note:** `risk-scorer.ts` is a parallel, **deprecated** scorer (its own
`BASE_BY_SEVERITY`, `ID_PREFIX_OVERRIDES`, `scoreFromTotals`). It still runs and
still populates `ScanResult.aggregateRisk`/`aggregateRiskBand` (a second,
independently-computed risk number shipped in the response), but the user-facing
`vibeScore` comes from the engine. `scan-deep.ts` uses risk-scorer's linear model
instead of the engine (§3).

---

## 6. Risk Class Mapping

| Class | Effective sev | Penalty (×conf) | Ceiling | Evidence required (design) | Belongs | Does NOT belong |
|---|---|---|---|---|---|---|
| **critical-exploit** | critical | 45 | 49 (F) | `verifiedImpact==true`: active-probe hit, real secret in body, provider secret detector at `critical`, broken TLS/no-HTTPS, Stage-3 confirmation, public bucket/RTDB listing, dangerous CORS+creds | reflected XSS, SQLi, `.env` w/ secrets, service-role key, confirmed RLS read | a missing header, a public anon key, bare source maps |
| **high-impact-misconfig** | high | 22 | 70 (C) | runtime-confirmed + (exploitable ∣ sensitiveData ∣ authImpact); CORS+creds; auth cookies missing hardening | Stage-2 secret-in-response, auth cookie w/o HttpOnly on /admin | a marketing page missing CSP |
| **medium-weakness** | medium | 10 | 79 (C) | authImpact (non-info); sensitive-route browser surface; warn/critical findings that fall through | weak CSP, auth-enum surface | advanced-header gaps |
| **low-hardening** | low | 3 | 89 (B) | `defenseInDepthOnly`: advanced headers, SRI, DNSSEC/CAA, SPF-softfail, DOM-sink heuristics | missing COOP/COEP/Permissions-Policy, no SRI | a leaked live key |
| **informational** | info | 0 | 100 | `meta` category, `ok`, known-public assets, public client IDs | WAF present, anon key, GA id, shared-platform notice | anything with real impact |

`uiGroupFor` (305) maps these to the report sections: confirmed-vulnerabilities /
likely-risks / needs-review / hardening-recommendations / informational-observations.

---

## 7. Verified Impact Gate

`verifiedImpactPredicate` (scoring-policy.ts:411) is the single source of truth for
"real danger vs hardening gap." It returns `true` only for:

1. Active-probe hits — `paths-xss-reflected`, `paths-sqli`, `paths-open-redirect`,
   `paths-traversal`, `paths-ssrf`.
2. Provider-specific secret detectors at `critical` (`PROVIDER_SPECIFIC_SECRET_IDS`,
   all prefixed `secrets-`) that aren't known-public.
3. Sensitive files (`paths-env`/`paths-git`/`paths-database-sql`/`paths-backup`/
   `paths-aws-credentials`) — require `evidenceContainsRealSecret(evidence)`;
   public buckets/RTDB/phpinfo pass on observation alone.
4. `sourcemaps-exposed-with-secrets`.
5. Plain-HTTP credential forms; `!httpsActive && cat==='tls'`; broken TLS
   (`tls-cert-expired`/`tls-old-version`/`tls-weak-cipher`).
6. Stage-3 confirmations (`stage3-rls-broken`/`-storage-public-write`/
   `-admin-unauth-data`/`-mass-assignment`/`-idor`/`-path-traversal`).
7. Subdomain takeover, CVE-matched deps at critical, dangerous CORS
   (`cors-credentials-wildcard`), directory listing, confirmed public write.

**The design is exactly right** — it demands evidence of *real* impact, not
best-practice gaps. **The implementation is broken** because the gate matches by
id-prefix and the detectors emit different prefixes:

| Gate expects | Scanner emits | Match? |
|---|---|---|
| `secrets-anthropic` / `secrets-stripe-secret` / `secrets-aws` / `secrets-supabase-service-role` | `secret-anthropic-<file>` / `secret-stripe-<file>` / `secret-aws-<file>` / `secret-supabase-service-role-<file>` | **No** (`secret-` vs `secrets-`) |
| `paths-env`, `paths-git`, `paths-aws-credentials` | `path--env`, `path--git-…`, `path---aws-credentials` | **No** (`path-` vs `paths-`) |
| `paths-xss-reflected` | `paths-reflected-xss` | **No** (word order) |
| `cors-credentials-wildcard` | `headers-cors-wildcard` | **No** |
| `stage3-rls-broken`, `stage3-idor`, … | `auth-rls-leak`, `auth-idor-rls`, … | **No** |
| `paths-sqli`, `paths-ssrf` | `paths-sqli-error`, `paths-ssrf-confirmed` | **Yes** (startsWith) |
| `tls-old-version`, `tls-weak-cipher`, `tls-cert-expired` | same | **Yes** |

So today the gate fires only for SQLi, SSRF, open-redirect, and TLS issues. Every
secret leak, every `.env` exposure, every reflected XSS, every dangerous CORS, and
every Stage-3 confirmation **silently fails the gate** and is graded a tier or two
too low.

---

## 8. Examples (current behavior vs intended)

Computed from the actual constants. "Current" = with the ID bug; "Intended" = if
IDs matched.

| Scenario | Findings | **Current score / grade** | **Intended** |
|---|---|---|---|
| **Professional site, only advanced headers missing** (COOP/COEP/CORP/Referrer/Permissions, all info) | 5× low-hardening @ ×0.45 → diminish ≈3.1, ceiling low=89 | **89 / B** ✅ correct | 89 / B |
| **Small-biz site missing CSP+HSTS+XFO** (3× warn) | **BUG:** 3× medium @ ×0.7=7 → diminish 13.7, ceiling **medium=79** | **79 / C** ❌ too harsh | 89 / B (3× low-hardening) |
| **App leaking only a public anon key** | anon key not emitted as finding; tokens whitelisted | **~95+ / A** ✅ correct | A |
| **App leaking a real secret** (Stripe `sk_live_`/OpenAI key) | **BUG:** `secret-stripe-…` critical → fails gate → medium @7, ceiling 79 | **79 / C** ❌ dangerously lenient | **49 / F** (critical-exploit) |
| **Supabase app, RLS properly enabled** | Stage-3 finds nothing | **~95+ / A** ✅ | A |
| **Supabase app, confirmed public data exposure** | Stage-3 `auth-rls-leak` critical | **BUG:** Stage-3 uses `100−20=80` → **80 / B** ❌ | **F** |
| **Dangerous CORS** (`ACAO:*`+creds) | `headers-cors-wildcard` critical → fails gate → medium | **79 / C** ❌ (intended high-impact) | ≤70 / C-low |
| **Many low hardening issues, no exploit** | advanced headers + SRI + DNSSEC + cookies | category caps + decay bound it | **~85–89 / B** mostly ✅ (dragged toward C by the CSP/HSTS warn bug) | 89 / B |

The pattern is unambiguous: **hardening-only sites are pushed down a grade;
genuinely compromised sites are pulled up two grades.** The two error directions
converge — a leaking site and a merely-unhardened site both land around C — which
is the worst possible outcome for a security score's credibility.

---

## 9. Current Weaknesses / Bugs / Contradictions

1. **[Critical] Finding-ID drift defeats the verified-impact gate.** `secret-*`
   vs `secrets-*`, `path--env` vs `paths-env`, `paths-reflected-xss` vs
   `paths-xss-reflected`, `headers-cors-wildcard` vs `cors-credentials-wildcard`.
   Net effect: leaked live keys, service-role keys, `.env`-with-secrets, and
   reflected XSS are all scored as `medium-weakness` (ceiling 79) instead of
   `critical-exploit` (ceiling 49). (scoring-policy.ts:243–255, 426–544 vs
   scanner.ts:2393, 2421, 2624, 2948, 2181.)

2. **[Critical] Stage 3 ignores the scoring engine.** `scan-deep.ts:160` uses
   `100 − crit*20 − warn*7 − info*2`; never calls `applyEngine`. A single
   *confirmed* RLS breach → 80/B. Also the Stage-3 finding ids (`auth-rls-leak`,
   etc.) don't match the engine's `stage3-*` gate, so even fixing #2 needs #1
   fixed too.

3. **[High] Missing CSP/HSTS/X-Frame-Options classified as medium, not low.**
   Their ids aren't in the `defenseInDepthOnly` list (scoring-engine.ts:152–158
   expects `headers-csp-missing`/`headers-no-hsts`/`headers-no-x-frame-options`),
   and they don't carry the advanced-header tokens, so they fall to the
   `severity==='warn' → medium-weakness` catch-all (scoring-engine.ts:285). One
   missing-header trio = C instead of B.

4. **[High] Inverted weighting on open redirect.** `paths-open-redirect`
   (detector `warn`) *does* match the gate's `activeProbeHit` → promoted to
   `critical-exploit` (F-tier), while a real secret leak sits at medium. A
   low-severity finding outranks a key compromise.

5. **[Medium] `cookie-<name>` findings not recognized as defense-in-depth**
   (policy expects `cookies-no-secure`/`cookies-no-samesite`), so cookie hardening
   gaps fall to the medium catch-all.

6. **[Medium] Two live scoring systems + a third formula.** `scoring-engine.ts`
   (vibeScore), `risk-scorer.ts` (deprecated but still emits
   `aggregateRisk`/`aggregateRiskBand` into the response), and `scan-deep.ts`'s
   inline linear formula. `scan-deep.ts` ships a result whose
   `grade`/`severityCounts` come from the engine (via `...stage1`) but whose
   `vibeScore` comes from the linear formula — they can contradict.

7. **[Low] Bookmarklet Stage-2 findings bypass the engine** (no
   `riskClass`/`uiGroup`/`confidence`/`vibeScore`), unlike the Playwright path.

8. **[Low] `paths-firebase-rtdb` vs gate `paths-firebase-rtdb-root`** — the
   scanner id doesn't match the gate's longer string; verify intent.

**What is NOT wrong (to be fair):** No brand whitelist exists. No artificial
score floor exists (the only hard cap is *downward* — no-HTTPS → 49).
Shared-platform DNS suppression is legitimate (the user genuinely can't set DNS on
`*.vercel.app`). The band-ceiling/decay/cap/confidence architecture is sound and
well-reasoned. The false-positive suppression (SPA shell, AST RHS,
public-client-id, console-noise) is mature.

---

## 10. Recommended Fix Direction (conceptual only — no code yet)

1. **Make finding IDs a single shared contract.** Define every finding id once (a
   `FINDING_IDS` registry/const) and import it into *both* the detector emit sites
   and the policy predicates, so the scanner and the scoring policy can never drift
   again. The scoring stays exactly as designed — only the strings get unified.

2. **Stop matching by brittle id-prefix where possible; match on structured
   traits.** The detector already knows the truth at emit time (it's a real secret,
   it's an active-probe hit, the body matched a secret pattern). Carry that as an
   explicit field (e.g. a `verifiedImpact`/`evidenceKind` flag set by the detector)
   and have the engine trust it, instead of re-deriving impact from the id string.
   The id should be for display/dedup, not the security decision.

3. **Route Stage 3 through `applyEngine` with `stage:3`,** and align Stage-3 ids
   (or the trait flag from #2) so confirmed deep-scan exploits become
   `critical-exploit` and hit the 49 ceiling. Delete the inline linear formula in
   `scan-deep.ts`.

4. **Collapse to one scorer.** Retire `risk-scorer.ts` as the source of any
   shipped number; if `aggregateRisk` is still wanted, derive it inside the engine
   so there's one truth.

5. **Add a round-trip invariant test:** for every id the
   scanner/deep-scanner/stage-2 can emit, assert the engine recognizes it and
   classifies it into the intended tier (a fixture of representative findings →
   expected `riskClass`/`vibeScore`). This is the test that would have caught all
   of §9 and prevents regression — far better than self-scanning one site to 100.

6. **Re-validate calibration after the wiring fix** against the §8 table: a real
   key leak must land F; a hardening-only professional site must land B; a
   confirmed RLS breach must land F. Keep the scoring *real and evidence-based* —
   the fix is to make the evidence actually reach the gate, not to add floors or
   whitelists.

---

**Bottom line:** V-Guards' scoring *philosophy* is already evidence-gated,
band-anchored, and calibrated. It just isn't *executing* that philosophy, because
the detector layer and the scoring layer speak slightly different dialects of the
same finding-ID language. Fix the vocabulary (one shared id contract + a
detector-set impact flag, plus routing Stage 3 through the engine) and the
designed calibration comes online — without a single brand whitelist or score
floor.
