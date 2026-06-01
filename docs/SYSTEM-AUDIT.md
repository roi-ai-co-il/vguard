# Vguard — Full Technical Audit

> Snapshot date: 2026-05-08. This doc reflects the **actual current implementation** at HEAD `5ce242e` of `roi-ai-co-il/vguard`. It is exhaustive and unflattering by design.
>
> Companion doc: [`SCANNER-AUDIT.md`](./SCANNER-AUDIT.md) covers the detector inventory + per-detector logic. This doc covers everything else: architecture, scoring engine internals, prompt generation, browser/runtime layer, bookmarklet, API surface, security model, known problems, data models, dependencies, file tree, and production-readiness review.

---

## 1. Full Architecture

### 1.1 Frontend

- **Stack:** React 19.2, Vite 8, Tailwind 4 (`@theme` block in `src/index.css`), framer-motion 12, lucide-react, shadcn-style primitives via Radix.
- **Routing:** there is no router. The frontend is a single SPA where `App.tsx` is the marketing shell + scan entry, and "pages" (`Privacy`, `Terms`, `Accessibility`, `AdminLogs`) are conditionally rendered via a tiny path-string match in `App.tsx`. SPA-style URLs (`/terms`, `/privacy`, `/accessibility`) are rewritten to `/index.html` by `vercel.json`.
- **State:** all in-component `useState` / `useRef`. No Redux, no Zustand, no Jotai. The scan pipeline holds state inside `<ScanForm>` (the orchestrator).
- **Build:** `tsc -b && vite build` -> `dist/`. Code-split chunks for the legal pages (`Privacy`, `Terms`, `Accessibility`) and the admin route. Single main bundle ~496 KB raw / ~146 KB gzipped.
- **Entry HTML:** `index.html` ships with Google Fonts preconnect + a non-render-blocking `<link rel="preload" as="style">` for Inter and JetBrains Mono. The full stylesheets swap in via `onload` to dodge ~70ms FCP/LCP. System fonts render first.
- **Components used in production view (not marketing):**
  - `ScanForm.tsx` — orchestrator. Owns scan state, NDJSON streaming consumer, error-state UX, filter chips, the new collapsed-by-default findings list, and the bulk-fix-prompt copy.
  - `NextStagesPanel.tsx` — Stage 2 / Stage 3 modal entry points. Generates the bookmarklet inline. Polls `/api/stage2-results` for bookmarklet collections. Hosts the ownership-verification UI for Stage 3 (file / DNS-TXT / Vercel-token paths).
  - `ui/vibe-score-gauge.tsx` — 270° SVG gauge. Color and label come from the engine `band`, not the score number.
  - `ui/scanning-loader.tsx` — animated SCANNING text + cyan rotating ring (replaces the old 0–100% circle).
  - `ContactSection.tsx` — Cloudflare Turnstile + `/api/contact` submit.
  - `AccessibilityWidget.tsx` — floating widget that toggles `data-a11y-*` attrs on `<html>` (font scale, contrast, motion, link underlining).

### 1.2 Backend

- **Hosting:** Vercel Functions with `runtime: 'nodejs'` and per-function `maxDuration` (configured in `vercel.json` for the long ones — `api/scan.ts`, `api/scan-stream.ts` at 30s; everything else inherits the 10s default that the function source explicitly sets).
- **Edge middleware:** a single `middleware.ts` running in Vercel's Edge Runtime. Two jobs: hard-404 the well-known path `/admin/logs` (so the real admin URL — held in `ADMIN_LOGS_PATH` env — isn't guessable), and rewrite the env-secret admin path back to `/index.html` so the SPA can render under that route while keeping `noindex` headers.
- **Stage 2 worker:** a separate Railway service running Express + `playwright-chromium`. Exposes `POST /scan` with bearer-token auth; the Vercel proxy at `api/scan-browser-assisted.ts` calls it.
- **Database:** Supabase (project `boyhmhrnsonynbvntjqf` — `roi-ai-internal`'s database, with a `vs_` table prefix to namespace Vguard tables in there).
- **Email:** Resend (`v-guards.com` is a verified sender domain). Used by `verify-email.ts` for ownership-verification confirmation + failure emails, and by `contact.ts` for inbound contact form messages.
- **Bot challenge:** Cloudflare Turnstile on the contact form. Site key in env, server-side validation in `api/contact.ts`.

### 1.3 Scan pipeline

```
USER POSTS URL
   |
   v
api/scan.ts (or api/scan-stream.ts for live progress)
   |-- early validation (URL parse, HTTPS scheme, hostname)
   |-- runScan() in api/_lib/scanner.ts
   |     |-- isPrivateHost()  ----  SSRF guard, runs before any fetch
   |     |-- parallel: fetchMain() + DNS lookups + TLS probe
   |     |     fetchMain():
   |     |        - GET / with SCANNER_UA, follow up to 5 redirects, FETCH_TIMEOUT_MS=4000
   |     |        - if 4xx + WAF signal: detectWafVendor() + stealth retry once
   |     |     DNS:
   |     |        - resolveTxt (SPF, DMARC, DKIM x 25 selectors, CAA)
   |     |        - resolveCname (takeover check)
   |     |        - resolveMx, resolveNs (informational)
   |     |        - DOH to 1.1.1.1 for DNSSEC (AD flag)
   |     |     TLS:
   |     |        - tls.connect(443), getProtocol() + getCipher() + cert
   |     |-- parseHtml() — collects forms, scripts, links, mixed content
   |     |-- parseBundles() — fetch up to MAX_BUNDLES=4 x MAX_BUNDLE_SIZE=2MB
   |     |     - regex SECRET_PATTERNS scan
   |     |     - @babel/parser AST for hardcoded creds, fetch URLs, DOM sinks
   |     |     - npm-CVE matching against package version strings
   |     |     - source-map URL extraction + .map fetch probe
   |     |-- activeProbes()
   |     |     - Open redirect (7 params x example.com canary)
   |     |     - Reflected XSS (6 params x `vsxsscanary7q3` canary)
   |     |     - SQLi error-based (5 params x `'`, 10 error patterns)
   |     |-- pathProbes() — 33 candidate paths from PATHS_TO_PROBE
   |     |-- headerAudit() + cookieAudit() + corsAudit()
   |     |-- buildAttackSurface() — flat machine-readable map
   |     |-- enrichFindings() + applyEngine() -> vibeScore + classified findings
   v
RESPONSE
   { ok:true, vibeScore, aggregateRiskBand, totals, findings[], meta, attackSurface }
   v
audit-log.ts insertion (vs_audit_log row, ip_hash + scan_outcome)
   v
UI renders by uiGroup buckets, gauge color from aggregateRiskBand
```

### 1.4 Scoring pipeline

The engine is in `api/_lib/scoring-engine.ts`. Pure-functional, browser-safe, no I/O. Two entry points:

- `applyEngine(findings, ctx)` — full flow used by scanner.ts.
- `runScoringEngine(findings, ctx)` — internal, returns the structured ScoringResult.

For each finding:

1. `extractTraits()` — derives 13 traits (exploitable, secretPattern, authImpact, publicExposure, sensitiveData, browserSurface, runtimeConfirmed, defenseInDepthOnly, configurationFlaw, highAbuseLikelihood, **verifiedImpact**, knownPublicAsset, authCookie). Pattern-driven, no per-id table.
2. `classifyRiskClass()` — maps traits -> one of {`critical-exploit`, `high-impact-misconfig`, `medium-weakness`, `low-hardening`, `informational`}. Hard gate: `critical-exploit` requires `verifiedImpact = true`.
3. `classifyConfidence()` — `confirmed` / `likely` / `informational`.
4. `computeFindingRisk()` — 0–10 risk score with confidence multiplier and trait amplifiers.
5. `uiGroupFor()` — maps to one of 5 UI buckets: `confirmed-vulnerabilities`, `likely-risks`, `needs-review`, `hardening-recommendations`, `informational-observations`.

For the whole scan: `runScoringEngine()` aggregates per-class `scoreImpact` with diminishing returns (factor 0.6 decay), applies caps, and computes `vibeScore` + `aggregateBand`.

Full formula in §3.

### 1.5 Queue / workers

- **No queue.** Stage 1 is fully synchronous inside a single Vercel function invocation.
- **Stage 2 worker (Railway):** stateless. Browser is a singleton lazily launched on first request and reused (`getBrowser()` memo). No queue — concurrency is whatever Railway's CPU happens to handle. If multiple scans land at once, they share the browser instance.
- **Stage 2 bookmarklet collector:** `api/stage2-collect.ts` (POST) writes to `vs_stage2_collections` with a 1-hour TTL. `api/stage2-results.ts` (GET) polls. No queue, no worker — the bookmarklet IS the producer.
- **Stage 3 deep scan:** triggered synchronously via `api/scan-deep.ts` after ownership verification. Uses `api/_lib/deep-scanner.ts`. Runs to completion in one function invocation (15s budget).

### 1.6 Browser scan flow (server-side Playwright)

Defined in `stage2-worker/index.ts`:

```
POST /scan { url, timeout? }     [auth: Bearer STAGE2_WORKER_TOKEN]
   v
isPrivateHost(host) — duplicated from scanner.ts (same SSRF guard)
   v
getBrowser() — lazy chromium.launch({ headless: true, args:['--no-sandbox'] })
   v
context = await browser.newContext({ userAgent, locale })
   v
page = await context.newPage()
   v
attach listeners:
   - page.on('request')  -> collect URL, method, resourceType
   - page.on('response') -> collect status, contentType, sizeBytes, durationMs,
                            hasAuthHeader, hasOriginHeader
   - page.on('console')  -> collect errors (with filter for HARMLESS_CONSOLE_NOISE)
   - page.on('pageerror')
   v
page.goto(url, { waitUntil: 'networkidle', timeout })
   v
runtime collection (in-page evaluate):
   - cookies: context.cookies() — sees HttpOnly cookies (browser context only)
   - localStorage / sessionStorage keys (no values)
   - JWTs found in any visible value: header + payload decoded server-side, no value sent back
   - sensitive-data scan on captured response bodies (PII regex bank with Luhn + Israeli ID checksum)
   - window globals: __NEXT_DATA__, supabase, firebase, firebaseConfig, __APP_CONFIG, root element
   v
analyzeStage2() in api/scan-browser-assisted.ts:
   - cookie-not-httponly findings (sensitive cookie names visible to JS)
   - localstorage-auth-tokens findings (sb-*-auth-token, firebase:authUser, etc.)
   - external-apis findings (network capture distilled)
   - jwt-* findings (alg=none, missing exp, sensitive claims)
   - sensitive-data findings (PII / secret hits in captured bodies)
   - public-api-2xx findings (first-party calls returning 2xx without Authorization/Cookie)
   v
return JSON to Vercel proxy -> forwarded to UI
```

### 1.7 Runtime analysis flow (Stage 2 bookmarklet)

When the user clicks the bookmarklet on their own origin:

```
javascript: bookmarklet runs in target site's window
   v
collects (NAMES ONLY — no values):
   - document.cookie split keys (only non-HttpOnly visible)
   - Object.keys(localStorage)
   - Object.keys(sessionStorage)
   - typeof checks for window.supabase / firebase / firebaseConfig / __APP_CONFIG / __NEXT_DATA__
   - performance.getEntriesByType('resource') first 80 URLs
   - navigator.userAgent
   v
fetch POST `${collectorOrigin}/api/stage2-collect` { uuid, url, ...data }
   v
api/stage2-collect.ts — writes vs_stage2_collections row, expires_at = now+1h
   v
UI is polling api/stage2-results?uuid=... every 2s
   v
when row arrives: stage2-results runs analyzeStage2() over the collected data
   v
UI appends Stage 2 findings into the same cards list (sorted by uiGroup)
```

Bookmarklet source is in §7. It is a single self-executing arrow function so it fits inside a `javascript:` URL.

### 1.8 Prompt generation flow

For every finding with a non-trivial fix, `api/_lib/fix-prompt-composer.ts` generates a paste-ready Markdown prompt:

```
Finding -> composeFixPrompt(finding, ctx)
   |-- normalizeContext(ctx)     — derives hostname / baseDomain / deployPlatform
   |-- playbookOrFallback(id)    — looks up PLAYBOOKS[id]; falls back to detector's fixPrompt
   |-- header                     — title, evidence, severity, rescan link
   |-- per-finding playbook       — step-by-step instructions (5–8 numbered steps)
   |-- PM_HINT                    — auto-detect package manager (pnpm/yarn/bun/npm)
   |-- regressionTest()           — vitest snippet pinned to THIS exact evidence
   |-- antiPatterns()             — "things NOT to do that look like fixes"
   |-- GUARDRAILS                 — 5 hard rules (minimum blast radius, no eslint-disable, etc.)
   |-- dnsProviderHint(ctx)       — per-DNS-host commands (GoDaddy / Cloudflare / Route53 / IONOS / Vercel)
   |-- deployHint(ctx)            — per-deploy-target redeploy commands
   '-- report-back checklist      — what the agent must output: test path, status, unrelated issues, rollback
```

### 1.9 Storage / database / cache

| Asset | Where | TTL | Purpose |
|---|---|---|---|
| `vs_audit_log` | Supabase | indefinite | every meaningful event: scan, page_visit, terms_viewed, badge_requested. Has `ip_hash`, never raw IP. |
| `vs_scan_log` | Supabase | indefinite | denormalized per-scan summary (hostname, score, top finding, country, WAF state) for the live ticker on the marketing page. |
| `vs_verified_domains` | Supabase | 30d (`expires_at`) | Stage 3 ownership proofs. Lookup by domain. |
| `vs_oauth_states` | Supabase | short (10–15 min) | OAuth flow CSRF state for the dormant Vercel-OAuth-integration code path. |
| `vs_stage2_collections` | Supabase | 1h | bookmarklet-posted runtime data. |
| Vercel Edge cache | CDN | per `Cache-Control` header | static assets get long TTL with hash; HTML and `/api/*` are no-store. |
| Vercel Function memory | per-invocation | n/a | rate-limit buckets in module scope (`api/admin/logs.ts`, `api/contact.ts`) — these are **not durable across cold starts**. Acceptable for these endpoints because abuse needs sustained pressure to exceed the limits anyway. |
| Browser localStorage | client | indefinite | `vguard-verify-email` (so email pre-fills next time), `vguard-stage3-uuid` (so verification proofs survive reload). |

### 1.10 Deployment topology

| Asset | Identifier | Region | Notes |
|---|---|---|---|
| Frontend + Vercel functions | Vercel project `vguard` (`prj_T7NIVw968V5i9QBQ54OkUhtMV1HD`) in team `team_evbzoCbdWuVIB4ZDwEfZ0Oeg` | Vercel default (us-east + iad replicas) | `v-guards.com` apex + `www.v-guards.com` (308 -> apex). Legacy aliases `vguard-tau.vercel.app` and `vibesecure-tau.vercel.app` still resolve. |
| Stage 2 worker | Railway project `vguard-stage2` (`19b15ff4-3a22-4c39-944d-95c8db4c5604`), service `stage2-worker` (`a3022f8a-f1b4-4fa2-8622-f985fef8865b`) | Railway us-west | Public URL `https://stage2-worker-production.up.railway.app`. Healthcheck `/healthz`. Auth: `Authorization: Bearer ${STAGE2_WORKER_TOKEN}`. |
| Database | Supabase project `boyhmhrnsonynbvntjqf` (eu-central-1) | shared with `roi-ai-internal` | Tables namespaced with `vs_` prefix. RLS not used because all writes happen from the Vercel functions with service role. |
| DNS | IONOS nameservers (`ns1069.ui-dns.*` etc.) | n/a | DNS records configured at IONOS; SPF + DKIM + DMARC + CAA + DNSSEC all hardened on `v-guards.com`. |
| Email | Resend, region eu-west-1 | Verified domain `v-guards.com`. |
| Bot protection | Cloudflare Turnstile widget `0x4AAAAAAC_BzqF_UH-VXX5R` | Allowed origins: `v-guards.com`. |

### 1.11 API routes map

All routes live under `api/`. Schema details in §8.

| Path | Method | Purpose |
|---|---|---|
| `/api/scan` | POST | Stage 1 synchronous scan (returns full ScanResult JSON) |
| `/api/scan-stream` | POST (NDJSON response) | Stage 1 with phase events streamed; UI uses this for the live progress |
| `/api/scan-browser-assisted` | POST | Vercel proxy -> Railway worker -> analyzed Stage 2 result |
| `/api/scan-deep` | POST | Stage 3 deep scan (requires verified domain) |
| `/api/stage2-collect` | POST | bookmarklet sink — writes runtime collection row |
| `/api/stage2-results` | GET | poll endpoint — returns Stage 2 findings when ready |
| `/api/verify` | POST | Stage 3 ownership verification (file-challenge / DNS-TXT) |
| `/api/verify-vercel-token` | POST | Stage 3 ownership verification (Vercel personal access token) |
| `/api/oauth/vercel/start` | GET | OAuth Integration flow (dormant — registration not yet on Vercel side) |
| `/api/oauth/vercel/callback` | GET | OAuth Integration callback (dormant) |
| `/api/recent-findings` | GET | live-ticker feed (last 4 redacted findings, used by the marketing globe section) |
| `/api/badge` | GET | SVG badge endpoint (`/api/badge?url=<host>`) — README embed |
| `/api/contact` | POST | contact-form submit (Turnstile-gated, rate-limited 5/min) |
| `/api/track` | POST | client-side telemetry event (page_visit / terms_viewed / privacy_viewed / badge_requested) |
| `/api/admin/logs` | GET | env-secret-gated admin-logs view (only via `ADMIN_LOGS_PATH` rewrite) |

### 1.12 Internal services map

```
Frontend (React SPA, v-guards.com)
   |-- direct: /api/scan, /api/scan-stream, /api/scan-browser-assisted,
   |           /api/scan-deep, /api/stage2-collect, /api/stage2-results,
   |           /api/verify, /api/verify-vercel-token, /api/recent-findings,
   |           /api/badge, /api/contact, /api/track, /api/admin/logs
   v
Vercel Functions (Node 20 runtime)
   |-- api/_lib/scanner.ts        (Stage 1 scan logic)
   |-- api/_lib/scoring-engine.ts (live engine)
   |-- api/_lib/risk-scorer.ts    (legacy CVSS-style — back-compat only)
   |-- api/_lib/attack-surface.ts (flat asset map builder)
   |-- api/_lib/js-ast.ts         (@babel/parser-driven analysis)
   |-- api/_lib/deep-scanner.ts   (Stage 3 only)
   |-- api/_lib/fix-prompt-composer.ts (per-finding playbook generator)
   |-- api/_lib/audit-log.ts      (Supabase writes + IP hashing)
   |-- api/_lib/scan-telemetry.ts (live-ticker writer)
   |-- api/_lib/verify-email.ts   (Resend email senders)
   '-- api/_lib/verification-store.ts (vs_verified_domains lookups)
   v
Supabase (db.boyhmhrnsonynbvntjqf.supabase.co)
   - 5 vs_* tables (see §1.9)
   v
Railway Stage 2 worker (stage2-worker-production.up.railway.app)
   - Express + Playwright Chromium
   v
Resend (api.resend.com)
   - transactional emails
   v
Cloudflare Turnstile (challenges.cloudflare.com)
   - bot protection on /contact
```

### 1.13 Data flow between components

1. **User submits URL** -> SPA POSTs to `/api/scan-stream` (NDJSON) to get live progress, falls back to `/api/scan` if streaming is blocked.
2. **Stage 1 server** runs everything synchronously, calls `applyEngine`, persists 1 row to `vs_audit_log` + 1 row to `vs_scan_log`, returns full JSON.
3. **UI renders** with engine fields (`uiGroup`, `riskClass`, `confidence`, `riskBand`, `aggregateRiskBand`).
4. **Stage 2** auto-fires after Stage 1 lands: SPA POSTs to `/api/scan-browser-assisted`, which forwards to the Railway worker. Findings are merged into the same list client-side.
5. **Stage 3** is gated. SPA opens the verify modal, hits `/api/verify` (or `/api/verify-vercel-token`), on success persists a row to `vs_verified_domains` (30-day TTL). The deep-scan button then calls `/api/scan-deep` which short-circuits the verification check (cache lookup), runs `runDeepScan()`, and appends Stage 3 findings.
6. **Telemetry**: page-visit / terms-viewed events go to `/api/track` -> `vs_audit_log` (no PII; ip is sha256-hashed with a static pepper per session, but pepper rotates daily so the hash is stable for 24h then changes).

---

## 2. Scanning Engine

### 2.1 Stage 1 — passive scan

**Trigger:** `POST /api/scan` or `POST /api/scan-stream` with `{ url }`.

**Inputs:** raw URL string.

**Constants (from `api/_lib/scanner.ts`):**

```ts
const FETCH_TIMEOUT_MS  = 4000   // main HTML fetch
const PROBE_TIMEOUT_MS  = 2500   // each parallel probe (TLS, DNS, path probe, active probe)
const BUNDLE_TIMEOUT_MS = 4000   // each JS bundle fetch
const MAX_BUNDLES       = 4
const MAX_BUNDLE_SIZE   = 2 * 1024 * 1024  // 2 MB
```

**Phases:**

1. `parse + validate URL` — WHATWG `new URL(raw)`. Schemes other than `http://` / `https://` rejected.
2. `isPrivateHost(host)` — RFC1918 + loopback + link-local + mDNS check **before any network access**.
3. Parallel kickoff (`Promise.allSettled`):
   - `fetchWithTimeout(url, { redirect: 'manual' / 'follow' as needed })` — main HTML.
   - `gatherDns(hostname)` — TXT (SPF / DMARC / DKIM 25 selectors / CAA), CNAME, MX, NS, DOH-DNSSEC.
   - `probeTls(hostname)` — `tls.connect(443, { rejectUnauthorized: false })`, read `getProtocol()` + `getCipher()` + `getPeerCertificate()`.
   - `probeHttpHttps(hostname)` — fetches `http://<host>/` to detect 30x -> https redirect.
4. `parseHtml(html)` — collects `<form>`, `<a href>`, `<script src>`, `<link rel>`. Extracts framework signals.
5. `parseBundles()` — fetches up to 4 JS bundles. For each:
   - regex scan against `SECRET_PATTERNS` (12 entries: anthropic / openai-project / openai-legacy / google / github-pat / github-fine-grained / stripe-live / slack-bot / resend / aws / supabase-anon-jwt-decode / supabase-service-role-jwt-decode).
   - AST scan via `js-ast.ts` (`parseJs(code)` -> `analyzeAst(node)` returning DOM-sink list, fetch-template-literal list, hardcoded-creds list).
   - npm-CVE matching: `NPM_CVES` table with semver ranges per package; bundle string-search for `<pkg>@<version>` -> match against ranges.
   - sourceMappingURL extraction -> fetch `.map`, if 200 emit `sourcemaps-exposed`.
6. `headerAudit()` — iterates `HEADER_REQS`, generates findings for missing or weak. CSP gets per-directive analysis (script-src / style-src / connect-src / default-src / frame-ancestors / base-uri / form-action).
7. `cookieAudit()` — parses each `Set-Cookie` from main response. Per-cookie HttpOnly / Secure / SameSite / Domain / Max-Age check.
8. `corsAudit()` — sends OPTIONS preflight; reads main response's CORS headers; flags wildcards + null + regex-shaped values.
9. `pathProbes()` — `PATHS_TO_PROBE` (33 paths). GET each, 2.5s each, 200 = exposure.
10. `activeProbes()` — open redirect / reflected XSS / SQLi as documented in `SCANNER-AUDIT.md` §3.
11. `corpusDetections()` — Supabase project IDs, S3 hosts, Firebase IDs, AI endpoints (regex against the merged HTML+bundle text).
12. `enrichFindings()` — adds derived metadata (e.g. risk-band names).
13. `applyRisk()` — legacy CVSS-style scoring (`risk-scorer.ts`), kept for back-compat `riskScore`/`riskBand` on each finding.
14. `applyEngine()` — the live dynamic engine (see §3).
15. `buildAttackSurface()` — flat machine-readable map.
16. Synthetic `meta-waf-detected` finding pushed AFTER engine runs (with explicit `riskClass: 'informational'`, `uiGroup: 'informational-observations'`).
17. `audit-log` insertion.
18. Response.

**Confidence logic:** the detector emits a fixed severity. The engine reclassifies via `classifyConfidence()`:
- `confirmed` if the finding has `verifiedImpact` OR `runtimeConfirmed` traits.
- `informational` if `knownPublicAsset` OR `defenseInDepthOnly` OR `severity === 'info'`.
- otherwise `likely`.

**Fallback behavior:**
- If main HTML fetch returns 4xx with a recognized WAF signal, the scan does ONE stealth retry with full `Sec-Ch-Ua-*` + `Sec-Fetch-*` headers. If that also fails, a structured `blocked_by_waf` error is returned (with vendor + suggestedAction = `stage2-bookmarklet`).
- If a probe times out, no finding is emitted for that probe. The scan continues.
- If a bundle fails to fetch, it's skipped.

**Retry logic:**
- Stealth retry: at most one per scan, only on the main HTML response 4xx.
- DNS retries: built into Node's resolver.
- No app-level retry on bundle fetch / probe.

### 2.2 Stage 2 — browser-assisted

**Two paths.** Server-side Playwright is the default; bookmarklet is the fallback.

**Server-side path (default):**
- SPA POSTs `{ url }` to `/api/scan-browser-assisted` (Vercel function).
- Vercel function adds `Authorization: Bearer ${STAGE2_WORKER_TOKEN}` and forwards to Railway worker `POST /scan`.
- Railway worker runs the `chromium.launch` flow described in §1.6.
- Returns the runtime data; the Vercel function calls `analyzeStage2()` to convert raw collection into Vguard findings.

**Heuristics inside `analyzeStage2()`:**
- `stage2-cookie-not-httponly` (warn): cookies whose name matches `/sess|auth|token|jwt|sid|csrf/i` and are visible to JS (i.e. context.cookies returns them with `httpOnly: false`).
- `stage2-localstorage-auth-tokens` (warn): localStorage keys matching `sb-*-auth-token`, `firebase:authUser`, `access_token`, `refresh_token`.
- `stage2-firebase-config-global` (info): `window.firebaseConfig` exposed.
- `stage2-external-apis` (info): network entries the page hit, useful for CSP `connect-src` audit comparison.
- `stage2-public-api-2xx` (warn): first-party API calls (same baseDomain) returning 2xx without `Authorization` or `Cookie` headers. The engine demotes these to `informational` via the `knownPublicAsset` trait when no sensitive content was extracted.
- `stage2-jwt-*` findings: JWT analysis for `alg=none`, no `exp`, sensitive claim names. Token values never returned.
- `stage2-sensitive-data-*` findings: pattern bank with PII (email, phone-IL with Israeli ID checksum, credit card with Luhn) + secrets (AWS / GitHub / OpenAI / Anthropic / Stripe regexes — same as Stage 1) on captured response bodies.

**Thresholds:**
- Server-side: hard 30s page-load timeout; `waitUntil: 'networkidle'`; first-party scope only.
- Bookmarklet: best-effort, runs as long as the user keeps the tab open.

**Bookmarklet path (fallback):**
- UI generates a `javascript:` URL containing the bookmarklet (see §7).
- User drags to bookmarks bar, opens their site (logged in if needed), clicks.
- Bookmarklet POSTs collected data to `/api/stage2-collect`.
- UI polls `/api/stage2-results?uuid=…` until ready.

**Confidence boost in engine:** any finding with id starting `stage2-` triggers `runtimeConfirmed = true` in trait extraction. That doesn't auto-promote to critical — the strict gate still applies — but it does upgrade confidence to `confirmed`.

### 2.3 Stage 3 — verified deep scan

**Verification methods (any one suffices):**

1. **File challenge** (`api/verify.ts` with `method: 'file'`): user uploads `https://<domain>/.well-known/Vguard-verify.txt` containing the issued UUID. Vguard GETs that URL, exact-match check.
2. **DNS TXT** (`api/verify.ts` with `method: 'dns'`): user adds `_Vguard-verify.<domain> TXT "<uuid>"`. Vguard `dns.resolveTxt`.
3. **Vercel personal access token** (`api/verify-vercel-token.ts`): user pastes token from `vercel.com/account/tokens`. Vguard calls `GET /v9/projects` with that token, looks for the domain in any project alias, marks verified, **discards the token** (never persisted).

On success, a row is written to `vs_verified_domains` with `expires_at = now + 30 days`. The browser persists the UUID in `localStorage.vguard-stage3-uuid` so the user doesn't re-verify on reload.

**Deep scan execution** (`api/scan-deep.ts` -> `api/_lib/deep-scanner.ts`):

- Verifies `vs_verified_domains` row exists and `expires_at > now`.
- Runs Stage 1 again (so the deep result is self-contained).
- Adds aggressive probes:
  - **Supabase RLS testing** — for each detected `public.<table>` reference in bundles, probes anon-key SELECT with `?select=*&limit=10`. Any 200 + JSON rows = `stage3-rls-broken` (critical).
  - **Storage write-probe** — POST a benign empty file to detected Supabase Storage / Firebase Storage / S3 paths with the anon key. 200 = `stage3-storage-public-write`.
  - **Aggressive XSS / SQLi payload library** — beyond Stage 1's single-quote canary; uses ~20 polyglot payloads but ONLY against forms / endpoints that the user owns (verification gate).
  - **Admin route fuzzing** — extended to ~200 candidate paths (vs Stage 1's 11). 200 with admin-shaped body = `stage3-admin-unauth-data`.
  - **Path traversal** — `?file=../../etc/passwd` canaries.
  - **Mass-assignment** — for detected forms, includes extra fields and watches for accepted writes.
  - **Authenticated IDOR** — only when user provides a JWT in the Stage 3 modal. Vguard substitutes user IDs in detected GET endpoints.

All Stage 3 findings start with `stage3-` prefix, which triggers `runtimeConfirmed = true` AND most map to `verifiedImpact = true` in the engine — they cross into `critical-exploit` legitimately.

**Timeout:** 15s per Stage 3 run (limited by Vercel function maxDuration after Stage 1 ate ~5s).

### 2.4 Endpoint discovery

Three sources, deduplicated by path:

- **`html`** — `<a href>` extraction from main HTML.
- **`bundle`** — string-scan of fetched JS bundles for `'/api/<…>'` and template-literal patterns; AST analysis emits `fetch(...)` template-literal call sites.
- **`detected`** — known patterns: Supabase project URLs, Firebase RTDB hosts, AI provider endpoints.
- **`sitemap`** — if `/sitemap.xml` returned 200 and parsed cleanly.

Stored in `attackSurface.endpoints[]` with `{ path, source }`.

### 2.5 Tech stack detection

`detectFramework()` + `detectFrameworkAndVersion()` in scanner.ts:

| Framework | Signal |
|---|---|
| Next.js | `__NEXT_DATA__`, `next/router`, `next/head` in HTML; `x-powered-by: Next.js` header |
| Nuxt | `__NUXT__`, `@nuxt/`, `useFetch` |
| Vite + React | `@vitejs/plugin-react`, `/@vite/client` |
| Svelte / SvelteKit | `__app/immutable` paths |
| Remix | `@remix-run/react`, `x-powered-by: Remix` |
| Astro | `@astrojs/`, `astro/client` |

React version separately extracted from bundle (`React.version` reference or `react/package.json` substring).

CDN/WAF detection per §2.10 of `SCANNER-AUDIT.md`.

### 2.6 Exploit verification logic (verifiedImpact gate)

This is the central truth-test of the scoring engine. From `scoring-engine.ts`:

A finding becomes `critical-exploit` if any of:

```
verifiedImpact =
  activeProbeHit                                                           // canary reflected unencoded / SQL error matched / open redirect followed
  || (isProviderSpecificSecret && severity === 'critical' && !knownPublicClientId)
                                                                            // anthropic / openai / stripe-secret / aws / google / github-pat
                                                                            //   / github-fine-grained / supabase-service-role / resend / slack
  || (severity === 'critical' && id in {paths-env, paths-git, paths-aws-credentials,
                                       paths-database-sql, paths-backup,
                                       paths-firebase-rtdb-root, paths-s3-list,
                                       paths-supabase-storage-public,
                                       paths-firebase-storage-public, paths-phpinfo})
  || id startsWith 'sourcemaps-exposed'
  || (httpsActive===false && category==='tls' && publicExposure)            // plain HTTP
  || id in {tls-cert-expired, tls-old-version, tls-weak-cipher}
  || id in {stage3-rls-broken, stage3-storage-public-write, stage3-admin-unauth-data,
           stage3-mass-assignment, stage3-idor, stage3-path-traversal}
  || (authImpact && runtimeConfirmed && id in {auth-bypass-confirmed, rls-anon-select})
  || id startsWith 'dns-subdomain-takeover-ready'
  || (category==='mixed-content' && id in {mixed-content-form-credentials, mixed-content-form})
```

Anything else cannot be `critical-exploit`, regardless of detector severity. CSP weak / cookies missing flags / DOM sinks / public 2xx APIs / public client IDs / visible login pages / robots.txt / etc. all stay in lower buckets.

---

## 3. Scoring System

### 3.1 Trait model (full list)

| Trait | True when |
|---|---|
| `exploitable` | Active probe hit (paths-xss-reflected / paths-sqli / paths-open-redirect / paths-traversal / paths-ssrf), OR runtime-confirmed auth-disclosure / rls-anon-select / auth-idor |
| `secretPattern` | Category is `secrets` OR id matches paths-env / paths-git / paths-aws-credentials / paths-database-sql / paths-backup / sourcemaps-exposed / stage2-localstorage-auth-tokens |
| `authImpact` | Category is `auth` / `auth-enum` / `auth-weak` / `auth-disclosure` OR id starts with `auth-` / `rls-` / `idor-` / `jwt-` |
| `publicExposure` | Category is not `meta` AND severity is not `ok` |
| `sensitiveData` | (secretPattern AND !knownPublicClientId) OR (cookies + authCookie) OR firebase-rtdb-root / supabase-storage-public-list / s3-list |
| `browserSurface` | Category is `headers` / `mixed-content` / `integrity` / `html` OR id matches paths-xss / cookies- |
| `runtimeConfirmed` | id starts with `stage2-` / `stage3-` / `deep-` OR ctx.stage > 1 |
| `defenseInDepthOnly` | not exploitable, not sensitiveData, severity != critical, AND id is one of: advanced hardening header (COOP/COEP/CORP/Permissions-Policy/Referrer-Policy/Origin-Agent-Cluster), or headers-no-{x-content-type, hsts, x-frame-options, csp-missing, csp-weak, csp-unsafe-inline, csp-unsafe-eval, csp-wildcard, csp-no-base-uri, csp-no-frame-ancestors, csp-no-form-action}, cookies-no-{secure, samesite}, dom-sink-{innerhtml, outerhtml, insertadjacent, doc-write}, dns-no-{caa, dnssec}, email-{dmarc-monitor, spf-softfail}, integrity-no-sri, meta-* |
| `configurationFlaw` | evidence/desc contains `unsafe-inline` / `unsafe-eval` OR id matches headers-csp-unsafe / headers-csp-weak / cors-wildcard / cors-credentials-wildcard |
| `highAbuseLikelihood` | id matches paths-env / paths-git / paths-aws-credentials / sourcemaps-exposed / paths-xss-reflected / paths-sqli, OR id startsWith one of the high-value secret prefixes |
| `verifiedImpact` | see §2.6 above (the strict gate) |
| `knownPublicAsset` | known-public client identifiers (firebase_api_key, supabase_anon_key, pk_live_, pk_test_, next_public_, vite_, react_app_, expo_public_, analytics, gtag, gtm, mapbox, google_maps_api, sentry_dsn, recaptcha_site_key, turnstile_site_key, hcaptcha_site_key, etc.) OR id matches paths-robots / paths-sitemap / paths-swagger / paths-openapi / paths-api-docs / paths-graphql / paths-status / paths-well-known / paths-admin-login-visible / stage2-public-api-2xx / paths-api-public-2xx |
| `authCookie` | evidence/desc matches `(\b\|_)(sess\|session\|auth\|token\|jwt\|sid\|csrf\|xsrf\|access_token\|refresh_token)\b` |

### 3.2 Risk classification

```
classifyRiskClass(finding, traits, ctx):
  if severity === 'ok' -> 'informational'
  if knownPublicAsset && !verifiedImpact -> 'informational'
  if verifiedImpact -> 'critical-exploit'
  if runtimeConfirmed && (exploitable || sensitiveData || (authImpact && severity!='info'))
                     -> 'high-impact-misconfig'
  if defenseInDepthOnly:
    if routeContext === 'sensitive' && browserSurface -> 'medium-weakness'
    if category === 'cookies' && authCookie          -> 'medium-weakness'
    else                                              -> 'low-hardening'
  if authImpact && severity != 'info'                 -> 'medium-weakness'
  if configurationFlaw && browserSurface              -> 'low-hardening'
  if severity in {critical, warn}                     -> 'medium-weakness'
  else                                                -> 'informational'
```

### 3.3 Confidence

```
classifyConfidence(finding, traits):
  if severity === 'ok'           -> 'informational'
  if verifiedImpact              -> 'confirmed'
  if runtimeConfirmed            -> 'confirmed'
  if knownPublicAsset            -> 'informational'
  if defenseInDepthOnly          -> 'informational'
  if severity === 'info'         -> 'informational'
  else                           -> 'likely'
```

### 3.4 Per-finding 0–10 risk score

```
CLASS_BASE = {
  'critical-exploit':       9.0,
  'high-impact-misconfig':  6.0,
  'medium-weakness':        3.5,
  'low-hardening':          1.2,
  'informational':          0.4,
}
CONFIDENCE_MULT = { confirmed: 1.0, likely: 0.85, informational: 0.6 }

raw = CLASS_BASE[riskClass] * CONFIDENCE_MULT[confidence]
    + (runtimeConfirmed && verifiedImpact ? 0.6 : 0)
    + (highAbuseLikelihood && verifiedImpact ? 0.4 : 0)
    + (authImpact && routeContext === 'sensitive' ? 0.3 : 0)
    + (sensitiveData && routeContext === 'sensitive' ? 0.2 : 0)
    - (defenseInDepthOnly && routeContext === 'public' ? 0.5 : 0)

riskScore = clamp(raw, 0, 10) rounded to 1 decimal

riskBand: severe >= 8, high >= 6, medium >= 3, low < 3
```

### 3.5 Aggregation — diminishing returns + caps

```
CLASS_DAMAGE = {
  'critical-exploit':       30,
  'high-impact-misconfig':  12,
  'medium-weakness':         4,
  'low-hardening':           1.0,
  'informational':           0.15,
}

scoreImpact[finding] = CLASS_DAMAGE[class]
                     * CONFIDENCE_MULT[confidence]
                     * (riskScore/10 + 0.4)

diminishingSum(impacts):
  sort impacts descending
  total = 0; factor = 1.0
  for each impact:
    total += impact * factor
    factor *= 0.6
  return total

By risk class:
  criticalSum     = diminishingSum(critical-exploit impacts)
  highSum         = diminishingSum(high-impact-misconfig impacts)
  mediumSum       = diminishingSum(medium-weakness impacts)
  hardeningSum    = min(diminishingSum(low-hardening impacts), 10)
  informationalSum= min(diminishingSum(informational impacts), 1)

hasVerifiedImpact = exists finding with traits.verifiedImpact === true
allHardeningOnlyCats = every non-ok finding has category in {headers, cookies, html}

mediumLowInfo = mediumSum + hardeningSum + informationalSum
if !hasVerifiedImpact && allHardeningOnlyCats:
   mediumLowInfo = min(mediumLowInfo, 15)

totalPenalty = criticalSum + highSum + mediumLowInfo
vibeScore    = clamp(round(100 - totalPenalty), 0, 100)

aggregateBand:
  inverted = 100 - vibeScore
  if inverted >= 61 -> 'severe'
  elif inverted >= 36 -> 'high'
  elif inverted >= 15 -> 'medium'
  else -> 'low'

if !hasVerifiedImpact && aggregateBand in {severe, high}:
  aggregateBand = 'medium'
```

### 3.6 What does and doesn't lower the score

**Lowers it:**
- Anything in `critical-exploit` (verified impact only).
- Anything in `high-impact-misconfig` (runtime-confirmed real exploit / leak).
- `medium-weakness` findings when categories are diverse (DNS, email, auth, paths, ai, deps, tls, etc.).
- `medium-weakness` cookie/header/CSP findings, but capped at 15 pts combined when no verified impact.
- `low-hardening` findings, capped at 10 pts.
- `informational` findings, capped at 1 pt.

**Does NOT lower it:**
- Findings with `severity: 'ok'`.
- `meta-waf-detected` (synthetic; explicitly tagged informational because having a WAF is a defense, not a problem).
- Detected framework versions when not vulnerable.
- DKIM selectors that were discovered (informational).
- Sitemap / robots.txt / well-known files (informational).

### 3.7 False-positive mitigation

- Provider-prefix gate on secrets — AST heuristic (`js-ast-hardcoded-creds`) cannot trigger `verifiedImpact` even at `severity:critical`. It still surfaces but classifies as `medium-weakness` / `needs-review`.
- `knownPublicAsset` trait sweeps everything that looks like a publishable client identifier.
- `looksLikePublicClientIdentifier(id, evidence, description)` matches 21 token names: `client_id`, `clientid`, `public_key`, `publishable_key`, `pk_live_`, `pk_test_`, `next_public_`, `vite_`, `react_app_`, `expo_public_`, `analytics`, `gtag`, `gtm`, `mapbox`, `google_maps_api`, `sentry_dsn`, `recaptcha_site_key`, `turnstile_site_key`, `hcaptcha_site_key`, `firebase_api_key`, `supabase_anon_key`.
- `evidenceLooksSensitive()` matches a small bank — PEM private keys, `DB_PASSWORD`, `STRIPE_SECRET_KEY`, credit card / SSN / CVV patterns, Authorization Bearer.
- DOM sink suppression via preceding-statement check (React invariant pattern is recognized and skipped in `js-ast.ts`).
- Static-template-literal RHS (assigning constants to inner-HTML props) is suppressed.
- Sanitizer-wrapped fetch template literals (encodeURIComponent, etc.) are not flagged as SSRF surfaces.
- Shared-platform apex suppression — `*.vercel.app`, `*.netlify.app`, `*.pages.dev`, `*.github.io`, `*.lovable.app`, `*.replit.app` etc. don't get punished for missing apex DNS records (DMARC / SPF / DNSSEC / CAA) the platform owns.

### 3.8 Score overrides

There are **no per-finding score overrides** in the live engine. The legacy `risk-scorer.ts` had a `ID_PREFIX_OVERRIDES` table (e.g., `secrets-supabase-service-role: 9.8`); it's still in the codebase but only feeds `riskScore` / `riskBand` for back-compat. The user-visible `vibeScore` and `aggregateBand` come from the new dynamic engine.

### 3.9 Stage interaction

- Stage 2 findings inherit `runtimeConfirmed = true` because their ids start with `stage2-`. They don't re-run the scoring engine; they're appended to the merged list and the UI sorts by `uiGroup`. Their `vibeScore` impact is whatever the engine computed at Stage 1 — **the gauge does not change after Stage 2 in the current implementation**. (Documented gap in §10.)
- Stage 3 returns a fresh full ScanResult with engine fields recomputed including the Stage 3 findings — so the gauge updates honestly when deep scan results land.

---

## 4. Findings System

For the per-detector inventory — **75+ detectors with id, category, severity, evidence, false-positive guards** — see [`SCANNER-AUDIT.md`](./SCANNER-AUDIT.md) §2 through §4. That doc is canonical for finding-level details.

This section covers what the framework guarantees about every finding, regardless of detector.

### 4.1 Finding shape

```ts
interface Finding {
  id: string                                          // e.g. 'paths-env'
  severity: 'critical' | 'warn' | 'info' | 'ok'       // detector-set
  category: 'secrets' | 'auth' | 'auth-enum' | 'auth-weak' | 'auth-disclosure'
          | 'headers' | 'paths' | 'sourcemaps' | 'tls' | 'cookies'
          | 'integrity' | 'mixed-content' | 'html' | 'dns' | 'email'
          | 'methods' | 'ai' | 'deps' | 'meta'
  title: string
  description: string                                  // 2-3 sentences
  evidence: string                                     // raw evidence with redaction applied
  fixPrompt: string                                    // detector-set base; composer may overwrite
  // Engine-set fields (filled after applyEngine):
  riskScore?: number                                   // 0.0–10.0
  riskBand?: 'low' | 'medium' | 'high' | 'severe'
  riskClass?: 'critical-exploit' | 'high-impact-misconfig' | 'medium-weakness'
            | 'low-hardening' | 'informational'
  confidence?: 'confirmed' | 'likely' | 'informational'
  uiGroup?: 'confirmed-vulnerabilities' | 'likely-risks' | 'needs-review'
          | 'hardening-recommendations' | 'informational-observations'
}
```

### 4.2 Trigger / detection conventions

- Detectors live in `api/_lib/scanner.ts` (~3700 LoC). Each detector pushes onto a local `findings: Finding[]` array.
- Detectors set `severity` based on their own confidence; the engine then reclassifies.
- Detectors set `evidence` with redaction already applied (only first 8 + last 4 chars of secrets, for example).
- Detectors set a base `fixPrompt`; the composer may override with a per-id playbook from `fix-prompt-composer.ts` `PLAYBOOKS` table.
- Active vs passive: see `SCANNER-AUDIT.md` §3 for the active-probe list. Everything else is passive.
- Runtime-only: any id starting `stage2-` / `stage3-` / `deep-`.
- Browser-only (Stage 2): cookie HttpOnly check (server can't see HttpOnly cookies without a browser context), JWT extraction from cookies/storage, console-error capture.
- Confirmed vs heuristic: see §3.6 in `SCANNER-AUDIT.md`.

---

## 5. Prompt Generation System

### 5.1 Composer pipeline

`api/_lib/fix-prompt-composer.ts`:

```
composeFixPrompt(finding, ctx)
   |-- ctx = normalizeContext(rawCtx)         -> adds hostname, baseDomain, deployPlatform
   |-- playbook = PLAYBOOKS[finding.id]       -> optional; falls back to detector's base
   |-- render header (title + redacted evidence + severity + rescan link)
   |-- playbook steps (numbered, 5–8 instructions per finding)
   |-- PM_HINT — "if pnpm-lock.yaml exists use pnpm test, else yarn / bun / npm"
   |-- regressionTest(category, evidence, finalUrl) — copy-paste vitest pinned to evidence
   |-- antiPatterns(category) — "things NOT to do that look like fixes"
   |-- GUARDRAILS — 5 hard rules (minimum blast radius, no eslint-disable, etc.)
   |-- dnsProviderHint(ctx) — per-DNS-host commands (GoDaddy / CF / R53 / IONOS / Vercel)
   |-- deployHint(ctx) — per-deploy-target redeploy commands
   '-- report-back checklist — what the agent must report after fixing
```

### 5.2 Active playbooks

`PLAYBOOKS: Record<id, Playbook>` currently has explicit playbooks for:

| Finding ID | Playbook coverage |
|---|---|
| `email-no-spf` | full SPF record creation, per-DNS-host commands |
| `email-no-dkim` | full 5-step DKIM rotation (Resend / SES / Postmark / Mailgun) |
| `email-dmarc-monitor` | upgrade `p=none` -> `p=quarantine` -> `p=reject` |
| `dns-no-caa` | CAA record creation per DNS host |
| `dns-no-dnssec` | DNSSEC enable per registrar |
| `headers-no-x-frame-options` | header hardening per deploy platform |
| `stage2-console-errors` | console-error categorization + framework-specific resolution |

Everything else falls through to the detector's base `fixPrompt` (which is pre-composed in scanner.ts when the detector emits the finding).

### 5.3 Anti-patterns block (representative)

For category `headers`:
- Don't add `'unsafe-inline'` to CSP just to make the scan pass.
- Don't use `<meta http-equiv>` for `frame-ancestors` — it's ignored by browsers.
- Don't lower HSTS max-age below 31536000.
- Don't add the header at the application layer if the platform has a header config (you'll desync).

For category `auth`:
- Don't use `USING (true)` in RLS.
- Don't use `auth.uid() IS NOT NULL` as the sole guard — Supabase signup is open by default.
- Don't use `share_token IS NOT NULL` in an anon-readable RLS policy — it lets any anon caller list ALL share-tokenized rows.
- Don't disable RLS to "just make it work."
- Don't end-run RLS via `SECURITY DEFINER`.

For category `secrets`:
- Don't move the literal to `.env.example` — that's the same string, still in the repo.
- Don't rename `VITE_ANTHROPIC_KEY` -> `ANTHROPIC_KEY` while leaving the client fetch in place — the key is still in the bundle.
- Don't dump via `__NEXT_DATA__` or `getServerSideProps` to the page HTML.
- Don't skip rotation. The leaked key is compromised even if you remove it from the code.

(Full bank lives in `fix-prompt-composer.ts`.)

### 5.4 Confidence-aware prompts

When the engine sets `confidence: 'likely'` (passive evidence), the prompt opens with: "We saw evidence consistent with X. Verify before fixing." When `confidence: 'confirmed'` (verified impact), it opens with the imperative ("Stop serving X. Rotate Y."). The composer reads `finding.confidence` and switches the lead-in template.

### 5.5 Bulk fix prompt

`buildBulkFixPrompt(result)` in `ScanForm.tsx`:
- Buckets findings by `uiGroup` (was severity in v1).
- Renders mission ordering: confirmed-vulnerabilities -> likely-risks -> needs-review -> hardening-recommendations.
- Universal guardrails block (don't disable a security check just to make the scan pass, rotate before editing, etc.).
- Per-finding section with the composer's full per-finding prompt.
- Closing rescan link.

---

## 6. Browser / Chromium System

### 6.1 Setup

- **Library:** `playwright-chromium` 1.49.x (NOT Puppeteer).
- **Host:** Railway, separate service.
- **Image:** custom Docker (`stage2-worker/Dockerfile`) based on `mcr.microsoft.com/playwright:v1.49.x-jammy`.
- **Concurrency:** single browser instance, shared across requests via `let browserPromise: Promise<Browser> | null`.

### 6.2 Lifecycle

```
First request to /scan:
  browserPromise = chromium.launch({ headless: true, args: ['--no-sandbox'] })
  -> singleton lasts the lifetime of the Railway container.

Per-request:
  context = await browser.newContext({
    userAgent: '<Chrome 131 string>',
    locale: 'en-US',
    viewport: { width: 1280, height: 800 },
  })
  page = await context.newPage()
  ... do the scan ...
  await context.close()
```

The browser is never closed between requests — that's by design (cold-launch is ~500ms; we don't want to pay it per scan).

### 6.3 Navigation strategy

```
await page.goto(url, {
  waitUntil: 'networkidle',
  timeout: timeout ?? 25_000,
})
```

`networkidle` is "no network activity for 500ms". Some heavy SPAs never reach this; the timeout catches them and the scan still works on whatever loaded.

### 6.4 Timeout strategy

- Page-load timeout: 25s default, configurable via `{ timeout }` in the request body.
- Browser-level timeout: 30s hard ceiling on the Railway container response.
- Vercel proxy timeout: 30s (matches the function's `maxDuration`).

### 6.5 Retries

None. A failed scan returns the error to the proxy, which surfaces it to the UI as a Stage 2 unavailable state. UI offers the bookmarklet fallback.

### 6.6 Anti-bot / WAF / Cloudflare handling

- Default UA is the same Chrome 131 used by Stage 1.
- No CAPTCHA solving, no Cloudflare bypass — if the target shows a challenge, the page loads the challenge HTML and the network capture only sees the WAF assets. We surface that as a `stage2-blocked-by-challenge` finding.
- The bookmarklet path is the de-facto WAF bypass: it runs from the user's authenticated browser on their own origin, so WAFs see "real user" traffic.

### 6.7 Screenshot logic

There IS no screenshot step. Decided early not to ship visual evidence to keep payload sizes manageable on Vercel's response budget and to dodge the privacy debate. Page is purely instrumented for data, not pixels.

### 6.8 Request interception

Every request is observed via `page.on('request')`. NO requests are blocked. This means:
- Image / font / video bandwidth is paid by the worker. ~5-15 MB per scan typical.
- Third-party trackers are loaded — they show up in the network capture, which is intentional (we want to see them in the report).

If we ever need to control bandwidth, a `route('**/*', handler)` that aborts video/audio resourceTypes is a 5-line change.

### 6.9 Runtime instrumentation

Listeners attached:

```
page.on('request', req -> collect: url, method, resourceType)
page.on('response', async res -> collect:
   url, status, contentType, sizeBytes (from .body() with try/catch),
   durationMs, hasAuthHeader (req.headers Authorization OR Cookie present),
   hasOriginHeader (req.headers Origin present))
page.on('console', msg -> if msg.type === 'error': collect text)
page.on('pageerror', err -> collect err.message)
```

After `page.goto()`:

```
const cookies = await context.cookies()  // sees HttpOnly
const inPage = await page.evaluate(() -> ({
  localStorageKeys: Object.keys(localStorage),
  sessionStorageKeys: Object.keys(sessionStorage),
  globals: {
    hasSupabase: typeof window.supabase !== 'undefined',
    hasFirebase: typeof window.firebase !== 'undefined',
    hasFirebaseConfig: typeof window.firebaseConfig !== 'undefined',
    hasAppConfig: typeof window.__APP_CONFIG !== 'undefined' ||
                  typeof window.__NEXT_DATA__ !== 'undefined',
    hasReactRoot: !!document.getElementById('root'),
  },
  userAgent: navigator.userAgent,
}))
```

JWT extraction: server-side regex against cookie values + storage values. base64url decode, parse JSON, emit `{ alg, typ, hasExp, expSecondsFromNow, hasIss, hasAud, claimNames }`. **Token value never returned.**

Sensitive-data scan: 12 patterns (email, phone-IL with checksum, phone-intl, Israeli ID with checksum, credit card with Luhn, JWT in body, AWS / GitHub / OpenAI / Anthropic / Stripe keys, internal URLs, stack-trace absolute paths). PII patterns are skipped on `application/javascript` responses (high FP rate). Hits are reported as `{ type, redactedSample, sourceUrl }`.

### 6.10 CSP bypass

**None.** Playwright runs the page exactly like a real browser; CSP enforcement happens. We don't disable CSP. If the target CSP blocks our analysis, that fact is itself a finding (the scan saw a `connect-src` that the CSP wouldn't have allowed -> indicates a real bypass / misconfiguration).

### 6.11 fetch / XHR / WebSocket interception

- fetch / XHR: captured via `response` event (no request modification).
- WebSocket: captured via `request` event filtered to `resourceType === 'websocket'`. We see the URL but NOT the payload. WebSocket message inspection is **not implemented** — listed in §10.

---

## 7. Bookmarklet System

### 7.1 What the bookmarklet collects

**Names only — never values.**

- `document.cookie.split(';')` keys (only non-HttpOnly visible to JS — that absence is the signal).
- `Object.keys(localStorage)` — keys only.
- `Object.keys(sessionStorage)` — keys only.
- `window.supabase` / `window.firebase` / `window.firebaseConfig` / `window.__APP_CONFIG` / `window.__NEXT_DATA__` — `typeof` checks (boolean), no value extraction.
- `document.getElementById('root')` presence (heuristic for "is this an SPA").
- `performance.getEntriesByType('resource').slice(0, 80)` — recent fetch URLs, no headers, no bodies.
- `navigator.userAgent`.

### 7.2 What is intentionally excluded

- Cookie values.
- localStorage / sessionStorage values.
- Authorization headers / JWTs.
- Page DOM contents.
- Network response bodies.
- Form values.
- IndexedDB.
- WebSQL.
- Service worker state.
- Permissions (geolocation, notifications, etc.).

### 7.3 UUID / session handling

- UUID generated client-side (`crypto.randomUUID()` with fallback) and prefixed `vs2-`.
- Embedded in the bookmarklet source as a string literal.
- Collector writes a row keyed by UUID with `expires_at = now + 1h`.
- Polling endpoint `/api/stage2-results?uuid=…` returns 404 until the bookmarklet fires, then returns the analyzed findings.

### 7.4 POST flow

- `Content-Type: application/json`.
- `Origin` is whatever the target site is — collector accepts cross-origin POSTs.
- No `Authorization` header — UUID is sufficient because (a) UUIDs are unguessable, (b) bookmarklet only collects names, no values, (c) collector validates row-shape and rate-limits per IP.

### 7.5 Auth / session handling

The bookmarklet runs INSIDE the user's authenticated session on the target site. It sees what JS would see: non-HttpOnly cookies, session storage, app globals. It does NOT need any auth itself; it inherits the user's session implicitly via the browser context.

### 7.6 Privacy protections

- Names-only collection model.
- 1-hour TTL on stored data.
- No PII in the collection (no values means no email addresses / IDs / etc.).
- IP is hashed on the collector side; raw IP never persisted.
- No tracking pixel, no fingerprinting beyond UA.

### 7.7 CSP interactions

- The bookmarklet's `fetch()` is subject to the target site's CSP `connect-src`.
- If `connect-src` doesn't include `v-guards.com`, the fetch will fail.
- The bookmarklet `try/catch`-es the fetch and `alert()`s the user with the error.
- This is itself a useful signal — if the target site's CSP blocked the bookmarklet, the user knows their CSP is reasonably tight.

### 7.8 Limitations

- HttpOnly cookies invisible (use server-side Playwright path for that).
- Subresource Integrity violations not seen (the bookmarklet runs after page load).
- Service workers / push notifications / cache state not inspected.
- Iframes not traversed.
- DOM events / inner-HTML usage not captured.
- Errors thrown DURING page load (before the user clicks) not captured.

### 7.9 Browser compatibility

Tested on: Chrome 120+, Firefox 120+, Safari 17+, Edge 120+. No IE. Mobile bookmarklets work but most mobile browsers don't expose a bookmarks-bar UX, so they're awkward.

### 7.10 FULL bookmarklet source (current production)

Generated by `buildBookmarkletSource(uuid, collectorOrigin)` in `src/components/NextStagesPanel.tsx:272`:

```javascript
(()=>{
  try{
    var u='${uuid}';
    var ck=document.cookie.split(';').map(function(c){return c.split('=')[0].trim()}).filter(Boolean);
    var lk=Object.keys(localStorage||{});
    var sk=Object.keys(sessionStorage||{});
    var w=window;
    var g={
      hasSupabase: typeof w.supabase!=='undefined',
      hasFirebase: typeof w.firebase!=='undefined',
      hasFirebaseConfig: typeof w.firebaseConfig!=='undefined',
      hasAppConfig: typeof w.__APP_CONFIG!=='undefined' || typeof w.__NEXT_DATA__!=='undefined',
      hasReactRoot: !!document.getElementById('root')
    };
    var p=performance.getEntriesByType('resource').map(function(e){return e.name}).slice(0,80);
    var data={
      uuid:u,
      url:location.href,
      cookieKeys:ck,
      localStorageKeys:lk,
      sessionStorageKeys:sk,
      globals:g,
      performanceUrls:p,
      userAgent:navigator.userAgent
    };
    fetch('${collectorOrigin}/api/stage2-collect',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(data)
    })
    .then(function(r){return r.json()})
    .then(function(j){alert('Vguard Stage 2: data sent. Return to the scanner tab.')})
    .catch(function(e){alert('Vguard error: '+e.message)});
  }catch(e){alert('Vguard error: '+e.message)}
})()
```

The `javascript:` URL form is `encodeURIComponent`'d and prefixed with `javascript:`. Length stays under ~1.2 KB which most browsers accept.

---

## 8. API & Backend

### 8.1 Routes — request / response schemas

| Route | Method | Body / Query | Response | Auth |
|---|---|---|---|---|
| `/api/scan` | POST | `{ url: string }` | `ScanResponse` (ScanResult or ScanFailure) | none |
| `/api/scan-stream` | POST | `{ url }` | NDJSON stream of `{ phase, … }` events; final event is `{ phase: 'done', result: ScanResult }` | none |
| `/api/scan-browser-assisted` | POST | `{ url }` | `{ ok, findings, cookieCount, networkRequestCount, durationMs }` | none |
| `/api/scan-deep` | POST | `{ domain, uuid }` | `ScanResult` (with stage 3 findings appended) | requires `vs_verified_domains` row for `domain` with `expires_at > now` |
| `/api/stage2-collect` | POST | `{ uuid, url, cookieKeys, localStorageKeys, sessionStorageKeys, globals, performanceUrls, userAgent }` | `{ ok: true }` | none (UUID is the access token) |
| `/api/stage2-results` | GET | `?uuid=…` | `{ ok, ready, findings? }` | none |
| `/api/verify` | POST | `{ method: 'file' \| 'dns', domain, uuid }` | `{ ok: true, expires_at }` or `{ ok: false, error: { code, message } }` | none — proof IS the auth |
| `/api/verify-vercel-token` | POST | `{ token, domain, uuid }` | `{ ok: true, expires_at }` or `{ ok: false, error }` | token is the auth, then discarded |
| `/api/oauth/vercel/start` | GET | `?domain=…&uuid=…` | 302 to vercel.com OAuth dialog | dormant |
| `/api/oauth/vercel/callback` | GET | `?code=…&state=…` | success/failure HTML page | dormant |
| `/api/recent-findings` | GET | none | `{ findings: [{ hostname, severity, title, secondsAgo }, …] }` | none |
| `/api/badge` | GET | `?url=<host>` | SVG document | none |
| `/api/contact` | POST | `{ name, email, message, turnstileToken }` | `{ ok: true }` or `{ ok: false, error }` | Turnstile token validated server-side |
| `/api/track` | POST | `{ event_type, path?, session_id? }` | `{ ok }` | none, rate-limited |
| `/api/admin/logs` | GET | `?since=…&limit=…` | `{ ok, rows }` | only reachable via `ADMIN_LOGS_PATH` rewrite + bearer token |

### 8.2 Validation

- URL validation: `new URL(raw)`, must be `http:` / `https:`, hostname must parse.
- Body schemas: hand-rolled type checks (no zod). Each handler validates its own shape.
- Email validation: regex.
- UUID validation: shape match against `^vs[1-9]-[0-9a-f]{8}-[0-9a-f]{4}-…$`.
- Domain validation: `tldts` library for public-suffix-aware base domain extraction.

### 8.3 Rate limiting

| Route | Limit | Window |
|---|---|---|
| `/api/contact` | 5 | per 60s per IP |
| `/api/admin/logs` | 30 | per 60s per IP |
| `/api/track` | 60 | per 60s per IP |
| `/api/stage2-collect` | (per-UUID, not IP) — single submission per UUID then row exists | n/a |
| Other routes | none | n/a |

Rate-limit state lives in module-scope `Map`s. **Lost on cold start.** Acceptable for these endpoints because abuse needs sustained pressure to exceed the limits, and Vercel cold-starts typically happen ~hourly.

### 8.4 Internal middleware

`middleware.ts` (Edge):
- Hard-404 `/admin/logs` (the well-known guess path).
- Rewrite `${ADMIN_LOGS_PATH}` -> `/index.html` (so the SPA renders), set `X-Robots-Tag: noindex`.
- Pass-through everything else.

### 8.5 Admin routes

- `/${ADMIN_LOGS_PATH}` (env-secret URL) -> SPA `<AdminLogs>` page.
- `<AdminLogs>` calls `/api/admin/logs` with bearer in request header, not query.
- `/api/admin/logs` validates bearer with `crypto.timingSafeEqual` against `ADMIN_LOGS_BEARER` env.
- Returns recent rows from `vs_audit_log` + `vs_scan_log`.

### 8.6 Logging

- `vs_audit_log` row per scan, page visit, terms view, etc.
- `vs_scan_log` denormalized scan summary (hostname, score, top finding, country, WAF state).
- IP hashing: `sha256(ip + DAILY_SALT)` where `DAILY_SALT` rotates at 00:00 UTC. So a given IP is consistent within a 24h window but unlinkable across days.

### 8.7 Analytics

- Internal: `/api/track` events feeding `vs_audit_log`.
- External: NONE. No Google Analytics, no Plausible, no Mixpanel. By design — Vguard's own audits flag third-party trackers, so we don't ship any.

### 8.8 Storage

See §1.9 for the table-by-table breakdown.

---

## 9. Security Model

### 9.1 SSRF protection

- `isPrivateHost(host)` runs **before any network access** in both Stage 1 and Stage 2 worker.
- Blocks: `localhost`, `0.0.0.0`, `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `*.local`.
- DOES NOT currently block:
  - IPv6 link-local / ULA / loopback (`::1`, `fe80::/10`, `fc00::/7`).
  - Hostnames that resolve to private IPs *via DNS* (a public hostname pointing at `127.0.0.1` would slip through). **This is a real gap — see §10.**

### 9.2 Sandboxing

- Stage 1 runs inside a Vercel Function. AWS Lambda sandboxing is the boundary. We don't compile or dynamically evaluate user input, don't shell out, don't compile templates.
- Stage 2 worker runs Chromium with `--no-sandbox` (because Railway's container model doesn't support kernel-level sandboxing). The browser process itself is the trust boundary.

### 9.3 Browser isolation

- Each Stage 2 scan gets a fresh `BrowserContext`. Cookies / storage are isolated per-context.
- The browser itself is shared across all concurrent scans on the same Railway worker.

### 9.4 Rate limiting

See §8.3. App-level only, no Vercel WAF tier.

### 9.5 Abuse prevention

- No queueing -> cost of one scan is bounded by Vercel function billing + Railway compute. ~$0.001 per scan.
- No retries -> no amplification.
- SSRF guard prevents the scanner from being weaponized as an internal probe.

### 9.6 Scan restrictions

- Scans are allowed against any public hostname.
- No allow/deny list.
- A target who doesn't want to be scanned can detect the UA suffix and block (the default UA includes Chrome/131, but the request comes from Vercel Lambda IPs — easily blockable).

### 9.7 Domain validation

For Stage 3 ownership verification:
- File challenge -> exact UUID match.
- DNS TXT -> exact UUID match in `_Vguard-verify.<domain>`.
- Vercel token -> token must list a project that aliases `<domain>`.

`vs_verified_domains.expires_at = now + 30d` is hard.

### 9.8 Anti-RCE protections

- No dynamic-evaluation of user input. The `Function` constructor is not used. The `vm` module is not used. No template compilation that executes anything.
- No subprocess spawning.
- No template compilation (we use string interpolation only for the audit log SQL via `@supabase/supabase-js`, which uses parameterized queries).

### 9.9 Anti-pivot protections

- Stage 2 worker is on a separate VPC (Railway) — even if the scanner gets popped, it doesn't have access to the main DB.
- Supabase service-role key is only on the Vercel side. Railway worker has no DB access.
- No SSH between containers.

### 9.10 Admin protection

- Admin URL is held in `ADMIN_LOGS_PATH` env var. Not guessable.
- Bearer token for the API is `ADMIN_LOGS_BEARER` env. Validated with `timingSafeEqual`.
- Hard-404 on `/admin/logs` (the guessable path) so attackers can't enumerate.
- `noindex, nofollow, noarchive` on the admin shell.
- 30 requests/min/IP rate limit on the API.

### 9.11 Secrets management

- `.env.global` at `~/.claude/.env.global` (developer-side, sourced before deploy).
- Vercel env vars for runtime secrets (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `STAGE2_WORKER_TOKEN`, `RESEND_API_KEY`, `TURNSTILE_SECRET`, `ADMIN_LOGS_PATH`, `ADMIN_LOGS_BEARER`, `DAILY_SALT`).
- Secrets never hit the bundle (Vite-prefixed `VITE_*` vars are explicitly avoided for anything sensitive).
- Secrets are masked in logs via `redact()` (first 8 + last 4 chars only).

### 9.12 Environment isolation

- Production: Vercel project `vguard` deployed from `roi-ai-co-il/vguard:main`.
- Preview: every push creates a Vercel preview URL; preview shares the Supabase tables with prod (acceptable risk for now — see §10).
- No staging environment.

### 9.13 Logging / redaction

- `redact()` helper: first 8 + last 4 chars, middle replaced with `…`.
- IP addresses sha256-hashed before persistence.
- `evidence` field in findings: the only place where partial secret material can appear, always redacted.
- Audit-log `metadata` field: hand-curated keys only; nothing user-supplied is persisted raw.

### 9.14 CSP (Vguard's own)

From `vercel.json`:

```
default-src 'self';
script-src 'self' https://challenges.cloudflare.com;
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
img-src 'self' data: blob: https:;
font-src 'self' data: https://fonts.gstatic.com;
connect-src 'self' https://challenges.cloudflare.com;
frame-src https://challenges.cloudflare.com;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
object-src 'none';
upgrade-insecure-requests
```

`unsafe-inline` is in `style-src` only (Tailwind 4 + framer-motion need it for the styles they emit). `script-src` does NOT have `unsafe-inline` — Vite production build emits no inline scripts, so it's clean.

### 9.15 CSRF

- All write endpoints require POST. Single-page-app same-origin posts go through fetch with `credentials: 'omit'`.
- `/api/contact` requires Turnstile token (server-side validates it against Cloudflare).
- Verification endpoints don't have user accounts, so CSRF is moot.

### 9.16 Session security

There is no user session. Vguard has no signup, no login, no session cookies. The only "session" concept is:
- `localStorage.vguard-stage3-uuid` — UUID generated client-side, used to tie ownership-verifications to a browser. Not a security boundary; just convenience.
- Bookmarklet UUID — opaque, expires in 1 hour.

---

## 10. Known Problems

### 10.1 Weaknesses

- **No user accounts** — anyone can scan anything, no rate limit per identity. A single attacker behind a VPN with rotating IPs could hammer the API. Cost cap is Vercel's billing (and we'd notice if it spiked).
- **IPv6 SSRF gap** — `isPrivateHost` doesn't cover IPv6 private ranges. A target with an IPv6-only AAAA record pointing at `::1` would slip through.
- **DNS rebinding** — the SSRF guard checks the hostname pre-fetch, but Node's `fetch` resolves at fetch time. A target that resolves to a public IP first, then to `127.0.0.1` during the fetch, would bypass.
- **Stealth retry trips on a single 4xx** — a target that returns 403 once for any reason (rate-limit, geo-block, captcha) gets the stealth retry. We don't differentiate "WAF" from "any 4xx".
- **No deduplication on Stage 2 collect** — submitting the bookmarklet twice with the same UUID overwrites the first row. Real users hit this rarely; an attacker wanting to spam-overwrite a victim's UUID could.
- **Vercel token persistence path** — when a user pastes a Vercel token for verification, the token is held in memory during the request. If the function crashes between read and discard, it could end up in Vercel runtime logs. We try/finally to clear it but can't prove no leak.

### 10.2 Technical debt

- **Two scoring engines coexist** (`risk-scorer.ts` legacy, `scoring-engine.ts` live). The legacy one is only kept for back-compat `riskScore`/`riskBand` fields. Should be removed.
- **`scanner.ts` is ~3700 LoC** in a single file. Painful to navigate.
- **No integration tests**. Only unit tests for the scoring engine + audit-log + middleware. Stage 1 / Stage 2 / Stage 3 end-to-end paths have no automated coverage.
- **Stage 2 doesn't recompute `vibeScore`** when its findings merge — gauge stays at Stage 1 value. Stage 2 findings list correctly under `uiGroup`, but the score doesn't reflect them. Acceptable for now since Stage 2 findings are rarely in `critical-exploit` class, but it's a correctness gap.
- **`vs_audit_log` and `vs_scan_log` overlap**. Should be one table with a discriminator column.
- **`vs_oauth_states` table exists but the OAuth flow is dormant** — Vercel's OAuth Integration registration is UI-only and we haven't done it. Code is dead.
- **Bookmarklet UUID format** isn't a real UUID (it's `vs2-` + a hand-rolled random string). Fine functionally but inconsistent with `crypto.randomUUID()` everywhere else.
- **No env-config validation at boot.** A missing `STAGE2_WORKER_TOKEN` causes Stage 2 to silently 401 with no clear error. Should fail loud at function init.

### 10.3 False positives

- AST `js-ast-hardcoded-creds` flags any `{ key: "long-string" }` pattern. Apple's app-store IDs (`app_store-apl`, `books-0-apl`) trip it. Engine demotes to needs-review now, but the **finding card itself still says "5 hardcoded credentials"** which is misleading — should be "5 credential-shaped patterns (review)".
- DOM-sink detection in framework code (React's invariant pattern) is suppressed but only for the specific shape. Other framework internals (Vue 3 patch operations) might trip it.
- Open-redirect detection echoes `example.com` and looks for unencoded reflection. A site that URL-encodes the response body but still redirects 30x would be missed (false negative actually).

### 10.4 False negatives

- Stored XSS — not detected.
- DOM XSS — not detected (would need taint-tracking through the AST).
- Blind SQLi — not detected.
- Time-based / boolean-based SQLi — not detected.
- CSRF token correctness — only absence is detected; an invalid token (e.g. always the same string) is missed.
- Authorization issues that require valid creds (most IDOR) — Stage 3 only, and only with user-supplied JWT.
- WebSocket message-level issues — connection is seen, frames are not.
- Race conditions, business-logic bugs — out of scope.

### 10.5 Scalability issues

- Stage 2 worker is a single Railway container with one shared browser. ~2-5 concurrent scans before queueing happens. At 10+ concurrent the worker memory is exhausted.
- Vercel Functions are auto-scaled but `MAX_BUNDLES * MAX_BUNDLE_SIZE` = 8 MB of JS per scan held in memory. At sustained traffic, memory churn is ugly.
- No CDN cache on `/api/recent-findings` — every page load on the marketing site hits the function. Should cache at the edge for ~30s.
- `vs_audit_log` is unbounded; row count grows linearly with traffic. No archival policy.

### 10.6 Reliability issues

- Stage 2 worker has no health checks beyond `/healthz`. If Chromium hangs (it can, on weird CSP / cross-origin redirect chains), the worker's only recovery is Railway's autorestart on memory ceiling.
- Vercel's `maxDuration: 30` is a hard ceiling. A heavy scan that hits 31s gets killed mid-flight, leaving a partial audit log row but no scan log row.
- No idempotency keys on writes — a double-clicked Stage 3 verify could create two `vs_verified_domains` rows for the same domain.
- `/api/scan-stream` NDJSON consumers in browsers occasionally swallow events on slow networks. UI falls back to polling, but the UX is jittery.

### 10.7 Architectural concerns

- **Single-tenant DB.** All scans go into one Supabase project. A noisy customer would be visible to other customers' admin views (we don't ship per-customer admin yet, but this is a forward-compat issue).
- **No region pinning** for the Vercel functions. Some scans against EU-based targets traverse trans-Atlantic, adding 100-200ms latency.
- **OAuth integration is dormant.** The proper Stage 3 verification path (one-click via Vercel OAuth) requires Royi to register a Vercel Integration. Until then, users have to paste a personal token, which is a friction wall.
- **`vguard-tau.vercel.app` and `vibesecure-tau.vercel.app` legacy aliases** still resolve. They duplicate prod surface for no reason. Sunset planned.

### 10.8 Edge cases

- IDN domains (Punycode) — handled by `URL` constructor but `tldts` doesn't always resolve them correctly.
- Multi-A-record targets (round-robin DNS) — first record wins, not necessarily the canonical one.
- HTTP/2 server push assets — captured in network stream but not always with the right `resourceType`.
- Trailing-slash redirects (`/foo` -> `/foo/`) consume one of the 5 redirect slots.

### 10.9 Unstable scans

- Sites behind aggressive WAFs (Akamai Bot Manager) often need 2-3 retries before stealth bypass works. Currently we only retry once.
- Sites with very slow JS bundles (>5s to download a single bundle) hit `BUNDLE_TIMEOUT_MS` and we miss the secret/ast scan on that bundle.
- Sites with `noscript`-only fallbacks (rare) get scored as if they have no JS — which is technically correct but misleading.

### 10.10 Performance bottlenecks

- AST parse is the slowest single step (per bundle, ~80-200ms for a 1MB minified file).
- DOH DNSSEC query is sometimes >2s. Pushes the parallel `Promise.allSettled` deadline.
- Cookie parsing is hand-rolled regex. ~5ms for 50 cookies but unbounded scaling.
- Stage 2 worker boot (cold-start Railway container with Chromium image) is ~25s. After that, browser is hot.

---

## 11. Current UI/UX Logic

### 11.1 Result rendering

- `<ScanForm>` orchestrates everything. After a successful scan, it transitions to `state === 'result'` and renders the report card.
- Score gauge: `<VibeScoreGauge score={result.vibeScore} band={result.aggregateRiskBand} />`. Color + label come from band, not score.
- Header counters: `finalTotals` computed via `recomputeFinalTotals(mergedFindings)` which counts by `uiGroupOf(finding)`.
- Findings list: collapsed by default behind a "Show all N findings" toggle. When open, sorted by `UI_GROUP_ORDER` (engine-final).

### 11.2 Grouping

5 buckets (engine-set `uiGroup`):
1. **Confirmed vulnerabilities** — verified exploit / leak / bypass.
2. **Likely risks** — strong evidence, runtime not yet confirmed.
3. **Needs review** — auth-cookie / sensitive-route concerns.
4. **Hardening recommendations** — defense-in-depth, missing modern headers.
5. **Informational observations** — public assets, frameworks detected, clean checks.

### 11.3 Filtering

- Filter chips render the present groups + present categories.
- Click a chip -> narrows the cards list.
- Active filter visualized via accent-colored chip. "All" chip reset.

### 11.4 Severity coloring (CSS variables)

- `--color-danger` (#ff6b6b) — confirmed-vulnerabilities.
- `--color-warning` (#ffb84d) — likely-risks, needs-review.
- `--color-fg-muted` (#c0c0c8) — hardening-recommendations.
- `--color-fg-dim` (#8a8a96) — informational-observations.
- `--color-ok` (#4ade80) — clean / ok severity.

The detector severity colors are no longer used in the UI path.

### 11.5 Runtime badges

Findings with `runtimeConfirmed = true` (Stage 2 / Stage 3) show their badge with the same color as their `uiGroup` — no special "runtime" badge, the `uiGroup` already conveys it ("confirmed" only happens with verified impact, which usually means runtime).

### 11.6 Score display logic

- Score number: `result.vibeScore` (0-100, integer).
- Band label: `result.aggregateRiskBand` ("Healthy" / "Needs review" / "High risk" / "Critical").
- Gauge fill: from 0 to score over 1.4s with `cubic-bezier(0.16, 1, 0.3, 1)` easing.
- Indicator dot: at the gauge's current arc position.

### 11.7 Scan progress logic

- `/api/scan-stream` emits NDJSON `{ phase: <name> }` events.
- Each event bumps `stepIdx` in `<ScanForm>`.
- `<ScanStepList>` renders a 5-step list with check icons / spinners.
- Final event `{ phase: 'done', result }` transitions UI to `'result'`.
- Fallback: if streaming is blocked, falls back to `/api/scan` and shows the `<ScanningLoader>` (animated SCANNING text + cyan ring) until the response lands.

### 11.8 Failure handling

Three error states distinguished by `ScanError.code`:

- `invalid_url` — input was malformed; user gets the form back with an inline error.
- `unreachable` — DNS / network failure; "Couldn't reach <host>" card with retry.
- `blocked_by_waf` — structured card with vendor chip ("🛡 Akamai", HTTP 403), copy explaining "this isn't a Vguard failure", CTAs `Run Stage 2 (browser-assisted)` / `Retry Stage 1` / `Try another URL`.
- `blocked_by_target` — generic 4xx that wasn't a WAF.
- `timeout`, `too_large`, `rate_limited`, `internal` — generic cards.

### 11.9 Partial scan handling

If Stage 1 succeeds but Stage 2 fails, the report renders with Stage 1 findings + a Stage-2-failed banner. User can retry Stage 2 manually via the bookmarklet.

### 11.10 Retry behavior

- "Rescan" button: full new scan against the same URL.
- "Try another URL" button: resets state, scrolls back to the form (via useEffect watching state->idle), focuses the URL input.

---

## 12. Data Models

### 12.1 TypeScript interfaces (`src/lib/scanner-types.ts`, full)

```ts
export type Severity = 'critical' | 'warn' | 'info' | 'ok'

export type Category =
  | 'secrets' | 'auth' | 'auth-enum' | 'auth-weak' | 'auth-disclosure'
  | 'headers' | 'paths' | 'sourcemaps' | 'tls' | 'cookies'
  | 'integrity' | 'mixed-content' | 'html' | 'dns' | 'email'
  | 'methods' | 'ai' | 'deps' | 'meta'

export interface Finding {
  id: string
  severity: Severity
  category: Category
  title: string
  description: string
  evidence: string
  fixPrompt: string
  riskScore?: number                // 0.0–10.0
  riskBand?: 'low' | 'medium' | 'high' | 'severe'
  riskClass?: 'critical-exploit' | 'high-impact-misconfig' | 'medium-weakness'
            | 'low-hardening' | 'informational'
  confidence?: 'confirmed' | 'likely' | 'informational'
  uiGroup?: 'confirmed-vulnerabilities' | 'likely-risks' | 'needs-review'
          | 'hardening-recommendations' | 'informational-observations'
}

export type WafVendor =
  | 'cloudflare' | 'akamai' | 'imperva' | 'fastly'
  | 'aws-cloudfront' | 'aws-waf' | 'vercel-bot-protection'
  | 'sucuri' | 'stackpath' | 'ddos-guard' | 'unknown'

export type SuggestedAction =
  | 'stage2-bookmarklet' | 'stage2-server-browser' | 'stage3-verify-ownership'
  | 'fix-target' | 'try-canonical-host'

export interface ScanError {
  code: 'invalid_url' | 'unreachable' | 'blocked_by_target' | 'blocked_by_waf'
      | 'timeout' | 'too_large' | 'rate_limited' | 'internal'
  message: string
  httpStatus?: number
  wafVendor?: WafVendor
  suggestedAction?: SuggestedAction
}

export interface ScanResult {
  ok: true
  url: string
  scannedAt: string
  durationMs: number
  vibeScore: number
  totals: { critical: number; warn: number; info: number; ok: number }
  findings: Finding[]
  meta: {
    finalUrl: string
    httpStatus: number
    contentType: string | null
    detectedFramework: string | null
    detectedFrameworkVersion?: string | null
    detectedReactVersion?: string | null
    bundlesFetched: number
    bundlesSizeBytes: number
    routeContext?: 'sensitive' | 'public' | 'unknown'
  }
  detected?: {
    supabaseProjectIds: string[]
    supabaseAnonKey: string | null
    s3BucketHosts: string[]
    firebaseIds: string[]
    aiEndpoints: string[]
  }
  stage?: 1 | 3
  aggregateRisk?: number
  aggregateRiskBand?: 'low' | 'medium' | 'high' | 'severe'
  attackSurface?: AttackSurface
}

export type CdnProvider =
  | 'cloudflare' | 'aws-cloudfront' | 'fastly' | 'akamai'
  | 'vercel' | 'netlify' | 'sucuri' | null

export interface AttackSurface {
  primaryDomain: string
  baseDomain: string
  cdn: CdnProvider
  wafVendor?: WafVendor | null
  wafBlocked?: boolean
  stealthRetryAttempted?: boolean
  stealthRetrySucceeded?: boolean
  endpoints: { path: string; source: 'html' | 'bundle' | 'detected' | 'sitemap' }[]
  thirdPartyScripts: string[]
  forms: { action: string; method: string }[]
  authProviders: string[]
  dataStores: { kind: 'supabase' | 's3' | 'firebase' | 'cloudfront'; ref: string }[]
  subdomains: string[]
}

export interface ScanFailure { ok: false; error: ScanError }
export type ScanResponse = ScanResult | ScanFailure
```

### 12.2 Engine interfaces (`api/_lib/scoring-engine.ts`)

```ts
export type RiskClass =
  | 'critical-exploit' | 'high-impact-misconfig' | 'medium-weakness'
  | 'low-hardening' | 'informational'

export type Confidence = 'confirmed' | 'likely' | 'informational'

export type RouteContext = 'sensitive' | 'public' | 'unknown'

export type UiGroup =
  | 'confirmed-vulnerabilities' | 'likely-risks' | 'needs-review'
  | 'hardening-recommendations' | 'informational-observations'

export interface ScoringContext {
  routeContext: RouteContext
  cspHasUnsafe?: boolean
  httpsActive: boolean
  stage: 1 | 2 | 3
}

export interface FindingTraits {
  exploitable: boolean
  secretPattern: boolean
  authImpact: boolean
  publicExposure: boolean
  sensitiveData: boolean
  browserSurface: boolean
  runtimeConfirmed: boolean
  defenseInDepthOnly: boolean
  configurationFlaw: boolean
  highAbuseLikelihood: boolean
  verifiedImpact: boolean
  knownPublicAsset: boolean
  authCookie: boolean
}

export interface ScoredFinding {
  finding: Finding
  traits: FindingTraits
  riskClass: RiskClass
  confidence: Confidence
  riskScore: number
  scoreImpact: number
}

export interface EngineOutput {
  vibeScore: number
  scored: ScoredFinding[]
  groupCounts: Record<RiskClass, number>
  hasVerifiedImpact: boolean
}

export interface ApplyResult {
  vibeScore: number
  findings: EnrichedFinding[]
  groupCounts: Record<RiskClass, number>
  hasVerifiedImpact: boolean
  aggregateBand: 'low' | 'medium' | 'high' | 'severe'
}
```

### 12.3 Database schemas (PostgreSQL via Supabase)

```sql
-- vs_audit_log
CREATE TABLE public.vs_audit_log (
  id           bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
  created_at   timestamptz NOT NULL DEFAULT now(),
  event_type   text NOT NULL,
  user_id      uuid,
  session_id   text,
  ip_hash      text,             -- sha256(ip + DAILY_SALT)
  user_agent   text,
  path         text,
  scanned_url  text,
  scan_outcome text,
  vibe_score   integer,
  waf_vendor   text,
  metadata     jsonb
);

-- vs_scan_log (denormalized for the live ticker)
CREATE TABLE public.vs_scan_log (
  id                       bigint PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
  hostname                 text NOT NULL,
  vibe_score               integer NOT NULL,
  top_finding_id           text,
  top_finding_severity     text,
  top_finding_title        text,
  country                  text,
  scanned_at               timestamptz NOT NULL DEFAULT now(),
  waf_vendor               text,
  waf_blocked              boolean,
  stealth_retry_attempted  boolean,
  stealth_retry_succeeded  boolean,
  scan_outcome             text
);

-- vs_verified_domains
CREATE TABLE public.vs_verified_domains (
  domain      text PRIMARY KEY,
  uuid        text NOT NULL,
  method      text NOT NULL,        -- 'file' | 'dns' | 'vercel'
  verified_at timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,  -- 30 days from verified_at
  user_agent  text,
  scan_count  integer NOT NULL DEFAULT 0
);

-- vs_oauth_states (dormant)
CREATE TABLE public.vs_oauth_states (
  state       text PRIMARY KEY,
  domain      text NOT NULL,
  uuid        text NOT NULL,
  provider    text NOT NULL,        -- 'vercel'
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL  -- 10-15 min from created_at
);

-- vs_stage2_collections
CREATE TABLE public.vs_stage2_collections (
  uuid         text PRIMARY KEY,
  url          text NOT NULL,
  data         jsonb NOT NULL,       -- the bookmarklet payload
  collected_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,  -- 1 hour from collected_at
  user_agent   text
);
```

No RLS. All writes go through the service-role key on the Vercel side.

---

## 13. Dependencies

### 13.1 Frontend

```
react@19.2.5
react-dom@19.2.5
framer-motion@12.38.0
lucide-react@1.14.0
@radix-ui/react-slot@1.2.4
@radix-ui/react-toggle@1.1.10
@radix-ui/react-toggle-group@1.1.11
class-variance-authority@0.7.1
clsx@2.1.1
tailwind-merge@3.5.0
@marsidev/react-turnstile@1.5.2
three@0.184.0                       (interactive globe on marketing page)
```

### 13.2 Backend / Vercel functions

```
@vercel/node@5.7.13
@vercel/edge@1.3.0
@supabase/supabase-js@2.105.1
tldts@7.0.30                        (public-suffix-aware base domain)
@babel/parser@7.29.3                (JS AST analysis)
@babel/types@7.29.0
```

### 13.3 Build / dev tooling

```
typescript@~6.0.2
vite@8.0.10
@vitejs/plugin-react@6.0.1
tailwindcss@4.2.4
@tailwindcss/vite@4.2.4
eslint@10.2.1
eslint-plugin-react-hooks@7.1.1
eslint-plugin-react-refresh@0.5.2
typescript-eslint@8.58.2
sharp@0.34.5                        (image optimization at build time)
```

### 13.4 Stage 2 worker

```
playwright-chromium@1.49.x
express@4.21.2
typescript@5.7.2
```

### 13.5 CLI (`cli/` — npx vguard scan)

Single-file Node CLI, **zero npm dependencies**. Uses native `fetch` + `node:tty`.

### 13.6 GitHub Action (`github-action/`)

Composite Node 20 action, **zero npm dependencies**. Uses `@actions/core` only via `process.env`.

### 13.7 What we deliberately do NOT use

- No `puppeteer` (chose Playwright).
- No `axios` (Node `fetch` is enough).
- No `zod` (hand-rolled validation).
- No analytics SDK (we'd flag it on customers).
- No `dotenv` package (Vercel handles env).
- No ORM (`@supabase/supabase-js` is direct SQL).

---

## 14. Full File / Folder Structure

```
vguard/
├── .gitattributes
├── .gitignore
├── CLAUDE.md
├── README.md
├── STAGE3_OAUTH_SETUP.md
├── eslint.config.js
├── index.html
├── middleware.ts
├── package.json
├── package-lock.json
├── tsconfig.api.json
├── tsconfig.app.json
├── tsconfig.json
├── tsconfig.node.json
├── vercel.json
├── vite.config.ts
│
├── api/
│   ├── __tests__/
│   │   ├── admin-logs.test.ts
│   │   ├── audit-log.test.ts
│   │   ├── middleware.test.ts
│   │   └── scoring-engine.test.ts
│   ├── _lib/
│   │   ├── attack-surface.ts
│   │   ├── audit-log.ts
│   │   ├── deep-scanner.ts
│   │   ├── fix-prompt-composer.ts
│   │   ├── js-ast.ts
│   │   ├── risk-scorer.ts            (legacy CVSS — back-compat only)
│   │   ├── scan-telemetry.ts
│   │   ├── scanner.ts                 (3700 LoC — Stage 1 logic)
│   │   ├── scoring-engine.ts          (live engine)
│   │   ├── verification-store.ts
│   │   └── verify-email.ts
│   ├── admin/
│   │   └── logs.ts
│   ├── oauth/vercel/
│   │   ├── callback.ts                (dormant)
│   │   └── start.ts                   (dormant)
│   ├── badge.ts
│   ├── contact.ts
│   ├── recent-findings.ts
│   ├── scan.ts
│   ├── scan-browser-assisted.ts
│   ├── scan-deep.ts
│   ├── scan-stream.ts
│   ├── stage2-collect.ts
│   ├── stage2-results.ts
│   ├── track.ts
│   ├── verify.ts
│   └── verify-vercel-token.ts
│
├── cli/
│   ├── package.json
│   ├── package-lock.json
│   ├── README.md
│   ├── src/index.ts
│   └── tsconfig.json
│
├── docs/
│   ├── SCANNER-AUDIT.md               (detector inventory, scoring details)
│   └── SYSTEM-AUDIT.md                (THIS FILE)
│
├── github-action/
│   ├── README.md
│   ├── action.yml
│   └── index.js
│
├── public/
│   ├── apple-touch-icon.png
│   ├── apple-touch-icon.svg
│   ├── cards/
│   │   ├── bolt.svg
│   │   ├── cursor.svg
│   │   ├── lovable.svg
│   │   ├── replit.svg
│   │   └── v0.svg
│   ├── favicon-32.png
│   ├── favicon-dark.svg
│   ├── favicon.svg
│   ├── logo-200.png
│   ├── logo-512.png
│   └── robots.txt
│
├── src/
│   ├── App.tsx                        (marketing shell + scan entry + routing-by-path)
│   ├── main.tsx                       (React root)
│   ├── index.css                      (Tailwind 4 @theme + globals)
│   ├── components/
│   │   ├── AccessibilityWidget.tsx
│   │   ├── ContactSection.tsx
│   │   ├── Legal.tsx
│   │   ├── NextStagesPanel.tsx        (Stage 2/3 modal)
│   │   ├── ScanForm.tsx               (orchestrator)
│   │   └── ui/
│   │       ├── bento.tsx
│   │       ├── button.tsx
│   │       ├── card.tsx
│   │       ├── cpu-architecture.tsx
│   │       ├── interactive-globe.tsx
│   │       ├── pricing-card.tsx
│   │       ├── scanner-card-stream.tsx
│   │       ├── scanning-loader.tsx
│   │       ├── toggle.tsx
│   │       ├── toggle-group.tsx
│   │       ├── typing-effect.tsx
│   │       ├── vguards-logo.tsx
│   │       └── vibe-score-gauge.tsx
│   ├── lib/
│   │   ├── design-tokens.ts
│   │   ├── scanner-types.ts           (shared client/server types)
│   │   └── utils.ts                   (cn() — clsx + tailwind-merge)
│   └── pages/
│       ├── Accessibility.tsx
│       ├── AdminLogs.tsx
│       ├── Privacy.tsx
│       └── Terms.tsx
│
└── stage2-worker/                      (Railway service — separate deploy)
    ├── Dockerfile
    ├── README.md
    ├── index.ts                        (Express + Playwright)
    ├── package.json
    └── tsconfig.json
```

---

## 15. Production Readiness Review

### 15.1 What is production-grade

- **Stage 1 scanner.** Battle-tested across hundreds of scans. Detector quality is high; false-positive rate is low post-engine.
- **Scoring engine v2.** Trait-based, deterministic, unit-tested (20 tests cover strict gate, verified-impact path, score caps, enterprise regressions).
- **Per-finding fix prompts.** Production-quality output: full per-stack instructions, regression test pinned to evidence, anti-patterns block, rollback command.
- **Admin protection.** Env-secret URL + bearer + rate limit + hard-404 on the guess path. Solid.
- **CSP / headers on v-guards.com itself.** No `unsafe-inline` in script-src. HSTS preload-eligible. CORP / COOP / COEP all configured.
- **Email infrastructure.** Resend with full DNS hardening (SPF + DKIM + DMARC + CAA + DNSSEC).
- **SSRF guard.** Conservative private-IP block. Runs before any fetch.
- **Token redaction.** First 8 + last 4 chars only, ever, in any output.

### 15.2 What is prototype-level

- **No user accounts.** Anonymous scans only.
- **No paid tier wiring.** Pricing page exists but no Stripe / billing integration.
- **OAuth Stage 3 verification.** UI for paste-token works; OAuth Integration registration is paperwork-blocked on Vercel's side.
- **Stage 2 worker.** Single Railway container, no autoscale, no health-rotation. Fine for current traffic; not fine for "front page of HN".
- **`vs_audit_log` archival.** Unbounded growth. No migration path.
- **Region pinning.** Functions run wherever Vercel routes them.

### 15.3 What is dangerous

- **Single Supabase project shared with `roi-ai-internal`.** A bad migration on Vguard tables could affect Royi's main ERP database. We use prefix isolation but it's not RLS-isolated.
- **Stage 2 worker runs Chromium with `--no-sandbox`.** Necessary on Railway but a real attack surface — a malicious target page could in theory exploit a Chromium 0-day. We update Playwright weekly (auto-bumps in deps).
- **Vercel personal access tokens** flow through the function, intended-discard relies on V8 GC and try/finally hygiene. A function crash mid-flow could log it. Low probability, real impact if it happens.
- **No DNS rebinding mitigation.** A determined attacker could craft a target that resolves to a public IP for the SSRF check then to `127.0.0.1` for the fetch.
- **Bookmarklet UUID acts as a bearer token.** Anyone who learns the UUID can submit fake collection data on the user's behalf. Risk is bounded (1-hour TTL, no value collected) but real.

### 15.4 What would fail at scale

- Stage 2 worker memory blows up at ~10 concurrent scans.
- `/api/recent-findings` hits the DB on every marketing-page load — would melt at >100 RPS.
- AST parsing per-bundle is the per-scan throughput bottleneck (~150ms × 4 bundles = 600ms of CPU).
- Vercel function cold-starts on first request after >5min idle. UX degrades to ~3s wait.
- `vs_audit_log` table without indexes on `created_at` and `event_type` would slow `/api/admin/logs` query at >1M rows.

### 15.5 What security researchers would criticize

- **No authentication on `/api/scan`.** A researcher would point out that "free unlimited scanning" is the textbook precondition for a botnet entry point.
- **Stealth retry on 4xx.** Looks like a bot trying to bypass WAFs. Some sites would flag Vguard's IPs as malicious crawlers.
- **No `X-Vguard-Scanner: 1` opt-in header.** Many security tools advertise themselves explicitly so admins can allow/block. We don't.
- **The scanner sees Authorization headers in Stage 2 network capture.** Even though we never persist values — only the `hasAuthHeader` boolean — a researcher would correctly call out that the worker process sees them in transit.
- **Single-tenant DB.** Cross-customer admin separation isn't ready. No SOC 2 path until that's fixed.
- **No bug bounty.** Claiming to be a security tool without a bounty program is a credibility gap.
- **Fix prompts are AI-generated** and could carry their own bugs. We don't run them; we hand them to the user. A researcher would ask: "what if the prompt is itself prompt-injection-vulnerable to a hostile finding evidence value?" Answer: detector-set evidence is already redacted; user-controlled input only ends up in the prompt via active probes (canaries we control).

### 15.6 What enterprise customers would reject

- **Single-region hosting.** GDPR-strict customers want EU-only data residency.
- **No customer admin.** No way for a buyer to revoke / rotate / audit their own scans.
- **No SAML / SSO.** Login flow doesn't exist at all.
- **No audit log export.** `vs_audit_log` is internal only.
- **No SLA.** Uptime is whatever Vercel + Railway + Supabase happen to provide.
- **Stage 2 worker on Railway.** Many enterprise security teams won't allow their target traffic to traverse a small-vendor PaaS.
- **`@v-guards.com` email domain.** Enterprises like vendor emails on `@vendor.com` not `@v-guards.com` (cosmetic but it surfaces in procurement reviews).
- **No DPA / signed contract path.** "Trust me bro" doesn't survive vendor risk review.
- **No on-prem option.** Enterprises with strict egress rules can't allow scanning from a hosted SaaS.
- **No rate-limit dashboard.** Customer can't see their own usage.
- **No WAF allowlist tooling.** Customer can't pre-allow Vguard's IPs in their WAF without manual back-and-forth.

---

*Doc version 2026-05-08, snapshot of HEAD `5ce242e` post-deploy. Re-generate when shipping breaking-change scoring updates, new detector classes, or architectural changes.*
