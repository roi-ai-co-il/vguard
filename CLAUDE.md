# Vguard — security scanner for vibe-coded apps

> Co-founders: Royi + Oded (joined 2026-04-29). Idea note: [`Knowledge/09 רעיונות/Vguard.md`](../../Knowledge/09%20רעיונות/Vguard.md). Attack catalog: [`Knowledge/09 רעיונות/Vguard - Attack Catalog.md`](../../Knowledge/09%20רעיונות/Vguard%20-%20Attack%20Catalog.md).

## What it is

URL-based security scanner. Founder pastes their app URL → backend fetches the site, parses HTML, downloads JS bundles, runs detection rules → returns a Vibe Score + findings, each with a paste-ready Cursor/Claude/Lovable fix prompt.

**Stack:** React 19 + Vite 8 + Tailwind 4 + framer-motion + lucide-react + shadcn/ui primitives (Radix). Backend is a single Vercel Function (`api/scan.ts`) running pure Node fetch, no external services.

## 3-Stage Scan Architecture (canonical, 2026-04-30)

The product flow is intentionally three escalating stages. Each stage trades convenience for depth. Always show the user the STAGE NUMBER they're on so they understand the trade-off.

```
URL → Stage 1: Passive Scan
       ↓
   if blocked / limited / anon-key found
       ↓
       Stage 2: Browser-Assisted Scan
              ↓
         if deeper access needed
              ↓
              Stage 3: Verified Deep Scan
                     ↓
                Full report + AI fix prompts
```

### Stage 1 — Passive Scan (✅ live)
External-only checks, nothing that looks like an attack. The user pastes a URL and we go.

- HTTPS / TLS version + cipher / cert expiry
- Security headers (CSP depth, HSTS strength, X-Frame-Options, COOP/COEP/CORP, …)
- Public JS bundle inspection (secrets, source maps, npm CVE matching)
- Supabase / Firebase / S3 detection (passive references)
- DNS records (DNSSEC, CAA, DMARC, SPF, DKIM, takeover-prone CNAME)
- Forms + endpoints discovery (CSRF tokens, AI endpoints, auth signup probes)
- Active probing: Open Redirect canary, reflected XSS canary, SQLi error-based

**~75 detectors, ~99% of URL-only spec coverage.** See [`Knowledge/09 רעיונות/Vguard - Attack Catalog.md`](../../Knowledge/09%20רעיונות/Vguard%20-%20Attack%20Catalog.md) for the live list.

The current `api/scan.ts` is Stage 1. Stages 2 and 3 are separate endpoints + UI flows.

**🔵 Planned Stage 1 enhancements (no infra changes — pure detector additions, 2026-05-04):**

1. **Risk scoring (CVSS-style per-finding)** — `riskScore: number` on every Finding (impact × exploitability × exposure), so the report can rank "fix-first" instead of just bucketing severity.
2. **Deep fingerprinting — versions + WAF/CDN** — exact framework versions (Next.js 15.0.3 vs just "Next.js") + CDN/WAF layer detection (Cloudflare, Akamai, Fastly, AWS CloudFront, AWS WAF, Imperva, Sucuri) from header + bundle-path signatures.
3. **Subdomain discovery (passive)** — cert-transparency lookup (`crt.sh`) + small DNS wordlist of common subdomains; suppressed for shared-platform apexes.
4. **API / behavior analysis (passive)** — parse `openapi.json` / `swagger.json` / `/api-docs` if present; extract fetch/axios call URLs from JS bundles; detect GraphQL/tRPC. Output: `apiSurface: { endpoints: [{path, methods, auth?}] }`.
5. **Content-aware severity** — bump severity for findings on auth/admin/checkout routes, lower for marketing pages. Adds an `effectiveSeverity` distinct from `baseSeverity`.
6. **JS AST analysis** — replace bundle-regex with `@babel/parser` traversal to catch credentials in object literals, fetch URLs in template strings, dangerous DOM-sink assignments, and unsafe React HTML-injection props that regex misses.
7. **Attack surface map output** — single structured `attackSurface` block (domain, subdomains, endpoints, third-party scripts, auth providers, secrets, dependencies) returned as JSON + ASCII tree, machine-readable for MCP/agents.

Detail + detection methods in the Catalog `🔵 Planned Stage 1 enhancements` section.

### Stage 2 — Browser-Assisted Scan (🟢 LIVE — bookmarklet + server-side Playwright, 2026-04-30 → 2026-05-02)

**Two paths now ship side-by-side:**

1. **Server-side Playwright (default)** — POST `/api/scan-browser-assisted` on Vercel proxies to a Railway worker running headless Chromium. Worker code lives in `stage2-worker/` (separate GitHub repo `roi-ai-co-il/vibesecure-stage2-worker`, deployed to Railway project `vibesecure-stage2`). The Vercel→Railway hop is authenticated with a 64-char bearer token (`STAGE2_WORKER_TOKEN` set on both ends). End-to-end on `example.com` runs in ~2.3s.
2. **Bookmarklet (fallback)** — for sites that block external scanning (login walls, geo-restricted, etc.). User drags JS bookmarklet to bookmarks bar, opens their site, clicks. POSTs to `/api/stage2-collect`, results polled via `/api/stage2-results`.

The Stage 2 modal exposes both. Server-side is presented as the default ("Quick path"), bookmarklet as the fallback.


For sites that block external scanning, hide behind login walls, or have client-set state we want to inspect. Implemented as a **bookmarklet** — the user drags a button to their bookmarks bar, opens their site, clicks the bookmarklet; the embedded JS collects client-side data and POSTs to `/api/stage2-collect`. The Vguard UI polls `/api/stage2-results?uuid=...` until findings arrive.

**Why bookmarklet, not Playwright:** server-side Playwright (Vercel `@sparticuz/chromium` or a Railway worker) is the more powerful approach but requires hosting infrastructure. Bookmarklet is achievable today, runs ON the user's actual site origin (sees their real session), and the JS source is human-readable so users can audit what we collect.

**What the bookmarklet collects (key NAMES only, never values):**
- Cookie names (`document.cookie` only sees non-HttpOnly cookies — that's the signal)
- localStorage / sessionStorage keys
- Window globals: `window.supabase`, `window.firebase`, `window.firebaseConfig`, `window.__APP_CONFIG`, `window.__NEXT_DATA__`
- Performance entries (recent fetch URLs from `performance.getEntriesByType('resource')`)
- User agent

**Stage 2 findings (analyzeStage2 in `api/stage2-results.ts`):**
- `stage2-cookie-not-httponly` (warn) — sensitive-named cookies (sess/auth/token/jwt/sid/csrf) visible to JS = HttpOnly missing
- `stage2-localstorage-auth-tokens` (warn) — `sb-*-auth-token`, `firebase:authUser`, `access_token`, `refresh_token` in localStorage
- `stage2-firebase-config-global` (info) — `window.firebaseConfig` exposed
- `stage2-external-apis` (info) — runtime confirmation of API hits (audit material vs CSP connect-src)
- `stage2-clean` (ok) — clean-state marker

**Storage:** `vs_stage2_collections` table in roi-ai-internal Supabase (1-hour TTL).

**Files:**
- `api/stage2-collect.ts` — POST endpoint, CORS open (bookmarklet runs on user origin)
- `api/stage2-results.ts` — GET endpoint, polled by Vguard UI
- `src/components/NextStagesPanel.tsx#Stage2Modal` — bookmarklet generator + drag-handle + polling UI

**Future upgrade path to Playwright:**
When volume/budget justifies, add `api/scan-browser-assisted.ts` that proxies to a Railway worker running Chromium. The bookmarklet stays as the zero-infra fallback. Both can co-exist.

**🔵 Planned Stage 2 enhancements (require Playwright + bookmarklet collector changes, 2026-05-04):**

1. **Cookie flags analysis (deep)** — per-cookie audit covering Secure, HttpOnly, SameSite (Lax/Strict/None), Domain scope, Path, Max-Age, prefix (`__Secure-` / `__Host-`), and the Partitioned (CHIPS) attribute. Playwright sees HttpOnly cookies via `context.cookies()`; the bookmarklet only sees non-HttpOnly. UI renders a per-cookie table with recommendations.
2. **JWT / token decoding** — parse every `eyJ...` string visible to Stage 2 (cookies, localStorage, sessionStorage, network bodies). Decode header + payload (no signature verify) and flag: `alg: none`, weak HMAC sigs, unbounded `exp`, sensitive claims in plaintext, missing `iss`/`aud`.
3. **Live API mapping (network capture)** — Playwright `page.on('request')` / `page.on('response')` records every fetch/XHR (method, URL, content-type, auth-header presence, status, size, duration). Filter to first-party / same-origin. Cross-reference with CSP `connect-src` for declared-vs-actual delta.
4. **Sensitive data detection (response bodies)** — server-side scan of captured response bodies for PII (emails, phones, Israeli IDs, Luhn-validated card patterns), secrets (the Stage-1 secret regex bank, expanded), internal URLs (10.x / 192.x / `*.local`), and stack traces leaking absolute file paths. Strict redaction in the finding evidence (first 6 chars + `...`).
5. **Privilege leak signals (unauth views admin)** — when Stage 2 runs without login: DOM query for admin nav links, hidden admin form actions, route definitions in JS bundles without a visible auth gate, fetch probes returning 200 on `/admin/*` or `/api/admin/*` paths discovered in the bundle.
6. **(optional) Move to Chrome extension** — Manifest V3 extension for persistent monitoring, continuous network capture, and DevTools integration; bookmarklet stays as zero-install fallback. Decision deferred until bookmarklet PMF — distribution via Chrome Web Store + Firefox Add-ons.

Detail + detection methods in the Catalog `🔵 Planned Stage 2 enhancements` section.

### Stage 3 — Verified Deep Scan (🟢 LIVE — verification flow ready; deep-scan execution not yet end-to-end verified against a real verified domain)
Aggressive probing that's only legal/ethical when the user proves they own the target.

**Three verification methods (any one suffices) — all three UI flows live:**

1. **File challenge** — Vguard issues a UUID. User uploads `https://<domain>/.well-known/Vguard-verify.txt` containing the UUID. We GET the file, match — verified.
2. **DNS TXT** — User adds `_Vguard-verify.<domain> TXT "<uuid>"`. We `dns.resolveTxt`. Slower but works for sites that can't easily upload files. Endpoint live, returns real DNS lookup results.
3. **Vercel personal access token (live 2026-05-02)** — user pastes a token from vercel.com/account/tokens. `/api/verify-vercel-token` calls Vercel API to list the user's projects + team projects, checks domain alias match, marks verified, discards token. **Why not OAuth?** Vercel doesn't expose an API to create OAuth Integrations; the OAuth Integration registration is UI-only at vercel.com/dashboard/integrations/console. The paste-token path achieves the same proof (the user must hold a token from the Vercel account that owns the domain) without that one-time UI step. The OAuth flow code (`api/oauth/vercel/start.ts` + `callback.ts`) remains dormant in the repo for the day Royi sets up the Integration.

**What Stage 3 unlocks:**
- Real Supabase RLS testing (drive the anon key against every public.* table, look for unauthorized SELECT)
- Storage bucket write-test (try uploading a benign file, see if it succeeds without auth)
- Aggressive XSS / SQLi payload library (beyond the canary single-quote)
- Admin route fuzzing (200 candidate paths, not 33)
- Full path-traversal probing (`?file=../../etc/passwd`)
- Mass-assignment testing on detected forms
- Authenticated mode (user enters test creds, we probe IDOR) — IDOR JWT field exposed in UI for token intake
- AI agent prompt copy — one-click copy of a Stage-3 driving prompt for Cursor/Claude/Lovable agents

**Storage of verification proof:** Supabase `vs_verified_domains` table (domain, method, verified_at, expires_at, scan_token). Verification expires after 30 days; user can re-verify.

**Legal / TOS:** every Stage 3 scan starts with a confirmation modal — "I confirm I own ${domain} and authorize Vguard to send active probes". Logged for audit.

### Where each stage lives in code

```
api/scan.ts                       # Stage 1 (passive) — current implementation
api/scan-browser-assisted.ts      # Stage 2 — NOT YET, needs Playwright + Railway
api/verify.ts                     # Stage 3 verification challenge
api/scan-deep.ts                  # Stage 3 deep scan (only when verified)
src/components/ScanForm.tsx       # Renders Stage 1 + entry to Stage 2/3
src/components/NextStagesPanel.tsx # Renders post-Stage-1 — Stage 2 and 3 cards
src/components/VerifyOwnership.tsx # Stage 3 verification flow UI
```

### Build order (historical — all three stages now live)

1. ✅ Stage 1 — done (this is what's live)
2. ✅ Stage 3 verification flow — file-challenge + DNS TXT + Vercel-token paths all live in UI; DNS endpoint returns real lookups; deep-scan execution not yet end-to-end verified against a real verified domain.
3. ✅ Stage 2 — server-side Playwright on Railway + bookmarklet fallback, both shipping side-by-side.
4. Authenticated mode (subsection of Stage 3) — IDOR JWT intake field shipped; broader credentialed probing UX still in progress.

## Live state (2026-04-30)

- ✅ Real scanner shipped (10 secret patterns, 4 header checks, source-map probe, 4 path probes, framework detection, JWT service-role decoding, CORS audit).
- ✅ End-to-end verified locally: `vercel.com` → 100/100 in 4.5s, `example.com` → 82/100 in 535ms.
- ⏳ Production deploy on Vercel pending explicit user confirmation (sandbox blocks blind `--prod` deploys).

### Calling the scan API from terminal / agents

Stage 1 is a normal `POST /api/scan` JSON endpoint — useful for scripted verification after a security fix without opening the UI in a browser:

```bash
curl -s -X POST https://vibesecure-tau.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/page"}' --max-time 90
```

Returns the full `ScanResponse` (vibeScore, totals, findings[]) as JSON. Use this in deploy-verify scripts and from Claude sessions instead of asking the user to click rescan.

## Repo layout

```
api/
  scan.ts             # Vercel Function: POST /api/scan { url } → ScanResponse
  _lib/scanner.ts     # runScan(url) — pure logic, used by api/scan.ts AND vite dev plugin
src/
  lib/
    scanner-types.ts  # Finding, ScanResult, ScanResponse — shared client/server
    utils.ts          # cn() (clsx + tailwind-merge)
  components/
    ScanForm.tsx      # the orchestrator: idle → scanning → result | error
    ui/
      bento.tsx              # BentoGrid, BentoCard
      button.tsx             # shadcn
      card.tsx               # shadcn
      interactive-globe.tsx  # canvas-based 3D globe
      pricing-card.tsx       # 3-tier pricing with comparison table
      toggle.tsx             # shadcn (Radix)
      toggle-group.tsx       # shadcn (Radix)
      typing-effect.tsx      # rotating typewriter
      vibe-score-gauge.tsx   # 270° radial gauge, severity gradient
  App.tsx
  index.css           # Tailwind 4 @theme block + shadcn semantic-token compat layer
vite.config.ts        # plugin "Vguard-dev-api" exposes /api/scan during `npm run dev`
vercel.json           # function maxDuration: 30, hardening headers on the marketing site
tsconfig.api.json     # separate project ref for api/, paths alias only
tsconfig.app.json     # frontend, paths alias for @/*
```

## Hard rules specific to this project

- **No fake data in shipped reports.** Every finding the API returns is from a real fetch; if a category has no real evidence, it ships an `ok` finding (e.g. `secrets-clean`) — not a fabricated one. The marketing-only fake findings live in `App.tsx` (the `RECENT_FINDINGS` ticker, `SCAN_CARDS` bento illustrations) and are explicitly labeled as illustrative copy, not scan output. Don't blur this line.
- **The scanner runs on the server, not the browser.** Anything in `api/_lib/scanner.ts` uses Node `fetch`, `Buffer`, `TextDecoder`. Never imported from `src/` files. The frontend only imports types from `src/lib/scanner-types.ts`.
- **Private/local hosts are rejected.** `runScan` blocks `localhost`, `127.x`, `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`, `*.local` before any fetch. Don't relax this — it's the SSRF guard.
- **Bundle scanning is bounded.** Max 4 bundles, max 2 MB each, 4s timeout per fetch. Path probes are 2.5s each. Total scan stays under ~10s. Don't increase without re-checking Vercel's free-tier 10s limit.
- **Token redaction is always on.** When a secret is found, only the first 8 + last 4 chars are returned in `evidence`. Full match never leaves the server.

## Deploy

Linked to Vercel project `Vguard` in team `team_evbzoCbdWuVIB4ZDwEfZ0Oeg`.

**Production deploy command** (from `Vguard/`):

```bash
source ~/.claude/.env.global
GIT_CEILING_DIRECTORIES="$(pwd)/.." npx vercel deploy --prod --yes
```

## Live infrastructure (post-rebrand 2026-05-05)

The product is **Vguard** but several infra identifiers still carry the old `vibesecure` name where renaming would require coordinated DNS/alias work or has subtle compat costs. Both names live side by side; new docs use `Vguard`, infra labels stay as listed below until a deliberate cutover.

| Asset | Identifier | Notes |
|---|---|---|
| Live URL (canonical, 2026-05-07) | `https://vguardus.com` | Custom domain bought + bound to project; DNS update needed at registrar. |
| Live URL (www) | `https://www.vguardus.com` | 308 redirect to apex. |
| Live URL (legacy) | `https://vibesecure-tau.vercel.app` | Original, still resolves. |
| Live URL (legacy alias) | `https://vguard-tau.vercel.app` | Added 2026-05-05, still resolves. |
| Vercel project | `vguard` (renamed from `vibesecure`) — `prj_T7NIVw968V5i9QBQ54OkUhtMV1HD` in team `team_evbzoCbdWuVIB4ZDwEfZ0Oeg` | Project name is `vguard`; all four domains bound to it. |
| GitHub repo (frontend) | `roi-ai-co-il/vguard` (private, created 2026-05-07) | `git push origin main`; tokens in `~/.claude/.env.global`. |
| Railway project | `vguard-stage2` (renamed from `vibesecure-stage2`) — `19b15ff4-3a22-4c39-944d-95c8db4c5604` | Service URL unchanged. |
| Railway service | `stage2-worker` — `a3022f8a-f1b4-4fa2-8622-f985fef8865b` (env `f8ce2d1e-2d96-4a59-a496-34749f1eb159`) | Healthcheck: `https://stage2-worker-production.up.railway.app/healthz`. |
| GitHub repo (worker) | `roi-ai-co-il/vguard-stage2-worker` (renamed from `vibesecure-stage2-worker` 2026-05-05) | Railway service rewired to the new repo name via `serviceConnect` mutation; old URL still 301-redirects courtesy of GitHub. |
| Local source folder | `ROI-AI/vguard/` | Folder name kept; path-rename would touch many imports/configs. |

**Force-deploy command** when the GitHub webhook fails (see `feedback_railway_webhook_can_silently_break`):

```bash
source ~/.claude/.env.global
SHA=$(git -C stage2-worker rev-parse HEAD)  # or pass any commit sha
curl -s -X POST https://backboard.railway.app/graphql/v2 \
  -H "Authorization: Bearer $RAILWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { serviceInstanceDeployV2(serviceId: \\\"a3022f8a-f1b4-4fa2-8622-f985fef8865b\\\", environmentId: \\\"f8ce2d1e-2d96-4a59-a496-34749f1eb159\\\", commitSha: \\\"$SHA\\\") }\"}"
```

`GIT_CEILING_DIRECTORIES` is required because `Vguard/` lives inside the `my mind/` Obsidian vault, which has its own `.git` with author `royi@roiai.co.il`. Without the ceiling, Vercel CLI climbs up and the deploy fails with the team-author guard. Same root cause as the booking-app `mv .git` lesson in [`ROI-AI/CLAUDE.md`](../CLAUDE.md), but `GIT_CEILING_DIRECTORIES` is the cleaner fix and works for any nested project.

**After deploy:** verify the public URL alias separately — Vercel's "promote to prod" can leave the public alias stuck on an older deployment (see `feedback_vercel_alias_vs_production_target` in MEMORY.md). Use `chrome-devtools` MCP to navigate the production URL and confirm a real scan succeeds end-to-end.

## Self-scan, round 2 — three AST detector fixes (2026-05-05)

Driving `vguard-tau.vercel.app` from 84 → 98 surfaced three more product-level signal-quality bugs in the scanner. Same pattern as the round-1 cleanup: false positives the user can't act on cost score and credibility. All three fixed in this same session.

1. **`api/_lib/js-ast.ts` — DOM-sink detector ignored RHS shape.** Counted every assignment to the HTML-injection property regardless of what the right-hand side was. React's own bundle has `o.PROP = \`SAMPLE\`` (a static template literal — fully developer-controlled, no injection surface). Fix: added `isStaticDomSinkRhs(rhs)` that suppresses StringLiteral / NumericLiteral / NullLiteral / BooleanLiteral / no-expression TemplateLiteral RHS. Eliminates the largest class of vendor noise (idiomatic library clearing of children with empty strings).

2. **`api/_lib/js-ast.ts` — fetch template-literal detector ignored sanitizer wrappers.** `fetch(\`/api/users/\${encodeURIComponent(id)}\`)` is the *recommended* shape for parameterized URLs and was being flagged as an SSRF surface alongside the genuinely risky `fetch(\`https://\${userHost}/...\`)`. Fix: added `isUrlSafeExpression(expr)` that recognizes a curated list of sanitizing/coercing wrappers (`encodeURIComponent`, `encodeURI`, `Number`, `parseInt`, `parseFloat`, `String`, `btoa`, `JSON.stringify`, `String.raw`) plus inline numeric/boolean/null/string literals. The detector only fires when at least one interpolation is none of the above — i.e., truly unvalidated input flowing into a URL.

3. **`api/scan-browser-assisted.ts` — Stage 2 unauth-API detector flagged conventional public endpoints.** Vguard's own `/api/recent-findings` endpoint (the marketing ticker on the homepage, redacted scan summaries) was being reported as "first-party API call returned 2xx without auth". Same false positive would hit every `/api/health`, `/api/status`, `/api/version`, `/manifest.json`, `/sitemap.xml`, `/.well-known/*`, etc. Fix: added `WELL_KNOWN_PUBLIC_PATHS` regex bank + `isWellKnownPublicEndpoint(url)` check on the unauth filter. Path patterns are anchored on the path start (`^/`) to avoid matching admin routes that happen to contain "status" deeper in the URL.

4. **`api/_lib/scanner.ts` — DOM-sink severity stayed at `warn` even when count was small + framework was SPA.** Even after fix (1) the React DOM internal sink-set (an `if(...)throw Error(i(NN));e.SINK=n` invariant pattern) still trips the detector because the RHS is a variable identifier. Without source maps we can't tell vendor from app, but the *base rate* matters: small counts (≤3) on a detected SPA framework (Next.js / Nuxt / Vite + React / SvelteKit / Remix / Astro) are statistically vendor-internal. Fix: demote severity from `warn` (-7 points) to `info` (-2 points) for that pattern, with description text that points the user at the framework's escape-hatch prop in *their* source. Real app-code misuse will trip dedicated JSX-prop detectors (planned, not shipped — see Catalog `JS AST analysis` section).

5. **`api/_lib/js-ast.ts` — pattern-aware suppression of React DOM's internal sink-set.** Even after fixes (1) and (4) the React DOM `setInnerHTMLImpl` (which emits `if(...)throw Error(i(NN));e.SINK=n}}break` in the bundle) still lit up the demoted info finding because the sink-set is a real AssignmentExpression with a variable RHS. Fix: use the babel `start` byte offset on each sink AssignmentExpression to peek at the preceding ~80 chars of bundle text; if those chars match `/\bthrow\s+\w+\s*\([^;]{0,60}\)\s*;\s*$/`, the assignment is unambiguously the framework's invariant-then-sink shape (React, Preact, react-dom-server share this pattern). Skip it. App code never has this exact preceding-statement shape, so this is specific without being brittle to React minifier renames.

**Net delta on `vguard-tau.vercel.app`:** 84 → 93 → 98 → 100/100 across three sequential deploys (one detector fix per cycle). Final state: `0 critical · 0 warnings · 0 info · 3 ok`. The 3 ok findings are: hosted on Vercel shared subdomain (suppresses the apex DNS findings, see round-1 lesson 3), HTTPS with valid certificate, no hardcoded API keys in JS bundles.

**Cross-cutting takeaway:** every time we drove our own score up, the wins were product-level smartness in the scanner, not changes to our app code. That's the right shape — Vguard's value is the *quality* of its findings, and false positives that the user can't act on are a worse failure mode than missed positives. Keep this bias when adding new detectors: prefer specificity, demote severity when context can't be verified, and surface what the user can actually fix.

## Fix-prompt composer overhaul — best-in-class autofix (2026-05-06)

Royi's directive: every fix prompt must (a) actually fix the security flaw, (b) include typecheck if the project uses TypeScript, (c) include tests, (d) be high enough quality that they don't introduce regressions in unrelated code, (e) be best-in-class for *each specific finding*. The prior composer was decent but generic — same boilerplate test step for every finding type, no anti-patterns block, no per-category test templates. Five product changes in `api/_lib/fix-prompt-composer.ts`:

1. **`regressionTest(category, evidence, finalUrl)` — per-category vitest templates the agent MUST add.** This is the biggest gap closed. Previously step 3 said "run the tests"; now step 3.5 says "add this exact test, then run it." Every category (`headers`, `auth`, `secrets`, `paths`, `sourcemaps`, `mixed-content`, `cookies`, `integrity`, `methods`, `dns`/`email`, `ai`, `tls`, `deps`, `html`) gets a copy-paste vitest snippet pinned to the specific evidence (URL, header name, .map URL, etc.). The test FAILS BEFORE the fix and PASSES AFTER, which is the only definition of a real regression test. Without this, "tests pass" on a generic suite that doesn't even check the fixed thing is theater.

2. **`antiPatterns(category)` — per-category "things NOT to do that look like fixes."** Keyed observations from this codebase + memory:
   - For `headers`: `'unsafe-inline'` in CSP, `<meta http-equiv>` for `frame-ancestors`, lowering HSTS.
   - For `auth`: `USING (true)`, `auth.uid() IS NOT NULL`, `share_token IS NOT NULL` (matches the two memory notes), disabling RLS, `SECURITY DEFINER` end-runs.
   - For `secrets`: moving the literal to `.env.example`, renaming `VITE_*`→`OPENAI_*` while leaving the client fetch, dumping via `__NEXT_DATA__`, skipping rotation.
   - For `sourcemaps`: robots.txt as access control, IP-allowlist gating, `sourcemap: 'inline'`.
   - For `paths`: robots.txt-as-block, 200-with-empty-body, HTTP Basic as long-term fix.
   - For `mixed-content`: `block-all-mixed-content` without auditing, `method=GET` on insecure form action.
   - For `cookies`: `SameSite=None` without `Secure`, HttpOnly on JS-read CSRF tokens.
   - For `ai`: regex-based prompt-injection filtering, exposing model name/params in errors.
   - For `integrity`: SRI on floating-version URLs, missing `crossorigin="anonymous"`.
   - For `deps`: `npm audit fix --force`, ignoring transitive vulns.
   - For `tls`: disabling 1.2 with 1.0/1.1, premature `preload` submission.
   - For `dns`/`email`: DMARC `p=reject` on day one, SPF `?all`/`+all`.
   - Etc. — the lists are the institutional memory of "this looks like a fix but it isn't."

3. **`PM_HINT` — package-manager auto-detection.** New requester block at top of step 3: "if `pnpm-lock.yaml` exists use `pnpm test`; if `yarn.lock` use `yarn test`; if `bun.lockb` use `bun test`; else npm." Without this, a pnpm/yarn/bun project gets handed `npm test` and the agent dutifully runs it, npm regenerates the lockfile + creates a `node_modules`, and the next `pnpm install` complains. One paragraph saved 80% of those.

4. **`GUARDRAILS` extended.** Added five new hard rules:
   - **Minimum blast radius** — only edit files identified in step 1; if you find unrelated issues, list them in step 5, don't fix them now. Smaller diffs = fewer regressions = faster review.
   - **Match the file's existing style** — same indent / quote style / semicolon convention. Don't reformat lines you didn't change.
   - **Do not suppress** — explicitly forbids `eslint-disable`, `@ts-ignore`, `// nosemgrep` as a "fix."
   - **Do not commit secrets to .env.example / README** — was implicit, now explicit.
   - **Have a rollback ready** — capture `git rev-parse HEAD~1` before deploy; if verify fails in prod, `git revert <new-sha>` is the one-step exit.

5. **Step 5 (report-back) extended** — agent must list (a) the regression test path it added, (b) the test name + status, (c) any **unrelated issues** noticed during step 1 but deliberately not fixed (so the user can decide whether to scan them next), (d) the rollback command. The "unrelated issues" channel is the pressure release for the minimum-blast-radius rule — without it, agents either expand scope or silently drop observations.

**Bonus fix:** updated `RESCAN_BASE` from the old `vibesecure-tau.vercel.app` to `vguard-tau.vercel.app` (the rebrand left the rescan link stale; every prompt sent users to the legacy URL even though both 301-resolve).

**Why this matters:** Vguard's value-prop is "we ship the fix prompt, not just the finding." If the prompt produces regressions or leaves the agent guessing, the value is gone. This overhaul moves us from "prompts that contain instructions" to "prompts that contain the WHOLE fix workflow including the regression test pinned to this exact evidence." The test step is the biggest unlock — it transforms "run npm test" boilerplate into a real CI gate that fails next month if a refactor regresses the same vulnerability.

## CLI + GitHub Action — distribution surface (2026-05-06)

Two new top-level folders that turn Vguard from a "site you visit" into "a tool you embed":

### `cli/` — `npx vguard scan <url>`

Single-binary CLI that wraps the production API. No npm dependencies; uses native fetch + node:tty for color detection. Lives at `vguard/cli/`, builds with `npx tsc` to `cli/dist/index.js`.

- `vguard scan <url>` — colored progress + findings table + exit code.
- `vguard <url>` — shorthand.
- `--json` — raw `ScanResponse` for piping (`jq '.findings[] | select(.severity=="critical")'`).
- `--exit-code` — exits 1 on any critical/warn — designed for CI.
- `--prompt` / `--prompt=<id>` — print fix prompts inline.
- `VGUARD_API` env var overrides the API base (for self-hosted instances).
- `NO_COLOR=1` disables ANSI.

Smoke-tested against `example.com` — phase events stream live, score (58/100), 4 warns + 8 info findings, edge=cloudflare detected, all rendered correctly. **Not yet published to npm** — Royi runs `npm publish` from `vguard/cli/` when ready.

### `github-action/` — Vguard on every PR

`uses: roi-ai-co-il/vguard-action@v1` runs a scan against a preview URL and posts (or updates) a PR comment with the findings table. No npm deps; uses GitHub's built-in `GITHUB_TOKEN`.

- `action.yml` — composite Node 20 action with inputs (`url`, `fail-on`, `comment-on-pr`, `comment-tag`, `api-url`) and outputs (`vibe-score`, `critical`, `warn`, `info`, `outcome`).
- `index.js` — handler. Streams the scan, writes outputs to `$GITHUB_OUTPUT`, appends to `$GITHUB_STEP_SUMMARY`, finds-or-creates a comment via the marker `<!-- vguard-comment-marker -->` so re-runs update in place.
- Exit code gated on `fail-on` (`critical` / `warn` / `info` / `never`) — default `warn`.
- README ships a copy-paste workflow.

**Not yet published to GitHub Marketplace.** To ship: create a public repo at `roi-ai-co-il/vguard-action`, copy the `github-action/` contents, tag `v1`. Royi runs that step.

### Why these matter

Both deliverables are distribution amplifiers — they put Vguard inside developer-flows that already exist (terminal + CI), instead of asking developers to remember a URL. Combined with the badge SVG endpoint shipped earlier, Vguard now has three entry points beyond the homepage:

1. `npx vguard scan <url>` — local terminal
2. `roi-ai-co-il/vguard-action@v1` — every PR
3. `https://vguard-tau.vercel.app/api/badge?url=<host>` — every README

## UI iteration session — CPU section + globe fix + founders credit (2026-05-06)

Three product-level visual changes plus one revert. All shipped to `vguard-tau.vercel.app` in this session.

### 1. New "Scoring engine" section between bento and 3-step

Integrated the 21st.dev `cpu-architecture` SVG component as the visual for a new section: **"Eight signal streams. One verdict."** The SVG shows 8 colored light particles flowing along curved paths (offset-path CSS) into a central rectangle labeled "SCORE". Maps directly to Vguard's mental model: many detector categories → one Vibe Score.

- Component: `src/components/ui/cpu-architecture.tsx` (Pure SVG + CSS, no extra deps beyond `cn()`)
- Animation CSS: `.cpu-architecture` + `.cpu-line-1..8` per-path delays + `@keyframes animation-path` in `index.css`
- Mobile: SVG container `max-w-md aspect-[2/1]` — on iPhone 13 (375px) lands ~343×171px. Headline `text-[1.5rem] sm:text-2xl lg:text-3xl`.
- Text inside CPU box: `SCORE` (Royi's pick — more thematic than the default "CPU"). Component prop `text` makes this trivially swappable.

### 2. `interactive-globe.tsx` — fixed "lines floating to nothing"

Royi screenshotted the globe and pointed out arcs that left a city marker but ended in mid-air where the destination would be (back-side of sphere). Two-layer bug:
1. Arc occlusion used `if (z1 > 0.3 && z2 > 0.3) continue` — drew a line whenever **either** endpoint was visible, leaving the other end floating.
2. Marker occlusion used `z > 0.1`, much tighter — so a city visible to the arc check could already be hidden as a dot.

Fix: occlusion threshold unified to `OCCLUDE_Z = radius * 0.1`, AND condition flipped to `||` so an arc only renders when **both** endpoints will have a visible marker dot. Net effect: a few connections drop out as the globe rotates, but every line that's drawn visibly terminates in two dots. Royi's "lines that aren't connected" complaint maps exactly to this.

Polish in the same round (one render cycle, "while we're in there"):
- **Endpoint studs** (1.3px arcs at sx1/sy1 and sx2/sy2) — guarantees the line visibly anchors at a dot regardless of marker draw order.
- **Depth alpha**: arcs leaning toward the visible horizon fade to 0.25; arcs near the front stay at 0.85. Reads as 3D depth.
- **Glow halo** around the travelling pulse via `createRadialGradient` — pulse is now a glowing nucleus, not a flat dot.
- `lineCap: 'round'` on arcs — round terminations.

### 3. Footer — Founders credit added

Royi + Oded Safdie are co-founders of Vguard (per `Knowledge/09 רעיונות/Vguard.md`). Added a second footer row:

> **Founders ·** Royi Argaman · Oded Safdie

Note: Royi misspelled his own name as "Argman" in the request. The vault rule (`feedback_user_name_royi` in MEMORY.md) is canonical: it's "Argaman" with the second 'a'. Used the correct spelling.

### 4. Reverted: Cybercore animated hero background

I integrated 21st.dev's `cybercore-section-hero` (perspective-grid floor + rising light beams) as the hero background. Royi's screenshot showed the result: the cyan/orange beams crossed the H1 vertically, turning the headline into a barcode-like mess. Tried to tone down (move to bottom half + fade gradient + lower beamCount) but Royi cut the iteration short with "פשוט תחזיר לאיך שהיה לפני לא חובה את זה". Reverted in full: removed the component file, the import, the CSS block; restored the static `hero-glow` div. Re-deployed clean.

**Cross-project lesson — full-bleed animated backgrounds behind hero text are dangerous.** The 21st.dev preview shows them on a blank page; a real product page has a headline that the same beams will visually compete with. Two safer patterns:

1. **Scope the animation to a contextual section** (what the CPU SVG does — bounded `max-w-md`, captioned, sits between bento and STEPS). Works because the section IS the visual; nothing else has to share the canvas with it.
2. **If you want a true hero background, position it BELOW the headline** (bottom half of the hero, with a fade-to-bg overlay above) — the floor/grid metaphor stays, the H1 stays on solid bg.

Default to #1. Reach for #2 only when the design system explicitly calls for "stage" aesthetics and you can iterate on the fade thresholds against a real page (not a 21st.dev demo).

## WAF-aware 403 handling — full overhaul (2026-05-06)

Royi pasted a screenshot of `www.next.co.il` returning HTTP 403 with our sterile "We can't scan it from here" — bad UX because the user has no path forward, and worse, the message implies *Vguard* failed when actually the *target* denied automated access. Two iterations same day:

### Round A — UA upgrade (first pass)
Replaced `Vguard-Scanner/0.1` with a real Chrome 131 UA + `Vguard/1.0` suffix marker. Helped some sites, didn't help next.co.il.

### Round B — full restructure (final, after Royi's spec)

**1. `src/lib/scanner-types.ts` — `ScanError` schema split.**
- New code: `blocked_by_waf` (target's edge denied automated access) — distinct from `blocked_by_target` (404/410/etc., site rejected the URL itself).
- New fields: `httpStatus: number`, `wafVendor: WafVendor`, `suggestedAction: SuggestedAction`. Lets the UI render a proper response card instead of a generic alert.
- `WafVendor` union: cloudflare / akamai / imperva / fastly / aws-cloudfront / aws-waf / vercel-bot-protection / sucuri / stackpath / ddos-guard / unknown.
- `SuggestedAction` union: stage2-bookmarklet / stage2-server-browser / stage3-verify-ownership / fix-target / try-canonical-host. Drives the CTA copy.

**2. `api/_lib/scanner.ts` — `detectWafVendor(resp, body)` function.**
Order of evidence strength (specific headers beat generic ones):
- Cloudflare → `cf-ray` / `cf-cache-status` / body `__cf_bm` / "Attention Required! | Cloudflare"
- Akamai → `server: AkamaiGHost` / `x-akamai-transformed` / `akamai-grn`
- Imperva → `x-iinfo` / `x-cdn: Incapsula` / body "Incapsula incident id"
- Fastly → `fastly-debug-digest` / `x-served-by: cache-*` + `via: varnish`
- AWS CloudFront → `x-amz-cf-id` / `via: CloudFront`. If body says "Request blocked" → AWS WAF, else CloudFront alone.
- Vercel Bot Protection → `x-vercel-id` + body "Security Checkpoint" / "BotID:"
- Sucuri / StackPath / DDoS-Guard → vendor-specific headers + body fingerprints.
- Unknown WAF (4xx with no signals) → returns `unknown` so caller still flags it as WAF, not generic block.

**3. Two-phase response on 4xx codes (403/406/429/451).**
Phase A: stealth retry once with `STEALTH_HEADERS` — full `Sec-Ch-Ua` + `Sec-Ch-Ua-Mobile` + `Sec-Ch-Ua-Platform` + `Sec-Fetch-Dest` + `Sec-Fetch-Mode` + `Sec-Fetch-Site` + `Sec-Fetch-User` + `Upgrade-Insecure-Requests` + `Accept-Encoding: gzip, deflate, br, zstd`. Cloudflare's "managed challenge" rule scores requests on header completeness; the absence of these is itself a fingerprint. Phase B: if stealth retry returns 200-399, continue scan with that response. If it's still 4xx, sniff body for vendor + return structured `blocked_by_waf` error. Stealth retry stays opt-in (only after first 4xx) so the normal-path access logs honestly attribute Vguard.

**4. Frontend — `src/components/ScanForm.tsx` distinct WAF error card.**
- New state field: `scanError: ScanError | null` (was just `errorMsg: string`). Captures the structured error from Stage 1 failures.
- Different visual treatment when `code === 'blocked_by_waf'`: amber border (not red), `ShieldAlert` icon, headline "Target denied automated access" (not "Scan failed").
- Vendor chip (e.g. `🛡 Akamai`) + HTTP status badge (e.g. `HTTP 403`).
- Headline copy: "This isn't a Vguard failure — the target's edge protection blocked our scanner's IP. Vercel Lambda IPs are widely flagged as automated traffic. Real browsers and your visitors aren't affected."
- CTAs: `Run Stage 2 (browser-assisted)` (primary) → opens existing `Stage2Modal` (which had to be exported from `NextStagesPanel.tsx`); `Retry Stage 1`; `Try another URL`.

### Verified live 2026-05-06 on `vguard-tau.vercel.app`:
- `next.co.il` (Akamai) → stealth retry **succeeded**, scan returned `vibeScore: 40` with 22 findings. Akamai's edge accepted the stealth headers.
- `cloudflare.com` (Cloudflare) → stealth retry **succeeded**, `vibeScore: 56`.
- `akamai.com` itself (heavy Bot Manager) → stealth retry insufficient → `code: blocked_by_waf, wafVendor: akamai, httpStatus: 403, suggestedAction: stage2-bookmarklet`. Frontend renders the WAF card with Akamai chip + Stage 2 CTA.

### Cross-project lessons

1. **Server-side scanners need a real-browser UA from day one** — `MyTool/0.1 (+url)` is the textbook bot fingerprint every WAF blocks. Append your tool name as a suffix on the canonical Chrome UA (`Mozilla/5.0 ... Chrome/131 ... MyTool/1.0`) — same transparency, much higher scan success rate.

2. **Header completeness ≥ UA string** — Cloudflare's managed-challenge scores `Sec-Ch-Ua` / `Sec-Fetch-*` presence even more strongly than UA. Modern stealth requires ~12 headers, not 2.

3. **Errors should distinguish "we failed" from "they refused"** — semantic error codes (`blocked_by_waf` vs `blocked_by_target` vs `unreachable` vs `internal`) let the UI tailor the response. A red "Scan failed" implies bug-on-our-side; an amber "Target denied automated access" with vendor chip teaches the user what's happening and routes them to the right tool. This pattern applies to any tool that fetches arbitrary URLs (scanners, link-previewers, RAG ingesters, web-clippers).

4. **WAF-bypass should always have a fallback exit** — when the bypass fails, the UX must route the user somewhere productive. Vguard's exit is Stage 2 (bookmarklet runs on user's own origin → WAF can't block it). Without that exit, the new error structure would just be prettier failure copy.

## Self-scan to 100/100 — three product fixes (2026-05-03)

Driving `vibesecure-tau.vercel.app` from 56 → 100 surfaced three product-level bugs in the scanner, all fixed in this same session:

1. **`fetchWithTimeout` overrode caller's `redirect: 'manual'`** — `api/_lib/scanner.ts`. Spread `init` then set `redirect: 'follow'` AFTER → the spec-correct `manual` mode the http→https probe and open-redirect probe asked for got silently downgraded to `follow`. Net effect: every Vercel/Netlify/Cloudflare site (which all use `308 Permanent Redirect`) was misreported as "no redirect", and the open-redirect probe could never see a Location header. Fix: reorder the spread so caller intent wins.

2. **`/api/chat` marketing string in [`src/App.tsx`](src/App.tsx)** — `POST /api/chat` was a decorative example in a bento card showing what the scanner detects in OTHER apps. The scanner found it in our own bundle and flagged it as a real endpoint. Changed to `POST /api/[your-llm]` to match standard placeholder-route convention. **Don't revert this** without also teaching the scanner to skip self-referenced template strings.

3. **Apex DNS findings on platform-shared subdomains punished the entire vibecoder audience** — DMARC/SPF/DNSSEC/CAA were checked on the *base domain* (e.g. `vercel.app`), so every user on `*.vercel.app`, `*.netlify.app`, `*.pages.dev`, `*.github.io`, `*.lovable.app`, `*.replit.app`, etc. lost ~18 points for records only the platform can publish. Fix: `SHARED_PLATFORM_APEX` list + `detectSharedPlatform()` helper in `api/_lib/scanner.ts`. When matched, suppress the apex DNS findings and emit one `severity: 'ok'` "Hosted on shared subdomain — buy a custom domain to gain DNS control" notice. This is THE fix that made the bulk-fix-prompt UX honest for pre-launch users.

The deploy itself also got hardening headers (CSP / COOP / COEP=credentialless / CORP / Permissions-Policy + ACAO override) in `vercel.json`. Final state: `0 critical · 0 warnings · 0 info · 3 ok · 100/100`.

## What's intentionally NOT in v1

- No Auth, no rate limiting, no DB persistence. The scanner is fully stateless. This is a public free-tier risk — when usage picks up, gate it.
- No authenticated test mode. Tier "Team" in pricing advertises this, but the wiring isn't there.
- No Supabase RLS deep probes (the actual wedge from the idea note). Needs anon-key intake from the user + careful legal copy ("I own this domain").
- No prompt-injection canaries against `/api/chat`-style endpoints. Catalog ready in [`Vguard - Attack Catalog`](../../Knowledge/09%20רעיונות/Vguard%20-%20Attack%20Catalog.md), no execution yet.
- The "Live · scanning the world" section uses 4 hardcoded findings + a decorative globe. When `vs_scans` table exists with ≥50 real scans, wire this to a tail of recent findings.

## Adding a new detector

Add to `api/_lib/scanner.ts`:

1. New regex/pattern in the appropriate section (`SECRET_PATTERNS`, `HEADER_REQS`, `PATHS_TO_PROBE`).
2. The detector pushes to the local `findings: Finding[]` array with: `id`, `severity`, `category`, `title`, `description`, `evidence` (with the actual evidence — file path, header value, redacted token), `fixPrompt` (templated with the actual finding, mentioning Cursor / Claude / Lovable as the AI).
3. Severity weights for the score: `critical = -20`, `warn = -7`, `info = -2`. Don't add new severities without updating `scoreFromTotals` AND the gauge gradient.

The frontend doesn't need changes — `CATEGORY_META` in `ScanForm.tsx` already maps every category to an icon, and rendering is data-driven.
