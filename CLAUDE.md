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

### Stage 3 — Verified Deep Scan (🟡 scaffolded, partially implemented)
Aggressive probing that's only legal/ethical when the user proves they own the target.

**Three verification methods (any one suffices):**

1. **File challenge** — Vguard issues a UUID. User uploads `https://<domain>/.well-known/Vguard-verify.txt` containing the UUID. We GET the file, match — verified.
2. **DNS TXT** — User adds `_Vguard-verify.<domain> TXT "<uuid>"`. We `dns.resolveTxt`. Slower but works for sites that can't easily upload files.
3. **Vercel personal access token (live 2026-05-02)** — user pastes a token from vercel.com/account/tokens. `/api/verify-vercel-token` calls Vercel API to list the user's projects + team projects, checks domain alias match, marks verified, discards token. **Why not OAuth?** Vercel doesn't expose an API to create OAuth Integrations; the OAuth Integration registration is UI-only at vercel.com/dashboard/integrations/console. The paste-token path achieves the same proof (the user must hold a token from the Vercel account that owns the domain) without that one-time UI step. The OAuth flow code (`api/oauth/vercel/start.ts` + `callback.ts`) remains dormant in the repo for the day Royi sets up the Integration.

**What Stage 3 unlocks:**
- Real Supabase RLS testing (drive the anon key against every public.* table, look for unauthorized SELECT)
- Storage bucket write-test (try uploading a benign file, see if it succeeds without auth)
- Aggressive XSS / SQLi payload library (beyond the canary single-quote)
- Admin route fuzzing (200 candidate paths, not 33)
- Full path-traversal probing (`?file=../../etc/passwd`)
- Mass-assignment testing on detected forms
- Authenticated mode (user enters test creds, we probe IDOR)

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

### Build order

1. ✅ Stage 1 — done (this is what's live)
2. 🟡 Stage 3 verification challenge first — easier than Stage 2, unlocks the deep-scan TOS framework. Build file-challenge + DNS TXT before OAuth.
3. 🟡 Stage 2 — Playwright on Railway. Build after Stage 3 because Stage 2 deep findings should be saved to the verified-scan record.
4. Authenticated mode (subsection of Stage 3) — last, requires careful UX to handle credential intake safely.

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
| Live URL (canonical) | `https://vibesecure-tau.vercel.app` | Original, stays. |
| Live URL (new alias) | `https://vguard-tau.vercel.app` | Added 2026-05-05, also serves the latest deploy. |
| Vercel project | `vguard` (renamed from `vibesecure`) — `prj_T7NIVw968V5i9QBQ54OkUhtMV1HD` in team `team_evbzoCbdWuVIB4ZDwEfZ0Oeg` | Project name is `vguard`; both domains bound to it. |
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
