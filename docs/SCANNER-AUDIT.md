# Vguard — Scanner Audit Document

> Full technical breakdown of the Vguard URL security scanner.
> Version: 2026-05-08. Source-of-truth: `api/_lib/scanner.ts` (~3600 lines), `api/_lib/scoring-engine.ts`, `api/scan-browser-assisted.ts`, `api/_lib/deep-scanner.ts`. All file:line references in this doc point to the live tree at `https://github.com/roi-ai-co-il/vguard`.

---

## Table of Contents

1. [Input Handling](#1-input-handling)
2. [Passive Checks](#2-passive-checks)
3. [Active Checks](#3-active-checks)
4. [Vulnerability Detection](#4-vulnerability-detection)
5. [Scoring Engine](#5-scoring-engine)
6. [Output to the User](#6-output-to-the-user)
7. [Limitations](#7-limitations)
8. [Final Reference Table](#8-final-reference-table)

---

## 1. Input Handling

### 1.1 What happens when the user enters a URL

1. The user submits a URL via `<form>` in `src/components/ScanForm.tsx`. The form posts JSON `{ url }` to `POST /api/scan` (`api/scan.ts:80-89`).
2. Server-side handler receives the body, validates the URL string, and invokes `runScan(url)` from `api/_lib/scanner.ts`.
3. The scanner runs all detectors in parallel where possible (DNS lookups, TLS probe, OPTIONS request, path probes, active probes, bundle fetches), then synthesizes findings, runs the scoring engine, and returns a `ScanResponse` JSON.

### 1.2 URL normalization

- The raw input is parsed with the WHATWG `URL` constructor (`scanner.ts:1776-1801`).
- Trailing whitespace is trimmed; relative paths are rejected; non-`http(s):` schemes (`javascript:`, `data:`, `file:`) are rejected outright.
- The normalized URL is reused for every downstream check so scheme/host casing is consistent.

### 1.3 Validation

- URL must start with `http://` or `https://` (`scan.ts:80-89`).
- Hostname must be a registered DNS name (validated by `URL.hostname` parse + lowercase).
- A 400 response with `code: 'invalid_url'` is returned on any parse failure.

### 1.4 Blocked / private IP checks (SSRF guard)

`isPrivateHost(host)` (`scanner.ts:417-426`) rejects:

| Pattern | Block |
|---|---|
| `localhost`, `0.0.0.0`, `127.x.x.x` | loopback |
| `10.x`, `172.16-31.x`, `192.168.x` | RFC1918 |
| `169.254.x` | link-local |
| `*.local` | mDNS |

The check runs **before any network access**. The result is a `code: 'blocked_by_target'` ScanError. This prevents Vguard from being used as an internal-network probe (SSRF).

### 1.5 Redirect handling

- The main fetch follows up to 5 redirects (`scanner.ts:1873-1920`).
- Each `Location` header is captured; the final URL is stored in `meta.finalUrl` and shown to the user.
- Redirect loops are detected and reported (`code: 'unreachable'`).
- HTTP→HTTPS redirect is **separately probed** (see §2.4) — this is part of the scoring, not just the redirect-following behavior.

### 1.6 Timeout limits

| Constant | Value | Where |
|---|---|---|
| `FETCH_TIMEOUT_MS` | 4000 ms | main HTML fetch |
| `PROBE_TIMEOUT_MS` | 2500 ms | each parallel probe (TLS, DNS, path probe, active probe) |
| `BUNDLE_TIMEOUT_MS` | 4000 ms | each JS bundle fetch |
| `MAX_BUNDLE_SIZE` | 2 MB | per bundle |
| `MAX_BUNDLES` | 4 | total bundles fetched |
| Total scan budget | ~10 s | designed for Vercel free-tier (10 s function limit) |

All probes are non-fatal: a probe timeout doesn't abort the scan, it just produces no finding for that probe.

### 1.7 User-Agent strategy

- **Default UA** (`scanner.ts:25-26`): a complete Chrome/131 string with no Vguard suffix. Sites with mild bot-protection accept this.
- **Stealth UA + headers** (`scanner.ts:31-53`, retried on 403/406/429/451): adds full `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Sec-Fetch-Dest/Mode/Site/User`, `Upgrade-Insecure-Requests`, varied `Accept-Language`, `Referer` set to the target's own origin. Cloudflare's managed challenge scores header completeness — not just UA.
- **One stealth retry per scan**, attempted only after the first 4xx WAF response. If it succeeds, the scan continues with the second response. If it fails, the scan returns a structured `blocked_by_waf` error with the detected vendor + a `Stage 2 / Stage 3` next-step CTA.

### 1.8 Stage flow

```
URL submitted
   |
   v
Stage 1 (Passive Scan, ~2-10s, no auth)  -- api/scan.ts -> api/_lib/scanner.ts
   |
   |-- if WAF blocks: structured error + recommend Stage 2
   |
   v
Stage 2 (Browser-Assisted, optional)     -- api/scan-browser-assisted.ts (Railway worker) OR bookmarklet
   |
   v
Stage 3 (Verified Deep Scan, requires ownership proof) -- api/scan-deep.ts -> api/_lib/deep-scanner.ts
```

---

## 2. Passive Checks

Everything in this section happens **without sending anything that looks like an attack**. It's the equivalent of an external auditor reading the response — no probing, no payloads.

### 2.1 DNS checks (`scanner.ts:535-584`, audit logic 2693-2949)

| Record | What's checked | Severity assigned |
|---|---|---|
| **SPF** (`v=spf1`) | TXT records on apex; counts mechanisms; flags `~all`/`?all` (soft-fail) | `info` -> `warn` if soft-fail or absent |
| **DMARC** (`_dmarc.<domain>`) | `p=` policy: `none`/`quarantine`/`reject` | `info` (none/quarantine), `ok` (reject) |
| **DKIM** | Brute-checks 25 common selectors at `<sel>._domainkey.<domain>`: default, google, selector1, selector2, s1, s2, k1, k2, mail, dkim, resend, amazonses, postmark, sg, sm, mailgun, fm1, fm2, fm3, protonmail, zoho, mxvault | `info` per discovered selector; never reports "missing DKIM" because we can't enumerate exhaustively |
| **CAA** | TXT/CAA records: `issue`, `issuewild`, `iodef` | `info` if missing |
| **DNSSEC** | DOH query to `1.1.1.1`; `AD` (authenticated data) flag | `info` if missing/not validated |
| **MX** | Used to detect mail-receiving domains (informs DMARC/SPF severity) | `meta` only |
| **NS** | Authoritative nameserver list | `meta` only |
| **TXT (full)** | Used for verification records, additional signals | `meta` only |
| **CNAME takeover** | Compares CNAME target against `TAKEOVER_PRONE_HOSTS` (github.io, herokuapp, vercel.app, netlify.app, cloudfront.net, s3.amazonaws.com, azurewebsites.net, elasticbeanstalk.com, bitbucket.io, firebaseapp.com, pages.dev, fly.dev) | `critical` if CNAME target unregistered |

DNS lookups are bounded by `PROBE_TIMEOUT_MS` (2.5s each).

### 2.2 HTTP / HTTPS availability

- The main fetch tries the user-supplied scheme.
- If `http://...` is given, Vguard records it but **also** probes `https://<host>` to compare.
- A separate http->https redirect probe runs in parallel (see §2.4).

### 2.3 TLS / SSL checks (`scanner.ts:586-645`, audit 2621-2673)

| Check | Method | Severity |
|---|---|---|
| **TLS protocol version** | `node:tls.connect`, read `socket.getProtocol()` (e.g., `TLSv1.3`) | `critical` if < TLSv1.2 |
| **Cipher suite** | `socket.getCipher().name` | `critical` if NULL/EXPORT/RC4/3DES; `warn` if CBC mode without AEAD |
| **Cert expired** | `cert.valid_to` parsed; compared to `now()` | `critical` |
| **Cert expiring soon** | `cert.valid_to < now + 30d` | `warn` |
| **Self-signed** | `cert.issuer.CN === cert.subject.CN` | `warn` |
| **Cert chain** | Chain is read; intermediates not validated server-side in Stage 1 (Stage 2 browser does proper PKIX validation) | `meta` only |
| **HSTS preload eligibility** | Inferred from cert + HSTS header (see §2.5) | `info` |

TLS probe runs against port 443 with `rejectUnauthorized: false` so we **see** broken certs without the connection failing.

### 2.4 HTTP -> HTTPS redirect

- Probes `http://<hostname>/` (root only).
- A 301/302/307/308 with `Location: https://...` = pass.
- Anything else (200 on plain HTTP, no redirect, error) = `warn` `tls-no-http-redirect`.

### 2.5 Security headers (`HEADER_REQS` at `scanner.ts:271-340`, audited at 1988-2098)

Every header below is queried from the main response. "Missing" = absent; "Weak" = present but mis-configured.

| Header | Default severity if missing | Weak-config severity | Notes |
|---|---|---|---|
| **Content-Security-Policy** | `warn` (`headers-csp-missing`) | `critical` if `script-src` allows `'unsafe-inline'` / wildcard scheme; `warn` for weak `default-src` / `style-src` / `connect-src` | Tokenized per RFC; `nonce-`/`hash-`/`'strict-dynamic'` recognized as mitigations |
| **Strict-Transport-Security** (HTTPS only) | `warn` (`headers-hsts-missing`) | `warn` if `max-age < 31536000`; `info` if `preload` missing | Numeric `max-age` validated |
| **X-Frame-Options** | `warn` | `warn` if `ALLOW-FROM` (deprecated, browser-inconsistent) | `SAMEORIGIN`/`DENY` are accepted; CSP `frame-ancestors` is treated as equivalent |
| **X-Content-Type-Options** | `warn` | n/a | Must equal `nosniff` |
| **Referrer-Policy** | `info` | `info` -> `warn` for `unsafe-url`, `no-referrer-when-downgrade`, `origin` | Browsers default to `strict-origin-when-cross-origin` (acceptable fallback) |
| **Permissions-Policy** | `info` | `warn` if `geolocation`/`microphone`/`camera`/`payment`/`usb` allowed via `*` | Per-directive analysis |
| **Cross-Origin-Opener-Policy** (COOP) | `info` | n/a | Defense-in-depth — engine treats absence as low-impact (see §5) |
| **Cross-Origin-Embedder-Policy** (COEP) | `info` | n/a | Same |
| **Cross-Origin-Resource-Policy** (CORP) | `info` | n/a | Same |
| **Server / X-Powered-By** | n/a | `info` if version-leaking | Triggers CVE matching (§4.13) |

CSP weakness analysis is the deepest header check (`scanner.ts:2006-2066`). It tokenizes the policy, classifies each directive, and emits a separate finding for each directive that's missing or weakened. The new scoring engine treats a CSP **with** unsafe-inline as a `configurationFlaw` trait, which scores higher than a CSP that's just absent — because misconfiguration is more dangerous than absence (the developer thinks they're protected).

### 2.6 Cookie flags (`scanner.ts:2118-2168`)

Each `Set-Cookie` header on the main response is parsed (case-insensitive) into name/value/flags:

| Flag | Detection | Severity | Notes |
|---|---|---|---|
| **Secure** | Token `; Secure` present | `critical` if absent **on HTTPS** | HTTP cookies expected to lack Secure |
| **HttpOnly** | Token `; HttpOnly` present | `critical` if absent on cookies whose name matches `/sess\|auth\|token\|jwt\|sid\|csrf/i` | Plain UI/preference cookies don't trigger |
| **SameSite** | `SameSite=Lax/Strict/None` | `warn` if `Lax` or absent on auth-named cookies; `critical` if `None` without `Secure` | Spec violation (None requires Secure) |

### 2.7 Source-map disclosure (`scanner.ts:2407-2443`)

- Each fetched bundle is scanned for `sourceMappingURL` comments.
- The referenced `.map` file is fetched (HEAD then GET).
- A 200 response = `warn` `sourcemaps-exposed` finding with the URL as evidence.

### 2.8 Mixed content (passive)

- The HTML body is scanned for absolute `http://` URLs in `src=`/`href=`/`action=` attributes.
- Each occurrence is classified by tag (script, image, link, form).
- `critical` if a script/iframe/form action is plain HTTP on an HTTPS page; `warn` for image/CSS.

### 2.9 Subresource Integrity (SRI)

- `<script src="...">` and `<link rel="stylesheet" href="...">` to **cross-origin** hosts are checked for `integrity="sha384-..."`.
- Missing SRI on cross-origin tag = `info` `integrity-no-sri`.

### 2.10 CDN / WAF detection (`detectWafVendor` at `scanner.ts:65-127`)

Header signatures are checked **in order of specificity** (most specific wins):

| Vendor | Strongest signal | Other signals |
|---|---|---|
| **Cloudflare** | `cf-ray` header | `cf-cache-status`, body `__cf_bm`, "Attention Required! \| Cloudflare" |
| **Akamai** | `Server: AkamaiGHost` | `x-akamai-transformed`, `akamai-grn` |
| **Imperva / Incapsula** | `x-iinfo` | `x-cdn: Incapsula`, body "Incapsula incident id" |
| **Fastly** | `fastly-debug-digest` | `x-served-by: cache-*` + `via: varnish` |
| **AWS CloudFront** | `x-amz-cf-id` | `via: CloudFront` |
| **AWS WAF** | CloudFront + body "Request blocked" | distinguishes from CloudFront alone |
| **Vercel BotID** | `x-vercel-id` + body "Security Checkpoint" / "BotID:" | |
| **Sucuri** | `Server: SucuriWAF` / `Sucuri/Cloudproxy` | `x-sucuri-id` |
| **StackPath** | `Server: StackPath` / `Highwinds` | `x-stackpath-*` |
| **DDoS-Guard** | `Server: DDoS-Guard` | body markers |

If a 403/406/429/451 came back with no recognizable vendor signal, the WAF is recorded as `unknown` (still flagged).

CDN providers are recorded separately (`AttackSurface.cdn` field) — a site can sit behind a CDN without a WAF, or vice-versa.

---

## 3. Active Checks

Active checks **send a payload** to the target and look for response-level evidence. Vguard's active checks are intentionally narrow: only signals that can be detected with a single request per parameter, with a payload that doesn't change server state.

### 3.1 Which requests are sent

Every active probe is `GET` (no `POST`/`PUT`/`DELETE`/`PATCH`). No login attempts. No data writes. No file uploads. Path probes use `GET` with a 2.5s timeout.

### 3.2 Endpoint enumeration

- Discovery: HTML `<a href>` extraction + bundle string-scan for fetch URLs.
- Probing: `PATHS_TO_PROBE` list (see §4.6) — 33 candidate paths covering env files, VCS dirs, backups, admin panels, debug endpoints, well-known files.

### 3.3 Active payloads

| Probe | Payload | Where |
|---|---|---|
| **Open redirect** | `?<param>=https://example.com/` (canary external domain) | 7 params: `url`, `redirect`, `next`, `return`, `returnUrl`, `redirect_uri`, `continue` (`scanner.ts:1072-1097`) |
| **Reflected XSS** | `?<param>=vsxsscanary7q3` (unique alphanumeric token; **not** a script payload) | 6 params: `q`, `search`, `query`, `s`, `name`, `id` (`scanner.ts:1100-1115`) |
| **SQL injection** | `?<param>='` (single quote — error-based detection only) | 5 params: `id`, `q`, `search`, `page`, `category`. Response body is then matched against 10 SQL error patterns (MySQL, PostgreSQL, SQLite, MSSQL, Oracle, MongoDB) (`scanner.ts:1184-1223`) |
| **Path traversal** | Not in Stage 1. Stage 3 only. | |
| **Subdomain takeover** | Passive — DNS CNAME comparison only. No payload. | |

**Why no "real" XSS payloads?** A reflected canary that the server echoes back unencoded is sufficient evidence of an XSS surface. Sending an actual `<script>` would be the same finding with worse legal optics.

### 3.4 How destructive testing is avoided

1. **GET only** — no state changes.
2. **No login attempts** in Stage 1. No credential harvesting.
3. **Canary payloads are visibly non-malicious** — the `vsxsscanary7q3` token contains no HTML/JS; the open-redirect canary is `example.com`; the SQLi canary is a single `'`.
4. **Probe rate is ~30 requests total** for Stage 1 across all detectors. No directory bursting, no brute force.
5. **Private hosts are blocked** before any active probe (§1.4).
6. **Stage 3** (deep scan) requires **proof of ownership** before any aggressive probing — file challenge / DNS TXT / Vercel personal token (see §7).

### 3.5 Rate limits

- Vguard itself rate-limits its own probes via the parallel-fetch budget (~10s total).
- No per-target throttling beyond the timeout — but the total request count per scan is ~30-60 (well under any sane WAF threshold).
- There is currently **no Vguard-level user rate limit** — anyone can scan freely. (Documented limitation; see §7.)

### 3.6 User-Agent for active probes

Active probes inherit the same `SCANNER_UA` (see §1.7). The UA string identifies the request as Chrome 131; there is no `Vguard/x.y` suffix on active-probe requests because that increases WAF block rates without helping the user.

### 3.7 Shallow vs deep

Stage 1 is **deliberately shallow** — fast, broad, low-risk. Deep probing (RLS testing, admin fuzzing with 200 paths, IDOR probes, mass-assignment testing) lives in Stage 3, gated behind ownership proof.

---

## 4. Vulnerability Detection

For every category below: **what's checked -> how it's detected -> evidence collected -> severity (passed to scoring engine, then dynamically reclassified — see §5) -> confidence -> false-positive guards.**

### 4.1 Cross-Site Scripting (XSS)

- **What:** reflected XSS via query parameters.
- **How:** unique canary `vsxsscanary7q3` injected into 6 common parameters; response body searched for the canary unescaped.
- **Evidence:** the parameter, the URL containing it, and a snippet of the body where the canary was reflected.
- **Severity:** `critical` (`paths-xss-reflected`).
- **Confidence:** `confirmed` — the reflection is observed.
- **FP guards:** canary is unique; only unencoded reflection counts; common search/filter param names only.
- **Limitations:** stored XSS, DOM XSS, and XSS in non-query input vectors are **not** detected in Stage 1.

### 4.2 SQL Injection (error-based)

- **What:** error-based SQLi — does the server leak a database error when given a single quote?
- **How:** `?<param>='` injected into 5 params; response body matched against 10 vendor error patterns.
- **Evidence:** the parameter, the matched error string, the URL.
- **Severity:** `critical` (`paths-sqli`).
- **Confidence:** `confirmed`.
- **FP guards:** 10 distinct error patterns; the error must appear in the response body (not generic 500 page).
- **Limitations:** blind SQLi (timing/boolean) is **not** detected. Stored-procedure / JSON-path SQLi not detected.

### 4.3 Open Redirect

- **What:** `?url=https://example.com/` causes the server to redirect to the canary.
- **How:** 7 common redirect parameters tested; both reflected-in-Location and reflected-in-body counted.
- **Evidence:** the parameter, the redirect target, the response status.
- **Severity:** `critical` if Location-based redirect; `warn` if echoed in body without redirect.
- **Confidence:** `confirmed`.
- **FP guards:** canary is unambiguous external domain; redirect must actually happen; 30x status required.

### 4.4 CORS misconfiguration (`scanner.ts:2100-2116`)

| Pattern | Severity |
|---|---|
| `Access-Control-Allow-Origin: *` **and** `Access-Control-Allow-Credentials: true` | `critical` (spec violation, allows credentialed cross-origin reads) |
| `Access-Control-Allow-Origin: null` | `critical` (any sandboxed iframe can access) |
| `Access-Control-Allow-Origin: <regex-like value>` (`.*example.com`, `.+`, `\|`) | `warn` |
| `Access-Control-Allow-Origin: *` with no credentials | `info` only (intended for public APIs; flagged for awareness) |

Detected by sending an `OPTIONS` preflight + reading the main response's CORS headers. Case-insensitive matching.

### 4.5 Exposed files / directory listing

- **Path probes** (`PATHS_TO_PROBE` at `scanner.ts:237-269`): 33 candidate paths.
- **Detection:** `GET /<path>`, treat 200 = exposed, 401/403 = protected (still informational), 404 = clean.
- **Evidence:** full URL, status code, first 1KB of body if 200.
- **Directory listing:** detected when path returns 200 + body contains `<title>Index of /` or Apache/Nginx default-listing markers.

### 4.6 Path probes — full list (33 paths, `scanner.ts:237-269`)

| # | Path | Severity if exposed | Category |
|---|---|---|---|
| 1 | `/.env` | critical | env |
| 2 | `/.env.local` | critical | env |
| 3 | `/.env.development.local` | critical | env |
| 4 | `/.env.production.local` | critical | env |
| 5 | `/.env.staging.local` | critical | env |
| 6 | `/.env.bak` | critical | env-backup |
| 7 | `/.env.backup` | critical | env-backup |
| 8 | `/.git/config` | critical | vcs |
| 9 | `/.git/HEAD` | critical | vcs |
| 10 | `/.git/refs/heads/main` | critical | vcs |
| 11 | `/.gitignore` | info | vcs-meta |
| 12 | `/.hg/` | warn | vcs |
| 13 | `/.svn/` | warn | vcs |
| 14 | `/config.json` | critical | config |
| 15 | `/config.php` | critical | config |
| 16 | `/web.config` | warn | config |
| 17 | `/web.config.old` | critical | backup |
| 18 | `/backup.tar` | critical | backup |
| 19 | `/backup.tar.gz` | critical | backup |
| 20 | `/backup.zip` | critical | backup |
| 21 | `/admin` | critical | admin |
| 22 | `/wp-admin` | critical | admin |
| 23 | `/phpmyadmin` | critical | admin |
| 24 | `/adminer.php` | critical | admin |
| 25 | `/swagger.json` | info | api-docs |
| 26 | `/openapi.json` | info | api-docs |
| 27 | `/api-docs` | info | api-docs |
| 28 | `/graphql` | info | api |
| 29 | `/debug` | warn | debug |
| 30 | `/status` | info | health |
| 31 | `/.well-known/security.txt` | info | meta |
| 32 | `/sitemap.xml` | info | meta |
| 33 | `/robots.txt` | info | meta |

A 30-page HEAD request budget per scan caps total probes.

### 4.7 Missing security headers

See §2.5. Each missing/weak header generates a finding. The dynamic engine then reclassifies them — for example, missing COOP/COEP/CORP/Permissions-Policy on a public marketing site land in the `low-hardening` UI bucket and barely move the score, while missing X-Frame-Options on a site with admin routes lands in `medium-weakness`.

### 4.8 Weak TLS

See §2.3. Detection is at the protocol level: TLS version, cipher suite, cert validity. The full TLS chain is recorded; weaknesses are flagged.

### 4.9 Information disclosure

Three sources:

- **Server header / X-Powered-By** — version leakage flagged as `info`; if the version matches a known CVE range (see §4.13), severity escalates to `critical`.
- **Source maps** — see §2.7. Source-code disclosure if `.map` files are publicly served.
- **JS bundles** — see §4.11 for secret detection. Stack traces, internal URLs (10.x / 192.x / *.local), and absolute file paths in error messages are flagged via `paths-stacktrace` when detected in a 5xx response body.

### 4.10 Admin / debug panels

- 11 paths in `PATHS_TO_PROBE` cover the most common admin surfaces.
- 200 = `critical` `paths-admin`; 302 to a login page = `warn` (admin exists but auth-gated).
- Stage 3 expands this to ~200 candidate paths after ownership verification.

### 4.11 Secret detection (`SECRET_PATTERNS` at `scanner.ts:163-233`, `js-ast.ts`)

Bundles are fetched (max 4 × 2 MB) and scanned with regex + JS AST analysis.

| Pattern | Provider | Severity | Format |
|---|---|---|---|
| `sk-ant-api03-[A-Za-z0-9_-]{32,}` | Anthropic | critical | API key |
| `sk-proj-[A-Za-z0-9_-]{32,}` | OpenAI (project) | critical | API key |
| `sk-[A-Za-z0-9_-]{20,}` | OpenAI (legacy) | critical | API key |
| `AIza[0-9A-Za-z\-_]{35}` | Google | critical | API key |
| `ghp_[0-9a-zA-Z]{36,255}` | GitHub | critical | PAT |
| `github_pat_[0-9a-zA-Z]{22,255}` | GitHub | critical | fine-grained PAT |
| `sk_live_[0-9a-zA-Z]{20,}` | Stripe | critical | live secret key |
| `xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,34}` | Slack | critical | bot token |
| `re_[0-9a-zA-Z]{24,}` | Resend | critical | API key |
| `AKIA[0-9A-Za-z]{16}` | AWS | critical | access key ID |
| JWT `eyJ.eyJ.eyJ`, decoded -> `role: "service_role"` | Supabase | critical (highest priority) | service-role JWT |

**Redaction:** when a secret matches, only the first 8 + last 4 chars are returned in `evidence`. The full match never leaves the server (`scanner.ts` `redact()` at line 360).

**False-positive guards:**
- Specific provider prefixes — generic `sk-` is the highest FP risk and is deprioritized in scoring.
- JWT decoder validates base64 + structure before extracting claims.
- AST analysis (`js-ast.ts`) suppresses static-template-literal RHS for DOM-sink detection — the React invariant pattern in framework code is specifically suppressed via preceding-statement pattern matching.

### 4.12 Supabase / Firebase / S3 (passive)

- **Supabase project IDs:** detected from bundle URLs matching `https://<projectId>.supabase.co`. Anon keys (JWT with `role: "anon"`) are extracted but treated as informational (anon keys are public by design). Service-role JWTs are critical.
- **Supabase Storage buckets:** 10 common bucket names probed (avatars, public, images, uploads, files, media, attachments, profiles, documents, assets) (`scanner.ts:841-901`).
- **Supabase Edge Functions:** 11 common function names probed via OPTIONS (`scanner.ts:1118-1153`).
- **Firebase Realtime DB:** `/.json` endpoint on detected `*.firebaseio.com` host. 200 with JSON body = `critical` `paths-firebase-rtdb-root`.
- **Firebase Storage:** `/v0/b/<projectId>.appspot.com/o` probed (`scanner.ts:1100-1115`).
- **S3 buckets:** detected from bundle URLs; `?list-type=2` probe checks if ListBucket is enabled (`scanner.ts:904-925`).

### 4.13 Dependency CVE matching (`NPM_CVES` at `scanner.ts:928-1069`, `SERVER_CVES` at `scanner.ts:1276-1403`)

| Source | Detected packages |
|---|---|
| **npm bundles** | axios, lodash, next, jsonwebtoken, jquery, express, moment, minimist, node-fetch, follow-redirects, semver, webpack, xml2js, tar, undici (15 packages × multiple CVEs each) |
| **Server header** | Apache, nginx, IIS, PHP versions (4 server families) |

For each match, severity is `critical` if the version falls in a CVE range; `info` if the version is detected but not vulnerable (informational disclosure only).

### 4.14 Server / version leakage

`Server` and `X-Powered-By` headers are parsed (`scanner.ts:2545-2587`). Any version disclosure is `info` `meta-server-version-leak`. If the version maps to a CVE, severity escalates to `critical`.

### 4.15 AI endpoint / prompt injection signals

- AI endpoint references are detected from bundle URLs (8 patterns: openai, anthropic, google gemini, Azure OpenAI, Hugging Face, Replicate, Groq, Together).
- Prompt-injection signals: AST analysis flags dynamic-evaluation patterns (the `Function` constructor, runtime-evaluation calls on LLM output, unsanitized template literals where the LLM response flows into DOM).
- RAG context-leak signals: code patterns that concatenate user input + retrieved context into a single prompt without separator/role markers.

These are detected only when the relevant code is in the public JS bundle. Server-side prompts are invisible to Vguard.

### 4.16 HTML / form audit

- All `<form>` tags collected; method, action, fields enumerated.
- Forms with `method="POST"` over plain HTTP = `critical` `mixed-content-form`.
- Login forms (auto-detected by field names: password/email/username) without CSRF token = `warn` `auth-csrf-missing`.

---

## 5. Scoring Engine

The scoring engine is **dynamic and trait-based**. The current version (2026-05-08 v2) enforces a **strict Critical gate**: a finding may be `critical-exploit` ONLY when there is verified impact (real exploit, sensitive data observed in evidence, auth bypass demonstrated, usable server-side secret, confirmed SQLi error, confirmed reflected XSS in unsafe context, public write/delete confirmed, .env / .git with real sensitive content, weak TLS allowing real downgrade, expired cert).

**Passive signals are not vulnerabilities.** CSP weakness, unsafe-inline / unsafe-eval, missing CSP directives, missing security headers, cookies without Secure on non-auth cookies, DOM sinks without taint flow, public 2xx APIs that return non-sensitive content, public client identifiers (Stripe `pk_*`, Firebase web SDK key, Supabase anon key, mapbox/recaptcha site keys, analytics tokens), visible admin login pages, source maps, robots.txt / sitemap / swagger / openapi, COOP/COEP/CORP/Permissions-Policy — all are `hardening-recommendations` or `informational-observations` unless paired with verified impact.

The previous engine treated CSP weakness + browser-surface as automatically high-impact. That punished enterprise sites (apple.com, amazon.com) for normal frontend architecture. **That escalation rule is removed.** All detectors still fire — the change is purely in classification, severity, risk class, score impact, caps, and UI grouping.

The legacy static `scoreFromTotals` (which deducted -20 / -7 / -2 per critical/warn/info) is retained only for back-compat debug compare; the live `vibeScore` comes from the new engine.

### 5.1 Trait extraction (`scoring-engine.ts:105-192`)

Every finding is analyzed and tagged with a subset of these 10 traits:

| Trait | Meaning |
|---|---|
| `exploitable` | Active probe hit OR runtime-observed (XSS canary reflected, SQLi error, RLS leak) |
| `secretLeak` | Leaks credentials or sensitive data once obtained |
| `authImpact` | Affects auth/authorization/RLS/admin surface |
| `publicExposure` | Reachable on the public web without credentials |
| `sensitiveData` | Could expose PII, financial data, session state |
| `browserSurface` | Increases browser-side attack surface (XSS, clickjack, mixed content) |
| `runtimeConfirmed` | Confirmed at runtime in Stage 2/3 (vs inferred passively) |
| `defenseInDepthOnly` | No exploit alone — only matters paired with another flaw |
| `configurationFlaw` | Header **misconfiguration** (e.g., CSP with unsafe-inline) vs absence |
| `highAbuseLikelihood` | Real-world attackers actively scan for this (env files, .git, source maps, live keys) |

Trait extraction is **pattern-driven**, not a per-finding table. Adding a new detector requires zero scoring-table edits.

### 5.2 Risk class (`scoring-engine.ts:198-236`)

Findings are grouped into 5 classes:

| Class | Trigger conditions | Base damage |
|---|---|---|
| `critical-exploit` | (exploitable AND runtimeConfirmed) OR (secretLeak AND highAbuseLikelihood) OR (plain-HTTP TLS finding) | 35 |
| `high-impact-misconfig` | secretLeak OR (authImpact AND severity!=info) OR (configurationFlaw AND browserSurface) OR exploitable | 18 |
| `medium-weakness` | severity in {critical, warn} not matching above; defense-in-depth on sensitive routes | 6 |
| `low-hardening` | defenseInDepthOnly on non-sensitive routes (COOP/COEP/CORP/Permissions-Policy on marketing pages) | 1.5 |
| `informational` | severity = info or below | 0.2 |

### 5.3 Confidence (`scoring-engine.ts:238-248`)

| Confidence | Multiplier | Trigger |
|---|---|---|
| `confirmed` | 1.00 | `runtimeConfirmed`, OR exploitable + highAbuseLikelihood |
| `likely` | 0.85 | severity = critical/warn, passive evidence |
| `informational` | 0.60 | severity = info, defense-in-depth-only |

### 5.4 Per-finding risk score (`scoring-engine.ts:254-288`)

```
raw = CLASS_BASE[riskClass] * CONFIDENCE_MULTIPLIER[confidence]
    + (runtimeConfirmed       ? +0.6 : 0)
    + (highAbuseLikelihood    ? +0.4 : 0)
    + (configFlaw + browserSurface ? +0.5 : 0)
    + (authImpact + sensitive route ? +0.5 : 0)
    + (sensitiveData + sensitive route ? +0.3 : 0)
    - (defenseInDepthOnly + public route ? 0.5 : 0)
riskScore = clamp(raw, 0, 10)  // rounded to 1 decimal
```

`riskBand`: severe >=8, high >=6, medium >=3, low <3.

### 5.5 Vibe Score aggregation — diminishing returns (`scoring-engine.ts:294-320`)

This is the key change from the old static formula.

For each risk class, sort the per-finding `scoreImpact` descending, then apply factor 1.00, 0.60, 0.36, 0.22, 0.13, ... (×0.6 per step):

```
totalPenalty = sum_per_class( diminishingSum(scoreImpacts) )
vibeScore    = clamp(100 - totalPenalty, 0, 100)
```

**Why:** 10 missing-COOP findings cannot drown out 1 leaked Stripe key. The first hit in each class lands at full strength; subsequent hits decay quickly. A wall of low-hardening misses tops out at ~5 points off the score — realistic for "site is fine, just not hardened".

### 5.6 What lowers the score

| Class | First-hit damage | Realistic max from class |
|---|---|---|
| `critical-exploit` | up to 35 pts | ~58 pts (saturates fast — 1 critical = bad day) |
| `high-impact-misconfig` | up to 18 pts | ~30 pts |
| `medium-weakness` | up to 6 pts | ~10 pts |
| `low-hardening` | up to 1.5 pts | ~2.5 pts (a swarm of 10 advanced-hardening misses) |
| `informational` | up to 0.2 pts | ~0.3 pts |

### 5.7 What does NOT lower the score

- Findings with `severity: 'ok'` (positive findings — the equivalent of "this is configured correctly").
- The synthetic `meta-waf-detected` info finding (having a WAF is good, not bad).
- Detected framework versions when not vulnerable (informational disclosure only).
- DKIM selector discovery (informational).
- Sitemap/robots.txt presence (informational).

### 5.8 Verified-impact gate (the new strict policy)

A finding becomes `critical-exploit` only if at least one of these is true:

- An active probe verified the exploit (XSS canary reflected unencoded, SQLi error pattern matched, open-redirect Location followed).
- A confirmed server-side secret was found (Supabase service-role JWT, Stripe live secret, AWS, Anthropic, OpenAI, GitHub PAT) AND it is not a public client identifier.
- A `.env` / `.git` / backup file returned 200 AND the body contains real sensitive content (matched against `SENSITIVE_BODY_PATTERNS`: PEM private keys, `DB_PASSWORD`, `STRIPE_SECRET_KEY`, `Authorization: Bearer`, etc.).
- TLS is critically broken: cert expired, version below TLS 1.2, plain-HTTP serving on what should be HTTPS.
- Stage 3 confirmed RLS broken / public storage write / unauth admin data / mass-assignment / IDOR / path-traversal.
- Authenticated runtime confirmed an auth bypass.
- Subdomain takeover-ready (CNAME points to NXDOMAIN platform suffix).
- Mixed-content form submitting credentials over HTTP.

If none of these is true, the finding cannot be `critical-exploit` — regardless of its declared severity in the detector. Examples that explicitly **do not** qualify:

- CSP missing / CSP with unsafe-inline / unsafe-eval / wildcard / missing base-uri / frame-ancestors / form-action -> `low-hardening` (default), max upgrade `medium-weakness` on a sensitive route.
- Cookie without Secure on a non-auth cookie -> `low-hardening`. Auth cookie -> `medium-weakness`. Never `critical-exploit` without a confirmed session compromise.
- DOM sinks (innerHTML / outerHTML / insertAdjacentHTML / doc-write) without taint flow -> `informational`. Upgrade requires user-controlled source reaching sink + no sanitizer + runtime confirmation.
- Public 2xx API endpoint with non-sensitive content (locale, nav, search-suggestions, health, public config) -> `informational`.
- Frontend public client identifier (Firebase web SDK key, Supabase anon JWT, Stripe pk_*, Mapbox token, Sentry DSN, reCAPTCHA / Turnstile / hCaptcha site keys, GA / GTM tokens) -> `informational`.
- Visible admin login page (302 -> /login or 200 with a sign-in form) -> `informational`. Critical only if the dashboard data or admin actions are reachable without auth.
- Source maps, robots.txt, sitemap.xml, swagger.json, openapi.json, /.well-known/*, /status -> `informational`.
- COOP / COEP / CORP / Permissions-Policy / Referrer-Policy missing -> `low-hardening`.

### 5.9 Impact-aware caps (no verified impact = no Critical band)

When `hasVerifiedImpact === false`, these caps apply. Note: **there is no artificial vibeScore floor.** The per-class caps alone bound the worst-case penalty to ~15 (so the natural floor is ~85), and a site with many hardening gaps legitimately loses points down toward that — we don't fake a perfect score.

| Cap | Value |
|---|---|
| `aggregateBand` ceiling | `low` (never `medium` / `high` / `severe`) |
| Hardening-only total penalty | <= 10 pts |
| Informational-only total penalty | <= 1 pt |
| Cookie/header/CSP-only combined penalty | <= 15 pts |
| Effective natural floor (worst case, no verified impact) | ~85 |

This is what makes apple.com / amazon.com profile-style scans return scores in the 85-95 range despite a fistful of CSP misconfigurations, missing modern headers, public 2xx APIs, and visible login pages. The only way the score breaks past ~85 is a verified exploit. The only way the band shows above `low` is a verified exploit.

**The scanner distinguishes "could be improved" from "actively dangerous."** Passive frontend architecture patterns are not treated like confirmed exploits, and a confirmed exploit (one verified XSS, one usable secret, one expired cert) immediately lifts the caps and drives the score down honestly.

### 5.10 UI grouping (5-bucket model)

Findings are split into five separate sections:

| UI group | Risk classes inside | What the user sees |
|---|---|---|
| **Confirmed vulnerabilities** | `critical-exploit` (verified) | "Fix now" — exploit-confirmed findings only |
| **Likely risks** | `high-impact-misconfig` | "Likely exploitable but not yet runtime-confirmed" |
| **Needs review** | `medium-weakness` | "Worth investigating — auth-cookie hardening, sensitive-route header gaps" |
| **Hardening recommendations** | `low-hardening` | "Improve when you have time — CSP weakness, advanced hardening headers, defense-in-depth" |
| **Informational observations** | `informational` + `ok` | "FYI — framework, WAF, public assets, public client identifiers, clean checks" |

A site with vibeScore=90 and zero `confirmed-vulnerabilities` is **legitimately secure-enough** for production — the gap is hardening, not exploits.

---

## 6. Output to the User

### 6.1 What the user sees on the UI

Returned by `POST /api/scan` as `ScanResponse` JSON:

| Field | Shown as |
|---|---|
| `vibeScore` (0–100) | Big radial gauge with severity gradient (red -> amber -> green) |
| `aggregateRisk` (0–100, inverse) + `aggregateRiskBand` | Risk-level chip ("low" / "medium" / "high" / "severe") |
| `totals` | `0 critical · 4 warn · 8 info · 1 ok` chips |
| `findings[]` | Each rendered with: severity dot, category icon, title, expandable description, evidence block, **fix prompt** (paste-ready for Cursor/Claude/Lovable) |
| `findings[].riskScore` (0.0–10.0) + `riskBand` | Per-finding chip — used to rank within a severity bucket |
| `findings[].riskClass` + `confidence` + `uiGroup` | Drives the new 3-section grouping (Security Risks / Hardening Improvements / Informational) |
| `meta.finalUrl` | Final URL after redirects, shown in the report header |
| `meta.detectedFramework` (+ version, React version) | "Next.js 16.2.6" chip |
| `meta.routeContext` | "sensitive" / "public" / "unknown" — surfaces why a header miss might be weighted higher |
| `attackSurface` | A flat machine-readable map: domains, endpoints, third-party scripts, auth providers, data stores. Rendered as both a JSON download and an ASCII tree. |
| Stage 2 / Stage 3 CTAs | Surfaced when WAF blocks Stage 1, or when the user explicitly opts in |

### 6.2 Per-finding details

Every finding includes:

- **Title** — one short sentence: "Source map exposed at /assets/index.js.map".
- **Description** — 2-3 sentences explaining the impact.
- **Evidence** — the actual data: redacted secret prefix, exposed URL, header value, response status.
- **Fix prompt** — multi-step Markdown prompt (`api/_lib/fix-prompt-composer.ts`): root cause + per-finding playbook + per-category vitest regression test pinned to this exact evidence + anti-patterns block + minimum-blast-radius guardrails + rollback command + report-back checklist. Paste-ready for any AI coding agent.
- **Rescan link** — `https://v-guards.com/?url=<host>&deepscan=1` after the fix is shipped.

### 6.3 What is hidden from the user

- **Full secret values** — only first 8 + last 4 chars, never the middle.
- **Internal probe details** — the user doesn't see "we sent 30 GETs"; they see the findings.
- **Stage 2 / Stage 3 collected data** — JWT tokens visible in browser context are flagged but not displayed in full.
- **Vguard's own scoring math** — the user sees the score and the per-finding `riskScore`, not the trait extraction details (those live in this audit doc).
- **Headers used during stealth retry** — internal anti-WAF logic, not surfaced.
- **The legacy `scoreFromTotals` value** — kept for debug compare only.

### 6.4 Audit log

Every scan is logged in Supabase `vs_audit_log` (target URL, timestamp, IP hash, user agent, vibeScore, top finding ids). No PII; no payloads stored.

---

## 7. Limitations

The scanner is intentionally **not a full pentest tool**. The following are **out of scope**:

| Out of scope | Reason |
|---|---|
| **Authenticated areas** | No login attempts in Stage 1. Stage 3 supports authenticated mode only after explicit ownership proof + user-supplied test credentials. |
| **Full pentest logic** | No exploitation chains, no privilege-escalation testing, no AD enumeration. |
| **Business logic bugs** | E-commerce coupon abuse, race conditions on credit-deduction, two-factor bypass via business-rule edge cases — none detectable from outside. |
| **Internal network issues** | SSRF guard prevents private-IP scanning by design (§1.4). |
| **Issues requiring login** | Most IDOR, mass assignment, broken access control — needs valid session. Stage 3 attempts a subset with provided credentials. |
| **WAF bypasses** | Vguard does **one** stealth retry (§1.7); when that fails, it routes the user to Stage 2 (browser-assisted) which runs in the user's own session and naturally bypasses WAFs. We don't develop WAF-evasion payloads. |
| **Advanced exploitation** | No payload mutation, no SSTI fuzzing, no XXE, no SSRF chain construction, no deserialization probing, no race-condition exploitation. |
| **Stored XSS / DOM XSS** | Stage 1 detects reflected only. Stage 2 (Playwright with mutation observers) is the path for these — partially shipped. |
| **Blind SQLi / time-based / boolean-based** | Only error-based SQLi in Stage 1. |
| **CSRF token validation** | Detected if absent on a login form; correctness of the token is not validated (would require a full auth round-trip). |
| **API authentication bypass** | OAuth scope confusion, JWT forgery, token replay — needs valid baseline credentials. Stage 3 only. |
| **Source-code review** | Vguard reads the **bundled output** and source maps if exposed. It does not review the original source repo (that's CodeQL/Snyk's job). |
| **Compliance audits** | No PCI-DSS / HIPAA / SOC 2 control mapping. Findings are technical, not regulatory. |
| **Mobile apps / native code** | URL-based scanner only. iOS/Android binaries out of scope. |
| **Rate limiting on the scanner itself** | Currently not enforced — anyone can run scans. Documented gap. |

---

## 8. Final Reference Table

| Stage | Check name | What it tests | Method | Risk impact (scoring class) | User-facing output |
|---|---|---|---|---|---|
| 1 | URL validation | Scheme + host parseable | WHATWG URL | (gate) | `code:invalid_url` if fails |
| 1 | SSRF guard | Private IP block | `isPrivateHost` regex | (gate) | `blocked_by_target` if private |
| 1 | Redirect follow | <=5 hops | `fetch` with manual redirect | (meta) | `meta.finalUrl` |
| 1 | DNS — SPF | TXT v=spf1, mechanism count, soft-fail | DNS resolveTxt | medium-weakness | finding `email-spf-*` |
| 1 | DNS — DMARC | _dmarc TXT, p= policy | DNS resolveTxt | medium-weakness / low-hardening | finding `email-dmarc-*` |
| 1 | DNS — DKIM | 25 selectors brute-checked | DNS resolveTxt × 25 | informational | finding `email-dkim-discovered` |
| 1 | DNS — CAA | issue/issuewild presence | DNS resolveCaa | low-hardening | finding `dns-no-caa` |
| 1 | DNS — DNSSEC | DOH AD flag | Cloudflare 1.1.1.1 DOH | low-hardening | finding `dns-no-dnssec` |
| 1 | DNS — CNAME takeover | TAKEOVER_PRONE_HOSTS match | DNS resolveCname | critical-exploit | finding `dns-subdomain-takeover` |
| 1 | TLS protocol | Version >= 1.2 | node:tls.connect | high-impact-misconfig | finding `tls-old-version` |
| 1 | TLS cipher | Suite strength | tls.getCipher | high-impact-misconfig | finding `tls-weak-cipher` |
| 1 | TLS cert expiry | valid_to vs now | cert.valid_to | high-impact-misconfig | finding `tls-cert-expired/expiring` |
| 1 | HTTP->HTTPS redirect | http://host returns 30x to https | fetch http://host | medium-weakness | finding `tls-no-http-redirect` |
| 1 | CSP | Header presence + per-directive analysis | header parse | medium-weakness or high-impact-misconfig (if unsafe-inline) | finding `headers-csp-*` |
| 1 | HSTS | Header + max-age + preload | header parse | medium-weakness | finding `headers-hsts-*` |
| 1 | X-Frame-Options | Present + not ALLOW-FROM | header parse | medium-weakness | finding `headers-x-frame-options-*` |
| 1 | X-Content-Type-Options | nosniff | header parse | low-hardening | finding `headers-no-x-content-type` |
| 1 | Referrer-Policy | Present + safe value | header parse | low-hardening | finding `headers-referrer-policy-*` |
| 1 | Permissions-Policy | Present + no `*` | header parse | low-hardening | finding `headers-permissions-policy-*` |
| 1 | COOP / COEP / CORP | Presence | header parse | low-hardening | finding `headers-cross-origin-*` |
| 1 | Cookies — Secure | Flag presence on HTTPS | Set-Cookie parse | medium-weakness | finding `cookies-no-secure` |
| 1 | Cookies — HttpOnly | Flag presence on session cookies | Set-Cookie parse | medium-weakness or high-impact-misconfig | finding `cookies-no-httponly` |
| 1 | Cookies — SameSite | Lax/Strict/None+Secure | Set-Cookie parse | medium-weakness | finding `cookies-no-samesite` |
| 1 | Source maps | sourceMappingURL + .map fetch | bundle scan + GET | high-impact-misconfig | finding `sourcemaps-exposed` |
| 1 | Mixed content | http:// in HTTPS HTML | HTML scan | medium-weakness or high-impact-misconfig (forms) | finding `mixed-content-*` |
| 1 | SRI | Cross-origin script/style integrity | HTML scan | low-hardening | finding `integrity-no-sri` |
| 1 | CORS | ACAO + ACAC analysis | OPTIONS + headers | high-impact-misconfig | finding `cors-*` |
| 1 | Open redirect | 7 params × example.com canary | GET each param | critical-exploit | finding `paths-open-redirect` |
| 1 | Reflected XSS | 6 params × unique canary | GET each param | critical-exploit | finding `paths-xss-reflected` |
| 1 | SQLi (error-based) | 5 params × `'`, 10 error patterns | GET each param | critical-exploit | finding `paths-sqli` |
| 1 | Path probes | 33 candidates (.env, .git, backups, admin, debug, well-known) | GET each path | critical-exploit (env/git) -> low-hardening (well-known) | finding `paths-*` |
| 1 | Secret detection | 11 regex patterns + JWT decode | bundle scan | critical-exploit (live keys) or high-impact-misconfig (anon keys) | finding `secrets-*` |
| 1 | Supabase project | Anon key, project ID, storage buckets, edge fn | bundle + path probe | high-impact-misconfig | finding `supabase-*`, `paths-supabase-*` |
| 1 | Firebase | Project ID, RTDB root, Storage | bundle + path probe | critical-exploit (RTDB open) | finding `firebase-*`, `paths-firebase-*` |
| 1 | S3 | Bucket host detection + ListBucket | bundle + path probe | critical-exploit (list enabled) | finding `paths-s3-list` |
| 1 | Framework fingerprint | Next.js / Nuxt / Vite+React / Svelte / Remix / Astro + version | header + bundle scan | informational | meta only |
| 1 | npm CVEs | 15 packages × CVE ranges | bundle version extract + range match | high-impact-misconfig (per CVE) | finding `deps-<pkg>-cve` |
| 1 | Server CVEs | Apache / nginx / IIS / PHP versions | Server header + range match | high-impact-misconfig (per CVE) | finding `deps-<server>-cve` |
| 1 | Server version leak | Server / X-Powered-By | header parse | informational | finding `meta-server-version-leak` |
| 1 | AI endpoint detection | 8 provider domains in bundles | bundle scan | informational | finding `ai-endpoints-passive` |
| 1 | AI prompt-injection signals | AST analysis on bundles | @babel/parser | medium-weakness or high-impact-misconfig | finding `ai-prompt-injection` |
| 1 | Form / CSRF | login forms without token | HTML scan | medium-weakness | finding `auth-csrf-missing` |
| 1 | WAF detection | 10 vendor signatures | header + body scan | informational (presence is good) | meta `meta-waf-detected` |
| 1 | Stealth retry | one retry on 4xx WAF | header injection | (operational) | retry attempt logged in evidence |
| 2 | Cookie deep audit | HttpOnly cookies (only visible via Playwright) | context.cookies() | medium-weakness | finding `stage2-cookie-not-httponly` |
| 2 | LocalStorage tokens | sb-*-auth-token, firebase:authUser, etc. | window.localStorage scan | high-impact-misconfig (runtime confirmed) | finding `stage2-localstorage-auth-tokens` |
| 2 | Network capture | All fetch/XHR + auth-header presence | Playwright network events | informational + audit | runtime endpoint inventory |
| 2 | Console errors | Page-load console.* messages | Playwright console events | low-hardening | finding `stage2-console-errors` |
| 2 | JWT decode (runtime) | Every eyJ* in cookies/storage/network | server-side decode | high-impact-misconfig | finding `stage2-jwt-*` |
| 2 | Privilege leak signals | Admin nav links, hidden form actions in unauth view | DOM scan + JS bundle | high-impact-misconfig | finding `stage2-privilege-leak` |
| 3 | Ownership verification | File / DNS TXT / Vercel token | challenge response check | (gate) | unlocks Stage 3 |
| 3 | Supabase RLS testing | Anon key probe across public.* tables | live SELECT/INSERT | critical-exploit | finding `stage3-rls-broken` |
| 3 | Storage write probe | Unauth upload attempt | live POST | critical-exploit | finding `stage3-storage-public-write` |
| 3 | Admin route fuzzing (200 paths) | Extended admin/dashboard candidates | GET each | critical-exploit | finding `stage3-admin-unauth` |
| 3 | Path traversal | `../../etc/passwd` canaries | GET probe | critical-exploit | finding `stage3-path-traversal` |
| 3 | Mass-assignment | Detected forms × extra fields | live POST | critical-exploit | finding `stage3-mass-assignment` |
| 3 | Authenticated IDOR | User-supplied creds + ID enumeration | live GET | critical-exploit | finding `stage3-idor` |

---

## Appendix A — Where each piece lives in the code

| Area | File |
|---|---|
| Stage 1 entry | `api/scan.ts` |
| Stage 1 logic (3600 LoC) | `api/_lib/scanner.ts` |
| Stage 2 entry (Playwright proxy) | `api/scan-browser-assisted.ts` |
| Stage 2 worker (Playwright) | `stage2-worker/` (Railway service `stage2-worker`) |
| Stage 2 bookmarklet collector | `api/stage2-collect.ts` + `api/stage2-results.ts` |
| Stage 3 verification | `api/verify.ts`, `api/verify-vercel-token.ts`, `api/_lib/verify-email.ts` |
| Stage 3 deep scanner | `api/_lib/deep-scanner.ts` |
| Risk scoring (legacy CVSS) | `api/_lib/risk-scorer.ts` |
| **Risk scoring (live, dynamic)** | `api/_lib/scoring-engine.ts` |
| Attack surface map | `api/_lib/attack-surface.ts` |
| JS AST analysis | `api/_lib/js-ast.ts` |
| Fix-prompt composer | `api/_lib/fix-prompt-composer.ts` |
| Audit log to Supabase | `api/_lib/audit-log.ts` |
| Telemetry | `api/_lib/scan-telemetry.ts` |
| Shared types (client + server) | `src/lib/scanner-types.ts` |
| UI rendering | `src/components/ScanForm.tsx`, `src/components/NextStagesPanel.tsx` |

---

*Doc version 2026-05-08 — synced with the dynamic scoring engine ship (commit 67ec262). Re-generate when adding new detector classes or changing the engine formula.*
