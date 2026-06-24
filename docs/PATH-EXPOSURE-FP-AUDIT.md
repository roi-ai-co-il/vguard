# Path-Exposure False-Positive Audit — PayPal (and any large CDN/WAF)

> 2026-06-25 · **Audit + generic fix shipped.** Phase 1 was audit-only. Phase 2
> (this update) implements the brand-agnostic shape-aware fallback lane described
> in "Suggested generic fix" below. See **"IMPLEMENTED"** at the bottom.

---

## ✅ IMPLEMENTED (2026-06-25, phase 2)

**No brand/CDN/WAF allowlist. No hardcoded hosts.** A new generic
soft-404/fallback classification lane was added to the sensitive-path detector,
**before** the `exposed-needs-review` lane.

**Files changed**
- `api/_lib/scanner.ts` — new exported, unit-tested pure helpers
  (`contentTypeFamily`, `controlFamilyForPath`, `buildPathFingerprint`,
  `sameFallbackShape`, `classifyPathProbe`, types `ControlFamily` / `PathFingerprint`
  / `PathControl` / `PathProbeLane`); the probe block now fetches **4 shape-matched
  controls** (dotfile / sql / json / plain), computes a **cross-probe identity
  clamp**, and routes every probe through `classifyPathProbe`. Replaces the single
  `.txt` catch-all canary (its flag is preserved for the legacy meta note).
- `api/__tests__/path-fallback.test.ts` — regression tests A–E + helper units (14 tests).
- Temp debug block (`VGUARD_DEBUG_PATHS=1`) kept — opt-in, no-op in prod, pushes no findings.

**New decision flow (the contract, in `classifyPathProbe`)**
```
GET path → !r.ok ? drop
  → body < 8 ?                                   → info  "empty 200"
  → sensitive && real-secret evidence ?          → CRITICAL verifiedImpact   ← ALWAYS wins
  → SPA shell ?                                   → info  "SPA shell"
  → matches same-SHAPE guaranteed-404 control ?  → generic-fallback (suppress, 0 penalty)
  → same template across ≥2 probed paths ?       → generic-fallback (suppress, 0 penalty)
  → sensitive && content-type == html (no secret)? → info "rendered page, not raw file"
  → legacy plain catch-all ?                     → suppress (0 penalty)
  → else                                         → exposed-needs-review (warn) / configured sev
```
"same shape" = exact body hash **OR** (same content-type family + length within
~5%/64 B + same template head **or** `<title>`). Fuzzy because fallback templates
echo the requested path/nonce, so exact-hash alone misses them (PayPal proved this).

**Before / after (live `runScan`)**
- **PayPal** `https://www.paypal.com`: **76 / C → 99 / A**. The three soft-404
  `.env*` / `.hg/hgrc` golden-kind `warn`s are gone; `/graphql` (info) +
  `robots.txt` disclosure (info) remain (correct). *(Brief cited 67; the live
  number drifts with which paths 200 that day — same mechanism, same fix.)*
- **Real-secret leak (regression test B, end-to-end equivalent):** a `/.env.production`
  returning `text/plain` with `DATABASE_URL=…`, or `/.aws/credentials` with a PEM
  block, still classifies **`real-secret` → CRITICAL `verifiedImpact: true`** — even
  with `catchAll: true`. Suppression can never hide a real leak. *(No safe live
  intentionally-vulnerable target was probed; the guarantee is enforced by the
  classifier order + unit test B, and the critical-finding emission code is unchanged.)*

**Verification:** `tsc -p tsconfig.api.json` clean · `npm test` 284/284 ·
backend verifier 0 fail · eslint net-neutral (the 8 remaining errors pre-exist on HEAD).

**Confirmations**
- ✅ No PayPal/brand/CDN allowlist; no hardcoded hosts. Logic is "you look identical
  to a path that cannot exist" + "html on a raw-file path" — generic for any origin.
- ✅ Verified real-secret leaks still produce critical findings (order guarantees it).
- ✅ Generic HTML/WAF/denial/soft-404 pages no longer counted as exposed `.env` files.
- ✅ Sites returning a real raw file (plausible content-type) with no secret still
  get `exposed-needs-review`.

---

> The remainder below is the original phase-1 audit (kept for the evidence trail).

## TL;DR

PayPal scores ~67 (grade **D**) because the sensitive-path prober reports
`/.env.production`, `/.env.local`, `/.env.development` as exposed. They are **not**
exposed — PayPal returns its **branded ~7.8 KB `text/html` landing/error shell**
with **HTTP 200** for those (and for *any* nonexistent dotfile). The scanner's only
generic safety net (the catch-all canary) **misses it**, because PayPal's fallback
is **shape-dependent**: a `.txt` canary at root gets a real **404**, while a dotfile
gets a **200 template**. The canary shape ≠ the probe shape, so `catchAll` stays
`false` and each `.env*` 200 becomes an "exposed — needs review" `warn` finding that
carries the **`.env` golden-kind penalty** (scaled down, but still 3× per scan).

## 1. Files & functions responsible

| Concern | File · symbol |
|---|---|
| Path list (base) | `api/_lib/scanner.ts` · `PATHS_TO_PROBE` (incl. `/.env`, `/.env.production`, `/.env.local`, `/.aws/credentials`, `/.git/HEAD`) |
| Path list (extended, "work harder") | `api/_lib/scanner.ts` · `EXTENDED_PATHS_TO_PROBE` (incl. `/.env.development`, `/.env.staging`, `/.env.backup`) |
| Which paths may be "critical" | `api/_lib/scanner.ts` · `sensitivePathIds` Set |
| The probe loop (the decision) | `api/_lib/scanner.ts` · inside `runScan`, the `pathsToProbe` / `probeResults` block |
| Catch-all / soft-404 guard | `api/_lib/scanner.ts` · the `canaryUrl` (`/vguard-nonexistent-canary-9q7z2x.txt`) → `catchAll` flag |
| SPA-shell suppression | `api/_lib/scoring-policy.ts` · `isSpaShellBody(body, mainHtml)` |
| Real-secret gate | `api/_lib/scoring-policy.ts` · `evidenceContainsRealSecret(body)` + `SENSITIVE_BODY_PATTERNS` |
| Finding → `.env` golden kind | `api/_lib/finding-ids.ts` · `isEnvFileId` → `isSensitiveFileId` → `isGoldenKindId` / `isGradeCapGoldenId` |
| Confidence of `-exposed-needs-review` | `api/_lib/scoring-engine.ts` · `classifyConfidence` → returns `possible` (×0.2) |
| Customer-facing mapping (#11) | `api/_lib/canonical-checks.ts` · "sensitive path exposure" |

## 2. Per-path "reachable / exposed" logic (current)

For each probe path the loop does, in order:

1. `GET <origin><path>` (2.5 s timeout). **If `!r.ok` → dropped** (this is why
   PayPal's `406`/`404` paths like `/.env`, `/.aws/credentials`, `/.git/HEAD`,
   `/backup.sql` produce **no** finding — only the **200** ones survive).
2. Read first 8192 bytes of body.
3. **`body.length < 8`** → `info` "empty 200", stop.
4. **`isSpaShellBody(body, mainHtml)`** → `info` "returned the SPA shell", stop.
5. **sensitive path AND `evidenceContainsRealSecret(body)`** → `critical`,
   `verifiedImpact: true`, redacted secret shown. (This is the only TRUE positive lane.)
6. **`catchAll`** (canary returned a non-SPA 200) → suppressed, counted, stop.
7. **Else** → finding emitted. `critical` paths are **downgraded to `warn`** with id
   `path-…-exposed-needs-review` and the text *"Body is not the SPA shell but no real
   secret patterns matched — needs manual review to confirm exposure."* ← **PayPal lands here.**

## 3. What the detector relies on today

| Signal | Used? | Notes |
|---|---|---|
| HTTP status | ✅ primary | only `r.ok` (2xx/3xx-ish) paths are considered at all |
| Body text — secret patterns | ✅ | gates the `critical` lane (`SENSITIVE_BODY_PATTERNS`) |
| Body text — SPA shell | ✅ | `isSpaShellBody` (title + ±5% length + same root-mount, 2-of-3 vote) |
| Body length | ⚠️ only `< 8` (empty) and inside SPA-shell ratio | **not** compared across probes or vs control |
| Comparison vs ONE random control path | ⚠️ partial | single `.txt` canary at root → `catchAll`; **shape-blind** |
| **Content-type** | ❌ **not used** | a `.env` returning `text/html` is never checked |
| **Redirect chain / final URL** | ❌ not used for the decision | captured elsewhere, not here |
| **Cross-path body identity (hash)** | ❌ not used | N paths returning the same template isn't detected |
| **Shape-matched control (dotfile)** | ❌ not used | the exact gap PayPal exploits |
| Denial/WAF/branded-error body fingerprint | ❌ not used | no generic "this is an error page" check |

## 4. Exact decision flow

```
probe path
  → GET (2.5s)
  → r.ok ?  ── no ──▶ DROP (no finding)        // PayPal /.env, /.aws/* = 406 → dropped
      │ yes
  → body < 8 ? ─ yes ─▶ info "empty 200"
      │ no
  → isSpaShellBody ? ─ yes ─▶ info "SPA shell"
      │ no
  → sensitivePath && evidenceContainsRealSecret ? ─ yes ─▶ CRITICAL (verifiedImpact)  // true positive
      │ no
  → catchAll (canary 200, non-SPA) ? ─ yes ─▶ suppress + count
      │ no   ◀── PayPal reaches here: canary .txt = 404 → catchAll=false
  → emit finding
      • critical→warn, id `path-…-exposed-needs-review`
      • text "needs manual review to confirm exposure"
  → engine: id contains "env" → isEnvFileId → isGoldenKindId (golden BASE)
            classifyConfidence("-exposed-needs-review") → possible ×0.2
            verifiedImpact=false → NOT grade-cap, NOT critical
  → data-exposure risk category (40% weight) accrues penalty × N paths
  → Vibe Score drops → ~67 / D
```

## 5. Live evidence (captured 2026-06-25, www.paypal.com)

Real GETs, same UA/shape the scanner uses:

| Path | Status | Final URL | Content-Type | Bytes | Body hash | Head |
|---|---|---|---|---|---|---|
| `/.env` | **406** | paypal.com | — | 0 | — | (empty) → **dropped** |
| `/.aws/credentials` | **406** | paypal.com | — | 0 | — | (empty) → **dropped** |
| `/.git/HEAD` | **406** | paypal.com | — | 0 | — | (empty) → **dropped** |
| `/backup.sql` | **406** | paypal.com | — | 0 | — | (empty) → **dropped** |
| `/.env.production` | **200** | paypal.com | `text/html` | 7805 | `a3e369abd186` | `<!DOCTYPE html> …lower-than-ie9…` |
| `/.env.local` | **200** | paypal.com | `text/html` | 7809 | `9e30690e0258` | `<!DOCTYPE html> …lower-than-ie9…` |
| `/.env.development` | **200** | paypal.com | `text/html` | 7807 | `69c76c79e479` | `<!DOCTYPE html> …lower-than-ie9…` |
| `/config.json` | 404 | **paypalobjects.com** | text/html | 1104 | `24d099beac3d` | `…<title>404</title>…` |
| **CONTROL** `/__…_404_…​.txt` | **404** | paypalobjects.com | text/html | 1104 | `24d099beac3d` | `…<title>404</title>…` |
| **CONTROL** `/.vguards_control_…` (dotfile) | **200** | paypal.com | `text/html` | **7811** | `ea9a967445f6` | `<!DOCTYPE html> …lower-than-ie9…` |

Two facts that fully explain the bug:

1. **The three `.env*` 200s are byte-for-byte the same template as a guaranteed-
   nonexistent dotfile control** (7805/7807/7809/7811 bytes, identical `text/html`,
   identical head). They are PayPal's generic shell, not real files.
2. **Exact-hash matching alone does NOT catch them** — the template embeds the
   requested path / a nonce, so each hash differs by a few bytes. You need a
   **fuzzy shape** match (content-type + length-within-5% + same template head),
   and/or a **dotfile-shaped control** (not a `.txt`).

## 6. Why PayPal gets ~67 — what reduces the score

- **The 3 false positives** (`/.env.production`, `/.env.local`, `/.env.development`):
  each emits a `warn` `path-…env…-exposed-needs-review`.
- **`env` in the id ⇒ `.env` golden-kind base penalty** in the data-exposure
  category (40% weight). Confidence is `possible` (×0.2) and `verifiedImpact=false`,
  so they don't cap the grade at C — but three golden-kind `warn`s in the
  heaviest-weighted category still pull the score from A-band down to ~67 (D).
- Whatever other genuine/again-soft findings PayPal has add on top, but the
  `.env*` trio is the dominant, **incorrect** driver.

### What's a false positive vs real

- ❌ **False positive:** `/.env.production`, `/.env.local`, `/.env.development`
  (200 branded shell, `text/html`, ~7.8 KB, no secret, == dotfile control).
- ✅ **Correctly dropped:** `/.env`, `/.aws/credentials`, `/.git/HEAD`,
  `/backup.sql` (406/empty).
- ✅ **Would be a true positive** if any returned `text/plain` with
  `KEY=value` / PEM / token — `evidenceContainsRealSecret` already catches that.

## 7. Evidence the scanner HAS vs MISSES

**Has:** status (`r.ok`), SPA-shell similarity, real-secret body patterns, a single
root `.txt` catch-all canary.

**Missing (the gap):**
- a **shape-matched control** (dotfile + extension-matched), not just one `.txt`;
- **content-type** of the probe response (a `.env`/`.aws/credentials` served as
  `text/html` is structurally a rendered page, never a real dotfile);
- **cross-probe body similarity** (N "sensitive" paths returning the same ~length
  `text/html` template = a fallback, not N distinct secret files);
- **fuzzy** body comparison (length-bucket + content-type + template head), because
  exact-hash equality is defeated by per-path nonces/echoes;
- a generic **denial/soft-404/branded-error** body fingerprint.

## Suggested generic fix (NOT yet applied — no brand allowlists, no PayPal hardcode)

Make a 200 count as exposure only when it's **distinguishable from a known-bad
control of the same shape** AND **content-type-plausible** for the file type:

1. **Add a shape-matched control alongside the canary.** Fetch a guaranteed-
   nonexistent **dotfile** (`/.<random>`) and an extension-matched control per family
   (`/<random>.env`, `/<random>.sql`). Build a small set of "control fingerprints"
   = `{status, contentType, lenBucket, templateHead}`.
2. **Classify any probe 200 whose fingerprint ≈ a control fingerprint as
   `generic_fallback`** → suppress (same as `catchAll`), emit one honest meta note.
   "≈" = same `content-type` + length within ~5% + same leading template, OR same
   body hash. This is brand-agnostic — it's literally "you look identical to a path
   that cannot exist."
3. **Content-type plausibility gate for sensitive files.** A `.env*` / `.git/*` /
   `.aws/credentials` / `*.sql` returning `text/html` is almost never the real file.
   Require `text/plain` / `application/octet-stream` / empty-ish content-type (or a
   real-secret body match) before the `-exposed-needs-review` `warn`; otherwise
   downgrade to `info` "rendered page, not the file".
4. **Cross-probe identity clamp.** If ≥2 probed paths return the same body hash
   *or* same fuzzy shape, treat the whole cluster as a template and suppress the lot
   (keep only any member whose body actually contains a secret).
5. **Keep the real-secret lane untouched.** `evidenceContainsRealSecret` still wins
   over every suppression above — a true `.env` leak is unaffected. Cloudflare +
   exposed `.env` must still be F.

Net: this generalizes the existing `catchAll` idea from "one root `.txt`" to
"shape-aware control + content-type sanity + cross-probe identity," which catches
PayPal-class soft-404/denial pages on any large site without naming any of them.

## Temporary debug instrumentation (already in the tree, opt-in only)

`api/_lib/scanner.ts` → `debugProbeSensitivePaths()` (+ `debugProbeOne`,
`DENIAL_SOFT404_HINTS`, `DebugProbeRow`). Runs **only** when
`VGUARD_DEBUG_PATHS=1`. It re-probes every path plus a `.txt` control and a
dotfile control, and `console.log`s per path: requested URL, status, final URL,
redirected, content-type, body length, first 300 chars, body hash, SPA match,
real-secret match, denial/soft-404 hint match, exact-hash match vs each control,
**fuzzy-shape match vs each control**, shared-hash-across-probes, and a
`likelyGenericFallback` verdict. Pushes no findings, changes no score. Remove this
block once the fix above lands.

Run against prod:
```bash
# Vercel: set env VGUARD_DEBUG_PATHS=1 on the function, then
curl -s -X POST https://v-guards.com/api/scan -H "Content-Type: application/json" \
  -d '{"url":"https://www.paypal.com"}' --max-time 70 >/dev/null
# read the [VGUARD_DEBUG_PATHS] JSON line in the function logs
```
