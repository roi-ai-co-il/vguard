/**
 * Vguard — Fix Prompt Composer.
 *
 * Wraps every Finding's raw fixPrompt instruction with structured context
 * an AI agent (Cursor / Claude / Lovable) needs to actually execute the fix:
 *
 *   1. WHAT was found (title, description, severity)
 *   2. WHERE it was found (URL, evidence)
 *   3. STACK (auto-detected framework -> file paths + config snippets)
 *   4. THE TASK (the original fixPrompt content, preserved verbatim)
 *   5. VERIFICATION (concrete curl/dig command + rescan link)
 *   6. GUARDRAILS (don't disable the check, don't commit secrets, etc.)
 *
 * The wrapper is applied AFTER all detectors run, so it adds zero work to
 * the scanner hot path. It also short-circuits on `ok` / empty prompts.
 */

import type { Category, Finding, Severity } from '../../src/lib/scanner-types.js'

export interface ComposeContext {
  finalUrl: string
  detectedFramework: string | null
}

const RESCAN_BASE = 'https://vibesecure-tau.vercel.app/?url='

const SEVERITY_LINE: Record<Severity, string> = {
  critical: 'CRITICAL — fix before next deploy. Active risk.',
  warn: 'WARNING — fix this week. Hardening gap an attacker can exploit.',
  info: 'INFO — defense-in-depth. Not directly exploitable but raises the floor.',
  ok: 'OK',
}

function frameworkLabel(fw: string | null): string {
  if (!fw) return 'unknown — confirm by checking package.json'
  return fw
}

/**
 * Stack-specific hint for WHERE the fix usually lives.
 * Returns '' when we have nothing better than the generic instruction.
 */
function stackHint(framework: string | null, category: Category): string {
  const fw = (framework || '').toLowerCase()

  if (category === 'headers') {
    if (fw.includes('next')) {
      return [
        'Next.js: edit `next.config.ts` (or `.js`). Add or update the `headers()` function:',
        '```ts',
        '// next.config.ts',
        'export default {',
        '  async headers() {',
        '    return [{',
        '      source: "/(.*)",',
        '      headers: [',
        '        { key: "Content-Security-Policy", value: "<your value>" },',
        '        { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },',
        '      ],',
        '    }]',
        '  },',
        '}',
        '```',
        'Or set them at the edge in `middleware.ts` if you need per-route values.',
      ].join('\n')
    }
    if (fw.includes('vite') || fw.includes('svelte') || fw.includes('astro') || fw.includes('remix')) {
      return [
        'Static / Vite-style on Vercel: edit `vercel.json` at the project root (create it if missing):',
        '```json',
        '{',
        '  "headers": [{',
        '    "source": "/(.*)",',
        '    "headers": [',
        '      { "key": "Content-Security-Policy", "value": "<your value>" },',
        '      { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" }',
        '    ]',
        '  }]',
        '}',
        '```',
        'On Cloudflare Pages, use a `_headers` file in `public/` instead.',
      ].join('\n')
    }
    if (fw.includes('nuxt')) {
      return [
        'Nuxt: in `nuxt.config.ts`, use `routeRules` or `nitro.routeRules`:',
        '```ts',
        'export default defineNuxtConfig({',
        '  routeRules: {',
        '    "/**": { headers: { "Content-Security-Policy": "<your value>" } },',
        '  },',
        '})',
        '```',
      ].join('\n')
    }
    return [
      'Generic: add the header at your hosting / proxy layer.',
      '- Vercel: `vercel.json` -> `"headers"` array',
      '- Cloudflare Pages: `_headers` file in `public/`',
      '- Netlify: `_headers` file or `netlify.toml`',
      '- Nginx: `add_header "<name>" "<value>" always;` in the `server {}` block',
      '- Express: `app.use(helmet({ ... }))`',
    ].join('\n')
  }

  if (category === 'sourcemaps') {
    if (fw.includes('next')) {
      return 'Next.js: in `next.config.ts` set `productionBrowserSourceMaps: false` (this is the default — confirm it isn\'t overridden). For Sentry-style upload-but-hide, use the Sentry webpack plugin with `hideSourceMaps: true`.'
    }
    if (fw.includes('vite')) {
      return [
        'Vite: in `vite.config.ts` set:',
        '```ts',
        'export default defineConfig({',
        '  build: { sourcemap: false },  // or "hidden" to keep .map for error tracking',
        '})',
        '```',
        'Then redeploy and confirm the .map URL returns 404.',
      ].join('\n')
    }
    if (fw.includes('nuxt')) {
      return 'Nuxt: in `nuxt.config.ts` set `sourcemap: { client: false }`.'
    }
    if (fw.includes('astro')) {
      return 'Astro: in `astro.config.mjs` set `vite: { build: { sourcemap: false } }`.'
    }
    return 'Disable source maps for production in your build config: Vite `build.sourcemap: false`, Next `productionBrowserSourceMaps: false`, CRA `GENERATE_SOURCEMAP=false`, Webpack `devtool: false`. Then redeploy and confirm the `.map` URL returns 404.'
  }

  if (category === 'secrets') {
    if (fw.includes('next')) {
      return [
        'Next.js: any env var exposed to the browser must be prefixed `NEXT_PUBLIC_`. If a real secret is in the bundle, it means somebody named it `NEXT_PUBLIC_*` by mistake or hardcoded the literal value.',
        '1. `git grep "<first 8 chars of the leaked key>"` to find every reference.',
        '2. Move the call to an API route under `app/api/<name>/route.ts` (or `pages/api/`).',
        '3. Read the key on the server via `process.env.<NAME>` (no `NEXT_PUBLIC_` prefix).',
        '4. The browser calls your `/api/<name>` instead of the third-party API directly.',
        '5. **Rotate the leaked key** at the provider — assume it is fully compromised.',
      ].join('\n')
    }
    if (fw.includes('vite')) {
      return [
        'Vite: any env var exposed to the browser must be prefixed `VITE_`. If a real secret is in the bundle, it means somebody named it `VITE_*` by mistake or hardcoded the literal.',
        '1. `git grep "<first 8 chars of the leaked key>"` in `src/` to find every reference.',
        '2. Move the call to a server endpoint (Vercel Function under `api/`, or Supabase Edge Function).',
        '3. Read the key on the server via `process.env.<NAME>` (no `VITE_` prefix).',
        '4. The browser calls your `/api/<name>` instead of the third-party API directly.',
        '5. **Rotate the leaked key** at the provider — assume it is fully compromised.',
      ].join('\n')
    }
    return [
      '1. Find every reference: `git grep "<first 8 chars of the leaked key>"`.',
      '2. Move the call to a server endpoint and read the key from `process.env.<NAME>`.',
      '3. The client should hit your own backend, never the third-party API directly.',
      '4. **Rotate the leaked key** at the provider — assume it is fully compromised.',
    ].join('\n')
  }

  if (category === 'auth') {
    return [
      'For Supabase RLS issues:',
      '1. Open Supabase Dashboard -> Authentication -> Policies -> `public.<table>`.',
      '2. Replace any `USING (true)` or `USING (auth.uid() IS NOT NULL)` with ownership-aware predicates: `USING (auth.uid() = user_id)` for per-user data, or a join through a membership table for shared data.',
      '3. If you need an email allowlist (private apps), use `USING (auth.jwt() ->> \'email\' IN (\'a@x.com\', \'b@y.com\'))`.',
      '4. **Test with two real users** — login as A, query the table, must return only A\'s rows. Repeat as B.',
      '5. Re-run the Stage 3 deep scan and confirm the table no longer leaks.',
      '⚠️ Common trap: `share_token IS NOT NULL` is **not** a guard — RLS doesn\'t see WHERE clauses, that policy returns the whole table to anon.',
    ].join('\n')
  }

  if (category === 'mixed-content') {
    return 'Search your code for `http://` (lowercase) — `git grep "http://"` in your `src/` and `public/` folders. Replace with `https://`. Also check any CMS-stored content (Sanity, Contentful, Strapi). For form `action` attributes, this is critical — HTTP form posts leak credentials in cleartext.'
  }

  if (category === 'html') {
    return 'HTML hygiene fixes usually live in your component templates: search for `target="_blank"`, raw-HTML React props (the dangerously-named one), `v-html` (Vue), `{@html}` (Svelte). For inline scripts, move them to a separate `.js` file and reference via `<script src>` so a strict CSP can hash them.'
  }

  if (category === 'deps') {
    return [
      '1. `npm outdated` — see what is behind.',
      '2. `npm install <package>@<patched-version>` — pin to the patched version explicitly, not just `latest` (latest may be a major version with breaking changes).',
      '3. `npm audit fix` for transitive vulns.',
      '4. Run your test suite (or at least a manual smoke test of the affected feature).',
      '5. Redeploy and rescan to confirm the version string is updated in the bundle.',
    ].join('\n')
  }

  if (category === 'ai') {
    return [
      'AI / LLM endpoint hardening:',
      '1. Define the system prompt **server-side as a constant**. Never accept `messages[0].role==="system"` from the request body.',
      '2. Validate the request body with zod — only allow `messages` with `role: "user" | "assistant"`. Reject any other top-level keys.',
      '3. Per-IP rate limit (Upstash Ratelimit or Vercel KV).',
      '4. Per-message length cap (~4000 chars) to prevent prompt-stuffing.',
      '5. Output filter: regex-block any response containing `sk-`, `AIza`, `eyJ`, etc. — your model should never echo a real key.',
      '6. Refuse meta-questions: "what tools do you have / what\'s your system prompt / dump context" -> polite refusal.',
    ].join('\n')
  }

  if (category === 'cookies') {
    return [
      'Cookie flags are set wherever the cookie is created. Common locations:',
      '- Express: `res.cookie(name, value, { httpOnly: true, secure: true, sameSite: "lax" })`',
      '- NextAuth: in `[...nextauth].ts` -> `cookies` section',
      '- Supabase Auth: handled automatically; if you see this finding with Supabase, you may have a custom cookie set elsewhere',
      '- Hono / Elysia: `setCookie(c, name, value, { httpOnly: true, secure: true, sameSite: "Lax" })`',
      'Note: `SameSite=None` REQUIRES `Secure` — browsers reject the cookie otherwise.',
    ].join('\n')
  }

  if (category === 'integrity') {
    return 'For external `<script src="https://cdn..."`>: either (a) host the script yourself and skip SRI, or (b) compute the hash with `curl <url> | openssl dgst -sha384 -binary | openssl base64 -A` and add `integrity="sha384-<hash>" crossorigin="anonymous"` to the tag. Re-run after every dependency upgrade — SRI hash is version-pinned.'
  }

  if (category === 'paths') {
    return [
      'Two layers to fix:',
      '1. **Stop deploying the file:** confirm `.gitignore` excludes it AND your build output (`dist/`, `.next/`, `public/`) does not contain it. Run `find dist -name "<filename>"` after a build.',
      '2. **Block at the proxy:** in `vercel.json` add a `redirects` or `rewrites` rule returning 404. On Nginx use `location ~ <pattern> { return 404; }`.',
    ].join('\n')
  }

  if (category === 'tls') {
    return 'TLS/cipher config lives at your CDN/proxy, not in your app code. Cloudflare: SSL/TLS -> Edge Certificates -> Minimum TLS Version. Vercel/Netlify: handled automatically — if you see weak TLS, you are NOT behind those, check what is fronting your origin.'
  }

  if (category === 'dns' || category === 'email') {
    return 'DNS records live at your registrar / DNS provider (Cloudflare, Route 53, Namecheap, etc.) — NOT in your code. Add the record there, then run the verification command (e.g. `dig +short TXT _dmarc.<domain>`) to confirm propagation. DNS changes can take up to a few minutes to globally propagate.'
  }

  if (category === 'methods') {
    return 'HTTP method restrictions are usually at the framework/router level. Express: only mount routes for the methods you allow. Next.js App Router: only export the verbs (`GET`, `POST`) you support. Most CDNs (Cloudflare, Vercel) will let you block methods at the edge via firewall rules.'
  }

  return ''
}

/**
 * Concrete verification command an AI agent / human can run after the fix
 * to confirm it actually worked. Falls back to "rescan with Vguard".
 */
function verifyCommand(category: Category, finalUrl: string, evidence: string): string {
  let parsed: URL
  try {
    parsed = new URL(finalUrl)
  } catch {
    return `Re-run the scan via Vguard and confirm the finding is gone.`
  }
  const host = parsed.hostname
  const baseDomain = host.replace(/^www\./, '')

  if (category === 'headers') {
    const m = evidence.match(/missing ([a-z0-9-]+)/i)
    const header = m?.[1] ?? '<header-name>'
    return `\`curl -sI "${finalUrl}" | grep -i "${header}"\` — should print the new header value (was missing before).`
  }
  if (category === 'sourcemaps' || category === 'paths') {
    const probeMatch = evidence.match(/(https?:\/\/[\S]+)/)
    const target = probeMatch?.[1] ?? finalUrl
    const cleanTarget = target.replace(/[",)]+$/, '')
    return `\`curl -sI "${cleanTarget}" | head -1\` — should return \`HTTP/2 404\` (was 200 before).`
  }
  if (category === 'tls' || category === 'mixed-content') {
    return `Re-test with https://www.ssllabs.com/ssltest/analyze.html?d=${host} — aim for grade A or A+. Or rescan with Vguard.`
  }
  if (category === 'dns') {
    return `\`dig +short DNSKEY ${baseDomain}\` (DNSSEC) or \`dig +short CAA ${baseDomain}\` (CAA) — should return your records.`
  }
  if (category === 'email') {
    return `\`dig +short TXT _dmarc.${baseDomain}\` and \`dig +short TXT ${baseDomain}\` (SPF). Both should return the new policy.`
  }
  if (category === 'cookies') {
    return `\`curl -sI "${finalUrl}" | grep -i "set-cookie"\` — every session/auth cookie should include \`Secure; HttpOnly; SameSite=Lax|Strict\`.`
  }
  if (category === 'methods') {
    return `\`curl -sX OPTIONS "${finalUrl}" -i | grep -i "allow:"\` — should NOT list TRACE; only the methods you intentionally support.`
  }
  if (category === 'secrets' || category === 'deps' || category === 'integrity' || category === 'html' || category === 'ai' || category === 'auth') {
    return `Rescan with Vguard. The finding should disappear. (For secrets: also confirm the leaked key is rotated at the provider — \`curl\` with the old key should return 401.)`
  }
  return `Re-scan with Vguard at ${RESCAN_BASE}${encodeURIComponent(finalUrl)} and confirm the finding no longer appears.`
}

/**
 * Category-specific INVESTIGATE step. The agent runs these BEFORE editing.
 * Tied to evidence so commands include the concrete file/header/path.
 */
function investigateStep(category: Category, evidence: string, finalUrl: string): string {
  let host = ''
  try {
    host = new URL(finalUrl).hostname
  } catch {
    // ignore
  }

  if (category === 'headers') {
    const m = evidence.match(/missing ([a-z0-9-]+)/i)
    const header = m?.[1] ?? '<header-name>'
    return [
      `1. Confirm the header is missing on the live site:`,
      `   \`\`\`bash`,
      `   curl -sI "${finalUrl}" | grep -i "${header}"`,
      `   \`\`\``,
      `   Expected: empty output (header is missing — this is what we found).`,
      `2. Find where the headers config lives in this project:`,
      `   \`\`\`bash`,
      `   ls vercel.json next.config.* nuxt.config.* astro.config.* netlify.toml _headers public/_headers 2>/dev/null`,
      `   \`\`\``,
      `   Read whichever file exists. That's the file you'll edit in step 2.`,
    ].join('\n')
  }
  if (category === 'secrets') {
    const m = evidence.match(/"([A-Za-z0-9_-]{6,12})/)
    const sample = m?.[1] ?? '<first-8-chars-of-secret>'
    return [
      `1. Find every place the leaked secret is referenced:`,
      `   \`\`\`bash`,
      `   git grep -n "${sample}" -- ':!*.lock' ':!*-lock.json'`,
      `   \`\`\``,
      `   This is your hit list. Note each file:line you'll touch.`,
      `2. Identify how the secret got into the bundle. Common paths:`,
      `   - A \`VITE_*\` / \`NEXT_PUBLIC_*\` env var that should NOT be public.`,
      `   - A direct \`fetch("https://api.openai.com/...", { headers: { Authorization: ... } })\` call from the client.`,
      `   - A hardcoded literal in the source.`,
      `3. Read those files first; do NOT edit yet.`,
    ].join('\n')
  }
  if (category === 'sourcemaps') {
    const m = evidence.match(/(https?:\/\/[^\s")]+\.map)/)
    const target = m?.[1] ?? '<bundle-url>.map'
    return [
      `1. Confirm the sourcemap is publicly served:`,
      `   \`\`\`bash`,
      `   curl -sI "${target}" | head -1`,
      `   \`\`\``,
      `   Expected: HTTP/2 200 (this is the leak we found).`,
      `2. Find the build config:`,
      `   \`\`\`bash`,
      `   ls vite.config.* next.config.* nuxt.config.* astro.config.* webpack.config.* 2>/dev/null`,
      `   \`\`\``,
      `   Read whichever exists. You'll set sourcemap=false there in step 2.`,
    ].join('\n')
  }
  if (category === 'paths') {
    const m = evidence.match(/(https?:\/\/[^\s")]+)/)
    const target = m?.[1] ?? finalUrl
    return [
      `1. Confirm the path is exposed:`,
      `   \`\`\`bash`,
      `   curl -sI "${target}" | head -1`,
      `   \`\`\``,
      `   Expected: HTTP/2 200 (this is the exposure we found).`,
      `2. Two questions to answer before editing:`,
      `   - Is the file in the build output? Run \`find dist .next public -type f -name "<filename>"\` after a build.`,
      `   - Is it in \`.gitignore\` and your build's ignore list?`,
      `3. Read \`vercel.json\` / \`netlify.toml\` / \`_redirects\` if present — that's where you'll add the block in step 2.`,
    ].join('\n')
  }
  if (category === 'auth') {
    return [
      `1. List your Supabase RLS policies (assumes \`supabase\` CLI is linked):`,
      `   \`\`\`bash`,
      `   npx supabase db diff --linked --schema public 2>&1 | head -100`,
      `   \`\`\``,
      `   Or in the dashboard: Project → Authentication → Policies.`,
      `2. Identify the table flagged in the Evidence block. Read its current policy verbatim — note exactly what the USING clause says.`,
      `3. Identify the ownership column (\`user_id\`, \`owner_id\`, \`tenant_id\`, etc.). Open one row in Supabase Studio to confirm the column name. You'll use it in step 2.`,
    ].join('\n')
  }
  if (category === 'cookies') {
    return [
      `1. Show the live Set-Cookie headers:`,
      `   \`\`\`bash`,
      `   curl -sI "${finalUrl}" | grep -i "set-cookie"`,
      `   \`\`\``,
      `2. Find where each cookie is created:`,
      `   \`\`\`bash`,
      `   git grep -n "res.cookie\\|setCookie\\|cookies()\\.set\\|Set-Cookie"`,
      `   \`\`\``,
      `3. Read each call site. Note current flag values; you'll add Secure/HttpOnly/SameSite in step 2.`,
    ].join('\n')
  }
  if (category === 'mixed-content') {
    return [
      `1. Find every \`http://\` (lowercase, http only) reference in code:`,
      `   \`\`\`bash`,
      `   git grep -n "http://" -- src/ public/ ':!*.md' ':!CHANGELOG*'`,
      `   \`\`\``,
      `2. Note any \`<form action="http://...">\` — those are critical (cleartext credential post).`,
      `3. Also search CMS-stored content (Sanity / Contentful / Strapi) for hardcoded http URLs in payloads.`,
    ].join('\n')
  }
  if (category === 'integrity') {
    return [
      `1. List every external \`<script>\` tag in your shipped HTML:`,
      `   \`\`\`bash`,
      `   git grep -nE '<script[^>]*src="https?://' -- '*.html' '*.tsx' '*.jsx' '*.vue' '*.svelte'`,
      `   \`\`\``,
      `2. For each external src, note whether it has \`integrity=\` and \`crossorigin=\`. The ones missing both are what you'll fix in step 2.`,
    ].join('\n')
  }
  if (category === 'deps') {
    return [
      `1. Confirm the vulnerable version is what you ship:`,
      `   \`\`\`bash`,
      `   npm ls | grep -i "<package-name>"`,
      `   npm outdated`,
      `   \`\`\``,
      `2. Read the CVE description (link in the Evidence block) — confirm the patched version your fix needs to land on.`,
    ].join('\n')
  }
  if (category === 'dns' || category === 'email') {
    const baseDomain = host.replace(/^www\./, '')
    return [
      `1. Confirm the record is missing on the live domain:`,
      `   \`\`\`bash`,
      `   dig +short TXT _dmarc.${baseDomain}`,
      `   dig +short TXT ${baseDomain}`,
      `   dig +short DNSKEY ${baseDomain}`,
      `   dig +short CAA ${baseDomain}`,
      `   \`\`\``,
      `2. This is a DNS-side fix, NOT a code edit. Identify the DNS provider (Cloudflare / Route 53 / GoDaddy / Namecheap) before going to step 2.`,
    ].join('\n')
  }
  if (category === 'ai') {
    return [
      `1. Find the AI endpoint(s) flagged in the Evidence block:`,
      `   \`\`\`bash`,
      `   git grep -nE 'app\\.(post|all)\\(.*chat|/api/(chat|ai|completion|llm)' -- src/ api/ pages/ app/`,
      `   \`\`\``,
      `2. For each endpoint, read it in full. Note: (a) is the system prompt server-side or accepted from the body, (b) is there auth, (c) is there a rate limit, (d) is there input validation.`,
    ].join('\n')
  }
  if (category === 'methods') {
    return [
      `1. Confirm the method is enabled:`,
      `   \`\`\`bash`,
      `   curl -sX OPTIONS "${finalUrl}" -i | grep -i "allow:"`,
      `   curl -sX TRACE "${finalUrl}" -o /dev/null -w "%{http_code}\\n"`,
      `   \`\`\``,
      `2. Identify whether the method is allowed at the framework level (Express/Next route handlers) or at the proxy (Vercel/Cloudflare/Nginx). The fix in step 2 lives at whichever layer is responding.`,
    ].join('\n')
  }
  if (category === 'tls') {
    return [
      `1. Confirm the TLS issue on the live host:`,
      `   \`\`\`bash`,
      `   curl -sI -v "${finalUrl}" 2>&1 | grep -i "ssl\\|tls\\|cipher"`,
      `   \`\`\``,
      `2. TLS config lives at your CDN/proxy (Cloudflare / Vercel / Netlify / Fastly), NOT in app code. Identify what fronts the origin before step 2.`,
    ].join('\n')
  }
  return [
    `1. Re-read the Evidence block above carefully — it contains the exact location/value the scanner saw.`,
    `2. Map that to a file or config in this repo. \`git grep\` for unique fragments from the evidence.`,
    `3. Read those files BEFORE editing.`,
  ].join('\n')
}

/**
 * The do-not-do block. Same for every finding; consistency matters here —
 * the agent should learn to expect these guardrails and never overstep.
 */
const GUARDRAILS = [
  '## ⚠️ Hard rules',
  '- **Investigate before editing.** If you skip step 1, you will edit the wrong file or miss references.',
  '- **Do not disable the check.** Fix the root cause; do not suppress the finding so the scan passes.',
  "- **If a secret leaked, ROTATE FIRST.** Open the provider dashboard, generate a new key, swap it in `.env`, redeploy. THEN edit code. Doing it in the other order leaves a window of compromise.",
  '- **Do not commit any secret to git.** Use `process.env.<NAME>` server-side only.',
  '- **Regression checks are mandatory.** Step 3 (typecheck + lint + tests + build) MUST pass clean before you deploy. Do not skip "because the change is small".',
  '- **Verify is mandatory.** Step 4 is the acceptance test — do not declare done without running it and pasting the output.',
  '- **Do not ask the user to investigate for you.** You have the workspace; the commands above produce the answers.',
].join('\n')

export function composeFixPrompt(finding: Finding, ctx: ComposeContext): string {
  // Preserve `ok` / clean findings as-is — they have no action to take.
  if (!finding.fixPrompt || finding.severity === 'ok') return finding.fixPrompt

  const fw = frameworkLabel(ctx.detectedFramework)
  const stack = stackHint(ctx.detectedFramework, finding.category)
  const verify = verifyCommand(finding.category, ctx.finalUrl, finding.evidence)
  const investigate = investigateStep(finding.category, finding.evidence, ctx.finalUrl)
  const rescanLink = `${RESCAN_BASE}${encodeURIComponent(ctx.finalUrl)}`

  const blocks: string[] = [
    `# 🛡️ Vguard auto-fix — ${finding.title}`,
    ``,
    `**You are an AI coding agent (Cursor / Claude Code / Lovable / Bolt). Execute this fix end-to-end in the user's workspace. Follow the four steps in order; do NOT ask the user questions you can answer yourself by reading the codebase.**`,
    ``,
    `| | |`,
    `|---|---|`,
    `| **Severity** | ${SEVERITY_LINE[finding.severity]} |`,
    `| **Category** | \`${finding.category}\` |`,
    `| **Detected stack** | ${fw} |`,
    `| **Scanned URL** | ${ctx.finalUrl} |`,
    ``,
    `---`,
    ``,
    `## Step 1 — Investigate (read-only, no code edits yet)`,
    ``,
    investigate,
    ``,
    `When step 1 is done you should know: (a) the exact file(s) you'll edit, (b) the exact value/setting that needs to change, (c) the current state of those files. If anything is still unclear, run another \`git grep\` or \`cat\` — never guess.`,
    ``,
    `## Step 2 — Fix the code`,
    ``,
    finding.fixPrompt,
  ]

  if (stack) {
    blocks.push(``, `### Stack-specific guidance for \`${finding.category}\` on ${fw}`, ``, stack)
  }

  blocks.push(
    ``,
    `## Step 3 — Prevent regression (mandatory before deploying)`,
    ``,
    `Run every applicable check below in the project root. If any fail, your fix has a regression — return to step 2 and resolve before continuing.`,
    ``,
    `\`\`\`bash`,
    `# Type check — must pass with zero errors`,
    `npx tsc --noEmit`,
    ``,
    `# Lint — fix any new warnings/errors you introduced`,
    `npm run lint`,
    ``,
    `# Tests — run the full suite (or the targeted file if a full run is huge)`,
    `npm test -- --run    # vitest`,
    `npm run test:ci      # whatever the project uses`,
    ``,
    `# Build — must succeed (catches type errors that --noEmit hides + bundling issues)`,
    `npm run build`,
    `\`\`\``,
    ``,
    `Additionally:`,
    `- **For UI changes:** start the dev server (\`npm run dev\`), open the affected page in the browser at **both** mobile (375–390px) and desktop (≥1024px) viewports, click through the user flow that touches the changed code, and visually confirm nothing else broke. Type checking does not catch CSS regressions.`,
    `- **For backend / API changes:** run the affected endpoint with \`curl\` or your test runner against a local dev server before redeploying.`,
    `- **For env-var / secret changes:** confirm the new value works in the local \`.env\` AND on the deploy target (Vercel / Railway / etc.). A passing local build with a missing prod env is a silent prod break.`,
    ``,
    `Only proceed past this step when **typecheck, lint, tests, build, and the manual smoke pass clean**. Do not deploy with red tests "to verify in prod" — that's how regressions ship.`,
    ``,
    `## Step 4 — Verify the fix actually shipped`,
    ``,
    `Redeploy first (or wait for CI), THEN run:`,
    ``,
    verify,
    ``,
    `**If the verification fails, your fix is incomplete — go back to step 2.**`,
    ``,
    `## Step 5 — Report back to the user`,
    ``,
    `In one short message tell the user:`,
    `1. The file(s) you edited (path + line numbers).`,
    `2. A one-sentence summary of the change.`,
    `3. The result of the regression checks from step 3 (typecheck / lint / tests / build — all green, or which ones failed and how you resolved them).`,
    `4. The exact output of the verify command from step 4 (paste it).`,
    `5. The rescan link: ${rescanLink}`,
    ``,
    `---`,
    ``,
    `## Why this matters (context)`,
    ``,
    finding.description,
    ``,
    `## Raw evidence (from the scanner — your source of truth)`,
    ``,
    '```',
    finding.evidence,
    '```',
    ``,
    GUARDRAILS,
  )

  return blocks.join('\n')
}

/**
 * Apply composer to every finding in an array. Returns a NEW array;
 * does not mutate the input.
 */
export function enrichFindings(findings: Finding[], ctx: ComposeContext): Finding[] {
  return findings.map((f) => ({ ...f, fixPrompt: composeFixPrompt(f, ctx) }))
}
