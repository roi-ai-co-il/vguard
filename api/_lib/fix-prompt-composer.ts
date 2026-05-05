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
 * The do-not-do block. Same for every finding; consistency matters here —
 * the agent should learn to expect these guardrails and never overstep.
 */
const GUARDRAILS = [
  '## ⚠️ Do not',
  '- Don\'t disable the security check just to make the scan pass — fix the root cause.',
  '- Don\'t commit any secret. If a secret was leaked, **rotate it BEFORE editing the code** so a window of compromise is closed first.',
  '- Don\'t guess the file path from the title alone — use the **Evidence** block above to find the exact source line.',
  '- Don\'t skip verification. Run the verify command and rescan; the scan is your acceptance test, not the diff.',
].join('\n')

export function composeFixPrompt(finding: Finding, ctx: ComposeContext): string {
  // Preserve `ok` / clean findings as-is — they have no action to take.
  if (!finding.fixPrompt || finding.severity === 'ok') return finding.fixPrompt

  const fw = frameworkLabel(ctx.detectedFramework)
  const stack = stackHint(ctx.detectedFramework, finding.category)
  const verify = verifyCommand(finding.category, ctx.finalUrl, finding.evidence)
  const rescanLink = `${RESCAN_BASE}${encodeURIComponent(ctx.finalUrl)}`

  const blocks: string[] = [
    `# 🛡️ Vguard fix prompt`,
    ``,
    `**Finding:** ${finding.title}`,
    `**Severity:** ${SEVERITY_LINE[finding.severity]}`,
    `**Category:** ${finding.category}`,
    `**Scanned URL:** ${ctx.finalUrl}`,
    `**Detected stack:** ${fw}`,
    ``,
    `## What we found`,
    finding.description,
    ``,
    `## Evidence (raw, from the scan)`,
    '```',
    finding.evidence,
    '```',
    ``,
    `## Your task`,
    finding.fixPrompt,
  ]

  if (stack) {
    blocks.push(``, `## Where to edit (stack: ${fw})`, stack)
  }

  blocks.push(
    ``,
    `## Verify the fix worked`,
    verify,
    ``,
    `Then redeploy and rescan: ${rescanLink}`,
    `The "${finding.title}" finding should disappear from the report.`,
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
