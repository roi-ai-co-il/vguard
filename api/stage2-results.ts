import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import type { Finding } from '../src/lib/scanner-types.js'
import { applyEngine, defaultContext } from './_lib/scoring-engine.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

interface CollectedData {
  cookieKeys: string[]
  localStorageKeys: string[]
  sessionStorageKeys: string[]
  globals: Record<string, boolean>
  performanceUrls: string[]
  consoleErrorCount: number
}

function isValidUuid(s: string): boolean {
  return /^[a-z0-9-]{16,64}$/i.test(s)
}

function analyzeStage2(url: string, d: CollectedData): Finding[] {
  const findings: Finding[] = []

  // Sensitive cookie names visible to JS = HttpOnly is missing
  const sensitiveCookieNames = d.cookieKeys.filter((k) =>
    /sess|auth|token|jwt|sid|csrf|access/i.test(k),
  )
  if (sensitiveCookieNames.length > 0) {
    findings.push({
      id: 'stage2-cookie-not-httponly',
      severity: 'warn',
      category: 'auth-weak',
      title: `${sensitiveCookieNames.length} sensitive cookie${
        sensitiveCookieNames.length === 1 ? '' : 's'
      } readable from JavaScript`,
      description: `Cookies with sensitive-looking names are accessible via document.cookie, meaning HttpOnly is NOT set. An XSS payload can read them and exfiltrate session tokens.`,
      evidence: `Visible to JS: ${sensitiveCookieNames.join(', ')}`,
      fixPrompt: `Set HttpOnly on every session/auth cookie. The exact mechanism depends on your stack: Express - res.cookie(name, value, { httpOnly: true, secure: true, sameSite: 'lax' }); Next.js with NextAuth - configure cookies in [...nextauth].ts options; Supabase Auth - set in Supabase Auth settings. Re-run Stage 2 to confirm these names no longer appear.`,
    })
  }

  // localStorage with auth-token-shaped keys
  const lsAuthKeys = d.localStorageKeys.filter((k) =>
    /sb-.*-auth-token|supabase\.auth\.token|firebase:authUser|access_token|refresh_token/i.test(k),
  )
  if (lsAuthKeys.length > 0) {
    findings.push({
      id: 'stage2-localstorage-auth-tokens',
      severity: 'warn',
      category: 'auth-disclosure',
      title: 'Authentication tokens stored in localStorage',
      description: `${lsAuthKeys.join(
        ', ',
      )} are stored in localStorage. Any XSS on this origin can immediately read them. The recommended pattern is HttpOnly cookies for tokens, with localStorage only for non-sensitive UI state.`,
      evidence: lsAuthKeys.slice(0, 5).join('\n'),
      fixPrompt: `Move auth tokens to HttpOnly cookies. For Supabase: enable "useSession with cookies" pattern (server-side session via @supabase/ssr). For Firebase: use Firebase Hosting cookies or session cookies. The token will live in cookies (HttpOnly + Secure + SameSite=Lax) which JS cannot read, and your XSS exposure for credential theft drops to zero.`,
    })
  }

  // App configuration globals exposed
  const exposedGlobals = Object.entries(d.globals)
    .filter(([, v]) => v === true)
    .map(([k]) => k)
  if (exposedGlobals.includes('hasFirebaseConfig')) {
    findings.push({
      id: 'stage2-firebase-config-global',
      severity: 'info',
      category: 'meta',
      title: 'window.firebaseConfig is exposed globally',
      description: `Firebase configuration is attached to the window object. While the Firebase config (apiKey, authDomain, etc.) is meant to be public, having it on a window global makes any 3rd-party script trivially dump it.`,
      evidence: 'window.firebaseConfig is defined',
      fixPrompt: `Avoid attaching Firebase config to window globals. Initialize Firebase inside an IIFE / module scope, exposing only what your app needs. This won't fix any real CVE but it raises the bar against accidental third-party-script exfiltration. Also enable Firebase App Check for stronger client-side attestation.`,
    })
  }

  // Auth surface enumeration — auth-related globals + storage keys signal which auth provider is in use
  // (good for the user to know they have a discoverable enum surface).
  const allKeys = [...d.localStorageKeys, ...d.sessionStorageKeys, ...d.cookieKeys]
  const authProviderHits: string[] = []
  if (d.globals?.hasSupabaseClient) authProviderHits.push('window.supabase (Supabase Auth)')
  if (d.globals?.hasFirebaseClient || d.globals?.hasFirebaseConfig)
    authProviderHits.push('window.firebase / firebaseConfig (Firebase Auth)')
  if (allKeys.some((k) => /^sb-.*-auth-token/i.test(k))) authProviderHits.push('Supabase session key')
  if (allKeys.some((k) => /^firebase:authUser/i.test(k))) authProviderHits.push('Firebase session key')
  if (allKeys.some((k) => /^(clerk|nextauth|auth0|cognito)/i.test(k)))
    authProviderHits.push('Third-party auth provider session key')
  if (authProviderHits.length > 0) {
    findings.push({
      id: 'stage2-auth-enum-surface',
      severity: 'info',
      category: 'auth-enum',
      title: `Auth provider fingerprint visible to client (${authProviderHits.length} signal${
        authProviderHits.length === 1 ? '' : 's'
      })`,
      description: `Stage 2 confirmed which authentication system this site uses based on client-side globals and storage keys. This isn't a vulnerability on its own, but it tells an attacker exactly which enumeration playbook to run (Supabase signup-leak, Firebase email-link enum, Auth0 connection probing). Keep your login/signup/reset endpoints' responses identical for known and unknown users.`,
      evidence: authProviderHits.join('\n'),
      fixPrompt: `Make all auth endpoints return identical responses for known and unknown emails: same body, same status, same response time. For Supabase: customize Auth email templates so password-reset always sends a generic "if registered, check your inbox" message and the API returns 200 either way. For Firebase: configure passwordReset with handleCodeInApp and avoid different error codes. Add Turnstile / hCaptcha on all auth forms and per-IP rate limit (5 attempts / 15min).`,
    })
  }

  // Performance entries showing Supabase / Firebase / external API hits
  const externalApiUrls = d.performanceUrls.filter((u) =>
    /supabase\.co\/(rest|auth|storage|functions)|firebaseapp\.com|googleapis\.com|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/i.test(
      u,
    ),
  )
  if (externalApiUrls.length > 0) {
    findings.push({
      id: 'stage2-external-apis',
      severity: 'info',
      category: 'meta',
      title: `Browser confirmed ${externalApiUrls.length} external API call${
        externalApiUrls.length === 1 ? '' : 's'
      } from this page`,
      description: `Stage 1 detected references to these APIs from static HTML/bundle scanning. Stage 2 confirmed your browser actually hits them at runtime. Useful for verifying which integrations are live (vs dormant) and for auditing CSP connect-src directives.`,
      evidence: Array.from(new Set(externalApiUrls)).slice(0, 6).join('\n'),
      fixPrompt: `Audit your Content-Security-Policy connect-src directive against the URLs above. Every host your browser actually hits should be in connect-src; every host in connect-src should still be reachable here. Drift either way (allowed-but-unused or used-but-not-allowed) signals tech debt or stealth integrations.`,
    })
  }

  if (findings.length === 0) {
    findings.push({
      id: 'stage2-clean',
      severity: 'ok',
      category: 'meta',
      title: 'Stage 2 collection produced no additional findings',
      description: `The bookmarklet collected client-side data and we didn't find anything beyond what Stage 1 already flagged. No HttpOnly-bypassed cookies, no auth tokens in localStorage, no globally-exposed config.`,
      evidence: `Stage 2 collection at ${new Date().toISOString()} for ${url}`,
      fixPrompt: '',
    })
  }

  return findings
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const uuid = typeof req.query.uuid === 'string' ? req.query.uuid : ''
  if (!uuid || !isValidUuid(uuid)) {
    return res.status(400).json({ ok: false, error: 'Invalid uuid.' })
  }

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!supabaseUrl || !serviceKey) {
    return res
      .status(503)
      .json({ ok: false, error: 'Stage 2 results not configured (missing env).' })
  }

  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    const { data, error } = await client
      .from('vs_stage2_collections')
      .select('url, data, collected_at, expires_at')
      .eq('uuid', uuid)
      .maybeSingle()
    if (error || !data) {
      return res.status(200).json({ ok: true, ready: false })
    }
    if (new Date(data.expires_at as string).getTime() < Date.now()) {
      return res.status(200).json({ ok: true, ready: false, expired: true })
    }
    const rawFindings = analyzeStage2(data.url as string, data.data as CollectedData)
    // 2026-06-07 v5 — route the bookmarklet path through the SAME scoring engine
    // as the Playwright path so its findings ship with riskClass / effective
    // severity / confidence / uiGroup / verifiedImpact + a real vibeScore.
    // Previously the bookmarklet path returned raw detector findings, bypassing
    // the scoring brain entirely (audit §9.7).
    let stage2Pathname = '/'
    let isHttps = true
    try {
      const u = new URL(data.url as string)
      stage2Pathname = u.pathname
      isHttps = u.protocol === 'https:'
    } catch {
      /* keep defaults */
    }
    const engineOut = applyEngine(
      rawFindings,
      defaultContext({ pathname: stage2Pathname, isHttps, stage: 2 }),
    )
    return res.status(200).json({
      ok: true,
      ready: true,
      url: data.url,
      collectedAt: data.collected_at,
      stage: 2,
      vibeScore: engineOut.vibeScore,
      grade: engineOut.grade,
      severityCounts: engineOut.severityCounts,
      scoreBreakdown: engineOut.scoreBreakdown,
      aggregateRiskBand: engineOut.aggregateBand,
      hasVerifiedImpact: engineOut.hasVerifiedImpact,
      findings: engineOut.findings,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: msg })
  }
}
