import type { VercelRequest, VercelResponse } from '@vercel/node'
import { createClient } from '@supabase/supabase-js'
import { recordVerification } from '../../_lib/verification-store.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 15,
}

interface VercelTokenResponse {
  access_token?: string
  token_type?: string
  installation_id?: string
  user_id?: string
  team_id?: string
  error?: string
  error_description?: string
}

interface VercelProject {
  id: string
  name: string
  alias?: { domain: string; target?: string }[]
}

async function fetchTokenFromVercel(code: string): Promise<VercelTokenResponse> {
  const clientId = process.env.VERCEL_OAUTH_CLIENT_ID
  const clientSecret = process.env.VERCEL_OAUTH_CLIENT_SECRET
  const publicOrigin =
    process.env.VGUARD_PUBLIC_ORIGIN ||
    process.env.VIBESECURE_PUBLIC_ORIGIN ||
    'https://vguardus.com'
  const params = new URLSearchParams({
    client_id: clientId ?? '',
    client_secret: clientSecret ?? '',
    code,
    redirect_uri: `${publicOrigin}/api/oauth/vercel/callback`,
  })
  const r = await fetch('https://api.vercel.com/v2/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  })
  return (await r.json()) as VercelTokenResponse
}

async function userOwnsDomain(token: string, teamId: string | undefined, domain: string): Promise<boolean> {
  // Vercel API: list projects for the user/team, check each project's aliases for our domain
  try {
    const url = teamId
      ? `https://api.vercel.com/v9/projects?teamId=${encodeURIComponent(teamId)}&limit=100`
      : 'https://api.vercel.com/v9/projects?limit=100'
    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!r.ok) return false
    const json = (await r.json()) as { projects?: VercelProject[] }
    const projects = json.projects ?? []
    const dl = domain.toLowerCase()
    for (const p of projects) {
      const aliases = p.alias ?? []
      for (const a of aliases) {
        if (a.domain.toLowerCase() === dl || a.domain.toLowerCase().endsWith(`.${dl}`)) {
          return true
        }
      }
    }
    return false
  } catch {
    return false
  }
}

function htmlPage(title: string, body: string, ok: boolean): string {
  const accent = ok ? '#22d3ee' : '#ff6b6b'
  return `<!doctype html><html><head><meta charset="utf-8"/><title>${title}</title>
<style>body{margin:0;background:#09090b;color:#f5f5f7;font-family:system-ui,sans-serif;padding:60px 20px;text-align:center}
h1{font-size:1.5rem;margin:0 0 16px;color:${accent}}p{max-width:520px;margin:0 auto 16px;color:#9b9ba3;line-height:1.6}
a{color:#22d3ee}</style></head><body><h1>${title}</h1>${body}</body></html>`
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  const code = typeof req.query.code === 'string' ? req.query.code : ''
  const state = typeof req.query.state === 'string' ? req.query.state : ''
  const error = typeof req.query.error === 'string' ? req.query.error : ''

  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (error) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(400)
      .send(
        htmlPage(
          'Vercel OAuth declined',
          `<p>${error}</p><p><a href="/">Return to Vguard</a></p>`,
          false,
        ),
      )
  }

  if (!code || !state) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(400)
      .send(
        htmlPage(
          'OAuth callback invalid',
          '<p>Missing code or state. Try the verification flow again.</p>',
          false,
        ),
      )
  }

  if (!supabaseUrl || !serviceKey) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(503)
      .send(htmlPage('OAuth not configured', '<p>This deployment is missing Supabase env.</p>', false))
  }

  // Look up state
  const client = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  })
  const { data: stateRow } = await client
    .from('vs_oauth_states')
    .select('state, domain, uuid, provider, expires_at')
    .eq('state', state)
    .maybeSingle()

  if (!stateRow) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(400)
      .send(htmlPage('OAuth state expired', '<p>Start the verification flow again.</p>', false))
  }
  if (new Date(stateRow.expires_at as string).getTime() < Date.now()) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(400)
      .send(htmlPage('OAuth state expired', '<p>Start the verification flow again.</p>', false))
  }

  // Cleanup state row (best-effort)
  await client.from('vs_oauth_states').delete().eq('state', state)

  const domain = (stateRow.domain as string).toLowerCase()
  const uuid = stateRow.uuid as string

  const tokenResp = await fetchTokenFromVercel(code).catch(() => null)
  if (!tokenResp || !tokenResp.access_token) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(400)
      .send(
        htmlPage(
          'Vercel OAuth failed',
          `<p>${tokenResp?.error_description ?? 'Could not exchange code for token.'}</p>`,
          false,
        ),
      )
  }

  const owns = await userOwnsDomain(tokenResp.access_token, tokenResp.team_id, domain)
  if (!owns) {
    res.setHeader('Content-Type', 'text/html')
    return res
      .status(403)
      .send(
        htmlPage(
          'Ownership not confirmed',
          `<p>The Vercel account you authorized with does not own a project that aliases <b>${domain}</b>. Try DNS or file verification, or sign in with the correct Vercel account.</p><p><a href="/">Back to Vguard</a></p>`,
          false,
        ),
      )
  }

  await recordVerification(domain, uuid, 'oauth', 'vercel-oauth').catch(() => {
    // ignore
  })

  res.setHeader('Content-Type', 'text/html')
  return res
    .status(200)
    .send(
      htmlPage(
        'Verified',
        `<p>Confirmed via Vercel OAuth that you own <b>${domain}</b>.</p><p>Return to the Vguard tab and click <b>Verify now</b> — the cached proof will unlock Stage 3 instantly.</p><p><a href="/">Open Vguard</a></p>`,
        true,
      ),
    )
}
