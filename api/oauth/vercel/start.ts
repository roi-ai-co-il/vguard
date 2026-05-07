import type { VercelRequest, VercelResponse } from '@vercel/node'
import { randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 10,
}

function isValidDomain(s: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(s)
}

function isValidUuid(s: string): boolean {
  return /^[a-z0-9-]{16,64}$/i.test(s)
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  const domain = typeof req.query.domain === 'string' ? req.query.domain : ''
  const uuid = typeof req.query.uuid === 'string' ? req.query.uuid : ''

  if (!isValidDomain(domain) || !isValidUuid(uuid)) {
    return res.status(400).send('Invalid domain or uuid.')
  }

  const clientId = process.env.VERCEL_OAUTH_CLIENT_ID
  const supabaseUrl = process.env.SUPABASE_URL
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY
  const publicOrigin =
    process.env.VGUARD_PUBLIC_ORIGIN ||
    process.env.VIBESECURE_PUBLIC_ORIGIN ||
    'https://v-guards.com'

  if (!clientId || !supabaseUrl || !serviceKey) {
    return res
      .status(503)
      .send(
        'Vercel OAuth is not configured on this deployment. Use the file or DNS verification methods instead.',
      )
  }

  // Generate cryptographic state, persist, then redirect
  const state = randomBytes(16).toString('hex')
  try {
    const client = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    })
    await client.from('vs_oauth_states').insert({
      state,
      domain: domain.toLowerCase(),
      uuid,
      provider: 'vercel',
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).send(`Could not persist OAuth state: ${msg}`)
  }

  const redirectUri = `${publicOrigin}/api/oauth/vercel/callback`
  const authorizeUrl =
    `https://vercel.com/oauth/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&scope=read:project`

  res.statusCode = 302
  res.setHeader('Location', authorizeUrl)
  res.end()
}
