/**
 * Stage 3 verification via paste-your-Vercel-token.
 *
 * Why this exists alongside /api/oauth/vercel/start:
 * Vercel doesn't expose an API to create OAuth Integrations — those have to be
 * registered through their UI (vercel.com/dashboard/integrations/console).
 * For VibeSecure to provide Vercel-based ownership proof without that one-time
 * UI step, we accept a personal access token from the user, call the Vercel
 * API to list their projects + aliases, and verify the scanned domain is in
 * one of them. The token is never stored — we use it once and discard.
 */
import type { VercelRequest, VercelResponse } from '@vercel/node'
import { recordVerification } from './_lib/verification-store.js'

export const config = {
  runtime: 'nodejs',
  maxDuration: 15,
}

interface VerifyVercelTokenBody {
  domain?: string
  uuid?: string
  /** User-supplied Vercel personal access token (from vercel.com/account/tokens) */
  vercelToken?: string
}

interface VercelProject {
  id: string
  name: string
  alias?: { domain: string; target?: string }[]
}

interface VercelTeam {
  id: string
  name: string
  slug: string
}

function isValidDomain(s: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(s)
}

function isValidUuid(s: string): boolean {
  return /^[a-z0-9-]{16,64}$/i.test(s)
}

async function fetchProjectsForScope(
  token: string,
  teamId: string | undefined,
): Promise<VercelProject[]> {
  const url = teamId
    ? `https://api.vercel.com/v9/projects?teamId=${encodeURIComponent(teamId)}&limit=100`
    : 'https://api.vercel.com/v9/projects?limit=100'
  try {
    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!r.ok) return []
    const json = (await r.json()) as { projects?: VercelProject[] }
    return json.projects ?? []
  } catch {
    return []
  }
}

async function fetchUserTeams(token: string): Promise<VercelTeam[]> {
  try {
    const r = await fetch('https://api.vercel.com/v2/teams?limit=100', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!r.ok) return []
    const json = (await r.json()) as { teams?: VercelTeam[] }
    return json.teams ?? []
  } catch {
    return []
  }
}

function domainMatches(alias: string, target: string): boolean {
  const a = alias.toLowerCase()
  const t = target.toLowerCase()
  return a === t || a.endsWith('.' + t) || t.endsWith('.' + a)
}

async function userOwnsDomain(token: string, domain: string): Promise<{ owned: boolean; matchedProject?: string; matchedAlias?: string }> {
  // Check personal projects first
  const personal = await fetchProjectsForScope(token, undefined)
  for (const p of personal) {
    for (const a of p.alias ?? []) {
      if (domainMatches(a.domain, domain)) {
        return { owned: true, matchedProject: p.name, matchedAlias: a.domain }
      }
    }
  }
  // Then iterate user's teams
  const teams = await fetchUserTeams(token)
  for (const team of teams) {
    const teamProjects = await fetchProjectsForScope(token, team.id)
    for (const p of teamProjects) {
      for (const a of p.alias ?? []) {
        if (domainMatches(a.domain, domain)) {
          return { owned: true, matchedProject: `${team.slug}/${p.name}`, matchedAlias: a.domain }
        }
      }
    }
  }
  return { owned: false }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ ok: false, error: 'Method not allowed.' })
  }

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as VerifyVercelTokenBody
  const domain = (body.domain ?? '').trim().toLowerCase()
  const uuid = (body.uuid ?? '').trim()
  const vercelToken = (body.vercelToken ?? '').trim()

  if (!isValidDomain(domain)) {
    return res.status(400).json({ ok: false, error: 'Invalid domain.' })
  }
  if (!isValidUuid(uuid)) {
    return res.status(400).json({ ok: false, error: 'Invalid uuid.' })
  }
  if (!vercelToken || vercelToken.length < 20) {
    return res.status(400).json({ ok: false, error: 'Invalid Vercel token.' })
  }

  try {
    // Quick smoke test — does the token work at all?
    const meCheck = await fetch('https://api.vercel.com/v2/user', {
      headers: { Authorization: `Bearer ${vercelToken}` },
    })
    if (!meCheck.ok) {
      return res.status(200).json({
        ok: true,
        verified: false,
        method: 'vercel-token',
        hint: `Vercel rejected the token (HTTP ${meCheck.status}). Make sure you copied a fresh personal token from vercel.com/account/tokens with "Full Access" scope.`,
      })
    }

    const result = await userOwnsDomain(vercelToken, domain)
    if (result.owned) {
      const ua = (req.headers['user-agent'] as string | undefined) ?? null
      // Record verification without storing the user's Vercel token
      recordVerification(domain, uuid, 'oauth', `vercel-token:${ua ?? ''}`).catch(() => {
        // ignore
      })
      return res.status(200).json({
        ok: true,
        verified: true,
        method: 'vercel-token',
        matchedProject: result.matchedProject,
        matchedAlias: result.matchedAlias,
      })
    }
    return res.status(200).json({
      ok: true,
      verified: false,
      method: 'vercel-token',
      hint: `The token works, but ${domain} isn't an alias of any project in this Vercel account or its teams. Verify you signed in with the Vercel account that actually owns this domain, or use the file/DNS method instead.`,
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    return res.status(500).json({ ok: false, error: msg })
  }
}
