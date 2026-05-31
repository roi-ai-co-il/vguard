import type { VercelRequest, VercelResponse } from '@vercel/node'

export const config = {
  runtime: 'nodejs',
  maxDuration: 5,
}

// Lightweight liveness endpoint for the uptime monitor (health-monitor.mjs).
// Vguard's scan path is stateless, so a 200 here proves the function layer is
// up and the deploy is serving. Returns 200 always when the function boots.
export default function handler(_req: VercelRequest, res: VercelResponse) {
  res.setHeader('Cache-Control', 'no-store')
  res.status(200).json({
    ok: true,
    service: 'vguard',
    ts: new Date().toISOString(),
  })
}
