# Stage 2 Playwright Worker

Server-side browser-assisted scanning for Vguard. Replaces (or complements) the bookmarklet approach when we want full Playwright introspection without asking the user to drag a bookmark.

## Why this lives outside the main Vercel deployment

Playwright + Chromium is heavy:
- The Chromium binary alone is ~500MB
- `@sparticuz/chromium` for Vercel cold-starts in 10-30s, way too slow for an interactive UX
- Vercel free-tier function memory is 1024MB, headroom is tight

A small Railway worker (or Fly machine, or any container host) keeps a warm Chromium instance and responds in 2-4s.

## Deployment to Railway (recommended)

```bash
# 1. From this directory, init a Railway project
cd stage2-worker
railway init

# 2. Set env vars
railway variables set STAGE2_WORKER_TOKEN="$(openssl rand -hex 32)"

# 3. Deploy
railway up
```

Railway auto-detects the Dockerfile and builds. Note the public URL it returns — set it as `STAGE2_WORKER_URL` on the Vguard Vercel project, and the same `STAGE2_WORKER_TOKEN` value as `STAGE2_WORKER_TOKEN` env var on Vercel.

## Endpoint

```
POST https://<railway-url>/scan
Authorization: Bearer <STAGE2_WORKER_TOKEN>
Content-Type: application/json
{ "url": "https://example.com", "timeout": 15000 }

→ {
  "ok": true,
  "url": "https://example.com/",
  "finalUrl": "https://example.com/",
  "networkRequests": [{ "url": "...", "method": "GET", "status": 200, "resourceType": "fetch" }, ...],
  "consoleErrors": ["..."],
  "windowGlobals": { "hasSupabase": true, "hasFirebase": false, ... },
  "cookies": [{ "name": "...", "httpOnly": false, "secure": true, "sameSite": "Lax", "domain": "example.com" }],
  "localStorageKeys": ["sb-xxx-auth-token"],
  "sessionStorageKeys": [],
  "durationMs": 2841
}
```

## How Vguard consumes this

The Vercel-side `api/scan-browser-assisted.ts` proxies to `STAGE2_WORKER_URL` and feeds the response into the same Stage 2 finding-analyzer used by the bookmarklet path.

If `STAGE2_WORKER_URL` is not set, the proxy returns a graceful 503 with a hint pointing the user to the bookmarklet flow.

## Local dev

```bash
cd stage2-worker
npm install
STAGE2_WORKER_TOKEN=local-dev-token npm run dev
```

Then test:

```bash
curl -X POST http://localhost:8080/scan \
  -H "Authorization: Bearer local-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Cost considerations

Railway's free tier is small-but-real. If Vguard scales:
- Move the worker to a small dedicated machine (Hetzner, DO Droplet) — cheaper at volume
- Add LRU caching on `/scan` results keyed by URL hash (5-minute TTL) so repeat scans don't re-launch a context

## Status

- 🟡 Code ready, NOT deployed. The bookmarklet flow remains the primary Stage 2 path.
- When deployed, the proxy endpoint on the main Vercel project gives users a "Run server-side browser scan" alternative to the bookmarklet.
