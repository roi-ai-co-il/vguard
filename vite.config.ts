import { defineConfig, type Plugin, type Connect } from 'vite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * Dev-only middleware that exposes /api/scan during `npm run dev`.
 * In production, the request is handled by api/scan.ts as a Vercel Function.
 */
function devApi(): Plugin {
  return {
    name: 'Vguard-dev-api',
    apply: 'serve',
    configureServer(server) {
      const handler: Connect.NextHandleFunction = async (req, res, next) => {
        if (!req.url) return next()
        const isScanDeep = req.url.startsWith('/api/scan-deep')
        const isScanStream = req.url.startsWith('/api/scan-stream')
        const isVerify = req.url.startsWith('/api/verify')
        const isStage2Collect = req.url.startsWith('/api/stage2-collect')
        const isStage2Results = req.url.startsWith('/api/stage2-results')
        const isRecentFindings = req.url.startsWith('/api/recent-findings')
        const isVerifyVercelToken = req.url.startsWith('/api/verify-vercel-token')
        const isScan = req.url.startsWith('/api/scan') && !isScanDeep && !isScanStream
        if (
          !isScan &&
          !isScanStream &&
          !isVerify &&
          !isScanDeep &&
          !isStage2Collect &&
          !isStage2Results &&
          !isRecentFindings &&
          !isVerifyVercelToken
        ) {
          return next()
        }

        // Emulate the NDJSON streaming scan endpoint in dev by forwarding to the
        // real handler with a res adapter that passes write()/end() straight
        // through, so localhost behaves exactly like production.
        if (isScanStream) {
          if (req.method !== 'POST') {
            res.statusCode = 405
            res.end()
            return
          }
          try {
            const chunks: Buffer[] = []
            for await (const chunk of req) chunks.push(chunk as Buffer)
            const raw = Buffer.concat(chunks).toString('utf-8')
            const body = raw ? JSON.parse(raw) : {}
            const { default: handlerFn } = (await server.ssrLoadModule('/api/scan-stream.ts')) as {
              default: (r1: unknown, r2: unknown) => Promise<void> | void
            }
            const fakeReq = { method: 'POST', body, query: {}, headers: req.headers } as unknown
            const fakeRes = {
              statusCode: 200,
              setHeader: (k: string, v: string) => res.setHeader(k, v),
              flushHeaders: () => res.flushHeaders?.(),
              write: (chunk: string) => res.write(chunk),
              status(this: { statusCode: number }, code: number) {
                res.statusCode = code
                return this
              },
              json(obj: unknown) {
                res.setHeader('Content-Type', 'application/json')
                res.end(JSON.stringify(obj))
              },
              end: (chunk?: string) => res.end(chunk),
            }
            await handlerFn(fakeReq, fakeRes)
          } catch (err) {
            const msg = err instanceof Error ? err.message : 'unknown error'
            if (!res.headersSent) {
              res.statusCode = 500
              res.setHeader('Content-Type', 'application/json')
              res.end(JSON.stringify({ ok: false, error: { code: 'internal', message: msg } }))
            } else {
              res.end()
            }
          }
          return
        }

        if (isStage2Collect || isStage2Results || isRecentFindings || isVerifyVercelToken) {
          const modulePath = isStage2Collect
            ? '/api/stage2-collect.ts'
            : isStage2Results
              ? '/api/stage2-results.ts'
              : isRecentFindings
                ? '/api/recent-findings.ts'
                : '/api/verify-vercel-token.ts'
          try {
            const chunks: Buffer[] = []
            for await (const chunk of req) chunks.push(chunk as Buffer)
            const raw = Buffer.concat(chunks).toString('utf-8')
            let body: unknown = {}
            if (raw) {
              try {
                body = JSON.parse(raw)
              } catch {
                body = {}
              }
            }
            const url = new URL(req.url, 'http://localhost')
            const query: Record<string, string> = {}
            url.searchParams.forEach((v, k) => {
              query[k] = v
            })
            const { default: handlerFn } = (await server.ssrLoadModule(modulePath)) as {
              default: (r1: unknown, r2: unknown) => Promise<void> | void
            }
            const fakeReq = {
              method: req.method,
              body,
              query,
              headers: req.headers,
            } as unknown
            const fakeRes = {
              statusCode: 200,
              _headers: {} as Record<string, string>,
              setHeader(this: { _headers: Record<string, string> }, k: string, v: string) {
                this._headers[k.toLowerCase()] = v
              },
              status(this: { statusCode: number }, code: number) {
                this.statusCode = code
                return this
              },
              json(this: { statusCode: number; _headers: Record<string, string> }, obj: unknown) {
                res.statusCode = this.statusCode
                for (const [k, v] of Object.entries(this._headers)) {
                  res.setHeader(k, v)
                }
                res.setHeader('Content-Type', 'application/json')
                res.end(JSON.stringify(obj))
              },
              end(this: { statusCode: number; _headers: Record<string, string> }) {
                res.statusCode = this.statusCode
                for (const [k, v] of Object.entries(this._headers)) {
                  res.setHeader(k, v)
                }
                res.end()
              },
            }
            await handlerFn(fakeReq, fakeRes)
          } catch (err) {
            const msg = err instanceof Error ? err.message : 'unknown error'
            res.statusCode = 500
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ ok: false, error: msg }))
          }
          return
        }

        if (isScanDeep) {
          if (req.method !== 'POST') {
            res.statusCode = 405
            res.end()
            return
          }
          try {
            const chunks: Buffer[] = []
            for await (const chunk of req) chunks.push(chunk as Buffer)
            const raw = Buffer.concat(chunks).toString('utf-8')
            const body = raw ? JSON.parse(raw) : {}
            const { default: handlerFn } = (await server.ssrLoadModule('/api/scan-deep.ts')) as {
              default: (r1: unknown, r2: unknown) => Promise<void> | void
            }
            const fakeReq = { method: 'POST', body, query: {}, headers: req.headers } as unknown
            const fakeRes = {
              statusCode: 200,
              setHeader(_k: string, _v: string) {
                // headers are forwarded via the real res below
              },
              status(this: { statusCode: number }, code: number) {
                this.statusCode = code
                return this
              },
              json(this: { statusCode: number }, obj: unknown) {
                res.statusCode = this.statusCode
                res.setHeader('Content-Type', 'application/json')
                res.setHeader('Cache-Control', 'no-store')
                res.end(JSON.stringify(obj))
              },
            }
            await handlerFn(fakeReq, fakeRes)
          } catch (err) {
            const msg = err instanceof Error ? err.message : 'unknown error'
            res.statusCode = 500
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ ok: false, error: { code: 'internal', message: msg } }))
          }
          return
        }

        if (req.url.startsWith('/api/verify')) {
          // Forward to verify handler logic
          if (req.method !== 'POST') {
            res.statusCode = 405
            res.end()
            return
          }
          try {
            const chunks: Buffer[] = []
            for await (const chunk of req) chunks.push(chunk as Buffer)
            const raw = Buffer.concat(chunks).toString('utf-8')
            const body = raw ? JSON.parse(raw) : {}
            const { default: handlerFn } = (await server.ssrLoadModule('/api/verify.ts')) as {
              default: (r1: unknown, r2: unknown) => Promise<void> | void
            }
            const fakeReq = { method: 'POST', body, query: {}, headers: req.headers } as unknown
            const fakeRes = {
              statusCode: 200,
              _headers: {} as Record<string, string>,
              setHeader(this: { _headers: Record<string, string> }, k: string, v: string) {
                this._headers[k.toLowerCase()] = v
              },
              status(this: { statusCode: number }, code: number) {
                this.statusCode = code
                return this
              },
              json(this: { statusCode: number; _headers: Record<string, string> }, obj: unknown) {
                res.statusCode = this.statusCode
                res.setHeader('Content-Type', 'application/json')
                res.end(JSON.stringify(obj))
              },
            }
            await handlerFn(fakeReq, fakeRes)
          } catch (err) {
            const msg = err instanceof Error ? err.message : 'unknown error'
            res.statusCode = 500
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ ok: false, error: msg }))
          }
          return
        }

        try {
          const { runScan } = await server.ssrLoadModule('/api/_lib/scanner.ts')

          let url = ''
          if (req.method === 'GET') {
            const u = new URL(req.url, 'http://localhost')
            url = u.searchParams.get('url') ?? ''
          } else if (req.method === 'POST') {
            const chunks: Buffer[] = []
            for await (const chunk of req) chunks.push(chunk as Buffer)
            const raw = Buffer.concat(chunks).toString('utf-8')
            try {
              const body = raw ? JSON.parse(raw) : {}
              url = typeof body.url === 'string' ? body.url : ''
            } catch {
              res.statusCode = 400
              res.setHeader('Content-Type', 'application/json')
              res.end(
                JSON.stringify({
                  ok: false,
                  error: { code: 'invalid_url', message: 'Invalid JSON body.' },
                }),
              )
              return
            }
          } else {
            res.statusCode = 405
            res.setHeader('Allow', 'GET, POST')
            res.end()
            return
          }

          if (!url) {
            res.statusCode = 400
            res.setHeader('Content-Type', 'application/json')
            res.end(
              JSON.stringify({
                ok: false,
                error: { code: 'invalid_url', message: 'No URL provided.' },
              }),
            )
            return
          }

          const result = await (runScan as (u: string) => Promise<unknown>)(url)
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.setHeader('Cache-Control', 'no-store')
          res.end(JSON.stringify(result))
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : 'unknown error'
          res.statusCode = 500
          res.setHeader('Content-Type', 'application/json')
          res.end(
            JSON.stringify({
              ok: false,
              error: { code: 'internal', message: msg },
            }),
          )
        }
      }
      server.middlewares.use(handler)
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), devApi()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
