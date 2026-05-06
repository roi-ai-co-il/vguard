import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import handler from '../admin/logs.ts'

interface FakeReq {
  method: string
  headers: Record<string, string | string[] | undefined>
  query: Record<string, string>
  url?: string
}

interface FakeRes {
  statusCode: number
  body: unknown
  headers: Record<string, string>
  status(code: number): FakeRes
  json(data: unknown): FakeRes
  setHeader(k: string, v: string): void
  end(): FakeRes
}

function makeRes(): FakeRes {
  const r: FakeRes = {
    statusCode: 0,
    body: undefined,
    headers: {},
    status(code) {
      this.statusCode = code
      return this
    },
    json(data) {
      this.body = data
      return this
    },
    setHeader(k, v) {
      this.headers[k] = v
    },
    end() {
      return this
    },
  }
  return r
}

function makeReq(over: Partial<FakeReq>): FakeReq {
  return {
    method: 'GET',
    headers: { 'x-forwarded-for': '9.9.9.9' },
    query: {},
    ...over,
  }
}

const SECRET = 'unit-test-secret-' + Math.random().toString(36).slice(2)

describe('GET /api/admin/logs auth', () => {
  before(() => {
    process.env.ADMIN_SECRET = SECRET
    // Force "not configured" Supabase path so handler returns 503 (auth passed)
    // for the admin case, instead of trying real network.
    delete process.env.SUPABASE_URL
    delete process.env.SUPABASE_SERVICE_ROLE_KEY
  })
  after(() => {
    delete process.env.ADMIN_SECRET
  })

  it('non-admin (no header) → 404 not_found', async () => {
    const req = makeReq({})
    const res = makeRes()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await handler(req as any, res as any)
    assert.equal(res.statusCode, 404)
    assert.deepEqual(res.body, { ok: false, error: 'not_found' })
  })

  it('non-admin (wrong secret) → 404 not_found', async () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '1.1.1.1', 'x-admin-secret': 'wrong' } })
    const res = makeRes()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await handler(req as any, res as any)
    assert.equal(res.statusCode, 404)
  })

  it('admin (correct secret) passes auth (503 storage_not_configured proves auth gate cleared)', async () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '2.2.2.2', 'x-admin-secret': SECRET } })
    const res = makeRes()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await handler(req as any, res as any)
    assert.equal(res.statusCode, 503)
    assert.equal((res.body as { error: string }).error, 'storage_not_configured')
  })

  it('non-GET method → 404 (route hidden)', async () => {
    const req = makeReq({ method: 'POST', headers: { 'x-admin-secret': SECRET } })
    const res = makeRes()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await handler(req as any, res as any)
    assert.equal(res.statusCode, 404)
  })

  it('rate limit: 30 requests / minute per IP, 31st returns 429', async () => {
    const ip = '3.3.3.3'
    let lastRes: FakeRes | null = null
    for (let i = 0; i < 32; i++) {
      const req = makeReq({ headers: { 'x-forwarded-for': ip, 'x-admin-secret': SECRET } })
      const res = makeRes()
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await handler(req as any, res as any)
      lastRes = res
    }
    assert.equal(lastRes!.statusCode, 429)
    assert.equal((lastRes!.body as { error: string }).error, 'rate_limited')
  })
})
