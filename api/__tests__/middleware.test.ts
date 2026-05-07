import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'

const SECRET_PATH = '/internal-vg-logs-test-' + Math.random().toString(36).slice(2, 14)

function makeReq(path: string, base = 'https://vguardus.com'): Request {
  return new Request(new URL(path, base).toString())
}

let middleware: (req: Request) => Response

describe('Vercel Edge middleware: admin path gating', () => {
  before(async () => {
    process.env.ADMIN_LOGS_PATH = SECRET_PATH
    const mod = await import('../../middleware.ts')
    middleware = mod.default
  })

  after(() => {
    delete process.env.ADMIN_LOGS_PATH
  })

  it('/admin/logs → hard 404 with noindex (no redirect to new path)', () => {
    const res = middleware(makeReq('/admin/logs'))
    assert.equal(res.status, 404)
    assert.match(res.headers.get('X-Robots-Tag') || '', /noindex/i)
    assert.equal(res.headers.get('Cache-Control'), 'no-store')
  })

  it('/admin/logs/ trailing slash → 404', () => {
    const res = middleware(makeReq('/admin/logs/'))
    assert.equal(res.status, 404)
  })

  it('/admin/logs/anything → 404', () => {
    const res = middleware(makeReq('/admin/logs/dashboard'))
    assert.equal(res.status, 404)
  })

  it('wrong/random secret-shaped path → next() (Vercel will 404)', () => {
    const res = middleware(makeReq('/internal-vg-logs-wrongguess999'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
  })

  it('unrelated random path → next()', () => {
    const res = middleware(makeReq('/foo-bar-baz'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
  })

  it('correct secret path → rewrite to /index.html so SPA loads', () => {
    const res = middleware(makeReq(SECRET_PATH))
    const rewriteHeader = res.headers.get('x-middleware-rewrite')
    assert.ok(rewriteHeader, 'expected x-middleware-rewrite header')
    assert.match(rewriteHeader!, /\/index\.html$/)
    assert.match(res.headers.get('X-Robots-Tag') || '', /noindex/i)
  })

  it('correct secret path with trailing slash → rewrite', () => {
    const res = middleware(makeReq(SECRET_PATH + '/'))
    assert.ok(res.headers.get('x-middleware-rewrite'))
  })

  it('public / → next() (App loads)', () => {
    const res = middleware(makeReq('/'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
  })

  it('public /privacy → next()', () => {
    const res = middleware(makeReq('/privacy'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
  })

  it('ADMIN_LOGS_PATH unset → secret-shaped path falls through to next()', async () => {
    delete process.env.ADMIN_LOGS_PATH
    // Re-import to pick up new env value (module-level read).
    // Note: middleware reads env at call time, not import time, so re-import is unnecessary —
    // verify by calling directly.
    const res = middleware(makeReq('/internal-vg-logs-doesntmatter'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
    process.env.ADMIN_LOGS_PATH = SECRET_PATH
  })

  it('empty ADMIN_LOGS_PATH → next() (no admin route active)', () => {
    process.env.ADMIN_LOGS_PATH = ''
    const res = middleware(makeReq('/internal-vg-logs-anything'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
    process.env.ADMIN_LOGS_PATH = SECRET_PATH
  })

  it('malformed ADMIN_LOGS_PATH (no leading slash) → ignored, next()', () => {
    process.env.ADMIN_LOGS_PATH = 'no-leading-slash'
    const res = middleware(makeReq('/no-leading-slash'))
    assert.equal(res.headers.get('x-middleware-next'), '1')
    process.env.ADMIN_LOGS_PATH = SECRET_PATH
  })
})
