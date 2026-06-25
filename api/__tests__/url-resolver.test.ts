import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  resolveReachableUrl,
  generateCandidates,
  classifyNetworkError,
  type ResolverResult,
  type ResolverSuccess,
} from '../_lib/url-resolver.ts'
import { runScan } from '../_lib/scanner.ts'

// ── mock fetch helpers (no network) ──────────────────────────────────────────

function html(status = 200, body = '<!DOCTYPE html><html><body>ok</body></html>') {
  return () => new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8' } })
}
function redirectTo(location: string, status = 301) {
  return () => new Response(null, { status, headers: { location } })
}
function status(code: number) {
  return () => new Response('blocked', { status: code, headers: { 'content-type': 'text/html' } })
}
const errAbort = () => {
  throw Object.assign(new Error('The operation was aborted'), { name: 'AbortError' })
}
const errDns = () => {
  throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { cause: { code: 'ENOTFOUND' } })
}
const errTls = () => {
  throw Object.assign(new Error('certificate has expired'), { cause: { code: 'CERT_HAS_EXPIRED' } })
}
const errTcp = () => {
  throw Object.assign(new Error('connect ECONNREFUSED'), { cause: { code: 'ECONNREFUSED' } })
}

/** Build an injected fetch from a url→handler map. Unmapped urls → DNS error. */
function mockFetch(routes: Record<string, () => Response>) {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    const handler = routes[url]
    if (!handler) return errDns()
    return handler()
  }) as typeof fetch
}

const OPTS = { perCandidateTimeoutMs: 50, globalBudgetMs: 2000 }
async function resolve(input: string, routes: Record<string, () => Response>): Promise<ResolverResult> {
  return resolveReachableUrl(input, { ...OPTS, fetchFn: mockFetch(routes) })
}
function ok(r: ResolverResult): ResolverSuccess {
  assert.equal(r.ok, true, `expected resolver success, got ${r.ok ? '' : (r as { code: string }).code}`)
  return r as ResolverSuccess
}

// ── unit: candidate generation + ordering ────────────────────────────────────

describe('generateCandidates', () => {
  it('no protocol → HTTPS-first grid, www counterpart added, exact first', () => {
    const c = generateCandidates('example.com').map((x) => x.url)
    assert.deepEqual(c, [
      'https://example.com/',
      'https://www.example.com/',
      'http://example.com/',
      'http://www.example.com/',
    ])
  })
  it('explicit http:// → exact http first, never auto-upgraded before testing', () => {
    const c = generateCandidates('http://www.example.com')
    assert.equal(c[0].url, 'http://www.example.com/')
    assert.equal(c[0].protocol, 'http:')
    assert.equal(c[0].isExact, true)
    // https variants come AFTER the http ones
    assert.ok(c.findIndex((x) => x.protocol === 'http:') < c.findIndex((x) => x.protocol === 'https:'))
  })
  it('explicit https:// → exact https first', () => {
    const c = generateCandidates('https://example.com')
    assert.equal(c[0].url, 'https://example.com/')
    assert.equal(c[0].protocol, 'https:')
  })
})

describe('classifyNetworkError', () => {
  it('maps node error codes to structured types', () => {
    assert.equal(classifyNetworkError(Object.assign(new Error('x'), { name: 'AbortError' })), 'http_timeout')
    assert.equal(classifyNetworkError({ cause: { code: 'ENOTFOUND' } }), 'dns_error')
    assert.equal(classifyNetworkError({ cause: { code: 'ECONNREFUSED' } }), 'tcp_connect_timeout')
    assert.equal(classifyNetworkError({ cause: { code: 'CERT_HAS_EXPIRED' } }), 'tls_error')
    assert.equal(classifyNetworkError({ message: 'weird' }), 'unknown_network_error')
  })
})

// ── the 10 spec tests ────────────────────────────────────────────────────────

describe('resolver — spec tests', () => {
  it('Test 1: example.com, HTTPS works → https://example.com, scannable', async () => {
    const r = ok(await resolve('example.com', { 'https://example.com/': html() }))
    assert.equal(r.resolvedScanUrl, 'https://example.com/')
    assert.equal(r.reachability, 'scannable')
    assert.equal(r.httpDowngraded, false)
    assert.equal(r.usedFallback, false)
  })

  it('Test 2: HTTPS times out, HTTP works → http://example.com, http_only (HTTP finding fires in runScan)', async () => {
    const r = ok(
      await resolve('example.com', {
        'https://example.com/': errAbort,
        'https://www.example.com/': errAbort,
        'http://example.com/': html(),
      }),
    )
    assert.equal(r.resolvedScanUrl, 'http://example.com/')
    assert.equal(r.reachability, 'http_only')
    assert.equal(r.httpDowngraded, true) // → runScan sets httpsActive=false → tls-http critical + cap 49
    assert.equal(r.usedFallback, true)
  })

  it('Test 3: non-www fails, www works → www variant', async () => {
    const r = ok(
      await resolve('example.com', {
        'https://example.com/': errAbort,
        'https://www.example.com/': html(),
      }),
    )
    assert.equal(r.resolvedScanUrl, 'https://www.example.com/')
    assert.equal(r.reachability, 'scannable')
    assert.equal(r.usedFallback, true)
  })

  it('Test 4: www.example.com, www fails, apex works → apex variant', async () => {
    const r = ok(
      await resolve('www.example.com', {
        'https://www.example.com/': errAbort,
        'https://example.com/': html(),
      }),
    )
    assert.equal(r.resolvedScanUrl, 'https://example.com/')
  })

  it('Test 5: http://www.example.com → exact HTTP tested first, not auto-upgraded', async () => {
    const r = ok(await resolve('http://www.example.com', { 'http://www.example.com/': html() }))
    assert.equal(r.attempts[0].candidateUrl, 'http://www.example.com/')
    assert.equal(r.attempts[0].protocol, 'http:')
    assert.equal(r.attempts[0].selected, true)
    assert.equal(r.resolvedScanUrl, 'http://www.example.com/')
    assert.equal(r.reachability, 'http_only')
  })

  it('Test 6: https TLS error, HTTP works → completes on HTTP, TLS error in attempt metadata', async () => {
    const r = ok(
      await resolve('https://example.com', {
        'https://example.com/': errTls,
        'https://www.example.com/': errTls,
        'http://example.com/': html(),
      }),
    )
    assert.equal(r.resolvedScanUrl, 'http://example.com/')
    assert.equal(r.httpDowngraded, true)
    assert.ok(r.attempts.some((a) => a.errorType === 'tls_error'), 'a TLS error is recorded in attempts')
  })

  it('Test 7: all variants fail → all_candidates_failed with every attempt logged', async () => {
    const r = await resolve('example.com', {
      'https://example.com/': errDns,
      'https://www.example.com/': errAbort,
      'http://example.com/': errTcp,
      'http://www.example.com/': errTls,
    })
    assert.equal(r.ok, false)
    if (r.ok) return
    assert.equal(r.code, 'all_candidates_failed') // mixed error types → generic
    assert.equal(r.attempts.length, 4)
    assert.ok(r.attempts.every((a) => a.errorType !== null))
  })

  it('Test 8: homepage works → resolver succeeds so the scan can start (partial-probe resilience is runScan-level)', async () => {
    const r = ok(await resolve('example.com', { 'https://example.com/': html() }))
    assert.equal(r.reachability, 'scannable')
    // Every runScan probe is wrapped in .catch(() => empty), so a probe timeout
    // degrades that probe only — it cannot fail the whole scan once the homepage
    // resolved. (Verified structurally in scanner.ts; not re-fetched here.)
  })

  it('Test 9: best candidate is 403, no 2xx/3xx/HTML → reachable_but_blocked (not dead, not failed)', async () => {
    const r = ok(
      await resolve('example.com', {
        'https://example.com/': status(403),
        'https://www.example.com/': status(403),
        'http://example.com/': status(403),
        'http://www.example.com/': status(403),
      }),
    )
    assert.equal(r.reachability, 'reachable_but_blocked')
    assert.equal(r.status, 403)
  })

  it('Test 9b: WAF 429 on all candidates → reachable_but_blocked (NOT all_candidates_failed)', async () => {
    const r = ok(
      await resolve('example.com', {
        'https://example.com/': status(429),
        'https://www.example.com/': status(429),
        'http://example.com/': status(429),
        'http://www.example.com/': status(429),
      }),
    )
    assert.equal(r.reachability, 'reachable_but_blocked') // → runScan stealth retry → blocked_by_waf
    assert.equal(r.status, 429)
  })

  it('Test 9c: bare 404 on all candidates → reachable_but_blocked (host alive, runScan → blocked_by_target)', async () => {
    const r = ok(
      await resolve('example.com', {
        'https://example.com/': status(404),
        'https://www.example.com/': status(404),
        'http://example.com/': status(404),
        'http://www.example.com/': status(404),
      }),
    )
    assert.equal(r.reachability, 'reachable_but_blocked')
    assert.equal(r.status, 404)
  })

  it('Test 10: HTTP redirects to HTTPS and HTTPS works → final HTTPS URL, no HTTP downgrade', async () => {
    const r = ok(
      await resolve('http://example.com', {
        'http://example.com/': redirectTo('https://example.com/', 301),
        'https://example.com/': html(),
      }),
    )
    assert.equal(r.resolvedScanUrl, 'https://example.com/')
    assert.equal(r.httpDowngraded, false) // final protocol is https → no HTTP-only finding
    assert.equal(r.reachability, 'scannable')
    assert.ok(r.attempts[0].redirectChain.includes('http://example.com/'), 'redirect chain captured')
  })
})

// ── heavier integration: partial/degraded scan (spec §9 / test 8) ────────────

describe('runScan — partial scan when probes fail', () => {
  it('homepage resolves but EVERY downstream probe throws → scan still completes (not a ScanError)', async () => {
    const realFetch = globalThis.fetch
    const homepage =
      '<!DOCTYPE html><html><head><title>Partial</title></head><body><h1>hi</h1></body></html>'
    // Resolver homepage candidate → 200; every other fetch (robots, path probes,
    // bundles, control fetches, CT lookup, xss/sqli/redirect canaries, …) → abort.
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const u = typeof input === 'string' ? input : input.toString()
      if (u === 'https://example.com/' || u === 'https://example.com') {
        return new Response(homepage, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } })
      }
      throw Object.assign(new Error('The operation was aborted'), { name: 'AbortError' })
    }) as typeof fetch
    try {
      const r = await runScan('https://example.com')
      // The whole scan must NOT fail just because probes timed out.
      assert.equal(r.ok, true, `expected partial success, got error ${r.ok ? '' : (r as { error: { code: string } }).error.code}`)
      if (!r.ok) return
      assert.equal(r.resolution?.resolvedScanUrl, 'https://example.com/')
      assert.equal(r.resolution?.reachability, 'scannable')
      // Homepage was scanned → HTML-derived findings still exist despite probe failures.
      assert.ok(r.findings.length > 0, 'partial scan still produced findings')
      assert.ok(typeof r.vibeScore === 'number', 'a score was still computed')
    } finally {
      globalThis.fetch = realFetch
    }
  })
})
