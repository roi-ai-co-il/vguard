import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeMetadata, hashIp } from '../_lib/audit-log.ts'

describe('sanitizeMetadata', () => {
  it('strips forbidden keys (cookie, authorization, password, secret, token)', () => {
    const out = sanitizeMetadata({
      cookie: 'session=abc',
      authorization: 'Bearer xyz',
      password: 'p',
      api_key: 'k',
      'set-cookie': 'foo',
      x_admin_secret: 's',
      bearer: 't',
      safe: 'ok',
    })
    assert.deepEqual(Object.keys(out), ['safe'])
    assert.equal(out.safe, 'ok')
  })

  it('strips values that look like JWTs / API keys', () => {
    const out = sanitizeMetadata({
      jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmno',
      sk: 'sk-abc1234567890def',
      bearer_value: 'bearer abc.xyz.123',
      sbp: 'sbp_abc123def456',
      framework: 'Next.js',
    })
    assert.deepEqual(Object.keys(out), ['framework'])
  })

  it('keeps safe primitive values and truncates long strings', () => {
    const long = 'a'.repeat(1000)
    const out = sanitizeMetadata({
      framework: 'Next.js',
      duration_ms: 1234,
      ok: true,
      maybe: null,
      blob: long,
    })
    assert.equal(out.framework, 'Next.js')
    assert.equal(out.duration_ms, 1234)
    assert.equal(out.ok, true)
    assert.equal(out.maybe, null)
    assert.equal((out.blob as string).length, 500)
  })

  it('drops nested objects (safe-by-default)', () => {
    const out = sanitizeMetadata({
      ok: 'yes',
      nested: { a: 1 },
    })
    assert.deepEqual(Object.keys(out), ['ok'])
  })

  it('handles undefined input', () => {
    assert.deepEqual(sanitizeMetadata(undefined), {})
  })
})

describe('hashIp', () => {
  it('returns null when no salt is configured', () => {
    const orig = process.env.AUDIT_IP_SALT
    delete process.env.AUDIT_IP_SALT
    assert.equal(hashIp('1.2.3.4'), null)
    if (orig) process.env.AUDIT_IP_SALT = orig
  })

  it('returns null for null IP', () => {
    process.env.AUDIT_IP_SALT = 'test-salt'
    assert.equal(hashIp(null), null)
  })

  it('returns a 64-char hex hash for valid IP + salt', () => {
    process.env.AUDIT_IP_SALT = 'test-salt'
    const h = hashIp('1.2.3.4')
    assert.match(h ?? '', /^[a-f0-9]{64}$/)
  })

  it('produces different hashes for different IPs (no collision under same salt)', () => {
    process.env.AUDIT_IP_SALT = 'test-salt'
    assert.notEqual(hashIp('1.2.3.4'), hashIp('5.6.7.8'))
  })

  it('produces different hashes when salt changes', () => {
    process.env.AUDIT_IP_SALT = 'salt-a'
    const a = hashIp('1.2.3.4')
    process.env.AUDIT_IP_SALT = 'salt-b'
    const b = hashIp('1.2.3.4')
    assert.notEqual(a, b)
  })
})
