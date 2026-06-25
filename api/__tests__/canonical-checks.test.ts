import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  CANONICAL_CHECKS,
  SIGNAL_STREAMS,
  canonicalCheckForFinding,
  isCustomerFacingFinding,
  type CanonicalCheckKey,
} from '../_lib/canonical-checks.ts'
import type { Category, Finding } from '../../src/lib/scanner-types.ts'

// Minimal Finding factory — only id/category matter to the partition.
function f(id: string, category: Category = 'paths'): Pick<Finding, 'id' | 'category'> {
  return { id, category }
}

describe('canonical-checks — the 23-check registry', () => {
  it('has exactly 23 checks, numbered 1..23, with unique keys', () => {
    assert.equal(CANONICAL_CHECKS.length, 23)
    const nums = CANONICAL_CHECKS.map((c) => c.n)
    assert.deepEqual(
      nums,
      Array.from({ length: 23 }, (_, i) => i + 1),
    )
    const keys = new Set(CANONICAL_CHECKS.map((c) => c.key))
    assert.equal(keys.size, 23)
  })

  it('every check belongs to one of the 8 marketing signal streams', () => {
    const families = new Set(SIGNAL_STREAMS.map((s) => s.family))
    assert.equal(families.size, 8)
    for (const c of CANONICAL_CHECKS) assert.ok(families.has(c.family), `${c.key} has a known family`)
  })
})

describe('canonicalCheckForFinding — maps emitted ids to the 23 checks', () => {
  const cases: [string, Category, CanonicalCheckKey][] = [
    // #1 transport
    ['tls-https', 'tls', 'https-tls-reachability'],
    ['tls-http', 'tls', 'https-tls-reachability'],
    ['tls-old-version', 'tls', 'tls-version'],
    ['tls-weak-cipher', 'tls', 'weak-ciphers'],
    ['tls-cert-expired', 'tls', 'certificate-expiry'],
    ['tls-cert-near-expiry', 'tls', 'certificate-expiry'],
    ['tls-no-http-redirect', 'tls', 'http-to-https-redirect'],
    // #2 / #3 secrets
    ['secret-stripe-bundle.js', 'secrets', 'secrets-in-js'],
    ['secrets-clean', 'secrets', 'secrets-in-js'],
    ['secret-supabase-service-role-bundle.js', 'secrets', 'supabase-service-role-key'],
    // #7 mixed content
    ['mixed-content', 'mixed-content', 'mixed-content'],
    // #9 cookies
    ['cookie-session', 'cookies', 'cookie-session-hardening'],
    // #10 csrf
    ['html-form-no-csrf', 'html', 'csrf-post-forms'],
    // #11 sensitive paths
    ['path--env', 'paths', 'sensitive-path-exposure'],
    ['path--git-config', 'paths', 'sensitive-path-exposure'],
    ['paths-admin-unauth-data', 'auth', 'sensitive-path-exposure'],
    ['paths-openapi-spec-public', 'paths', 'sensitive-path-exposure'],
    // #12 / #13 recon-leak
    ['paths-robots-disclosure', 'paths', 'robots-sensitive-paths'],
    ['paths-sitemap-internal', 'paths', 'sitemap-internal-leak'],
    // #14 trace
    ['methods-trace-enabled', 'methods', 'trace-method'],
    // #15-#18 cloud storage
    ['paths-supabase-storage-public-listing', 'paths', 'supabase-storage-exposure'],
    ['paths-firebase-rtdb', 'paths', 'firebase-rtdb-exposure'],
    ['paths-firebase-storage-public', 'paths', 'firebase-storage-exposure'],
    ['paths-s3-listbucket', 'paths', 's3-listbucket-exposure'],
    // #19 rate limit — passive Stage-1 notice + active Stage-3 results
    ['auth-rate-limit-needs-consent', 'auth', 'login-rate-limit'],
    ['auth-rate-limit-missing', 'auth', 'login-rate-limit'],
    ['auth-rate-limit-ok', 'auth', 'login-rate-limit'],
    // #20-#22 injection
    ['paths-open-redirect', 'paths', 'open-redirect'],
    ['paths-reflected-xss', 'paths', 'reflected-xss'],
    ['paths-sqli-error', 'paths', 'sql-injection'],
    // #23 takeover
    ['dns-cname-takeover-hint', 'dns', 'subdomain-takeover'],
  ]

  for (const [id, cat, key] of cases) {
    it(`${id} → ${key}`, () => {
      assert.equal(canonicalCheckForFinding(f(id, cat)), key)
    })
  }

  it('every canonical key is reachable from at least one mapped id', () => {
    const mapped = new Set(cases.map(([, , key]) => key))
    for (const c of CANONICAL_CHECKS) assert.ok(mapped.has(c.key), `${c.key} has a test case`)
  })
})

describe('isCustomerFacingFinding — excluded detectors are NOT customer-facing', () => {
  // Every id below is an EXCLUDED detector per the 2026-06-22 spec. None may
  // appear in the main report or contribute to the score.
  const excluded: [string, Category][] = [
    ['headers-cors-wildcard', 'headers'],
    ['headers-content-security-policy', 'headers'],
    ['headers-csp-weak', 'headers'],
    ['headers-strict-transport-security', 'headers'],
    ['headers-hsts-weak', 'headers'],
    ['headers-x-frame-options', 'headers'],
    ['headers-cross-origin-opener-policy', 'headers'],
    ['headers-server-disclosure', 'headers'],
    ['headers-x-powered-by', 'headers'],
    ['sourcemaps-exposed', 'sourcemaps'],
    ['sourcemaps-exposed-with-secrets', 'sourcemaps'],
    ['integrity-no-sri', 'integrity'],
    ['dns-no-dnssec', 'dns'],
    ['dns-no-caa', 'dns'],
    ['email-no-dmarc', 'email'],
    ['email-spf-soft-fail', 'email'],
    ['email-no-dkim', 'email'],
    ['deps-npm-axios', 'deps'],
    ['deps-server-cve-cve-2021-1234', 'deps'],
    ['ai-endpoint-detected', 'ai'],
    ['auth-signup-endpoint-found', 'auth'],
    ['auth-edge-fn-detected', 'auth'],
    ['auth-edge-fn-cors-wildcard', 'auth'],
    ['auth-enum-surface', 'auth-enum'],
    ['auth-weak-jwt', 'auth-weak'],
    ['auth-disclosure-leak', 'auth-disclosure'],
    ['html-inline-xss-surface', 'html'],
    ['html-target-blank-no-rel', 'html'],
    ['js-ast-hardcoded-creds', 'secrets'],
    ['js-ast-dom-sink', 'html'],
    ['js-ast-runtime-codegen', 'html'],
    ['meta-waf-detected', 'meta'],
    ['meta-localhost-leak', 'meta'],
    ['meta-trpc-detected', 'meta'],
    ['paths-catch-all-200', 'meta'],
    ['paths-ssrf-confirmed', 'paths'],
    ['paths-s3-references', 'paths'],
    ['paths-graphql-detected', 'paths'],
    ['platform-shared-subdomain', 'dns'],
  ]

  for (const [id, cat] of excluded) {
    it(`${id} is excluded`, () => {
      assert.equal(isCustomerFacingFinding(f(id, cat)), false)
      assert.equal(canonicalCheckForFinding(f(id, cat)), null)
    })
  }

  it('service-role wins over the generic secret- prefix', () => {
    // Even though it starts with `secret-`, a service-role key is its own check.
    assert.equal(
      canonicalCheckForFinding(f('secret-supabase-service-role-app.js', 'secrets')),
      'supabase-service-role-key',
    )
  })
})
