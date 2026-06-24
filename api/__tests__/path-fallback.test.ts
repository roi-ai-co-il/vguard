import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildPathFingerprint,
  classifyPathProbe,
  contentTypeFamily,
  controlFamilyForPath,
  sameFallbackShape,
  type ControlFamily,
  type PathControl,
} from '../_lib/scanner.ts'
import type { Severity } from '../../src/lib/scanner-types.ts'

// ── helpers ────────────────────────────────────────────────────────────────

// A guaranteed-≥300-char fixed prefix so the template "head" is identical across
// variants; the echoed path / nonce is appended AFTER char 300 (mirrors PayPal:
// same shell, body differs by a few bytes because it echoes the requested path).
const PREFIX =
  '<!DOCTYPE html><!--[if lt IE 9]><html lang="en" class="no-js lower-than-ie9"><![endif]-->' +
  '<head><title>account</title></head><body><div class="branded-error">' +
  'x'.repeat(260)

/** A branded fallback/soft-404 HTML page that echoes `echoPath` past char 300. */
function fallbackHtml(echoPath: string, pad = 7400): string {
  return `${PREFIX}<!-- not found: ${echoPath} -->${'y'.repeat(pad)}</div></body></html>`
}

function control(
  family: ControlFamily,
  body: string,
  ct: string,
  active: boolean,
): PathControl {
  return {
    ...buildPathFingerprint(body, ct),
    family,
    status: active ? 200 : 404,
    active,
  }
}

function classify(over: {
  path: string
  isSensitive?: boolean
  configuredSeverity?: Severity
  body: string
  contentType: string | null
  mainHtml?: string | null
  controls?: PathControl[]
  clustered?: boolean
  catchAll?: boolean
}) {
  return classifyPathProbe({
    path: over.path,
    isSensitive: over.isSensitive ?? true,
    configuredSeverity: over.configuredSeverity ?? 'critical',
    body: over.body,
    contentType: over.contentType,
    mainHtml: over.mainHtml ?? '<!DOCTYPE html><html><head><title>real site</title></head><body>home</body></html>',
    fingerprint: buildPathFingerprint(over.body, over.contentType),
    controls: over.controls ?? [],
    clustered: over.clustered ?? false,
    catchAll: over.catchAll ?? false,
  })
}

const INACTIVE_PLAIN = control('plain', '', '', false)
const INACTIVE_DOTFILE = control('dotfile', '', '', false)

// ── unit: helpers ────────────────────────────────────────────────────────────

describe('contentTypeFamily', () => {
  it('normalizes charset + vendor noise', () => {
    assert.equal(contentTypeFamily('text/html; charset=utf-8'), 'html')
    assert.equal(contentTypeFamily('text/plain'), 'plain')
    assert.equal(contentTypeFamily('application/json; charset=utf-8'), 'json')
    assert.equal(contentTypeFamily('application/octet-stream'), 'binary')
    assert.equal(contentTypeFamily(''), 'none')
    assert.equal(contentTypeFamily(null), 'none')
  })
})

describe('controlFamilyForPath', () => {
  it('routes each probe to a shape-matched control family', () => {
    assert.equal(controlFamilyForPath('/.env.production'), 'dotfile')
    assert.equal(controlFamilyForPath('/.env.local'), 'dotfile')
    assert.equal(controlFamilyForPath('/.aws/credentials'), 'dotfile')
    assert.equal(controlFamilyForPath('/.git/HEAD'), 'dotfile')
    assert.equal(controlFamilyForPath('/backup.sql'), 'sql')
    assert.equal(controlFamilyForPath('/backup.tar.gz'), 'sql')
    assert.equal(controlFamilyForPath('/config.json'), 'json')
    assert.equal(controlFamilyForPath('/admin'), 'plain')
  })
})

describe('sameFallbackShape', () => {
  it('matches two near-identical templates even when exact hashes differ', () => {
    const a = buildPathFingerprint(fallbackHtml('/.env.production', 7405), 'text/html; charset=utf-8')
    const ctl = control('dotfile', fallbackHtml('/.vguards_control_abc', 7400), 'text/html', true)
    assert.notEqual(a.bodyHash, ctl.bodyHash) // bodies differ (echoed path)
    assert.equal(a.headHash, ctl.headHash) // template head identical
    assert.ok(sameFallbackShape(a, ctl))
  })
  it('never matches an inactive (404/empty) control', () => {
    const a = buildPathFingerprint(fallbackHtml('/.env.production'), 'text/html')
    assert.equal(sameFallbackShape(a, INACTIVE_DOTFILE), false)
  })
  it('does not match across content-type families or wildly different sizes', () => {
    const html = buildPathFingerprint(fallbackHtml('/.env.production'), 'text/html')
    const plainCtl = control('plain', 'KEY=value\n', 'text/plain', true)
    assert.equal(sameFallbackShape(html, plainCtl), false)
  })
})

// ── A. PayPal-style dotfile soft-404 ─────────────────────────────────────────

describe('A. PayPal-style dotfile soft-404 → generic-fallback', () => {
  it('200 text/html that matches the dotfile control is NOT an exposure', () => {
    const body = fallbackHtml('/.env.production', 7405)
    const dotfileCtl = control('dotfile', fallbackHtml('/.vguards_control_abc', 7400), 'text/html; charset=utf-8', true)
    const res = classify({
      path: '/.env.production',
      body,
      contentType: 'text/html; charset=utf-8',
      controls: [INACTIVE_PLAIN, dotfileCtl], // .txt control 404s, dotfile 200s
    })
    assert.equal(res.lane, 'generic-fallback')
  })
})

// ── B. Real .env leak (must stay critical-verified) ──────────────────────────

describe('B. Real secret in .env → real-secret (always wins)', () => {
  it('text/plain DATABASE_URL is critical even when catchAll is true', () => {
    const body = 'NODE_ENV=production\nDATABASE_URL=postgresql://u:sup3rs3cret@db.host:5432/app\nPORT=3000\n'
    const res = classify({
      path: '/.env.production',
      body,
      contentType: 'text/plain',
      catchAll: true, // even with a catch-all origin, a real secret must win
      controls: [control('dotfile', fallbackHtml('/.x'), 'text/html', true)],
    })
    assert.equal(res.lane, 'real-secret')
  })
  it('a PEM private key body is critical regardless of content-type', () => {
    const body = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n'
    const res = classify({ path: '/.aws/credentials', body, contentType: 'text/html' })
    assert.equal(res.lane, 'real-secret')
  })
})

// ── C. Raw plain file, no secret → needs review (allowed) ────────────────────

describe('C. Plausible raw file, no secret → exposed-needs-review', () => {
  it('text/plain config with no strong secret still flags for review', () => {
    const body = 'NODE_ENV=production\nPORT=3000\nLOG_LEVEL=info\nFEATURE_X=true\n'
    const res = classify({
      path: '/.env.local',
      body,
      contentType: 'text/plain',
      controls: [INACTIVE_DOTFILE, INACTIVE_PLAIN], // origin DOES 404 nonexistent paths
    })
    assert.equal(res.lane, 'exposed-needs-review')
  })
})

// ── D. HTML page on a raw-secret path, no secret → rendered-page ─────────────

describe('D. HTML on a raw-file path, no secret → rendered-page (info, not exposed)', () => {
  it('downgrades /.aws/credentials served as HTML', () => {
    const body = '<!DOCTYPE html><html><head><title>Oops</title></head><body>' + 'z'.repeat(600) + '</body></html>'
    const res = classify({
      path: '/.aws/credentials',
      body,
      contentType: 'text/html; charset=utf-8',
      controls: [INACTIVE_DOTFILE], // not a control match, not clustered
    })
    assert.equal(res.lane, 'rendered-page')
  })
})

// ── E. Multiple sensitive paths share one template → clustered ───────────────

describe('E. Same template across probes → generic-fallback via cluster clamp', () => {
  it('clustered=true suppresses the per-path finding', () => {
    const body = fallbackHtml('/.env.local', 7402)
    const res = classify({
      path: '/.env.local',
      body,
      contentType: 'text/html',
      clustered: true,
      controls: [INACTIVE_DOTFILE], // no control match — clustering is the signal
    })
    assert.equal(res.lane, 'generic-fallback')
  })
  it('the clustering basis: same template ⇒ equal headHash, differing bodyHash', () => {
    const a = buildPathFingerprint(fallbackHtml('/.env.local', 7400), 'text/html')
    const b = buildPathFingerprint(fallbackHtml('/.git/HEAD', 7400), 'text/html')
    const c = buildPathFingerprint(fallbackHtml('/backup.sql', 7400), 'text/html')
    assert.equal(a.headHash, b.headHash)
    assert.equal(b.headHash, c.headHash)
    assert.notEqual(a.bodyHash, b.bodyHash)
    assert.notEqual(b.bodyHash, c.bodyHash)
  })
})

// ── guard: empty + non-sensitive behavior unchanged ──────────────────────────

describe('lane order guards', () => {
  it('empty body → empty', () => {
    assert.equal(classify({ path: '/.env', body: '', contentType: 'text/html' }).lane, 'empty')
  })
  it('non-sensitive HTML 200 (e.g. /admin) is NOT downgraded as rendered-page', () => {
    const body = '<!DOCTYPE html><html><head><title>Admin</title></head><body>' + 'a'.repeat(400) + '</body></html>'
    const res = classify({
      path: '/admin',
      isSensitive: false,
      configuredSeverity: 'warn',
      body,
      contentType: 'text/html',
    })
    assert.equal(res.lane, 'exposed')
  })
})
