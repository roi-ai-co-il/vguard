import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  createOrGetChallenge,
  markVerifiedAndAuthorize,
  isAuthorizedForStage3,
  revokeAuthorization,
  tokenPresentIn,
  __resetMemoryForTests,
} from '../_lib/stage3-auth.ts'

// These run with no Supabase env → the store uses its in-memory backend, so the
// full challenge → authorization → gate flow is exercised deterministically.
describe('Stage 3 ownership authorization', () => {
  beforeEach(() => __resetMemoryForTests())

  it('owner email can verify and then run Stage 3', async () => {
    const ch = await createOrGetChallenge('example.com', 'owner@x.com', 'dns')
    assert.ok(ch?.token, 'server issued a challenge token')
    // The domain publicly exposes the server-issued token → verify passes.
    assert.equal(tokenPresentIn(ch.token, [ch.token]), true)
    const authz = await markVerifiedAndAuthorize('example.com', 'owner@x.com', 'dns')
    assert.ok(authz?.authToken, 'a private auth token was issued')
    const gate = await isAuthorizedForStage3('example.com', authz.authToken)
    assert.equal(gate.authorized, true)
    assert.equal(gate.email, 'owner@x.com')
  })

  it('attacker email CANNOT use the same public DNS/file code', async () => {
    const owner = await createOrGetChallenge('victim.com', 'owner@x.com', 'dns')
    const attacker = await createOrGetChallenge('victim.com', 'attacker@evil.com', 'dns')
    assert.ok(owner && attacker)
    // Different email → different server-issued token.
    assert.notEqual(owner.token, attacker.token)
    // victim.com's DNS publicly exposes the OWNER's token. The attacker's verify
    // checks the attacker's own token against it → no match → cannot verify.
    assert.equal(tokenPresentIn(attacker.token, [owner.token]), false)
    // And with no authorization, the gate denies.
    const gate = await isAuthorizedForStage3('victim.com', 'vga-' + 'a'.repeat(48))
    assert.equal(gate.authorized, false)
  })

  it('a client-supplied arbitrary code is not accepted', async () => {
    const owner = await createOrGetChallenge('victim.com', 'owner@x.com', 'dns')
    assert.ok(owner)
    // The PUBLIC DNS value (vs-…) is not a valid auth token → gate denies.
    assert.equal((await isAuthorizedForStage3('victim.com', owner.token)).authorized, false)
    // Random / malformed strings → denied.
    assert.equal((await isAuthorizedForStage3('victim.com', 'not-a-token')).authorized, false)
    assert.equal((await isAuthorizedForStage3('victim.com', '')).authorized, false)
  })

  it('a verified domain does NOT auto-authorize any other email/token', async () => {
    // Owner verifies victim.com.
    const authz = await markVerifiedAndAuthorize('victim.com', 'owner@x.com', 'dns')
    assert.ok(authz?.authToken)
    // The owner's token works…
    assert.equal((await isAuthorizedForStage3('victim.com', authz.authToken)).authorized, true)
    // …but a different (attacker) token for the same, now-verified domain does not.
    assert.equal(
      (await isAuthorizedForStage3('victim.com', 'vga-' + 'b'.repeat(48))).authorized,
      false,
    )
  })

  it('repeat visit of the same owner works without re-verification', async () => {
    const authz = await markVerifiedAndAuthorize('example.com', 'owner@x.com', 'dns')
    assert.ok(authz?.authToken)
    assert.equal((await isAuthorizedForStage3('example.com', authz.authToken)).authorized, true)
    // Same token again (a later visit) still authorizes — no re-challenge needed.
    assert.equal((await isAuthorizedForStage3('example.com', authz.authToken)).authorized, true)
  })

  it('a revoked authorization blocks Stage 3', async () => {
    const authz = await markVerifiedAndAuthorize('example.com', 'owner@x.com', 'dns')
    assert.ok(authz?.authToken)
    assert.equal((await isAuthorizedForStage3('example.com', authz.authToken)).authorized, true)
    await revokeAuthorization('example.com', 'owner@x.com')
    assert.equal((await isAuthorizedForStage3('example.com', authz.authToken)).authorized, false)
  })

  it('an auth token is bound to its exact domain', async () => {
    const authz = await markVerifiedAndAuthorize('example.com', 'owner@x.com', 'dns')
    assert.ok(authz?.authToken)
    // The same token must not authorize a different domain.
    assert.equal((await isAuthorizedForStage3('other.com', authz.authToken)).authorized, false)
  })

  it('domain and email are normalized (www / case-insensitive)', async () => {
    const authz = await markVerifiedAndAuthorize('Example.com', 'Owner@X.com', 'dns')
    assert.ok(authz?.authToken)
    const gate = await isAuthorizedForStage3('www.example.com', authz.authToken)
    assert.equal(gate.authorized, true)
    assert.equal(gate.email, 'owner@x.com')
  })
})
