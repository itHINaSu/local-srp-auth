import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'

import { AuditLogger } from '../src/audit/audit-logger.js'
import { AuthServer } from '../src/server-auth.js'
import { InviteManager } from '../src/invites.js'
import { MemoryUserStore, MemoryRoleStore, MemorySessionStore, MemoryInviteStore } from '../src/storage/memory-store.js'
import { JsonFileInviteStore } from '../src/storage/json-file-store.js'
import { SessionStore } from '../src/storage/storage-interface.js'
import { RateLimitExceededError } from '../src/rate-limit/rate-limiter.js'
import { SrpRegistration, SrpLoginAttempt } from '../src/srp/srp-client.js'
import { createNodeCryptoAdapter } from '../src/common/crypto-adapter-node.js'
import * as totp from '../src/totp/totp.js'
import { decode as base32Decode } from '../src/totp/base32.js'

const clientAdapter = createNodeCryptoAdapter()
const GENERIC = /invalid or expired invite/

class CapturingLogger extends AuditLogger {
  constructor () {
    super()
    this.events = []
  }

  async log (event) { this.events.push(event) }
}

function makeEnv ({ serverOpts = {}, inviteStore = new MemoryInviteStore(), managerOpts = {} } = {}) {
  const logger = new CapturingLogger()
  const server = new AuthServer({
    userStore: new MemoryUserStore(),
    roleStore: new MemoryRoleStore(),
    logger,
    ...serverOpts
  })
  const invites = new InviteManager(server, { inviteStore, ...managerOpts })
  return { server, invites, logger, inviteStore }
}

async function credentialFor (password) {
  return SrpRegistration.create({ password, adapter: clientAdapter })
}

async function login (server, username, password) {
  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  const { challengeId, salt, B, uid } = await server.beginLogin({ username, clientPublicEphemeral: A })
  const { M1 } = await client.finish({ password, salt, serverPublicEphemeral: B, uid })
  const result = await server.completeLogin({ challengeId, clientProof: M1 })
  await client.verifyServerProof(result.M2)
  return result
}

async function registerActive (server, username, password) {
  return server.registerUser({ username, ...(await credentialFor(password)) })
}

async function enrollTotp (server, uid) {
  const enrollment = await server.beginTotpEnrollment(uid)
  const secret = base32Decode(new URL(enrollment.otpauthUri).searchParams.get('secret'))
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })
  return secret
}

// 1. Happy paths -----------------------------------------------------------

test('activate: pending -> issue -> preview -> redeem -> SRP login succeeds', async () => {
  const { server, invites } = makeEnv()
  const pending = await server.createPendingUser({ username: 'grandma', roleIds: ['role-read'] })
  assert.equal(pending.username, 'grandma')

  const { invite, token } = await invites.issue({ uid: pending.id, purpose: 'activate', createdBy: 'admin-1' })
  assert.equal(invite.purpose, 'activate')
  assert.equal(invite.tokenHash, undefined, 'token hash must not be handed back')
  assert.equal(typeof token, 'string')

  const preview = await invites.preview({ token })
  assert.deepEqual(
    { uid: preview.uid, username: preview.username, purpose: preview.purpose },
    { uid: pending.id, username: 'grandma', purpose: 'activate' }
  )

  const user = await invites.redeem({ token, ...(await credentialFor('chosen password 1')) })
  assert.equal(user.id, pending.id)
  assert.equal(user.verifier, undefined)

  const result = await login(server, 'grandma', 'chosen password 1')
  assert.equal(result.mfaRequired, false)
  assert.equal((await server.getSession(result.sessionToken)).uid, pending.id)
})

test('credential-reset: old password fails, new works, prior sessions die', async () => {
  const { server, invites, logger } = makeEnv()
  const user = await registerActive(server, 'alice', 'old password')
  const { sessionToken } = await login(server, 'alice', 'old password')
  assert.ok(await server.getSession(sessionToken))

  const { token } = await invites.issue({ uid: user.id, purpose: 'credential-reset', createdBy: 'admin-1' })
  await invites.redeem({ token, ...(await credentialFor('new password')) })

  assert.equal(await server.getSession(sessionToken), null)
  assert.ok(logger.events.some((e) => e.type === 'invite.sessions_revoked'))
  await assert.rejects(login(server, 'alice', 'old password'), /login failed/)
  const result = await login(server, 'alice', 'new password')
  assert.equal(typeof result.sessionToken, 'string')
})

test('credential-reset without deleteByUid support completes but audits invite.sessions_not_revoked', async () => {
  class LegacySessionStore extends SessionStore {
    constructor () { super(); this._inner = new MemorySessionStore() }
    put (...a) { return this._inner.put(...a) }
    get (...a) { return this._inner.get(...a) }
    delete (...a) { return this._inner.delete(...a) }
  }
  const { server, invites, logger } = makeEnv({ serverOpts: { sessionStore: new LegacySessionStore() } })
  const user = await registerActive(server, 'alice', 'old password')
  const { token } = await invites.issue({ uid: user.id, purpose: 'credential-reset' })
  await invites.redeem({ token, ...(await credentialFor('new password')) })
  assert.ok(logger.events.some((e) => e.type === 'invite.sessions_not_revoked'))
  assert.ok(!logger.events.some((e) => e.type === 'invite.sessions_revoked'))
  await login(server, 'alice', 'new password')
})

test('issue enforces purpose/user-state pairing', async () => {
  const { server, invites } = makeEnv()
  const pending = await server.createPendingUser({ username: 'p' })
  const active = await registerActive(server, 'a', 'pw')
  await assert.rejects(invites.issue({ uid: pending.id, purpose: 'credential-reset' }))
  await assert.rejects(invites.issue({ uid: active.id, purpose: 'activate' }))
  await assert.rejects(invites.issue({ uid: 'nope', purpose: 'activate' }))
  await assert.rejects(invites.issue({ uid: pending.id, purpose: 'bogus' }))
})

test('createPendingUser enforces username uniqueness and audits', async () => {
  const { server, logger } = makeEnv()
  await server.createPendingUser({ username: 'dup' })
  await assert.rejects(server.createPendingUser({ username: 'dup' }), /already taken/)
  await assert.rejects(registerActive(server, 'dup', 'pw'), /already taken/)
  assert.ok(logger.events.some((e) => e.type === 'user.pending_created'))
  assert.equal(await server.userStore.countUsers(), 1)
})

// 2. Reuse / revoke / expiry / unknown are indistinguishable ---------------

test('reuse, revoked, expired, and unknown tokens all fail with the same generic error', async () => {
  const { server, invites } = makeEnv()
  const errors = []
  const capture = async (fn) => {
    try { await fn(); assert.fail('expected rejection') } catch (err) {
      if (err.code === 'ERR_ASSERTION') throw err
      errors.push(err)
    }
  }

  // reuse
  const u1 = await server.createPendingUser({ username: 'u1' })
  const t1 = (await invites.issue({ uid: u1.id, purpose: 'activate' })).token
  await invites.redeem({ token: t1, ...(await credentialFor('pw1')) })
  await capture(async () => invites.redeem({ token: t1, ...(await credentialFor('pw1b')) }))
  await capture(async () => invites.preview({ token: t1 }))

  // revoked
  const u2 = await server.createPendingUser({ username: 'u2' })
  const { invite: i2, token: t2 } = await invites.issue({ uid: u2.id, purpose: 'activate' })
  await invites.revoke(i2.id)
  await capture(async () => invites.redeem({ token: t2, ...(await credentialFor('pw2')) }))
  await capture(async () => invites.preview({ token: t2 }))

  // expired
  const u3 = await server.createPendingUser({ username: 'u3' })
  const t3 = (await invites.issue({ uid: u3.id, purpose: 'activate', ttlMs: 20 })).token
  await new Promise((resolve) => setTimeout(resolve, 40))
  await capture(async () => invites.redeem({ token: t3, ...(await credentialFor('pw3')) }))
  await capture(async () => invites.preview({ token: t3 }))

  // unknown / malformed
  await capture(async () => invites.redeem({ token: crypto.randomBytes(32).toString('base64url'), ...(await credentialFor('pw4')) }))
  await capture(async () => invites.preview({ token: 'garbage' }))
  await capture(async () => invites.preview({ token: undefined }))

  assert.equal(errors.length, 9)
  for (const err of errors) {
    assert.equal(err.constructor, Error)
    assert.match(err.message, GENERIC)
    assert.equal(err.message, errors[0].message)
  }
})

// 3. Re-issue revokes ------------------------------------------------------

test('re-issuing revokes the earlier outstanding invite for the same (uid, purpose)', async () => {
  const { server, invites } = makeEnv()
  const pending = await server.createPendingUser({ username: 'u' })
  const first = await invites.issue({ uid: pending.id, purpose: 'activate' })
  const second = await invites.issue({ uid: pending.id, purpose: 'activate' })

  await assert.rejects(invites.preview({ token: first.token }), GENERIC)
  await invites.preview({ token: second.token })

  const listed = await invites.listForUser(pending.id)
  assert.equal(listed.length, 2)
  assert.notEqual(listed.find((i) => i.id === first.invite.id).revokedAt, null)
  assert.equal(listed.find((i) => i.id === second.invite.id).revokedAt, null)
})

test('re-issuing for a different purpose does not revoke the other purpose', async () => {
  const { server, invites } = makeEnv()
  const user = await registerActive(server, 'a', 'pw')
  const reset = await invites.issue({ uid: user.id, purpose: 'credential-reset' })
  const reset2 = await invites.issue({ uid: user.id, purpose: 'credential-reset' })
  await assert.rejects(invites.preview({ token: reset.token }), GENERIC)
  await invites.preview({ token: reset2.token })
})

// 4. Pending users are indistinguishable from nonexistent ------------------

test('pending user: beginLogin looks like a nonexistent username and completeLogin never succeeds', async () => {
  const { server } = makeEnv()
  await server.createPendingUser({ username: 'pending-person' })

  const attempt = async (username) => {
    const client = new SrpLoginAttempt({ adapter: clientAdapter })
    const { A } = client.start()
    const resp = await server.beginLogin({ username, clientPublicEphemeral: A })
    return { client, resp }
  }
  const pend = await attempt('pending-person')
  const ghost = await attempt('nobody-here')

  assert.deepEqual(Object.keys(pend.resp).sort(), Object.keys(ghost.resp).sort())
  assert.match(pend.resp.uid, /^fake-/, 'pending users must take the fake-credential path')
  assert.equal(pend.resp.salt.length, ghost.resp.salt.length)
  assert.equal(pend.resp.B.length, ghost.resp.B.length)
  assert.equal(pend.resp.uid.length, ghost.resp.uid.length)
  // deterministic per username, like any nonexistent username
  const again = await attempt('pending-person')
  assert.equal(again.resp.uid, pend.resp.uid)
  assert.equal(again.resp.salt, pend.resp.salt)

  for (const { client, resp } of [pend, ghost]) {
    const { M1 } = await client.finish({ password: 'whatever', salt: resp.salt, serverPublicEphemeral: resp.B, uid: resp.uid })
    await assert.rejects(server.completeLogin({ challengeId: resp.challengeId, clientProof: M1 }), /login failed/)
  }
})

// 5. clearTotp both ways ---------------------------------------------------

test('credential-reset keeps TOTP by default: reset user still needs MFA', async () => {
  const { server, invites } = makeEnv()
  const user = await registerActive(server, 'alice', 'old password')
  const secret = await enrollTotp(server, user.id)

  const { invite, token } = await invites.issue({ uid: user.id, purpose: 'credential-reset' })
  assert.equal(invite.clearTotp, false)
  const redeemed = await invites.redeem({ token, ...(await credentialFor('new password')) })
  assert.equal(redeemed.mfaEnabled, true)

  const result = await login(server, 'alice', 'new password')
  assert.equal(result.mfaRequired, true)
  assert.equal(result.sessionToken, undefined)
  const { sessionToken } = await server.verifyMfaTotp({ mfaToken: result.mfaToken, code: totp.totpAt(secret, Date.now()) })
  assert.ok(await server.getSession(sessionToken))
})

test('credential-reset with clearTotp: true removes TOTP and recovery codes', async () => {
  const { server, invites } = makeEnv()
  const user = await registerActive(server, 'alice', 'old password')
  await enrollTotp(server, user.id)

  const { invite, token } = await invites.issue({ uid: user.id, purpose: 'credential-reset', clearTotp: true })
  assert.equal(invite.clearTotp, true)
  const redeemed = await invites.redeem({ token, ...(await credentialFor('new password')) })
  assert.equal(redeemed.mfaEnabled, false)

  const stored = await server.userStore.getUserById(user.id)
  assert.equal(stored.totp, null)
  assert.deepEqual(stored.recoveryCodeHashes, [])
  const result = await login(server, 'alice', 'new password')
  assert.equal(result.mfaRequired, false)
})

// 6. Rate limiting + audit without token material --------------------------

test('rate limit trips on preview and on redeem, and is shared across both', async () => {
  for (const op of ['preview', 'redeem']) {
    const { server, invites, logger } = makeEnv({
      serverOpts: { rateLimits: { invite: { maxAttempts: 3, windowMs: 60000 } } }
    })
    const cred = await credentialFor('pw')
    const call = () => op === 'preview'
      ? invites.preview({ token: 'wrong-token' })
      : invites.redeem({ token: 'wrong-token', ...cred })
    for (let i = 0; i < 3; i++) await assert.rejects(call(), GENERIC)
    await assert.rejects(call(), (err) => err instanceof RateLimitExceededError)
    assert.ok(logger.events.some((e) => e.type === 'invite.rate_limited'))
    void server
  }

  // shared surface: per-client layer counts preview + redeem together
  const { invites } = makeEnv({
    serverOpts: { rateLimits: { inviteClient: { maxAttempts: 2, windowMs: 60000 } } }
  })
  const cred = await credentialFor('pw')
  await assert.rejects(invites.preview({ token: 'a', clientKey: '1.2.3.4' }), GENERIC)
  await assert.rejects(invites.redeem({ token: 'b', ...cred, clientKey: '1.2.3.4' }), GENERIC)
  await assert.rejects(invites.preview({ token: 'c', clientKey: '1.2.3.4' }), (e) => e instanceof RateLimitExceededError)
})

test('audit events are emitted and contain no token material (raw token or its hash)', async () => {
  const { server, invites, logger } = makeEnv({
  })
  const user = await registerActive(server, 'alice', 'old password')
  await login(server, 'alice', 'old password')
  const stale = await invites.issue({ uid: user.id, purpose: 'credential-reset', createdBy: 'admin-1' })
  const { invite, token } = await invites.issue({ uid: user.id, purpose: 'credential-reset', createdBy: 'admin-1' })
  const garbage = 'definitely-not-a-token'

  await assert.rejects(invites.preview({ token: stale.token, clientKey: '9.9.9.9' }), GENERIC) // revoked, failed
  await invites.preview({ token })
  await invites.redeem({ token, ...(await credentialFor('new password')) })
  await assert.rejects(invites.preview({ token, clientKey: '9.9.9.9' }), GENERIC) // used, failed
  await assert.rejects(invites.preview({ token: garbage }), GENERIC)

  const types = new Set(logger.events.map((e) => e.type))
  for (const t of ['invite.issued', 'invite.revoked', 'invite.redeemed', 'invite.failed', 'invite.sessions_revoked']) {
    assert.ok(types.has(t), `missing audit event ${t}`)
  }
  assert.ok(logger.events.some((e) => e.type === 'invite.issued' && e.details.inviteId === invite.id))

  const dump = JSON.stringify(logger.events)
  const stored = await server.userStore.getUserById(user.id)
  for (const secret of [token, stale.token, garbage, crypto.createHash('sha256').update(token).digest('hex'),
    crypto.createHash('sha256').update(stale.token).digest('hex'), stored.verifier, stored.salt]) {
    assert.ok(!dump.includes(secret), 'audit log leaked secret material')
  }
})

test('rate-limit audit events never contain the submitted token or its hash', async () => {
  const { invites, logger } = makeEnv({
    serverOpts: { rateLimits: { invite: { maxAttempts: 1, windowMs: 60000 } } }
  })
  const token = 'some-guess-token'
  await assert.rejects(invites.preview({ token }), GENERIC)
  await assert.rejects(invites.preview({ token }), (e) => e instanceof RateLimitExceededError)
  const dump = JSON.stringify(logger.events)
  assert.ok(logger.events.some((e) => e.type === 'invite.rate_limited'))
  assert.ok(!dump.includes(token))
  assert.ok(!dump.includes(crypto.createHash('sha256').update(token).digest('hex')))
})

test('the raw token is never stored: the invite store holds only sha256(token)', async () => {
  const { server, invites, inviteStore } = makeEnv()
  const pending = await server.createPendingUser({ username: 'u' })
  const { invite, token } = await invites.issue({ uid: pending.id, purpose: 'activate' })
  const stored = await inviteStore.getInvite(invite.id)
  assert.equal(stored.tokenHash, crypto.createHash('sha256').update(token).digest('hex'))
  assert.ok(!JSON.stringify(stored).includes(token))
})

// 7. Concurrent redeem race ------------------------------------------------

test('concurrent double-redeem: exactly one wins', async () => {
  const { server, invites } = makeEnv()
  const pending = await server.createPendingUser({ username: 'u' })
  const { token } = await invites.issue({ uid: pending.id, purpose: 'activate' })
  const credA = await credentialFor('password A')
  const credB = await credentialFor('password B')

  const results = await Promise.allSettled([
    invites.redeem({ token, ...credA }),
    invites.redeem({ token, ...credB }),
    invites.redeem({ token, ...credA }),
    invites.redeem({ token, ...credB })
  ])
  const won = results.filter((r) => r.status === 'fulfilled')
  const lost = results.filter((r) => r.status === 'rejected')
  assert.equal(won.length, 1)
  assert.equal(lost.length, 3)
  for (const r of lost) assert.match(r.reason.message, GENERIC)
})

test('malformed credential input is rejected without burning the token', async () => {
  const { server, invites } = makeEnv()
  const pending = await server.createPendingUser({ username: 'u' })
  const { token } = await invites.issue({ uid: pending.id, purpose: 'activate' })
  await assert.rejects(invites.redeem({ token, salt: '', verifier: '' }), /required/)
  await invites.preview({ token }) // still valid
  await invites.redeem({ token, ...(await credentialFor('pw')) })
})

test('revoke is audited; listForUser hides token hashes', async () => {
  const { server, invites, logger } = makeEnv()
  const pending = await server.createPendingUser({ username: 'u' })
  const { invite } = await invites.issue({ uid: pending.id, purpose: 'activate' })
  await invites.revoke(invite.id)
  await invites.revoke(invite.id) // idempotent
  assert.ok(logger.events.some((e) => e.type === 'invite.revoked' && e.details.inviteId === invite.id))
  const listed = await invites.listForUser(pending.id)
  assert.equal(listed.length, 1)
  assert.equal(listed[0].tokenHash, undefined)
  await assert.rejects(invites.revoke('invite-nope'), /no such invite/)
})

test('MemorySessionStore.deleteByUid removes only that user\'s entries', async () => {
  const store = new MemorySessionStore()
  await store.put('s1', { uid: 'a' }, 60000)
  await store.put('mfa:x', { uid: 'a', stage: 'mfa-pending' }, 60000)
  await store.put('s2', { uid: 'b' }, 60000)
  await store.deleteByUid('a')
  assert.equal(await store.get('s1'), null)
  assert.equal(await store.get('mfa:x'), null)
  assert.deepEqual(await store.get('s2'), { uid: 'b' })
})

test('InviteManager works end to end on the JSON-file InviteStore, single-use under concurrency', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-invites-'))
  const { server, invites } = makeEnv({ inviteStore: new JsonFileInviteStore(path.join(dir, 'invites.json')) })
  const pending = await server.createPendingUser({ username: 'u' })
  const { token } = await invites.issue({ uid: pending.id, purpose: 'activate' })
  const cred = await credentialFor('pw')
  const results = await Promise.allSettled([invites.redeem({ token, ...cred }), invites.redeem({ token, ...cred })])
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1)
  await login(server, 'u', 'pw')
})
