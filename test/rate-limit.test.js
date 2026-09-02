import { test } from 'node:test'
import assert from 'node:assert/strict'

import { MemoryRateLimiter } from '../src/rate-limit/memory-rate-limiter.js'
import { RateLimitExceededError } from '../src/rate-limit/rate-limiter.js'
import { AuthServer } from '../src/server-auth.js'
import { MemoryUserStore, MemoryRoleStore } from '../src/storage/memory-store.js'
import { SrpRegistration, SrpLoginAttempt } from '../src/srp/srp-client.js'
import { createNodeCryptoAdapter } from '../src/common/crypto-adapter-node.js'

const clientAdapter = createNodeCryptoAdapter()

test('MemoryRateLimiter: allows up to maxAttempts, then throws with a positive retryAfterMs', async () => {
  const limiter = new MemoryRateLimiter()
  const rule = { maxAttempts: 3, windowMs: 60000 }
  await limiter.consume('test', 'key-a', rule)
  await limiter.consume('test', 'key-a', rule)
  await limiter.consume('test', 'key-a', rule)

  await assert.rejects(limiter.consume('test', 'key-a', rule), (err) => {
    assert.ok(err instanceof RateLimitExceededError)
    assert.ok(err.retryAfterMs > 0)
    return true
  })
})

test('MemoryRateLimiter: different keys have independent budgets', async () => {
  const limiter = new MemoryRateLimiter()
  const rule = { maxAttempts: 1, windowMs: 60000 }
  await limiter.consume('test', 'key-a', rule)
  await assert.rejects(limiter.consume('test', 'key-a', rule))
  await limiter.consume('test', 'key-b', rule) // unaffected by key-a's limit
})

test('MemoryRateLimiter: different buckets have independent budgets for the same key', async () => {
  const limiter = new MemoryRateLimiter()
  const rule = { maxAttempts: 1, windowMs: 60000 }
  await limiter.consume('login', 'alice', rule)
  await limiter.consume('mfa', 'alice', rule) // different bucket, same key — unaffected
})

test('MemoryRateLimiter: the window resets after windowMs elapses', async () => {
  const limiter = new MemoryRateLimiter()
  const rule = { maxAttempts: 1, windowMs: 30 }
  await limiter.consume('test', 'key-a', rule)
  await assert.rejects(limiter.consume('test', 'key-a', rule))
  await new Promise((resolve) => setTimeout(resolve, 50))
  await limiter.consume('test', 'key-a', rule) // window has rolled over
})

function makeServer (overrides = {}) {
  return new AuthServer({
    userStore: new MemoryUserStore(),
    roleStore: new MemoryRoleStore(),
    rateLimits: {
      login: { maxAttempts: 3, windowMs: 60000 },
      loginClient: { maxAttempts: 5, windowMs: 60000 }
    },
    ...overrides
  })
}

async function register (server, username, password) {
  const credential = await SrpRegistration.create({ password, adapter: clientAdapter })
  return server.registerUser({ username, ...credential })
}

test('AuthServer: beginLogin rate-limits repeated attempts for the same username', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')

  for (let i = 0; i < 3; i++) {
    const client = new SrpLoginAttempt({ adapter: clientAdapter })
    const { A } = client.start()
    await server.beginLogin({ username: 'alice', clientPublicEphemeral: A })
  }

  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  await assert.rejects(
    server.beginLogin({ username: 'alice', clientPublicEphemeral: A }),
    RateLimitExceededError
  )
})

test('AuthServer: the per-username login rate limit applies identically to a nonexistent username (enumeration resistance preserved)', async () => {
  const server = makeServer()

  for (let i = 0; i < 3; i++) {
    const client = new SrpLoginAttempt({ adapter: clientAdapter })
    const { A } = client.start()
    await server.beginLogin({ username: 'nobody-here', clientPublicEphemeral: A })
  }

  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  await assert.rejects(
    server.beginLogin({ username: 'nobody-here', clientPublicEphemeral: A }),
    RateLimitExceededError
  )
})

test('AuthServer: a different username is unaffected by another username hitting its rate limit', async () => {
  const server = makeServer()
  await register(server, 'alice', 'pw1')
  await register(server, 'bob', 'pw2')

  for (let i = 0; i < 3; i++) {
    const client = new SrpLoginAttempt({ adapter: clientAdapter })
    const { A } = client.start()
    await server.beginLogin({ username: 'alice', clientPublicEphemeral: A })
  }

  const bobClient = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A: bobA } = bobClient.start()
  await server.beginLogin({ username: 'bob', clientPublicEphemeral: bobA }) // must not throw
})

test('AuthServer: clientKey adds an additional, independent budget layer', async () => {
  const server = makeServer({
    rateLimits: {
      login: { maxAttempts: 100, windowMs: 60000 }, // effectively unlimited per-username here
      loginClient: { maxAttempts: 2, windowMs: 60000 }
    }
  })
  await register(server, 'alice', 'pw1')
  await register(server, 'bob', 'pw2')

  // Two different usernames from the same clientKey (simulating one IP
  // trying multiple accounts) should still trip the per-client limit.
  for (const username of ['alice', 'bob']) {
    const client = new SrpLoginAttempt({ adapter: clientAdapter })
    const { A } = client.start()
    await server.beginLogin({ username, clientPublicEphemeral: A, clientKey: '10.0.0.1' })
  }

  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  await assert.rejects(
    server.beginLogin({ username: 'alice', clientPublicEphemeral: A, clientKey: '10.0.0.1' }),
    RateLimitExceededError
  )
})

test('AuthServer: MFA verification is rate-limited per mfaToken', async () => {
  const server = makeServer({
    rateLimits: { mfa: { maxAttempts: 2, windowMs: 60000 }, mfaClient: { maxAttempts: 100, windowMs: 60000 } }
  })
  const credential = await SrpRegistration.create({ password: 'correct horse battery staple', adapter: clientAdapter })
  const { id: uid } = await server.registerUser({ username: 'alice', ...credential })

  const enrollment = await server.beginTotpEnrollment(uid)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)
  const totpMod = await import('../src/totp/totp.js')
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totpMod.totpAt(secret, Date.now()) })

  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  const begin = await server.beginLogin({ username: 'alice', clientPublicEphemeral: A })
  const { M1 } = await client.finish({ password: 'correct horse battery staple', salt: begin.salt, serverPublicEphemeral: begin.B, uid: begin.uid })
  const { mfaToken } = await server.completeLogin({ challengeId: begin.challengeId, clientProof: M1 })

  await server.verifyMfaTotp({ mfaToken, code: '000000' }).catch(() => {})
  await server.verifyMfaTotp({ mfaToken, code: '000000' }).catch(() => {})
  await assert.rejects(
    server.verifyMfaTotp({ mfaToken, code: '000000' }),
    RateLimitExceededError
  )
})
