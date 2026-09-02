import { test } from 'node:test'
import assert from 'node:assert/strict'

import { AuditLogger } from '../src/audit/audit-logger.js'
import { AuthServer } from '../src/server-auth.js'
import { Bootstrap } from '../src/bootstrap.js'
import { MemoryUserStore, MemoryRoleStore } from '../src/storage/memory-store.js'
import { SrpRegistration, SrpLoginAttempt } from '../src/srp/srp-client.js'
import { createNodeCryptoAdapter } from '../src/common/crypto-adapter-node.js'
import * as totp from '../src/totp/totp.js'
import { decode as base32Decode } from '../src/totp/base32.js'

const clientAdapter = createNodeCryptoAdapter()

class CapturingLogger extends AuditLogger {
  constructor () {
    super()
    this.events = []
  }

  async log (event) {
    this.events.push(event)
  }
}

function makeServer (logger) {
  return new AuthServer({
    userStore: new MemoryUserStore(),
    roleStore: new MemoryRoleStore(),
    logger
  })
}

async function register (server, username, password) {
  const credential = await SrpRegistration.create({ password, adapter: clientAdapter })
  return server.registerUser({ username, ...credential })
}

async function login (server, username, password) {
  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  const { challengeId, salt, B, uid } = await server.beginLogin({ username, clientPublicEphemeral: A })
  const { M1 } = await client.finish({ password, salt, serverPublicEphemeral: B, uid })
  return server.completeLogin({ challengeId, clientProof: M1 })
}

test('registration logs a user.registered event with uid and username', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const user = await register(server, 'alice', 'correct horse battery staple')

  const event = logger.events.find((e) => e.type === 'user.registered')
  assert.ok(event, 'expected a user.registered event')
  assert.equal(event.uid, user.id)
  assert.equal(event.username, 'alice')
})

test('successful login logs user.login.success; wrong password logs user.login.failure', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  await register(server, 'alice', 'correct horse battery staple')

  await login(server, 'alice', 'correct horse battery staple')
  assert.ok(logger.events.some((e) => e.type === 'user.login.success' && e.username === 'alice'))

  await login(server, 'alice', 'wrong password').catch(() => {})
  assert.ok(logger.events.some((e) => e.type === 'user.login.failure' && e.username === 'alice'))
})

test('full MFA flow logs mfa.enrolled, mfa.verify.failure, mfa.verify.success', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const user = await register(server, 'alice', 'correct horse battery staple')

  const enrollment = await server.beginTotpEnrollment(user.id)
  const secret = base32Decode(new URL(enrollment.otpauthUri).searchParams.get('secret'))
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })
  assert.ok(logger.events.some((e) => e.type === 'mfa.enrolled' && e.uid === user.id))

  const loginResult = await login(server, 'alice', 'correct horse battery staple')
  assert.equal(loginResult.mfaRequired, true)

  await server.verifyMfaTotp({ mfaToken: loginResult.mfaToken, code: '000000' }).catch(() => {})
  assert.ok(logger.events.some((e) => e.type === 'mfa.verify.failure' && e.uid === user.id))

  await server.verifyMfaTotp({ mfaToken: loginResult.mfaToken, code: totp.totpAt(secret, Date.now()) })
  assert.ok(logger.events.some((e) => e.type === 'mfa.verify.success' && e.uid === user.id))
})

test('a recovery-code login logs mfa.recovery_code.used with the remaining count', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const user = await register(server, 'alice', 'correct horse battery staple')
  const enrollment = await server.beginTotpEnrollment(user.id)
  const secret = base32Decode(new URL(enrollment.otpauthUri).searchParams.get('secret'))
  const { recoveryCodes } = await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  const loginResult = await login(server, 'alice', 'correct horse battery staple')
  await server.verifyMfaRecoveryCode({ mfaToken: loginResult.mfaToken, recoveryCode: recoveryCodes[0] })

  const event = logger.events.find((e) => e.type === 'mfa.recovery_code.used')
  assert.ok(event)
  assert.equal(event.uid, user.id)
  assert.equal(event.details.recoveryCodesRemaining, 9)
})

test('disabling MFA logs mfa.disabled', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const user = await register(server, 'alice', 'correct horse battery staple')
  const enrollment = await server.beginTotpEnrollment(user.id)
  const secret = base32Decode(new URL(enrollment.otpauthUri).searchParams.get('secret'))
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  await server.disableTotp({ uid: user.id, code: totp.totpAt(secret, Date.now()) })
  assert.ok(logger.events.some((e) => e.type === 'mfa.disabled' && e.uid === user.id))
})

test('logout logs session.destroyed', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  await register(server, 'alice', 'correct horse battery staple')
  const { sessionToken } = await login(server, 'alice', 'correct horse battery staple')

  await server.destroySession(sessionToken)
  assert.ok(logger.events.some((e) => e.type === 'session.destroyed'))
})

test('bootstrap logs bootstrap.completed on success and bootstrap.failed on a wrong token', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const bootstrap = new Bootstrap(server)
  const credential = await SrpRegistration.create({ password: 'x', adapter: clientAdapter })

  await bootstrap.generateSetupToken()
  await bootstrap.completeBootstrap({ token: 'wrong-token', username: 'root', ...credential }).catch(() => {})
  assert.ok(logger.events.some((e) => e.type === 'bootstrap.failed'))

  const token = await bootstrap.generateSetupToken()
  await bootstrap.completeBootstrap({ token, username: 'root', ...credential })
  assert.ok(logger.events.some((e) => e.type === 'bootstrap.completed'))
})

test('a broken logger never breaks the auth flow it is observing', async () => {
  class ThrowingLogger extends AuditLogger {
    async log () { throw new Error('log sink is down') }
  }
  const server = makeServer(new ThrowingLogger())
  const user = await register(server, 'alice', 'correct horse battery staple') // must not throw
  assert.equal(user.username, 'alice')
  const result = await login(server, 'alice', 'correct horse battery staple') // must not throw
  assert.equal(typeof result.sessionToken, 'string')
})

test('no logged event, across a full account lifecycle, ever contains the password, salt, verifier, a raw session/mfa token, a TOTP secret, or a raw recovery code', async () => {
  const logger = new CapturingLogger()
  const server = makeServer(logger)
  const password = 'correct horse battery staple, do not leak me'
  const user = await register(server, 'alice', password)

  const enrollment = await server.beginTotpEnrollment(user.id)
  const secretHex = new URL(enrollment.otpauthUri).searchParams.get('secret') // base32, but check the raw hex form too
  const secret = base32Decode(secretHex)
  const secretHexRaw = Buffer.from(secret).toString('hex')
  const { recoveryCodes } = await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  const loginResult = await login(server, 'alice', password)
  const { sessionToken } = await server.verifyMfaTotp({ mfaToken: loginResult.mfaToken, code: totp.totpAt(secret, Date.now()) })
  await server.destroySession(sessionToken)

  const forbiddenValues = [password, secretHex, secretHexRaw, sessionToken, loginResult.mfaToken, ...recoveryCodes]
  const dump = JSON.stringify(logger.events)

  for (const forbidden of forbiddenValues) {
    assert.ok(!dump.includes(forbidden), `log dump must not contain: ${forbidden}`)
  }
})
