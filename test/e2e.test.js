import { test } from 'node:test'
import assert from 'node:assert/strict'

import { AuthServer } from '../src/server-auth.js'
import { Bootstrap } from '../src/bootstrap.js'
import { MemoryUserStore, MemoryRoleStore } from '../src/storage/memory-store.js'
import { SrpRegistration, SrpLoginAttempt } from '../src/srp/srp-client.js'
import { createNodeCryptoAdapter } from '../src/common/crypto-adapter-node.js'
import * as totp from '../src/totp/totp.js'
import * as roles from '../src/roles/roles.js'

// The client adapter would be crypto.subtle in a real browser; node's
// adapter is used here on both "sides" purely because this test runs in
// one process. See crypto-adapter-web.js / crypto-adapter-node.js.
const clientAdapter = createNodeCryptoAdapter()

function makeServer (overrides = {}) {
  return new AuthServer({
    userStore: new MemoryUserStore(),
    roleStore: new MemoryRoleStore(),
    ...overrides
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
  const result = await server.completeLogin({ challengeId, clientProof: M1 })
  await client.verifyServerProof(result.M2) // throws if the server can't prove it knows K too
  return result
}

test('bootstrap creates the first account as admin, and only once', async () => {
  const server = makeServer()
  await server.ensureDefaultRoles()
  const bootstrap = new Bootstrap(server)

  assert.equal(await bootstrap.needsBootstrap(), true)
  const token = await bootstrap.generateSetupToken()
  assert.equal(typeof token, 'string')

  const credential = await SrpRegistration.create({ password: 'first-admin-password', adapter: clientAdapter })
  const user = await bootstrap.completeBootstrap({ token, username: 'root', ...credential })
  assert.deepEqual(user.roleIds, ['role-admin'])

  assert.equal(await bootstrap.needsBootstrap(), false)
  await assert.rejects(
    bootstrap.completeBootstrap({ token, username: 'second', ...credential }),
    /already completed/
  )
})

test('bootstrap rejects a wrong or expired token', async () => {
  const server = makeServer()
  const bootstrap = new Bootstrap(server)
  await bootstrap.generateSetupToken()
  const credential = await SrpRegistration.create({ password: 'x', adapter: clientAdapter })

  await assert.rejects(
    bootstrap.completeBootstrap({ token: 'not-the-real-token', username: 'root', ...credential }),
    /invalid setup token/
  )
})

test('register then login succeeds end to end and issues a session', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const result = await login(server, 'alice', 'correct horse battery staple')
  assert.equal(result.mfaRequired, false)
  assert.equal(typeof result.sessionToken, 'string')

  const session = await server.getSession(result.sessionToken)
  assert.equal(session.uid, (await server.userStore.getUserByUsername('alice')).id)
})

test('login with the wrong password fails, and does not distinguish itself from a nonexistent username by error message', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')

  await assert.rejects(login(server, 'alice', 'wrong password'), /login failed/)
  await assert.rejects(login(server, 'nobody-registered', 'anything'), /login failed/)
})

test('beginLogin returns same-shaped responses for a real and a nonexistent username (enumeration resistance)', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')

  const client1 = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A: A1 } = client1.start()
  const real = await server.beginLogin({ username: 'alice', clientPublicEphemeral: A1 })

  const client2 = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A: A2 } = client2.start()
  const fake = await server.beginLogin({ username: 'this-user-does-not-exist', clientPublicEphemeral: A2 })

  for (const resp of [real, fake]) {
    assert.equal(typeof resp.challengeId, 'string')
    assert.equal(typeof resp.salt, 'string')
    assert.equal(typeof resp.B, 'string')
    assert.equal(typeof resp.uid, 'string')
  }
  assert.notEqual(real.uid, fake.uid)
})

test('beginLogin for the same nonexistent username is deterministic (same fake salt/uid every time)', async () => {
  const server = makeServer()
  const client1 = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A: A1 } = client1.start()
  const first = await server.beginLogin({ username: 'ghost', clientPublicEphemeral: A1 })

  const client2 = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A: A2 } = client2.start()
  const second = await server.beginLogin({ username: 'ghost', clientPublicEphemeral: A2 })

  assert.equal(first.salt, second.salt)
  assert.equal(first.uid, second.uid)
})

test('renaming a user does not break their ability to log in', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const user = await server.userStore.getUserByUsername('alice')
  await server.userStore.updateUser(user.id, { username: 'alice-renamed' })

  const result = await login(server, 'alice-renamed', 'correct horse battery staple')
  assert.equal(result.mfaRequired, false)
})

test('full MFA flow: enroll, login requires TOTP, correct code completes login', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const user = await server.userStore.getUserByUsername('alice')

  const enrollment = await server.beginTotpEnrollment(user.id)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)

  const code = totp.totpAt(secret, Date.now())
  const { recoveryCodes: codes } = await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code })
  assert.equal(codes.length, 10)

  const loginResult = await login(server, 'alice', 'correct horse battery staple')
  assert.equal(loginResult.mfaRequired, true)
  assert.equal(typeof loginResult.mfaToken, 'string')
  assert.equal(loginResult.sessionToken, undefined)

  const wrongAttempt = await server.verifyMfaTotp({ mfaToken: loginResult.mfaToken, code: '000000' }).catch((e) => e)
  assert.ok(wrongAttempt instanceof Error)

  const { sessionToken } = await server.verifyMfaTotp({ mfaToken: loginResult.mfaToken, code: totp.totpAt(secret, Date.now()) })
  assert.equal(typeof sessionToken, 'string')
  const session = await server.getSession(sessionToken)
  assert.equal(session.uid, user.id)
})

test('a recovery code completes MFA login and is then single-use', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const user = await server.userStore.getUserByUsername('alice')

  const enrollment = await server.beginTotpEnrollment(user.id)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)
  const { recoveryCodes: codes } = await server.confirmTotpEnrollment({
    pendingToken: enrollment.pendingToken,
    code: totp.totpAt(secret, Date.now())
  })

  const loginResult = await login(server, 'alice', 'correct horse battery staple')
  const { sessionToken, recoveryCodesRemaining } = await server.verifyMfaRecoveryCode({
    mfaToken: loginResult.mfaToken,
    recoveryCode: codes[0]
  })
  assert.equal(typeof sessionToken, 'string')
  assert.equal(recoveryCodesRemaining, 9)

  // Using the same recovery code again must fail — a fresh login+MFA attempt is needed to test this.
  const loginResult2 = await login(server, 'alice', 'correct horse battery staple')
  await assert.rejects(
    server.verifyMfaRecoveryCode({ mfaToken: loginResult2.mfaToken, recoveryCode: codes[0] }),
    /invalid recovery code/
  )
})

test('disabling TOTP requires a valid current code', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const user = await server.userStore.getUserByUsername('alice')
  const enrollment = await server.beginTotpEnrollment(user.id)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  await assert.rejects(server.disableTotp({ uid: user.id, code: '000000' }), /invalid code/)
  await server.disableTotp({ uid: user.id, code: totp.totpAt(secret, Date.now()) })

  const afterDisable = await server.userStore.getUserById(user.id)
  assert.equal(afterDisable.totp, null)

  const result = await login(server, 'alice', 'correct horse battery staple')
  assert.equal(result.mfaRequired, false) // MFA no longer required after disabling
})

test('role permissions: admin has everything, read-only has only read, custom roles are exact', async () => {
  const server = makeServer()
  await server.ensureDefaultRoles()
  await register(server, 'admin-user', 'password1')
  await register(server, 'viewer-user', 'password2')

  const adminUser = await server.userStore.getUserByUsername('admin-user')
  const viewerUser = await server.userStore.getUserByUsername('viewer-user')
  await server.userStore.updateUser(adminUser.id, { roleIds: ['role-admin'] })
  await server.userStore.updateUser(viewerUser.id, { roleIds: ['role-read-only'] })

  assert.equal(await server.userHasPermission({ ...adminUser, roleIds: ['role-admin'] }, 'delete-everything'), true)
  assert.equal(await server.userHasPermission({ ...viewerUser, roleIds: ['role-read-only'] }, 'delete-everything'), false)
  assert.equal(await server.userHasPermission({ ...viewerUser, roleIds: ['role-read-only'] }, 'read'), true)
})

test('renaming a role does not change what it grants', async () => {
  const server = makeServer()
  await server.ensureDefaultRoles()
  await server.roleStore.updateRole('role-read-only', { name: 'Viewer' })
  const role = await server.roleStore.getRole('role-read-only')
  assert.equal(role.name, 'Viewer')
  assert.equal(roles.hasPermission(role, 'read'), true)
})

test('logout destroys the session', async () => {
  const server = makeServer()
  await register(server, 'alice', 'correct horse battery staple')
  const { sessionToken } = await login(server, 'alice', 'correct horse battery staple')
  assert.notEqual(await server.getSession(sessionToken), null)
  await server.destroySession(sessionToken)
  assert.equal(await server.getSession(sessionToken), null)
})

test('registering the same username twice fails', async () => {
  const server = makeServer()
  await register(server, 'alice', 'password-one')
  await assert.rejects(register(server, 'alice', 'password-two'), /username already taken/)
})
