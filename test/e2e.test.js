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

/** completePasswordReset() takes newSalt/newVerifier/newIterations/newGroup — SrpRegistration.create() returns salt/verifier/iterations/group. */
function asNewCredential (cred) {
  return { newSalt: cred.salt, newVerifier: cred.verifier, newIterations: cred.iterations, newGroup: cred.group }
}

/** Mirrors login()'s two-round-trip shape, but against beginPasswordChange()/completePasswordChange(). */
async function changePassword (server, uid, currentPassword, newPassword, extra = {}) {
  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  const begin = await server.beginPasswordChange({ uid, clientPublicEphemeral: A })
  const { M1 } = await client.finish({ password: currentPassword, salt: begin.salt, serverPublicEphemeral: begin.B, uid: begin.uid })
  const newCredential = await SrpRegistration.create({ password: newPassword, adapter: clientAdapter })
  const result = await server.completePasswordChange({
    uid,
    challengeId: begin.challengeId,
    clientProof: M1,
    newSalt: newCredential.salt,
    newVerifier: newCredential.verifier,
    newIterations: newCredential.iterations,
    newGroup: newCredential.group,
    ...extra
  })
  await client.verifyServerProof(result.M2)
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

test('changeUsername renames the account and rejects a collision', async () => {
  const server = makeServer()
  await register(server, 'alice', 'x')
  await register(server, 'bob', 'y')
  const alice = await server.userStore.getUserByUsername('alice')

  const renamed = await server.changeUsername({ uid: alice.id, newUsername: 'alice2' })
  assert.equal(renamed.username, 'alice2')
  assert.equal(await login(server, 'alice2', 'x').then((r) => r.mfaRequired), false)

  await assert.rejects(
    server.changeUsername({ uid: alice.id, newUsername: 'bob' }),
    /username already taken/
  )
})

// Regression test: every bucket _enforceRateLimit() can reach needs a
// config entry in DEFAULT_RATE_LIMITS, *and* its 'Client' counterpart,
// since a truthy clientKey (an IP, in a real deployment — always present)
// makes _enforceRateLimit() consume both. Every method below was written
// with a clientKey in these tests specifically to exercise that second,
// easy-to-forget bucket — the rest of this file's other tests mostly
// don't pass one, which is exactly how a missing '*Client' entry (a real
// bug caught manually, not by the suite) went unnoticed before this test
// was added.
test('every new self-service method works with a clientKey supplied (exercises the *Client rate-limit bucket too)', async () => {
  const server = makeServer({ passwordResetEnabled: true, passwordResetSender: async () => {} })
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')

  await server.changeUsername({ uid: alice.id, newUsername: 'alice2', clientKey: '127.0.0.1' })

  const client = new SrpLoginAttempt({ adapter: clientAdapter })
  const { A } = client.start()
  const begin = await server.beginPasswordChange({ uid: alice.id, clientPublicEphemeral: A, clientKey: '127.0.0.1' })
  const { M1 } = await client.finish({ password: 'old-password', salt: begin.salt, serverPublicEphemeral: begin.B, uid: begin.uid })
  const newCredential = await SrpRegistration.create({ password: 'new-password', adapter: clientAdapter })
  await server.completePasswordChange({ uid: alice.id, challengeId: begin.challengeId, clientProof: M1, ...asNewCredential(newCredential), clientKey: '127.0.0.1' })

  await server.requestPasswordReset({ username: 'alice2', clientKey: '127.0.0.1' })

  await server.setUserRoles({ uid: alice.id, roleIds: [], clientKey: '127.0.0.1' })
})

test('password change requires proving the current password, then the new password logs in', async () => {
  const server = makeServer()
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')

  await changePassword(server, alice.id, 'old-password', 'new-password')

  await assert.rejects(login(server, 'alice', 'old-password'), /login failed/)
  const result = await login(server, 'alice', 'new-password')
  assert.equal(result.mfaRequired, false)
})

test('password change fails if the submitted proof does not match the current password', async () => {
  const server = makeServer()
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')

  await assert.rejects(
    changePassword(server, alice.id, 'WRONG-current-password', 'new-password'),
    /password change failed/
  )
  // Old password must still work — the failed attempt must not have partially applied.
  const result = await login(server, 'alice', 'old-password')
  assert.equal(result.mfaRequired, false)
})

test('password change invalidates other sessions but keeps the one that made the change', async () => {
  const server = makeServer()
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')

  const { sessionToken: otherDeviceSession } = await login(server, 'alice', 'old-password')
  const { sessionToken: thisDeviceSession } = await login(server, 'alice', 'old-password')

  await changePassword(server, alice.id, 'old-password', 'new-password', { keepSessionToken: thisDeviceSession })

  assert.equal(await server.getSession(otherDeviceSession), null)
  assert.notEqual(await server.getSession(thisDeviceSession), null)
})

test('password change on an MFA-enabled account requires a valid code', async () => {
  const server = makeServer()
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')

  const enrollment = await server.beginTotpEnrollment(alice.id)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  await assert.rejects(
    changePassword(server, alice.id, 'old-password', 'new-password', { mfaCode: '000000' }),
    /password change failed/
  )
  // Still on the old password — the MFA-less attempt must not have applied.
  assert.equal(await login(server, 'alice', 'old-password').then((r) => r.mfaRequired), true)

  await changePassword(server, alice.id, 'old-password', 'new-password', { mfaCode: totp.totpAt(secret, Date.now()) })
  assert.equal(await login(server, 'alice', 'new-password').then((r) => r.mfaRequired), true)
})

test('password reset is a no-op unless passwordResetEnabled, but always resolves the same way', async () => {
  const server = makeServer() // passwordResetEnabled defaults false
  await register(server, 'alice', 'old-password')

  assert.deepEqual(await server.requestPasswordReset({ username: 'alice' }), { requested: true })
  assert.deepEqual(await server.requestPasswordReset({ username: 'nobody' }), { requested: true })
  await assert.rejects(
    server.completePasswordReset({ token: 'anything', newSalt: 'x', newVerifier: 'y' }),
    /password reset is not enabled/
  )
  // The old password must still work — nothing should have happened.
  assert.equal(await login(server, 'alice', 'old-password').then((r) => r.mfaRequired), false)
})

test('password reset end to end when enabled: sender receives the token, completing it changes the password and is single-use', async () => {
  const sent = []
  const server = makeServer({
    passwordResetEnabled: true,
    passwordResetSender: async (ctx) => { sent.push(ctx) }
  })
  await register(server, 'alice', 'old-password')

  await server.requestPasswordReset({ username: 'alice' })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].user.username, 'alice')
  const { token } = sent[0]

  const newCredential = await SrpRegistration.create({ password: 'reset-password', adapter: clientAdapter })
  await server.completePasswordReset({ token, ...asNewCredential(newCredential) })

  await assert.rejects(login(server, 'alice', 'old-password'), /login failed/)
  assert.equal(await login(server, 'alice', 'reset-password').then((r) => r.mfaRequired), false)

  // Single-use: the same token can't be replayed.
  const anotherCredential = await SrpRegistration.create({ password: 'third-password', adapter: clientAdapter })
  await assert.rejects(
    server.completePasswordReset({ token, ...asNewCredential(anotherCredential) }),
    /reset link expired or invalid/
  )
})

test('password reset on an MFA-enabled account requires a valid code, and does not leak whether MFA is on for unknown users', async () => {
  const sent = []
  const server = makeServer({
    passwordResetEnabled: true,
    passwordResetSender: async (ctx) => { sent.push(ctx) }
  })
  await register(server, 'alice', 'old-password')
  const alice = await server.userStore.getUserByUsername('alice')
  const enrollment = await server.beginTotpEnrollment(alice.id)
  const secretFromUri = new URL(enrollment.otpauthUri).searchParams.get('secret')
  const { decode } = await import('../src/totp/base32.js')
  const secret = decode(secretFromUri)
  await server.confirmTotpEnrollment({ pendingToken: enrollment.pendingToken, code: totp.totpAt(secret, Date.now()) })

  await server.requestPasswordReset({ username: 'alice' })
  const { token } = sent[0]
  const newCredential = await SrpRegistration.create({ password: 'reset-password', adapter: clientAdapter })

  await assert.rejects(
    server.completePasswordReset({ token, ...asNewCredential(newCredential), mfaCode: '000000' }),
    /MFA verification required/
  )
})

test('setUserRoles updates roles and logs out the account\'s existing sessions', async () => {
  const server = makeServer()
  await server.ensureDefaultRoles()
  await register(server, 'alice', 'x')
  const alice = await server.userStore.getUserByUsername('alice')
  await server.userStore.updateUser(alice.id, { roleIds: ['role-read-only'] })

  const { sessionToken } = await login(server, 'alice', 'x')
  assert.notEqual(await server.getSession(sessionToken), null)

  const updated = await server.setUserRoles({ uid: alice.id, roleIds: ['role-admin'] })
  assert.deepEqual(updated.roleIds, ['role-admin'])
  assert.equal(await server.getSession(sessionToken), null) // stale permissions invalidated

  await assert.rejects(
    server.setUserRoles({ uid: alice.id, roleIds: ['role-does-not-exist'] }),
    /no such role/
  )
})

test('listUsers never exposes salt/verifier/totp secrets', async () => {
  const server = makeServer()
  await register(server, 'alice', 'x')
  const [user] = await server.listUsers()
  assert.equal(user.username, 'alice')
  assert.equal('salt' in user, false)
  assert.equal('verifier' in user, false)
  assert.equal('totp' in user, false)
})
