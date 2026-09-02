import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createNodeCryptoAdapter } from '../src/common/crypto-adapter-node.js'
import { SrpRegistration, SrpLoginAttempt } from '../src/srp/srp-client.js'
import { beginLoginChallenge, completeLoginChallenge } from '../src/srp/srp-server.js'
import GROUPS from '../src/common/groups.js'
import * as core from '../src/srp/srp-core.js'

// Both "sides" use the same adapter here because we're testing protocol
// correctness in one process, not transport. In a real deployment the
// client adapter is the browser's crypto.subtle and the server adapter is
// node:crypto — see crypto-adapter-node.js / crypto-adapter-web.js.
const adapter = createNodeCryptoAdapter()

async function registerUser (password, group = GROUPS.DEFAULT) {
  return SrpRegistration.create({ password, adapter, group })
}

async function fullLogin ({ password, credential, uid, group = GROUPS.DEFAULT, serverUid = uid }) {
  const client = new SrpLoginAttempt({ adapter, group, iterations: credential.iterations })
  const { A } = client.start()

  const { b, B } = await beginLoginChallenge({ adapter, group, verifier: credential.verifier })

  const { M1 } = await client.finish({
    password,
    salt: credential.salt,
    serverPublicEphemeral: B,
    uid,
    iterations: credential.iterations
  })

  // serverUid models the server's own authoritative record of who this
  // verifier belongs to — independent of whatever uid the client sent.
  // Real integrations never let client input choose serverUid; a caller
  // that did would defeat the point of binding M1 to uid at all.
  const { M2, sessionKey: serverSessionKey } = await completeLoginChallenge({
    adapter,
    group,
    verifier: credential.verifier,
    serverEphemeralSecret: b,
    clientPublicEphemeral: A,
    clientProof: M1,
    uid: serverUid,
    salt: credential.salt
  })

  const clientSessionKey = await client.verifyServerProof(M2)

  return { clientSessionKey, serverSessionKey }
}

test('register + login round trip succeeds with the correct password and both sides agree on K', async () => {
  const credential = await registerUser('correct horse battery staple')
  const { clientSessionKey, serverSessionKey } = await fullLogin({
    password: 'correct horse battery staple',
    credential,
    uid: 'user-123'
  })
  assert.equal(clientSessionKey, serverSessionKey)
  assert.match(clientSessionKey, /^[0-9a-f]{64}$/)
})

test('login fails with the wrong password', async () => {
  const credential = await registerUser('correct horse battery staple')
  await assert.rejects(
    fullLogin({ password: 'wrong password', credential, uid: 'user-123' }),
    /client proof did not match/
  )
})

test('M1 is bound to uid: client and server disagreeing on uid fails even with the right password', async () => {
  const credential = await registerUser('correct horse battery staple')

  // Client believes it's logging in as one uid; the server's own record
  // (independent of client input, as it must be in a real integration)
  // says the verifier belongs to a different uid. Must fail even though
  // the password is right.
  await assert.rejects(
    fullLogin({
      password: 'correct horse battery staple',
      credential,
      uid: 'user-123',
      serverUid: 'someone-elses-uid'
    }),
    /client proof did not match/
  )
})

test('renaming a user (changing their username) never touches uid, salt, or verifier, so login is unaffected', async () => {
  const credential = await registerUser('correct horse battery staple')

  // The username never appears anywhere in the SRP calls at all — only
  // the stable uid does. This test's point is exactly that: nothing here
  // needs to change when a user is renamed, because nothing here ever
  // saw the username to begin with.
  const { clientSessionKey, serverSessionKey } = await fullLogin({
    password: 'correct horse battery staple',
    credential,
    uid: 'user-123'
  })
  assert.equal(clientSessionKey, serverSessionKey)
})

test('a tampered M1 is rejected', async () => {
  const credential = await registerUser('correct horse battery staple')
  const client = new SrpLoginAttempt({ adapter, iterations: credential.iterations })
  const { A } = client.start()
  const { b, B } = await beginLoginChallenge({ adapter, verifier: credential.verifier })
  const { M1 } = await client.finish({
    password: 'correct horse battery staple',
    salt: credential.salt,
    serverPublicEphemeral: B,
    uid: 'user-123',
    iterations: credential.iterations
  })

  const tamperedM1 = (BigInt(`0x${M1}`) ^ 1n).toString(16).padStart(M1.length, '0')

  await assert.rejects(
    completeLoginChallenge({
      adapter,
      verifier: credential.verifier,
      serverEphemeralSecret: b,
      clientPublicEphemeral: A,
      clientProof: tamperedM1,
      uid: 'user-123',
      salt: credential.salt
    }),
    /client proof did not match/
  )
})

test('a spoofed server M2 is rejected by the client', async () => {
  const credential = await registerUser('correct horse battery staple')
  const client = new SrpLoginAttempt({ adapter, iterations: credential.iterations })
  client.start()
  const { b, B } = await beginLoginChallenge({ adapter, verifier: credential.verifier })
  await client.finish({
    password: 'correct horse battery staple',
    salt: credential.salt,
    serverPublicEphemeral: B,
    uid: 'user-123',
    iterations: credential.iterations
  })

  const fakeM2 = '00'.repeat(32)
  await assert.rejects(client.verifyServerProof(fakeM2), /server proof did not match/)
})

test('a zero public ephemeral is rejected (RFC 5054 A/B safety check)', () => {
  assert.equal(core.isValidPublicValue(GROUPS.DEFAULT, 0n), false)
  assert.equal(core.isValidPublicValue(GROUPS.DEFAULT, hexToBigIntN()), false)
  assert.equal(core.isValidPublicValue(GROUPS.DEFAULT, 12345n), true)

  function hexToBigIntN () {
    return BigInt(`0x${GROUPS.DEFAULT.N}`) // A == N is 0 mod N, also invalid
  }
})

test('k multiplier is deterministic and non-zero for every shipped group', async () => {
  for (const bits of [2048, 3072, 4096]) {
    const k = await core.computeK(GROUPS[bits], adapter)
    assert.notEqual(k, 0n)
    const k2 = await core.computeK(GROUPS[bits], adapter)
    assert.equal(k, k2)
  }
})

test('two registrations of the same password produce different salts and different verifiers', async () => {
  const a = await registerUser('correct horse battery staple')
  const b = await registerUser('correct horse battery staple')
  assert.notEqual(a.salt, b.salt)
  assert.notEqual(a.verifier, b.verifier)
})

test('round trip works on every shipped group size', async () => {
  for (const bits of [2048, 3072, 4096]) {
    const group = GROUPS[bits]
    const credential = await registerUser('correct horse battery staple', group)
    const { clientSessionKey, serverSessionKey } = await fullLogin({
      password: 'correct horse battery staple',
      credential,
      uid: 'user-123',
      group
    })
    assert.equal(clientSessionKey, serverSessionKey, `mismatch for ${bits}-bit group`)
  }
})
