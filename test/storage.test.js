import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'

import { MemoryUserStore, MemoryRoleStore, MemoryChallengeStore, MemorySessionStore, MemoryInviteStore } from '../src/storage/memory-store.js'
import { JsonFileUserStore, JsonFileRoleStore, JsonFileInviteStore, JsonFileSessionStore } from '../src/storage/json-file-store.js'

function sampleUser (overrides = {}) {
  return {
    id: 'user-1',
    username: 'alice',
    salt: 'aa',
    verifier: 'bb',
    iterations: 600000,
    group: 3072,
    roleIds: ['role-admin'],
    totp: null,
    recoveryCodeHashes: [],
    createdAt: new Date().toISOString(),
    updatedAt: null,
    ...overrides
  }
}

// Runs the same behavioral contract against any UserStore implementation.
function describeUserStoreContract (name, makeStore) {
  test(`${name}: create + get by id + get by username`, async () => {
    const store = await makeStore()
    const created = await store.createUser(sampleUser())
    assert.equal(created.username, 'alice')
    assert.deepEqual(await store.getUserById('user-1'), created)
    assert.deepEqual(await store.getUserByUsername('alice'), created)
    assert.equal(await store.getUserById('nope'), null)
  })

  test(`${name}: rejects duplicate id and duplicate username`, async () => {
    const store = await makeStore()
    await store.createUser(sampleUser())
    await assert.rejects(store.createUser(sampleUser()))
    await assert.rejects(store.createUser(sampleUser({ id: 'user-2' })))
  })

  test(`${name}: updateUser merges fields and stamps updatedAt`, async () => {
    const store = await makeStore()
    await store.createUser(sampleUser())
    const updated = await store.updateUser('user-1', { username: 'alice2' })
    assert.equal(updated.username, 'alice2')
    assert.notEqual(updated.updatedAt, null)
    assert.equal(updated.id, 'user-1') // patch can't overwrite id
  })

  test(`${name}: renaming username (via updateUser) leaves id, salt, verifier untouched`, async () => {
    const store = await makeStore()
    await store.createUser(sampleUser())
    const updated = await store.updateUser('user-1', { username: 'renamed' })
    assert.equal(updated.id, 'user-1')
    assert.equal(updated.salt, 'aa')
    assert.equal(updated.verifier, 'bb')
    assert.deepEqual(await store.getUserByUsername('renamed'), updated)
    assert.equal(await store.getUserByUsername('alice'), null)
  })

  test(`${name}: deleteUser + listUsers + countUsers`, async () => {
    const store = await makeStore()
    await store.createUser(sampleUser())
    await store.createUser(sampleUser({ id: 'user-2', username: 'bob' }))
    assert.equal(await store.countUsers(), 2)
    await store.deleteUser('user-1')
    assert.equal(await store.countUsers(), 1)
    const remaining = await store.listUsers()
    assert.equal(remaining.length, 1)
    assert.equal(remaining[0].username, 'bob')
  })
}

describeUserStoreContract('MemoryUserStore', async () => new MemoryUserStore())
describeUserStoreContract('JsonFileUserStore', async () => new JsonFileUserStore(await tmpFile('users.json')))

test('JsonFileUserStore persists across separate store instances pointed at the same file', async () => {
  const filePath = await tmpFile('users-persist.json')
  const storeA = new JsonFileUserStore(filePath)
  await storeA.createUser(sampleUser())

  const storeB = new JsonFileUserStore(filePath)
  const fetched = await storeB.getUserById('user-1')
  assert.equal(fetched.username, 'alice')
})

test('JsonFileUserStore serializes concurrent writes without corrupting the file', async () => {
  const filePath = await tmpFile('users-concurrent.json')
  const store = new JsonFileUserStore(filePath)
  await Promise.all(
    Array.from({ length: 20 }, (_, i) => store.createUser(sampleUser({ id: `user-${i}`, username: `user${i}` })))
  )
  assert.equal(await store.countUsers(), 20)
  // The file itself must be valid JSON at rest, not partially written.
  const raw = await fs.readFile(filePath, 'utf8')
  assert.doesNotThrow(() => JSON.parse(raw))
})

test('MemoryRoleStore and JsonFileRoleStore: create, update (rename), delete, list', async () => {
  for (const store of [new MemoryRoleStore(), new JsonFileRoleStore(await tmpFile('roles.json'))]) {
    await store.createRole({ id: 'role-a', name: 'Original', permissions: ['read'], isBuiltIn: false, createdAt: new Date().toISOString() })
    const renamed = await store.updateRole('role-a', { name: 'Renamed' })
    assert.equal(renamed.name, 'Renamed')
    assert.equal(renamed.id, 'role-a') // id survives the rename
    assert.deepEqual(renamed.permissions, ['read']) // untouched by the rename
    assert.equal((await store.listRoles()).length, 1)
    await store.deleteRole('role-a')
    assert.equal((await store.listRoles()).length, 0)
  }
})

test('MemoryChallengeStore, MemorySessionStore, and JsonFileSessionStore: put/get/delete and TTL expiry', async () => {
  const stores = [new MemoryChallengeStore(), new MemorySessionStore(), new JsonFileSessionStore(await tmpFile('sessions.json'))]
  for (const store of stores) {
    await store.put('key-1', { hello: 'world' }, 50)
    assert.deepEqual(await store.get('key-1'), { hello: 'world' })

    await store.delete('key-1')
    assert.equal(await store.get('key-1'), null)

    await store.put('key-2', { x: 1 }, 10)
    await new Promise((resolve) => setTimeout(resolve, 30))
    assert.equal(await store.get('key-2'), null, 'entry should have expired')
  }
})

function sampleInvite (overrides = {}) {
  return {
    id: 'invite-1',
    tokenHash: 'a'.repeat(64),
    uid: 'user-1',
    purpose: 'activate',
    clearTotp: false,
    createdBy: 'admin-1',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(),
    usedAt: null,
    revokedAt: null,
    ...overrides
  }
}

// Runs the same behavioral contract against any InviteStore implementation.
function describeInviteStoreContract (name, makeStore) {
  test(`${name}: create + get by id + get by token hash`, async () => {
    const store = await makeStore()
    const created = await store.createInvite(sampleInvite())
    assert.deepEqual(await store.getInvite('invite-1'), created)
    assert.deepEqual(await store.getInviteByTokenHash('a'.repeat(64)), created)
    assert.equal(await store.getInvite('nope'), null)
    assert.equal(await store.getInviteByTokenHash('b'.repeat(64)), null)
  })

  test(`${name}: rejects duplicate id and duplicate token hash`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    await assert.rejects(store.createInvite(sampleInvite({ tokenHash: 'c'.repeat(64) })))
    await assert.rejects(store.createInvite(sampleInvite({ id: 'invite-2' })))
  })

  test(`${name}: markUsed is compare-and-set (second call returns false)`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    const t = new Date().toISOString()
    assert.equal(await store.markUsed('invite-1', t), true)
    assert.equal(await store.markUsed('invite-1', new Date().toISOString()), false)
    assert.equal((await store.getInvite('invite-1')).usedAt, t)
    assert.equal(await store.markUsed('missing', t), false)
  })

  test(`${name}: markUsed refuses a revoked invite`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    await store.revokeInvite('invite-1', new Date().toISOString())
    assert.equal(await store.markUsed('invite-1', new Date().toISOString()), false)
    assert.equal((await store.getInvite('invite-1')).usedAt, null)
  })

  test(`${name}: concurrent markUsed has exactly one winner`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    const results = await Promise.all(
      Array.from({ length: 10 }, () => store.markUsed('invite-1', new Date().toISOString()))
    )
    assert.equal(results.filter(Boolean).length, 1)
  })

  test(`${name}: revokeInvite is idempotent and keeps the first revokedAt`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    await store.revokeInvite('invite-1', '2030-01-01T00:00:00.000Z')
    await store.revokeInvite('invite-1', '2031-01-01T00:00:00.000Z')
    await store.revokeInvite('missing', '2031-01-01T00:00:00.000Z') // no throw
    assert.equal((await store.getInvite('invite-1')).revokedAt, '2030-01-01T00:00:00.000Z')
  })

  test(`${name}: listInvitesForUser returns only that user's invites`, async () => {
    const store = await makeStore()
    await store.createInvite(sampleInvite())
    await store.createInvite(sampleInvite({ id: 'invite-2', tokenHash: 'd'.repeat(64), purpose: 'credential-reset' }))
    await store.createInvite(sampleInvite({ id: 'invite-3', tokenHash: 'e'.repeat(64), uid: 'user-2' }))
    const mine = await store.listInvitesForUser('user-1')
    assert.deepEqual(mine.map((i) => i.id).sort(), ['invite-1', 'invite-2'])
    assert.deepEqual(await store.listInvitesForUser('nobody'), [])
  })
}

describeInviteStoreContract('MemoryInviteStore', async () => new MemoryInviteStore())
describeInviteStoreContract('JsonFileInviteStore', async () => new JsonFileInviteStore(await tmpFile('invites.json')))

test('MemorySessionStore.deleteByUid deletes only that uid\'s entries', async () => {
  const store = new MemorySessionStore()
  await store.put('s1', { uid: 'u1' }, 60000)
  await store.put('s2', { uid: 'u2' }, 60000)
  await store.deleteByUid('u1')
  assert.equal(await store.get('s1'), null)
  assert.deepEqual(await store.get('s2'), { uid: 'u2' })
})

test('JsonFileSessionStore persists sessions across separate store instances pointed at the same file — the whole point of it existing (surviving a process restart)', async () => {
  const filePath = await tmpFile('sessions.json')
  const storeA = new JsonFileSessionStore(filePath)
  await storeA.put('session-1', { uid: 'user-1' }, 60000)

  const storeB = new JsonFileSessionStore(filePath) // simulates a fresh process reading the same file after a restart
  assert.deepEqual(await storeB.get('session-1'), { uid: 'user-1' })
})

test('JsonFileSessionStore.deleteAllForUser removes only that user\'s real sessions, keeps pending "prefix:token" entries and other users\' sessions', async () => {
  const store = new JsonFileSessionStore(await tmpFile('sessions.json'))
  await store.put('session-a1', { uid: 'user-a' }, 60000)
  await store.put('session-a2', { uid: 'user-a' }, 60000)
  await store.put('session-b1', { uid: 'user-b' }, 60000)
  await store.put('mfa:some-token', { uid: 'user-a' }, 60000) // pending state, not a real session — must survive

  await store.deleteAllForUser('user-a', 'session-a2') // keep session-a2 (the caller's own)

  assert.equal(await store.get('session-a1'), null)
  assert.deepEqual(await store.get('session-a2'), { uid: 'user-a' })
  assert.deepEqual(await store.get('session-b1'), { uid: 'user-b' })
  assert.deepEqual(await store.get('mfa:some-token'), { uid: 'user-a' })
})

let tmpDirPromise = null
async function tmpFile (name) {
  if (!tmpDirPromise) tmpDirPromise = fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-test-'))
  const dir = await tmpDirPromise
  return path.join(dir, `${Date.now()}-${Math.random().toString(36).slice(2)}-${name}`)
}
