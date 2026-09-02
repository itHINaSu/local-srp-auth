import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'

import { MemoryUserStore, MemoryRoleStore, MemoryChallengeStore, MemorySessionStore } from '../src/storage/memory-store.js'
import { JsonFileUserStore, JsonFileRoleStore } from '../src/storage/json-file-store.js'

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

test('MemoryChallengeStore and MemorySessionStore: put/get/delete and TTL expiry', async () => {
  for (const StoreClass of [MemoryChallengeStore, MemorySessionStore]) {
    const store = new StoreClass()
    await store.put('key-1', { hello: 'world' }, 50)
    assert.deepEqual(await store.get('key-1'), { hello: 'world' })

    await store.delete('key-1')
    assert.equal(await store.get('key-1'), null)

    await store.put('key-2', { x: 1 }, 10)
    await new Promise((resolve) => setTimeout(resolve, 30))
    assert.equal(await store.get('key-2'), null, 'entry should have expired')
  }
})

let tmpDirPromise = null
async function tmpFile (name) {
  if (!tmpDirPromise) tmpDirPromise = fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-test-'))
  const dir = await tmpDirPromise
  return path.join(dir, `${Date.now()}-${Math.random().toString(36).slice(2)}-${name}`)
}
