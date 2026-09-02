// JSON-file-backed UserStore and RoleStore, for small single-instance
// deployments (or "I just want to try this out with a real file, not a
// database, yet"). Every write goes through the same
// write-to-temp-then-rename pattern used elsewhere for atomic config
// writes: a crash or concurrent read never observes a half-written file.
// Writes within one process are also serialized through a promise chain
// so two concurrent calls can't interleave and corrupt the file — this
// does NOT protect against two separate processes writing the same file,
// which is exactly the "single-instance" limitation above.
//
// ChallengeStore/SessionStore are intentionally not implemented here:
// their entries are short-lived by design, and persisting them to disk
// buys little. Use MemoryChallengeStore/MemorySessionStore (the default
// AuthServer already does), or write a store backed by whatever your
// deployment already runs (Redis, etc.) if you need multi-instance
// login-in-progress state.

import fs from 'node:fs/promises'
import path from 'node:path'
import { UserStore, RoleStore } from './storage-interface.js'

class JsonFileCollection {
  constructor (filePath) {
    this._filePath = filePath
    this._writeQueue = Promise.resolve()
  }

  async _load () {
    try {
      const raw = await fs.readFile(this._filePath, 'utf8')
      return JSON.parse(raw)
    } catch (err) {
      if (err.code === 'ENOENT') return []
      throw err
    }
  }

  async _save (records) {
    const dir = path.dirname(this._filePath)
    await fs.mkdir(dir, { recursive: true })
    const tmpPath = `${this._filePath}.${process.pid}.${Date.now()}.tmp`
    await fs.writeFile(tmpPath, JSON.stringify(records, null, 2), { mode: 0o600 })
    await fs.rename(tmpPath, this._filePath)
  }

  /** Runs `mutator(records)` with exclusive access, persists the result, returns mutator's return value. */
  async withRecords (mutator) {
    const run = async () => {
      const records = await this._load()
      const result = await mutator(records)
      await this._save(records)
      return result
    }
    const resultPromise = this._writeQueue.then(run, run)
    // Keep the queue alive even if this call fails, so later calls still run in order.
    this._writeQueue = resultPromise.catch(() => {})
    return resultPromise
  }

  async readRecords () {
    return this._load()
  }
}

class JsonFileUserStore extends UserStore {
  constructor (filePath) {
    super()
    this._collection = new JsonFileCollection(filePath)
  }

  async createUser (user) {
    return this._collection.withRecords((records) => {
      if (records.some((r) => r.id === user.id)) throw new Error(`user id already exists: ${user.id}`)
      if (records.some((r) => r.username === user.username)) throw new Error(`username already taken: ${user.username}`)
      records.push({ ...user })
      return { ...user }
    })
  }

  async getUserById (id) {
    const records = await this._collection.readRecords()
    const found = records.find((r) => r.id === id)
    return found ? { ...found } : null
  }

  async getUserByUsername (username) {
    const records = await this._collection.readRecords()
    const found = records.find((r) => r.username === username)
    return found ? { ...found } : null
  }

  async updateUser (id, patch) {
    return this._collection.withRecords((records) => {
      const idx = records.findIndex((r) => r.id === id)
      if (idx === -1) throw new Error(`no such user: ${id}`)
      const updated = { ...records[idx], ...patch, id, updatedAt: new Date().toISOString() }
      records[idx] = updated
      return { ...updated }
    })
  }

  async deleteUser (id) {
    return this._collection.withRecords((records) => {
      const idx = records.findIndex((r) => r.id === id)
      if (idx !== -1) records.splice(idx, 1)
    })
  }

  async listUsers () {
    const records = await this._collection.readRecords()
    return records.map((r) => ({ ...r }))
  }

  async countUsers () {
    const records = await this._collection.readRecords()
    return records.length
  }
}

class JsonFileRoleStore extends RoleStore {
  constructor (filePath) {
    super()
    this._collection = new JsonFileCollection(filePath)
  }

  async createRole (role) {
    return this._collection.withRecords((records) => {
      if (records.some((r) => r.id === role.id)) throw new Error(`role id already exists: ${role.id}`)
      records.push({ ...role })
      return { ...role }
    })
  }

  async getRole (id) {
    const records = await this._collection.readRecords()
    const found = records.find((r) => r.id === id)
    return found ? { ...found } : null
  }

  async updateRole (id, patch) {
    return this._collection.withRecords((records) => {
      const idx = records.findIndex((r) => r.id === id)
      if (idx === -1) throw new Error(`no such role: ${id}`)
      const updated = { ...records[idx], ...patch, id }
      records[idx] = updated
      return { ...updated }
    })
  }

  async deleteRole (id) {
    return this._collection.withRecords((records) => {
      const idx = records.findIndex((r) => r.id === id)
      if (idx !== -1) records.splice(idx, 1)
    })
  }

  async listRoles () {
    const records = await this._collection.readRecords()
    return records.map((r) => ({ ...r }))
  }
}

export { JsonFileUserStore, JsonFileRoleStore }
