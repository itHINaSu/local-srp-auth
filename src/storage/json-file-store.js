// JSON-file-backed UserStore, RoleStore, and SessionStore, for small
// single-instance deployments (or "I just want to try this out with a
// real file, not a database, yet"). Every write goes through the same
// write-to-temp-then-rename pattern used elsewhere for atomic config
// writes: a crash or concurrent read never observes a half-written file.
// Writes within one process are also serialized through a promise chain
// so two concurrent calls can't interleave and corrupt the file — this
// does NOT protect against two separate processes writing the same file,
// which is exactly the "single-instance" limitation above.
//
// ChallengeStore is intentionally not implemented here: its entries are
// mid-login-attempt state with a short TTL (minutes) by design, and
// losing an in-flight login on a restart just means trying again —
// persisting it to disk buys little. SessionStore, below, is a different
// story: losing every *already logged in* session on every restart
// (including a routine `docker compose restart` after a config change,
// not just a crash) is a real, avoidable annoyance for anyone actually
// using a deployment day to day — hence JsonFileSessionStore exists and
// MemoryChallengeStore/MemorySessionStore's in-memory tradeoff doesn't
// apply uniformly to both stores the way the original version of this
// comment implied. Write a store backed by whatever your deployment
// already runs (Redis, etc.) instead of either if you need multi-instance
// state for either one.

import fs from 'node:fs/promises'
import path from 'node:path'
import { UserStore, RoleStore, SessionStore } from './storage-interface.js'

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

/**
 * Persists sessions (and, since AuthServer reuses the same SessionStore for
 * both, the short-lived 'mfa:<token>'/'totp-enroll:<token>'/
 * 'password-reset:<token>' pending-state entries too — harmless to persist,
 * just not the point) to a JSON file, surviving process restarts. This is
 * what makes a `docker compose restart` (or a crash) not force-log-out
 * every already-authenticated user, the way the default in-memory
 * MemorySessionStore does.
 *
 * Expired entries are swept lazily: get() drops one it finds expired
 * on read, and put() also prunes every expired entry while it's already
 * loaded the file to write to it anyway — between the two, the file
 * doesn't grow unboundedly even though there's no separate background
 * timer doing periodic cleanup.
 */
class JsonFileSessionStore extends SessionStore {
  constructor (filePath) {
    super()
    this._collection = new JsonFileCollection(filePath)
  }

  async put (sessionId, data, ttlMs) {
    return this._collection.withRecords((records) => {
      pruneExpired(records)
      const idx = records.findIndex((r) => r.id === sessionId)
      const record = { id: sessionId, data, expiresAt: Date.now() + ttlMs }
      if (idx === -1) records.push(record)
      else records[idx] = record
    })
  }

  async get (sessionId) {
    const records = await this._collection.readRecords()
    const found = records.find((r) => r.id === sessionId)
    if (!found) return null
    if (Date.now() > found.expiresAt) {
      await this.delete(sessionId) // lazily sweep the one we just noticed is stale
      return null
    }
    return found.data
  }

  async delete (sessionId) {
    return this._collection.withRecords((records) => {
      const idx = records.findIndex((r) => r.id === sessionId)
      if (idx !== -1) records.splice(idx, 1)
    })
  }

  // Real session tokens are bare crypto.randomUUID() strings (no ':');
  // this store also holds pending MFA/enrollment/password-reset state
  // under 'prefix:token' keys (see server-auth.js/bootstrap.js) — the
  // ':' check keeps this from ever deleting one of those by accident,
  // same convention MemorySessionStore's own deleteAllForUser() follows.
  async deleteAllForUser (uid, exceptSessionId) {
    return this._collection.withRecords((records) => {
      for (let i = records.length - 1; i >= 0; i--) {
        const r = records[i]
        if (!r.id.includes(':') && r.data && r.data.uid === uid && r.id !== exceptSessionId) {
          records.splice(i, 1)
        }
      }
    })
  }
}

function pruneExpired (records) {
  const now = Date.now()
  for (let i = records.length - 1; i >= 0; i--) {
    if (now > records[i].expiresAt) records.splice(i, 1)
  }
}

export { JsonFileUserStore, JsonFileRoleStore, JsonFileSessionStore }
