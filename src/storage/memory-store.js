// In-memory reference implementations of every storage interface. Used
// by this package's own tests, and a reasonable starting point for a
// quick local prototype — but state is lost on process restart, and
// nothing here is shared across multiple server instances. Swap in
// json-file-store.js (or your own DB-backed store) for anything real.

import { UserStore, RoleStore, ChallengeStore, SessionStore, InviteStore } from './storage-interface.js'

class MemoryUserStore extends UserStore {
  constructor () {
    super()
    /** @type {Map<string, import('./storage-interface').UserRecord>} */
    this._byId = new Map()
  }

  async createUser (user) {
    if (this._byId.has(user.id)) throw new Error(`user id already exists: ${user.id}`)
    for (const existing of this._byId.values()) {
      if (existing.username === user.username) throw new Error(`username already taken: ${user.username}`)
    }
    this._byId.set(user.id, { ...user })
    return { ...user }
  }

  async getUserById (id) {
    const user = this._byId.get(id)
    return user ? { ...user } : null
  }

  async getUserByUsername (username) {
    for (const user of this._byId.values()) {
      if (user.username === username) return { ...user }
    }
    return null
  }

  async updateUser (id, patch) {
    const existing = this._byId.get(id)
    if (!existing) throw new Error(`no such user: ${id}`)
    const updated = { ...existing, ...patch, id, updatedAt: new Date().toISOString() }
    this._byId.set(id, updated)
    return { ...updated }
  }

  async deleteUser (id) {
    this._byId.delete(id)
  }

  async listUsers () {
    return [...this._byId.values()].map((u) => ({ ...u }))
  }

  async countUsers () {
    return this._byId.size
  }
}

class MemoryRoleStore extends RoleStore {
  constructor () {
    super()
    /** @type {Map<string, import('./storage-interface').RoleRecord>} */
    this._byId = new Map()
  }

  async createRole (role) {
    if (this._byId.has(role.id)) throw new Error(`role id already exists: ${role.id}`)
    this._byId.set(role.id, { ...role })
    return { ...role }
  }

  async getRole (id) {
    const role = this._byId.get(id)
    return role ? { ...role } : null
  }

  async updateRole (id, patch) {
    const existing = this._byId.get(id)
    if (!existing) throw new Error(`no such role: ${id}`)
    const updated = { ...existing, ...patch, id }
    this._byId.set(id, updated)
    return { ...updated }
  }

  async deleteRole (id) {
    this._byId.delete(id)
  }

  async listRoles () {
    return [...this._byId.values()].map((r) => ({ ...r }))
  }
}

class TtlMemoryStore {
  constructor () {
    this._entries = new Map()
  }

  async put (key, data, ttlMs) {
    this._entries.set(key, { data, expiresAt: Date.now() + ttlMs })
  }

  async get (key) {
    const entry = this._entries.get(key)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this._entries.delete(key)
      return null
    }
    return entry.data
  }

  async delete (key) {
    this._entries.delete(key)
  }

  /** Deletes every non-expired entry for which `predicate(key, data)` returns true (also sweeps expired entries it passes over). */
  async deleteWhere (predicate) {
    const now = Date.now()
    for (const [key, entry] of this._entries) {
      if (now > entry.expiresAt) { this._entries.delete(key); continue }
      if (predicate(key, entry.data)) this._entries.delete(key)
    }
  }
}

class MemoryChallengeStore extends ChallengeStore {
  constructor () {
    super()
    this._impl = new TtlMemoryStore()
  }

  async put (challengeId, data, ttlMs) { return this._impl.put(challengeId, data, ttlMs) }
  async get (challengeId) { return this._impl.get(challengeId) }
  async delete (challengeId) { return this._impl.delete(challengeId) }
}

class MemorySessionStore extends SessionStore {
  constructor () {
    super()
    this._impl = new TtlMemoryStore()
  }

  async put (sessionId, data, ttlMs) { return this._impl.put(sessionId, data, ttlMs) }
  async get (sessionId) { return this._impl.get(sessionId) }
  async delete (sessionId) { return this._impl.delete(sessionId) }
  // Deletes sessions AND pending (prefixed) entries for the uid — the
  // credential-reset path wants everything gone.
  async deleteByUid (uid) { return this._impl.deleteWhere((key, data) => data && data.uid === uid) }

  // Real session tokens are bare crypto.randomUUID() strings (no ':');
  // this store also holds pending MFA/enrollment/password-reset state
  // under 'prefix:token' keys (see server-auth.js/bootstrap.js) — the
  // ':' check keeps this from ever deleting one of those by accident.
  async deleteAllForUser (uid, exceptSessionId) {
    await this._impl.deleteWhere((key, data) => !key.includes(':') && data.uid === uid && key !== exceptSessionId)
  }
}

class MemoryInviteStore extends InviteStore {
  constructor () {
    super()
    /** @type {Map<string, import('./storage-interface').InviteRecord>} */
    this._byId = new Map()
  }

  async createInvite (invite) {
    if (this._byId.has(invite.id)) throw new Error(`invite id already exists: ${invite.id}`)
    for (const existing of this._byId.values()) {
      if (existing.tokenHash === invite.tokenHash) throw new Error('invite token hash already exists')
    }
    this._byId.set(invite.id, { ...invite })
    return { ...invite }
  }

  async getInviteByTokenHash (tokenHash) {
    for (const invite of this._byId.values()) {
      if (invite.tokenHash === tokenHash) return { ...invite }
    }
    return null
  }

  async getInvite (id) {
    const invite = this._byId.get(id)
    return invite ? { ...invite } : null
  }

  // Synchronous check-and-set inside one async tick: atomic w.r.t. other callers.
  async markUsed (id, usedAt) {
    const invite = this._byId.get(id)
    if (!invite || invite.usedAt || invite.revokedAt) return false
    invite.usedAt = usedAt
    return true
  }

  async revokeInvite (id, revokedAt) {
    const invite = this._byId.get(id)
    if (invite && !invite.revokedAt) invite.revokedAt = revokedAt
  }

  async listInvitesForUser (uid) {
    return [...this._byId.values()].filter((i) => i.uid === uid).map((i) => ({ ...i }))
  }
}

export { MemoryUserStore, MemoryRoleStore, MemoryChallengeStore, MemorySessionStore, MemoryInviteStore }
