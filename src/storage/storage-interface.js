// Storage contracts. AuthServer (server-auth.js) is written entirely
// against these interfaces, never against a concrete backend — that's
// what makes "works with any user storage system (JSON, DB, whatever)" a
// real property instead of a README claim. Ship your own backend by
// extending these classes; every method a subclass doesn't override
// throws NOT_IMPLEMENTED so a missing method fails loudly at first use,
// not silently at 3am.
//
// Two reference implementations ship in this package: memory-store.js
// (for tests and quick starts) and json-file-store.js (atomic-write JSON
// file, for small single-instance deployments). Both implement all the
// interfaces below, except InviteStore, which is only required if you use
// InviteManager (src/invites.js).

function notImplemented (className, methodName) {
  throw new Error(`${className}.${methodName}() is not implemented — extend the base class and implement it`)
}

/**
 * @typedef {object} UserRecord
 * @property {string} id stable, never reused, never changes
 * @property {string} username mutable, unique, used only for login lookup
 * @property {string|null} salt hex; null while the user is pending (no credential yet)
 * @property {string|null} verifier hex; null while pending
 * @property {number|null} iterations PBKDF2 iterations used for this user's x; null while pending
 * @property {number|null} group SRP group bit size used for this user's verifier; null while pending
 * @property {string[]} roleIds
 * @property {object|null} totp { secret: hex, enabledAt: string } | null
 * @property {string[]} recoveryCodeHashes hex sha256 hashes, single-use
 * @property {string} createdAt ISO timestamp
 * @property {string|null} updatedAt ISO timestamp
 */

class UserStore {
  /** @param {UserRecord} user @returns {Promise<UserRecord>} */
  async createUser (user) { notImplemented('UserStore', 'createUser') }
  /** @param {string} id @returns {Promise<UserRecord|null>} */
  async getUserById (id) { notImplemented('UserStore', 'getUserById') }
  /** @param {string} username @returns {Promise<UserRecord|null>} */
  async getUserByUsername (username) { notImplemented('UserStore', 'getUserByUsername') }
  /** @param {string} id @param {Partial<UserRecord>} patch @returns {Promise<UserRecord>} */
  async updateUser (id, patch) { notImplemented('UserStore', 'updateUser') }
  /** @param {string} id @returns {Promise<void>} */
  async deleteUser (id) { notImplemented('UserStore', 'deleteUser') }
  /** @returns {Promise<UserRecord[]>} */
  async listUsers () { notImplemented('UserStore', 'listUsers') }
  /** @returns {Promise<number>} */
  async countUsers () { notImplemented('UserStore', 'countUsers') }
}

/**
 * @typedef {object} RoleRecord
 * @property {string} id stable, never reused, never changes
 * @property {string} name mutable, display only
 * @property {string[]} permissions
 * @property {boolean} isBuiltIn
 * @property {string} createdAt ISO timestamp
 */

class RoleStore {
  /** @param {RoleRecord} role @returns {Promise<RoleRecord>} */
  async createRole (role) { notImplemented('RoleStore', 'createRole') }
  /** @param {string} id @returns {Promise<RoleRecord|null>} */
  async getRole (id) { notImplemented('RoleStore', 'getRole') }
  /** @param {string} id @param {Partial<RoleRecord>} patch @returns {Promise<RoleRecord>} */
  async updateRole (id, patch) { notImplemented('RoleStore', 'updateRole') }
  /** @param {string} id @returns {Promise<void>} */
  async deleteRole (id) { notImplemented('RoleStore', 'deleteRole') }
  /** @returns {Promise<RoleRecord[]>} */
  async listRoles () { notImplemented('RoleStore', 'listRoles') }
}

/**
 * Short-lived state for an in-flight SRP login (the server's ephemeral
 * secret `b`, plus enough context to finish the exchange). Entries
 * should expire on their own (ttlMs) even if never explicitly deleted,
 * so an abandoned login attempt can't accumulate server-side state.
 */
class ChallengeStore {
  /** @param {string} challengeId @param {object} data @param {number} ttlMs @returns {Promise<void>} */
  async put (challengeId, data, ttlMs) { notImplemented('ChallengeStore', 'put') }
  /** @param {string} challengeId @returns {Promise<object|null>} null if missing or expired */
  async get (challengeId) { notImplemented('ChallengeStore', 'get') }
  /** @param {string} challengeId @returns {Promise<void>} */
  async delete (challengeId) { notImplemented('ChallengeStore', 'delete') }
}

/** Authenticated sessions issued after a successful login (+ MFA, if enabled). */
class SessionStore {
  /** @param {string} sessionId @param {object} data @param {number} ttlMs @returns {Promise<void>} */
  async put (sessionId, data, ttlMs) { notImplemented('SessionStore', 'put') }
  /** @param {string} sessionId @returns {Promise<object|null>} null if missing or expired */
  async get (sessionId) { notImplemented('SessionStore', 'get') }
  /** @param {string} sessionId @returns {Promise<void>} */
  async delete (sessionId) { notImplemented('SessionStore', 'delete') }
  /**
   * Deletes every entry whose stored `uid` field equals `uid` (sessions,
   * pending-MFA and pending-enrollment entries alike). Optional for
   * backward compatibility: InviteManager feature-detects it and, if a
   * store lacks it, emits `invite.sessions_not_revoked` after a credential
   * reset instead of failing.
   * @param {string} uid @returns {Promise<void>}
   */
  async deleteByUid (uid) { notImplemented('SessionStore', 'deleteByUid') }
}

/**
 * @typedef {object} InviteRecord
 * @property {string} id 'invite-' + randomUUID, stable
 * @property {string} tokenHash hex sha256 of the raw token; the raw token is never stored
 * @property {string} uid the user this invite is bound to
 * @property {'activate'|'credential-reset'} purpose
 * @property {boolean} clearTotp credential-reset only: also remove the user's TOTP on redeem
 * @property {string|null} createdBy acting admin's uid, for the audit trail
 * @property {string} createdAt ISO timestamp
 * @property {string} expiresAt ISO timestamp
 * @property {string|null} usedAt
 * @property {string|null} revokedAt
 */

/** Invite / credential-reset tokens (see src/invites.js). */
class InviteStore {
  /** @param {InviteRecord} invite @returns {Promise<InviteRecord>} */
  async createInvite (invite) { notImplemented('InviteStore', 'createInvite') }
  /** @param {string} tokenHash @returns {Promise<InviteRecord|null>} */
  async getInviteByTokenHash (tokenHash) { notImplemented('InviteStore', 'getInviteByTokenHash') }
  /** @param {string} id @returns {Promise<InviteRecord|null>} */
  async getInvite (id) { notImplemented('InviteStore', 'getInvite') }
  /**
   * Compare-and-set: sets usedAt only if the invite exists and is neither
   * used nor revoked. This is the single-use guarantee under concurrent
   * redeems, so it MUST be atomic in your backend (e.g. a conditional
   * UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL).
   * @param {string} id @param {string} usedAt @returns {Promise<boolean>} false if it did not apply
   */
  async markUsed (id, usedAt) { notImplemented('InviteStore', 'markUsed') }
  /** Idempotent. @param {string} id @param {string} revokedAt @returns {Promise<void>} */
  async revokeInvite (id, revokedAt) { notImplemented('InviteStore', 'revokeInvite') }
  /** @param {string} uid @returns {Promise<InviteRecord[]>} */
  async listInvitesForUser (uid) { notImplemented('InviteStore', 'listInvitesForUser') }
}

export { UserStore, RoleStore, ChallengeStore, SessionStore, InviteStore }
