// Invite & credential-reset tokens ("magic links"). Generalizes Bootstrap's
// pattern: a random token gates one SRP registration against a specific
// account, the password still never leaves the browser, and the token burns
// on use. See docs/DESIGN-invite-tokens.md for the full design.
//
// The raw token exists server-side only inside issue()'s return path; the
// InviteStore only ever sees sha256(token). Every guessing surface
// (preview, redeem) is rate-limited and audited, and every failure path
// throws the same generic error.

import crypto from 'node:crypto'
import { publicUser } from './server-auth.js'

const TOKEN_BYTES = 32
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000
const PURPOSES = ['activate', 'credential-reset']
const GENERIC_ERROR_MESSAGE = 'invalid or expired invite'

function genericError () {
  return new Error(GENERIC_ERROR_MESSAGE)
}

function sha256Hex (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function constantTimeHexEqual (a, b) {
  const aBuf = Buffer.from(String(a))
  const bBuf = Buffer.from(String(b))
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

/** A pending user has no credential yet. */
function isPending (user) {
  return !user.verifier
}

/** Never hand the stored token hash back to callers. */
function publicInvite (invite) {
  const { tokenHash, ...rest } = invite
  return rest
}

class InviteManager {
  /**
   * @param {import('./server-auth').AuthServer} authServer
   * @param {object} opts
   * @param {import('./storage/storage-interface').InviteStore} opts.inviteStore
   * @param {number} [opts.defaultTtlMs]
   */
  constructor (authServer, { inviteStore, defaultTtlMs = DEFAULT_TTL_MS } = {}) {
    if (!authServer) throw new Error('InviteManager requires an authServer')
    if (!inviteStore) throw new Error('InviteManager requires an inviteStore')
    this._authServer = authServer
    this._store = inviteStore
    this._defaultTtlMs = defaultTtlMs
  }

  /**
   * Issues an invite for `uid`. 'activate' requires a pending user;
   * 'credential-reset' requires an active (credentialed) user. Revokes any
   * outstanding unexpired invite for the same (uid, purpose).
   * @param {object} opts
   * @param {string} opts.uid
   * @param {'activate'|'credential-reset'} opts.purpose
   * @param {number} [opts.ttlMs]
   * @param {string} [opts.createdBy] acting admin's uid
   * @param {boolean} [opts.clearTotp] credential-reset only: also remove the user's TOTP when redeemed
   * @returns {Promise<{ invite: object, token: string }>} the only moment the raw token is available
   */
  async issue ({ uid, purpose, ttlMs = this._defaultTtlMs, createdBy = null, clearTotp = false }) {
    const server = this._authServer
    if (!PURPOSES.includes(purpose)) throw new Error(`invalid invite purpose: ${purpose}`)
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error('ttlMs must be a positive number')

    const user = await server.userStore.getUserById(uid)
    if (!user) throw new Error('no such user')
    if (purpose === 'activate' && !isPending(user)) throw new Error('user is already active; use a credential-reset invite')
    if (purpose === 'credential-reset' && isPending(user)) throw new Error('user is pending; use an activate invite')

    const now = Date.now()
    await this._revokeOutstanding(uid, purpose, now, 'superseded')

    const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url')
    const record = {
      id: `invite-${crypto.randomUUID()}`,
      tokenHash: sha256Hex(token),
      uid,
      purpose,
      clearTotp: purpose === 'credential-reset' && Boolean(clearTotp),
      createdBy,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
      usedAt: null,
      revokedAt: null
    }
    const created = await this._store.createInvite(record)
    await server._log('invite.issued', {
      uid,
      details: { inviteId: created.id, purpose, createdBy, expiresAt: created.expiresAt, clearTotp: created.clearTotp }
    })
    return { invite: publicInvite(created), token }
  }

  /**
   * Lets the app greet the invitee before they choose a password.
   * @returns {Promise<{ uid: string, username: string, purpose: string, expiresAt: string }>}
   */
  async preview ({ token, clientKey }) {
    await this._enforce(token, clientKey)
    const { invite, user } = await this._validate(token, clientKey)
    return { uid: user.id, username: user.username, purpose: invite.purpose, expiresAt: invite.expiresAt }
  }

  /**
   * Burns the token and installs the credential. The caller already ran
   * SrpRegistration.create() in the browser; only (salt, verifier, ...)
   * arrive here.
   * @returns {Promise<object>} the updated user, public shape
   */
  async redeem ({ token, salt, verifier, iterations, group, clientKey }) {
    const server = this._authServer
    await this._enforce(token, clientKey)

    // Credential shape is checked before any token lookup so this error
    // cannot act as an oracle for token validity.
    iterations = iterations ?? server.pbkdf2Iterations
    group = group ?? server.group.bits
    if (typeof salt !== 'string' || !salt || typeof verifier !== 'string' || !verifier) {
      throw new Error('salt and verifier are required')
    }
    if (!Number.isInteger(iterations) || iterations <= 0) throw new Error('invalid iterations')
    if (group !== server.group.bits) {
      throw new Error(`client used a ${group}-bit SRP group but this server is configured for ${server.group.bits}-bit`)
    }

    const { invite, user } = await this._validate(token, clientKey)

    // Compare-and-set: exactly one concurrent redeemer wins. Done before
    // touching the user, and before reporting success.
    const won = await this._store.markUsed(invite.id, new Date().toISOString())
    if (!won) return this._fail(clientKey, invite, 'redeem')

    const patch = { salt, verifier, iterations, group }
    if (invite.purpose === 'credential-reset' && invite.clearTotp) {
      patch.totp = null
      patch.recoveryCodeHashes = []
    }
    const updated = await server.userStore.updateUser(user.id, patch)

    await server._log('invite.redeemed', {
      uid: user.id,
      clientKey,
      details: { inviteId: invite.id, purpose: invite.purpose, totpCleared: Boolean(patch.totp === null) }
    })

    if (invite.purpose === 'credential-reset') {
      await this._revokeSessions(user.id, invite)
    }

    return publicUser(updated)
  }

  async revoke (inviteId) {
    const invite = await this._store.getInvite(inviteId)
    if (!invite) throw new Error('no such invite')
    await this._store.revokeInvite(inviteId, new Date().toISOString())
    await this._authServer._log('invite.revoked', {
      uid: invite.uid,
      details: { inviteId, purpose: invite.purpose, reason: 'manual' }
    })
  }

  /** For an admin UI's "outstanding invites" list. Token hashes are never returned. */
  async listForUser (uid) {
    return (await this._store.listInvitesForUser(uid)).map(publicInvite)
  }

  // ---- internals ----------------------------------------------------------

  /**
   * Shared preview/redeem guessing-surface rate limit. The primary key is a
   * digest of the submitted token under a domain-separation prefix: it is
   * not the stored lookup hash (so a rate-limiter backend never holds
   * anything usable against the InviteStore) and it never reveals whether
   * the token exists. clientKey adds the per-source layer. No token
   * material is passed into the rate-limit log fields.
   */
  async _enforce (token, clientKey) {
    const key = sha256Hex(`invite-rate-limit:${typeof token === 'string' ? token : ''}`)
    await this._authServer._enforceRateLimit('invite', key, clientKey)
  }

  async _fail (clientKey, invite, op) {
    const details = { reason: 'invalid_invite', op }
    if (invite) details.inviteId = invite.id
    await this._authServer._log('invite.failed', { clientKey, ...(invite ? { uid: invite.uid } : {}), details })
    throw genericError()
  }

  /** Resolves a raw token to a live invite + its user, or throws the one generic error. */
  async _validate (token, clientKey) {
    if (typeof token !== 'string' || token.length === 0) return this._fail(clientKey, null, 'validate')

    const tokenHash = sha256Hex(token)
    const invite = await this._store.getInviteByTokenHash(tokenHash)
    if (!invite || !constantTimeHexEqual(invite.tokenHash, tokenHash)) return this._fail(clientKey, null, 'validate')

    if (invite.usedAt || invite.revokedAt || Date.now() >= Date.parse(invite.expiresAt)) {
      return this._fail(clientKey, invite, 'validate')
    }

    const user = await this._authServer.userStore.getUserById(invite.uid)
    if (!user) return this._fail(clientKey, invite, 'validate')
    if (invite.purpose === 'activate' && !isPending(user)) return this._fail(clientKey, invite, 'validate')
    if (invite.purpose === 'credential-reset' && isPending(user)) return this._fail(clientKey, invite, 'validate')

    return { invite, user }
  }

  async _revokeOutstanding (uid, purpose, nowMs, reason) {
    const existing = await this._store.listInvitesForUser(uid)
    for (const old of existing) {
      if (old.purpose !== purpose || old.usedAt || old.revokedAt) continue
      if (Date.parse(old.expiresAt) <= nowMs) continue
      await this._store.revokeInvite(old.id, new Date(nowMs).toISOString())
      await this._authServer._log('invite.revoked', {
        uid,
        details: { inviteId: old.id, purpose, reason }
      })
    }
  }

  async _revokeSessions (uid, invite) {
    const server = this._authServer
    const store = server.sessionStore
    let revoked = false
    if (store && typeof store.deleteByUid === 'function') {
      try {
        await store.deleteByUid(uid)
        revoked = true
      } catch {
        // A third-party store extending the base class inherits a
        // deleteByUid() that throws NOT_IMPLEMENTED; treat as absent.
      }
    }
    await server._log(revoked ? 'invite.sessions_revoked' : 'invite.sessions_not_revoked', {
      uid,
      details: { inviteId: invite.id, purpose: invite.purpose }
    })
  }
}

export { InviteManager }
