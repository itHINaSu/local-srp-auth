// AuthServer: the single class most integrations touch. Wires SRP login,
// TOTP MFA, roles, and sessions together against whatever storage you
// pass in. Every dependency (stores, crypto adapter, group, timings) is
// a constructor option with a sane default — nothing here reaches for a
// global or a specific backend.

import crypto from 'node:crypto'
import { hexToBigInt, bigIntToHex } from './common/bigint.js'
import GROUPS from './common/groups.js'
import * as core from './srp/srp-core.js'
import * as srpServer from './srp/srp-server.js'
import * as totp from './totp/totp.js'
import * as base32 from './totp/base32.js'
import * as recoveryCodes from './totp/recovery-codes.js'
import * as roles from './roles/roles.js'
import { createNodeCryptoAdapter } from './common/crypto-adapter-node.js'
import { MemoryChallengeStore, MemorySessionStore } from './storage/memory-store.js'

const DEFAULT_CHALLENGE_TTL_MS = 2 * 60 * 1000
const DEFAULT_MFA_PENDING_TTL_MS = 5 * 60 * 1000
const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1000

class AuthServer {
  /**
   * @param {object} opts
   * @param {import('./storage/storage-interface').UserStore} opts.userStore
   * @param {import('./storage/storage-interface').RoleStore} opts.roleStore
   * @param {import('./storage/storage-interface').ChallengeStore} [opts.challengeStore]
   * @param {import('./storage/storage-interface').SessionStore} [opts.sessionStore]
   * @param {import('./common/crypto-adapter').CryptoAdapter} [opts.adapter]
   * @param {object} [opts.group] one of GROUPS
   * @param {number} [opts.pbkdf2Iterations]
   * @param {Buffer} [opts.enumerationDefenseSecret] shared across instances
   *   in a multi-server deployment so the fake-verifier response for a
   *   nonexistent username is consistent across servers. Defaults to a
   *   random per-process secret — fine for a single instance, but a
   *   restart or a second instance would compute different fake
   *   verifiers, which is a (minor, not exploitable) inconsistency.
   */
  constructor ({
    userStore,
    roleStore,
    challengeStore = new MemoryChallengeStore(),
    sessionStore = new MemorySessionStore(),
    adapter = createNodeCryptoAdapter(),
    group = GROUPS.DEFAULT,
    pbkdf2Iterations = core.DEFAULT_PBKDF2_ITERATIONS,
    challengeTtlMs = DEFAULT_CHALLENGE_TTL_MS,
    mfaPendingTtlMs = DEFAULT_MFA_PENDING_TTL_MS,
    sessionTtlMs = DEFAULT_SESSION_TTL_MS,
    enumerationDefenseSecret = crypto.randomBytes(32)
  }) {
    if (!userStore) throw new Error('AuthServer requires a userStore')
    if (!roleStore) throw new Error('AuthServer requires a roleStore')

    this.userStore = userStore
    this.roleStore = roleStore
    this.challengeStore = challengeStore
    this.sessionStore = sessionStore
    this.adapter = adapter
    this.group = group
    this.pbkdf2Iterations = pbkdf2Iterations
    this.challengeTtlMs = challengeTtlMs
    this.mfaPendingTtlMs = mfaPendingTtlMs
    this.sessionTtlMs = sessionTtlMs
    this._enumerationDefenseSecret = enumerationDefenseSecret
  }

  // ---- Roles ----------------------------------------------------------

  /** Seeds the four default roles if the role store is currently empty. Safe to call on every startup. */
  async ensureDefaultRoles () {
    const existing = await this.roleStore.listRoles()
    if (existing.length > 0) return existing
    const seeded = []
    for (const role of roles.defaultRoles()) {
      seeded.push(await this.roleStore.createRole(role))
    }
    return seeded
  }

  async getUserRoles (user) {
    const resolved = []
    for (const roleId of user.roleIds || []) {
      const role = await this.roleStore.getRole(roleId)
      if (role) resolved.push(role)
    }
    return resolved
  }

  async userHasPermission (user, permission) {
    const userRoles = await this.getUserRoles(user)
    return roles.anyRoleHasPermission(userRoles, permission)
  }

  // ---- Registration -----------------------------------------------------
  // The caller already ran SrpRegistration.create() in the browser and is
  // handing us only (salt, verifier) — never a password, hashed or not.

  /**
   * @param {object} opts
   * @param {string} opts.username
   * @param {string} opts.salt hex
   * @param {string} opts.verifier hex
   * @param {number} [opts.iterations] defaults to this server's configured PBKDF2 iterations
   * @param {number} [opts.group] SRP group bit size used by the client; must match this server's configured group
   * @param {string[]} [opts.roleIds]
   */
  async registerUser ({ username, salt, verifier, iterations = this.pbkdf2Iterations, group = this.group.bits, roleIds = [] }) {
    if (!username || typeof username !== 'string') throw new Error('username is required')
    if (group !== this.group.bits) {
      throw new Error(`client used a ${group}-bit SRP group but this server is configured for ${this.group.bits}-bit`)
    }
    const existing = await this.userStore.getUserByUsername(username)
    if (existing) throw new Error('username already taken')

    const now = new Date().toISOString()
    const user = {
      id: crypto.randomUUID(),
      username,
      salt,
      verifier,
      iterations,
      group,
      roleIds,
      totp: null,
      recoveryCodeHashes: [],
      createdAt: now,
      updatedAt: null
    }
    const created = await this.userStore.createUser(user)
    return publicUser(created)
  }

  // ---- Login (SRP) -------------------------------------------------------

  /**
   * Step 1: client sends { username, A }. Returns { challengeId, salt, B, uid }.
   * Behaves identically (timing and response shape) whether or not the
   * username exists, via a deterministic fake verifier — see
   * _deriveFakeCredential() — so a login attempt can't be used to probe
   * which usernames are registered.
   */
  async beginLogin ({ username, clientPublicEphemeral }) {
    const realUser = await this.userStore.getUserByUsername(username)
    const credential = realUser
      ? { uid: realUser.id, salt: realUser.salt, verifier: realUser.verifier }
      : this._deriveFakeCredential(username)

    const { b, B } = await srpServer.beginLoginChallenge({
      adapter: this.adapter,
      group: this.group,
      verifier: credential.verifier
    })

    const challengeId = crypto.randomUUID()
    await this.challengeStore.put(challengeId, {
      uid: credential.uid,
      salt: credential.salt,
      verifier: credential.verifier,
      serverEphemeralSecret: b,
      clientPublicEphemeral,
      real: Boolean(realUser)
    }, this.challengeTtlMs)

    return { challengeId, salt: credential.salt, B, uid: credential.uid }
  }

  /**
   * Step 2: client sends { challengeId, M1 }. On success, returns
   * { M2, mfaRequired, sessionToken? , mfaToken? }. Throws a generic
   * "login failed" error on any failure — callers should show the user a
   * single generic message regardless of which check failed.
   */
  async completeLogin ({ challengeId, clientProof }) {
    const challenge = await this.challengeStore.get(challengeId)
    if (!challenge) throw new Error('login failed')
    await this.challengeStore.delete(challengeId) // single use, success or failure

    let result
    try {
      result = await srpServer.completeLoginChallenge({
        adapter: this.adapter,
        group: this.group,
        verifier: challenge.verifier,
        serverEphemeralSecret: challenge.serverEphemeralSecret,
        clientPublicEphemeral: challenge.clientPublicEphemeral,
        clientProof,
        uid: challenge.uid,
        salt: challenge.salt
      })
    } catch {
      throw new Error('login failed')
    }

    if (!challenge.real) throw new Error('login failed')

    const user = await this.userStore.getUserById(challenge.uid)
    if (!user) throw new Error('login failed')

    if (user.totp) {
      const mfaToken = crypto.randomUUID()
      await this.sessionStore.put(`mfa:${mfaToken}`, { uid: user.id, stage: 'mfa-pending' }, this.mfaPendingTtlMs)
      return { M2: result.M2, mfaRequired: true, mfaToken }
    }

    const sessionToken = await this._createSession(user)
    return { M2: result.M2, mfaRequired: false, sessionToken }
  }

  /** Deterministic-per-username fake (uid, salt, verifier) for nonexistent accounts. */
  _deriveFakeCredential (username) {
    const uidSeed = hmacSha256Hex(this._enumerationDefenseSecret, `uid:${username}`)
    const saltSeed = hmacSha256Hex(this._enumerationDefenseSecret, `salt:${username}`)
    const verifierSeed = hmacSha256Hex(this._enumerationDefenseSecret, `verifier:${username}`)

    const byteLen = core.groupByteLength(this.group)
    // Stretch the verifier seed to the group's byte length by repeated
    // hashing (a simple, adapter-free KDF — this value is never a secret
    // an attacker benefits from learning, it just needs to look like a
    // real verifier and be stable across calls).
    let verifierHex = verifierSeed
    while (verifierHex.length < byteLen * 2) {
      verifierHex += hmacSha256Hex(this._enumerationDefenseSecret, verifierHex)
    }
    verifierHex = verifierHex.slice(0, byteLen * 2)
    const verifier = bigIntToHex(hexToBigInt(verifierHex) % hexToBigInt(this.group.N), byteLen)

    return {
      uid: `fake-${uidSeed.slice(0, 32)}`,
      salt: saltSeed.slice(0, core.SALT_BYTES * 2),
      verifier
    }
  }

  // ---- TOTP enrollment ----------------------------------------------------

  /** Starts enrollment for an authenticated user. Returns the secret (base32) and otpauth:// URI for a QR code. */
  async beginTotpEnrollment (uid) {
    const user = await this.userStore.getUserById(uid)
    if (!user) throw new Error('no such user')
    const secretBytes = totp.generateSecret()
    const pendingToken = crypto.randomUUID()
    await this.sessionStore.put(`totp-enroll:${pendingToken}`, {
      uid,
      secretHex: Buffer.from(secretBytes).toString('hex')
    }, this.mfaPendingTtlMs)

    return {
      pendingToken,
      secretBase32: base32.encode(secretBytes),
      otpauthUri: totp.otpauthUri({ secretBytes, issuer: 'local-srp-auth', accountName: user.username })
    }
  }

  /** Confirms enrollment with a code from the authenticator app. Persists the secret and returns one-time recovery codes. */
  async confirmTotpEnrollment ({ pendingToken, code }) {
    const pending = await this.sessionStore.get(`totp-enroll:${pendingToken}`)
    if (!pending) throw new Error('enrollment expired or not found, start over')

    const secretBytes = Buffer.from(pending.secretHex, 'hex')
    const { matched } = totp.verifyTotp(secretBytes, code)
    if (!matched) throw new Error('invalid code')

    await this.sessionStore.delete(`totp-enroll:${pendingToken}`)

    const codes = recoveryCodes.generateRecoveryCodes()
    const hashes = codes.map((c) => recoveryCodes.hashRecoveryCode(c))

    await this.userStore.updateUser(pending.uid, {
      totp: { secret: pending.secretHex, enabledAt: new Date().toISOString() },
      recoveryCodeHashes: hashes
    })

    return { recoveryCodes: codes } // shown once — the caller must display these now, they cannot be retrieved again
  }

  /** Disables TOTP. Requires a currently-valid code as a safeguard against a hijacked session silently dropping MFA. */
  async disableTotp ({ uid, code }) {
    const user = await this.userStore.getUserById(uid)
    if (!user || !user.totp) throw new Error('MFA is not enabled')
    const secretBytes = Buffer.from(user.totp.secret, 'hex')
    const { matched } = totp.verifyTotp(secretBytes, code)
    if (!matched) throw new Error('invalid code')
    await this.userStore.updateUser(uid, { totp: null, recoveryCodeHashes: [] })
  }

  // ---- MFA verification (completes a login that returned mfaRequired) ----

  async verifyMfaTotp ({ mfaToken, code }) {
    const pending = await this.sessionStore.get(`mfa:${mfaToken}`)
    if (!pending) throw new Error('MFA challenge expired or not found, log in again')
    const user = await this.userStore.getUserById(pending.uid)
    if (!user || !user.totp) throw new Error('MFA challenge invalid')

    const secretBytes = Buffer.from(user.totp.secret, 'hex')
    const { matched } = totp.verifyTotp(secretBytes, code)
    if (!matched) throw new Error('invalid code')

    await this.sessionStore.delete(`mfa:${mfaToken}`)
    const sessionToken = await this._createSession(user)
    return { sessionToken }
  }

  async verifyMfaRecoveryCode ({ mfaToken, recoveryCode }) {
    const pending = await this.sessionStore.get(`mfa:${mfaToken}`)
    if (!pending) throw new Error('MFA challenge expired or not found, log in again')
    const user = await this.userStore.getUserById(pending.uid)
    if (!user || !user.totp) throw new Error('MFA challenge invalid')

    const idx = recoveryCodes.verifyRecoveryCode(user.recoveryCodeHashes, recoveryCode)
    if (idx === -1) throw new Error('invalid recovery code')

    const remaining = user.recoveryCodeHashes.slice()
    remaining.splice(idx, 1) // single use
    await this.userStore.updateUser(user.id, { recoveryCodeHashes: remaining })

    await this.sessionStore.delete(`mfa:${mfaToken}`)
    const sessionToken = await this._createSession(user)
    return { sessionToken, recoveryCodesRemaining: remaining.length }
  }

  // ---- Sessions -----------------------------------------------------------

  async _createSession (user) {
    const sessionToken = crypto.randomUUID()
    const userRoles = await this.getUserRoles(user)
    await this.sessionStore.put(sessionToken, {
      uid: user.id,
      roleIds: user.roleIds,
      permissions: [...new Set(userRoles.flatMap((r) => r.permissions))]
    }, this.sessionTtlMs)
    return sessionToken
  }

  async getSession (sessionToken) {
    return this.sessionStore.get(sessionToken)
  }

  async destroySession (sessionToken) {
    return this.sessionStore.delete(sessionToken)
  }
}

function hmacSha256Hex (key, message) {
  return crypto.createHmac('sha256', key).update(message).digest('hex')
}

/** Strips SRP secrets (salt, verifier) and the TOTP secret from a user record before it leaves the server. */
function publicUser (user) {
  const { salt, verifier, totp: totpInfo, recoveryCodeHashes, ...rest } = user
  return { ...rest, mfaEnabled: Boolean(totpInfo) }
}

export { AuthServer, publicUser }
