// First-run bootstrap: "if no user exists, one is created on first
// deployment." Concretely, that means a guarded, one-time registration
// endpoint that only accepts requests carrying a random setup token —
// generated at process startup and surfaced to whoever has access to the
// server's console/logs (or filesystem, if the integrator chooses to
// write it out; that's their call, not this module's).
//
// The bootstrap account still goes through the normal SRP registration
// path (registerUser()) — the password itself never reaches this module
// or the server in any form, exactly like every other account.

import crypto from 'node:crypto'

const SETUP_TOKEN_BYTES = 32
const DEFAULT_TOKEN_TTL_MS = 30 * 60 * 1000 // 30 minutes

class Bootstrap {
  /**
   * @param {import('./server-auth').AuthServer} authServer
   * @param {object} [opts]
   * @param {number} [opts.tokenTtlMs]
   */
  constructor (authServer, { tokenTtlMs = DEFAULT_TOKEN_TTL_MS } = {}) {
    this._authServer = authServer
    this._tokenTtlMs = tokenTtlMs
    this._token = null
    this._tokenExpiresAt = 0
  }

  async needsBootstrap () {
    return (await this._authServer.userStore.countUsers()) === 0
  }

  /**
   * Generates (or returns the still-valid existing) one-time setup
   * token. Call this at startup if needsBootstrap() is true, and print
   * or log the result somewhere the deploying operator will see it —
   * this module does not do that on your behalf, since "where does a
   * secret token belong" is a deployment decision (stdout? a file with
   * restrictive permissions? neither is universally right).
   * @returns {Promise<string|null>} null if bootstrap is no longer needed
   */
  async generateSetupToken () {
    if (!(await this.needsBootstrap())) return null
    if (this._token && Date.now() < this._tokenExpiresAt) return this._token

    this._token = crypto.randomBytes(SETUP_TOKEN_BYTES).toString('hex')
    this._tokenExpiresAt = Date.now() + this._tokenTtlMs
    return this._token
  }

  /**
   * Completes bootstrap: creates the first user (assigned the built-in
   * admin role) if, and only if, the token matches, hasn't expired, and
   * no user has been created since the token was issued (closes the
   * race between two concurrent bootstrap requests).
   */
  async completeBootstrap ({ token, username, salt, verifier, iterations, group }) {
    if (!(await this.needsBootstrap())) {
      throw new Error('bootstrap already completed')
    }
    if (!this._token || Date.now() >= this._tokenExpiresAt) {
      throw new Error('no valid setup token — call generateSetupToken() again')
    }
    if (!constantTimeStringEqual(token, this._token)) {
      throw new Error('invalid setup token')
    }

    const user = await this._authServer.registerUser({
      username,
      salt,
      verifier,
      iterations,
      group,
      roleIds: ['role-admin']
    })

    // One-time: burn the token so a second request (even with the
    // correct token) can't create a second bootstrap-privileged account.
    this._token = null
    this._tokenExpiresAt = 0

    return user
  }
}

function constantTimeStringEqual (a, b) {
  const aBuf = Buffer.from(String(a))
  const bBuf = Buffer.from(String(b))
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

export { Bootstrap }
