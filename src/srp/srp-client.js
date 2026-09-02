// Browser-facing SRP-6a client. Deliberately transport-agnostic: this
// module never calls fetch() itself. The integrating app wires its own
// HTTP calls between these steps, so this file (and everything it
// requires) works unmodified regardless of framework or backend shape.
//
// The password is only ever used locally to derive `x` (PBKDF2-HMAC-
// SHA256 over salt+password) or a verifier from `x`. Neither the
// password nor any single fixed hash of it is ever placed on an object
// this module returns — only one-time ephemeral protocol values (A, M1)
// that are useless for authenticating a second time.

import { hexToBigInt, bigIntToHex, bigIntToBytes, hexToBytes, bytesToHex, constantTimeEqualBytes } from '../common/bigint.js'
import * as core from './srp-core.js'
import GROUPS from '../common/groups.js'

class SrpRegistration {
  /**
   * Computes a new (salt, verifier) pair for a password. Send both to the
   * server as this user's credential — the password itself is discarded
   * when this function returns.
   * @param {object} opts
   * @param {string} opts.password
   * @param {import('../common/crypto-adapter').CryptoAdapter} opts.adapter
   * @param {object} [opts.group] one of GROUPS, defaults to GROUPS.DEFAULT
   * @param {number} [opts.iterations] PBKDF2 iteration count
   */
  static async create ({ password, adapter, group = GROUPS.DEFAULT, iterations = core.DEFAULT_PBKDF2_ITERATIONS }) {
    const saltBytes = adapter.randomBytes(core.SALT_BYTES)
    const x = await core.computeX(adapter, password, saltBytes, iterations)
    const v = core.computeVerifier(group, x)
    return {
      salt: bytesToHex(saltBytes),
      verifier: bigIntToHex(v, core.groupByteLength(group)),
      iterations,
      group: group.bits
    }
  }
}

/**
 * One in-flight login attempt. Create a new instance per attempt — it
 * holds the ephemeral private value `a` (and, briefly, the password) in
 * memory between the two round trips a login requires.
 */
class SrpLoginAttempt {
  constructor ({ adapter, group = GROUPS.DEFAULT, iterations = core.DEFAULT_PBKDF2_ITERATIONS } = {}) {
    this._adapter = adapter
    this._group = group
    this._iterations = iterations
    this._a = null
    this._A = null
    this._K = undefined
    this._M1 = undefined
  }

  /**
   * Step 1: generate this attempt's ephemeral keypair. Send the returned
   * `A` to the server together with the username.
   */
  start () {
    this._a = core.generateEphemeralPrivate(this._adapter)
    this._A = core.computeClientPublic(this._group, this._a)
    return { A: bigIntToHex(this._A, core.groupByteLength(this._group)) }
  }

  /**
   * Step 2: given the server's response (salt, its public ephemeral B,
   * and the account's stable uid), derive the session key and this
   * client's proof M1. Send M1 back to the server; keep the returned
   * `K` to verify the server's M2 in verifyServerProof().
   * @param {object} opts
   * @param {string} opts.password
   * @param {string} opts.salt hex
   * @param {string} opts.serverPublicEphemeral hex (B)
   * @param {string} opts.uid the account's stable id
   * @param {number} [opts.iterations] overrides the instance default —
   *   pass the value the server returns alongside salt/B so a later
   *   increase to the global default doesn't break existing accounts.
   */
  async finish ({ password, salt, serverPublicEphemeral, uid, iterations }) {
    if (this._a === null) throw new Error('call start() before finish()')

    const group = this._group
    const adapter = this._adapter
    const saltBytes = hexToBytes(salt)
    const B = hexToBigInt(serverPublicEphemeral)

    if (!core.isValidPublicValue(group, B)) {
      throw new Error('server sent an invalid public ephemeral (B mod N == 0)')
    }

    const k = await core.computeK(group, adapter)
    const x = await core.computeX(adapter, password, saltBytes, iterations ?? this._iterations)
    const u = await core.computeU(group, adapter, this._A, B)

    if (u === 0n) throw new Error('computed u == 0, aborting (would leak the session key)')

    const S = core.computeClientS(group, k, x, this._a, u, B)
    const K = await core.computeSessionKey(adapter, S)
    const M1 = await core.computeM1(group, adapter, uid, saltBytes, this._A, B, K)

    this._K = K
    this._M1 = M1
    return { M1: bigIntToHex(M1, 32) }
  }

  /**
   * Step 3: verify the server actually knows the session key too (proves
   * it holds the real verifier, not a phished one). Throws on mismatch —
   * treat that as a failed/spoofed login, not a UI-only warning.
   * @param {string} serverM2 hex
   * @returns {Promise<string>} the confirmed session key, hex-encoded
   */
  async verifyServerProof (serverM2) {
    if (this._K === undefined) throw new Error('call finish() before verifyServerProof()')
    const expected = await core.computeM2(this._group, this._adapter, this._A, this._M1, this._K)
    // Constant-time comparison — see the matching note in srp-server.js's
    // completeLoginChallenge(). Less critical here (forging this would
    // require a MITM already impersonating the server), but there's no
    // reason for the two sides of the same proof scheme to hold different
    // standards.
    const actualBytes = bigIntToBytes(hexToBigInt(serverM2), 32)
    if (!constantTimeEqualBytes(bigIntToBytes(expected, 32), actualBytes)) {
      throw new Error('server proof did not match — possible MITM, aborting')
    }
    return bigIntToHex(this._K, 32)
  }
}

export { SrpRegistration, SrpLoginAttempt }
