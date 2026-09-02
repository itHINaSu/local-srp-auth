// Server-facing SRP-6a functions. Stateless by design: the server can't
// assume it will handle both requests of a login round trip (load
// balancers, restarts), so instead of a stateful class this module takes
// and returns plain hex values. The caller (AuthServer, in
// server-auth.js) is responsible for persisting the ephemeral secret `b`
// between beginLoginChallenge() and completeLoginChallenge() — see
// storage/storage-interface.js's ChallengeStore contract.

import { hexToBigInt, bigIntToHex, bigIntToBytes, hexToBytes, constantTimeEqualBytes } from '../common/bigint.js'
import * as core from './srp-core.js'
import GROUPS from '../common/groups.js'

/**
 * Step 1 (server side): given a user's stored verifier, generate this
 * login attempt's ephemeral keypair (b, B). Persist `b` (via
 * ChallengeStore) keyed however you like, and send `B` to the client
 * along with the user's salt.
 */
async function beginLoginChallenge ({ adapter, group = GROUPS.DEFAULT, verifier }) {
  const v = hexToBigInt(verifier)
  const k = await core.computeK(group, adapter)
  const b = core.generateEphemeralPrivate(adapter)
  const B = core.computeServerPublic(group, k, v, b)
  return {
    b: bigIntToHex(b, core.groupByteLength(group)),
    B: bigIntToHex(B, core.groupByteLength(group))
  }
}

/**
 * Step 2 (server side): verify the client's proof M1 against the
 * persisted challenge state and the stored verifier. Throws on any
 * failure (invalid A, wrong password, tampered proof) — callers should
 * treat every throw here identically (generic "login failed") so the
 * error doesn't leak which check failed.
 * @returns {Promise<{ M2: string, sessionKey: string }>} hex-encoded
 */
async function completeLoginChallenge ({
  adapter,
  group = GROUPS.DEFAULT,
  verifier,
  serverEphemeralSecret, // b, hex — from beginLoginChallenge
  clientPublicEphemeral, // A, hex — from the client
  clientProof, // M1, hex — from the client
  uid,
  salt // hex
}) {
  const v = hexToBigInt(verifier)
  const b = hexToBigInt(serverEphemeralSecret)
  const A = hexToBigInt(clientPublicEphemeral)

  if (!core.isValidPublicValue(group, A)) {
    throw new Error('invalid client public ephemeral (A mod N == 0)')
  }

  const B = core.computeServerPublic(group, await core.computeK(group, adapter), v, b)
  const u = await core.computeU(group, adapter, A, B)
  if (u === 0n) throw new Error('computed u == 0')

  const S = core.computeServerS(group, v, u, b, A)
  const K = await core.computeSessionKey(adapter, S)

  const saltBytes = hexToBytes(salt)
  const expectedM1 = await core.computeM1(group, adapter, uid, saltBytes, A, B, K)

  // Constant-time comparison: this is a MAC-style proof verification, and
  // a data-dependent-time inequality check here (a plain BigInt !==, or
  // a byte loop that returns early on the first mismatch) is exactly the
  // shape of bug that turns into a timing oracle for forging a proof
  // without knowing the password. bigIntToBytes(..., 32) also rejects an
  // oversized clientProof outright (throws RangeError, caught by
  // AuthServer as a generic "login failed" like any other bad input).
  const actualM1Bytes = bigIntToBytes(hexToBigInt(clientProof), 32)
  if (!constantTimeEqualBytes(bigIntToBytes(expectedM1, 32), actualM1Bytes)) {
    throw new Error('client proof did not match — wrong password or tampered request')
  }

  const M2 = await core.computeM2(group, adapter, A, expectedM1, K)

  return {
    M2: bigIntToHex(M2, 32),
    sessionKey: bigIntToHex(K, 32)
  }
}

export { beginLoginChallenge, completeLoginChallenge }
