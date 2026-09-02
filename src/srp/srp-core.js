// SRP-6a protocol math (RFC 5054), shared verbatim between client and
// server code. Every function here is pure given its inputs plus the
// injected CryptoAdapter — no globals, no I/O — so it can be exercised
// identically in Node tests and in the browser.
//
// Two deliberate departures from a textbook RFC 5054 implementation, both
// required by this package's "username is not identity" design goal
// (see README "Why the username is never part of the crypto"):
//
//   1. x (the private key derived from the password) is computed from
//      (salt, password) only — RFC 5054 mixes in the username too. If it
//      did here, renaming a user would silently invalidate their stored
//      verifier the next time they tried to log in.
//   2. The M1/M2 session-proof hashes bind to the user's stable `uid`
//      instead of their username, for the same reason. This still
//      authenticates identity (uid is what the server looked up the
//      verifier by) without coupling it to a mutable display name.
//
// x is also stretched with PBKDF2-HMAC-SHA256 (RFC 5054 uses a single
// hash) so that a leaked verifier database costs an attacker one PBKDF2
// evaluation per password guess, not one cheap SHA-256.

import { hexToBigInt, bigIntToBytes, bytesToBigInt, padBytes, modPow, mod, concatBytes, constantTimeEqualBytes } from '../common/bigint.js'

const DEFAULT_PBKDF2_ITERATIONS = 600000 // OWASP 2023 minimum for PBKDF2-HMAC-SHA256
const SALT_BYTES = 16
const EPHEMERAL_BYTES = 32 // 256 bits of entropy for the private ephemeral (a/b)

function groupByteLength (group) {
  return group.bits / 8
}

async function computeK (group, adapter) {
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)
  const byteLen = groupByteLength(group)
  const paddedN = bigIntToBytes(N, byteLen)
  const paddedG = padBytes(bigIntToBytes(g), byteLen)
  const digest = await adapter.sha256(concatBytes(paddedN, paddedG))
  return bytesToBigInt(digest)
}

/**
 * x = PBKDF2-HMAC-SHA256(password, salt, iterations) interpreted as an
 * integer. Salt and password are the only inputs — see module comment.
 */
async function computeX (adapter, password, saltBytes, iterations) {
  const derived = await adapter.pbkdf2Sha256(
    new TextEncoder().encode(password),
    saltBytes,
    iterations,
    32
  )
  return bytesToBigInt(derived)
}

function computeVerifier (group, x) {
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)
  return modPow(g, x, N)
}

function generateEphemeralPrivate (adapter) {
  return bytesToBigInt(adapter.randomBytes(EPHEMERAL_BYTES))
}

function computeClientPublic (group, a) {
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)
  return modPow(g, a, N)
}

function computeServerPublic (group, k, v, b) {
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)
  return mod(k * v + modPow(g, b, N), N)
}

async function computeU (group, adapter, A, B) {
  const byteLen = groupByteLength(group)
  const digest = await adapter.sha256(concatBytes(
    padBytes(bigIntToBytes(A), byteLen),
    padBytes(bigIntToBytes(B), byteLen)
  ))
  return bytesToBigInt(digest)
}

// Client: S = (B - k*g^x) ^ (a + u*x) mod N
function computeClientS (group, k, x, a, u, B) {
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)
  const base = mod(B - mod(k * modPow(g, x, N), N), N)
  const exponent = a + u * x
  return modPow(base, exponent, N)
}

// Server: S = (A * v^u) ^ b mod N
function computeServerS (group, v, u, b, A) {
  const N = hexToBigInt(group.N)
  const base = mod(A * modPow(v, u, N), N)
  return modPow(base, b, N)
}

async function computeSessionKey (adapter, S) {
  const digest = await adapter.sha256(bigIntToBytes(S))
  return bytesToBigInt(digest)
}

/**
 * M1 = H(H(N) xor H(g), H(uid), s, A, B, K)
 * Binds the proof to the group, the (immutable) user id, the salt, both
 * public ephemerals, and the derived session key.
 */
async function computeM1 (group, adapter, uid, saltBytes, A, B, K) {
  const byteLen = groupByteLength(group)
  const N = hexToBigInt(group.N)
  const g = hexToBigInt(group.g)

  const hN = await adapter.sha256(bigIntToBytes(N, byteLen))
  const hG = await adapter.sha256(padBytes(bigIntToBytes(g), byteLen))
  const xorNG = xorBytes(hN, hG)
  const hUid = await adapter.sha256(new TextEncoder().encode(uid))

  const digest = await adapter.sha256(concatBytes(
    xorNG,
    hUid,
    saltBytes,
    padBytes(bigIntToBytes(A), byteLen),
    padBytes(bigIntToBytes(B), byteLen),
    padBytes(bigIntToBytes(K), 32)
  ))
  return bytesToBigInt(digest)
}

/** M2 = H(A, M1, K) — proves the server also derived the same session key. */
async function computeM2 (group, adapter, A, M1, K) {
  const byteLen = groupByteLength(group)
  const digest = await adapter.sha256(concatBytes(
    padBytes(bigIntToBytes(A), byteLen),
    padBytes(bigIntToBytes(M1), 32),
    padBytes(bigIntToBytes(K), 32)
  ))
  return bytesToBigInt(digest)
}

function xorBytes (a, b) {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]
  return out
}

function isValidPublicValue (group, value) {
  const N = hexToBigInt(group.N)
  return mod(value, N) !== 0n
}

export {
  DEFAULT_PBKDF2_ITERATIONS,
  SALT_BYTES,
  EPHEMERAL_BYTES,
  groupByteLength,
  computeK,
  computeX,
  computeVerifier,
  generateEphemeralPrivate,
  computeClientPublic,
  computeServerPublic,
  computeU,
  computeClientS,
  computeServerS,
  computeSessionKey,
  computeM1,
  computeM2,
  isValidPublicValue,
  constantTimeEqualBytes
}
