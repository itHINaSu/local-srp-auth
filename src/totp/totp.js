// TOTP (RFC 6238, built on HOTP / RFC 4226). Server-side only: the
// server is the only party holding the shared secret after enrollment,
// so unlike the SRP modules this one talks to node:crypto directly
// rather than through the isomorphic CryptoAdapter.
//
// Algorithm is HMAC-SHA1, deliberately, even though this package uses
// SHA-256 everywhere else: SHA-1 remains the de facto standard for TOTP
// and is what virtually every authenticator app (Google Authenticator,
// Authy, 1Password, Apple's built-in one, ...) expects. HMAC-SHA1 is not
// weakened by SHA-1's collision attacks — those break SHA-1's use as a
// general-purpose hash, not its use as an HMAC key-derivation/PRF
// primitive, which is what matters here. Using SHA-256 would silently
// break compatibility with most real authenticator apps for no security
// benefit.

import crypto from 'node:crypto'
import * as base32 from './base32.js'

const DEFAULT_STEP_SECONDS = 30
const DEFAULT_DIGITS = 6
const DEFAULT_SECRET_BYTES = 20 // 160 bits, RFC 4226's recommended HOTP secret length

function generateSecret (byteLength = DEFAULT_SECRET_BYTES) {
  return crypto.randomBytes(byteLength)
}

function hotp (secretBytes, counter, digits = DEFAULT_DIGITS) {
  const counterBuffer = Buffer.alloc(8)
  // Counter is a 64-bit big-endian integer; Node's DataView-free bigint
  // write keeps this correct for counters far beyond 2^32 (irrelevant in
  // practice at 30s steps, but cheap to do right).
  counterBuffer.writeBigUInt64BE(BigInt(counter))

  const hmac = crypto.createHmac('sha1', secretBytes).update(counterBuffer).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)

  const code = (binCode % 10 ** digits).toString().padStart(digits, '0')
  return code
}

function totpAt (secretBytes, timeMs, { step = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS } = {}) {
  const counter = Math.floor(timeMs / 1000 / step)
  return hotp(secretBytes, counter, digits)
}

/**
 * Verifies a user-entered code, tolerating clock drift by checking a
 * window of adjacent time steps. Returns the matched step offset (0 for
 * the current step, negative/positive for drift) or null if no step in
 * the window matched — callers should treat any non-null match as valid
 * and, if they resync stored drift, use the returned offset once and
 * reject a proof of the *same* code+step pair a second time to prevent
 * replay within its 30s validity window (see roles/README notes on
 * single-use enforcement).
 * @param {Uint8Array} secretBytes
 * @param {string} code
 * @param {object} [opts]
 * @param {number} [opts.windowSteps=1] how many steps before/after "now" to accept
 * @returns {{ matched: boolean, stepOffset: number|null }}
 */
function verifyTotp (secretBytes, code, { timeMs = Date.now(), step = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS, windowSteps = 1 } = {}) {
  const normalized = String(code).trim()
  if (!/^\d+$/.test(normalized) || normalized.length !== digits) {
    return { matched: false, stepOffset: null }
  }

  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    const candidate = totpAt(secretBytes, timeMs + offset * step * 1000, { step, digits })
    if (constantTimeStringEqual(candidate, normalized)) {
      return { matched: true, stepOffset: offset }
    }
  }
  return { matched: false, stepOffset: null }
}

function constantTimeStringEqual (a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/**
 * otpauth:// URI for QR-code enrollment. This package does not render a
 * QR code itself (that would mean bundling a QR-generation library and
 * breaking the zero-dependency goal) — feed this string to any pure-JS
 * QR renderer of your choice, or show it as a manual-entry fallback.
 */
function otpauthUri ({ secretBytes, issuer, accountName, digits = DEFAULT_DIGITS, step = DEFAULT_STEP_SECONDS }) {
  const label = encodeURIComponent(`${issuer}:${accountName}`)
  const params = new URLSearchParams({
    secret: base32.encode(secretBytes),
    issuer,
    algorithm: 'SHA1',
    digits: String(digits),
    period: String(step)
  })
  return `otpauth://totp/${label}?${params.toString()}`
}

export {
  DEFAULT_STEP_SECONDS,
  DEFAULT_DIGITS,
  DEFAULT_SECRET_BYTES,
  generateSecret,
  hotp,
  totpAt,
  verifyTotp,
  otpauthUri
}
