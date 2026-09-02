// TOTP recovery codes: single-use bypass codes issued once at MFA
// enrollment, for when the user loses their authenticator device.
//
// Unlike the password, these are high-entropy, server-generated,
// random tokens (not user-chosen secrets), so a fast general-purpose
// hash is appropriate — OWASP's password-storage stretching guidance is
// specifically about defending low-entropy, human-chosen secrets against
// offline guessing. Stretching a 100-bit random token with PBKDF2 would
// only slow down legitimate verification, not attackers (who'd still
// have to search the same 100-bit space).

import crypto from 'node:crypto'
import { encode as base32Encode } from './base32.js'

const DEFAULT_CODE_COUNT = 10
const CODE_BYTES = 10 // 80 bits per code

function generateRecoveryCodes (count = DEFAULT_CODE_COUNT) {
  const codes = []
  for (let i = 0; i < count; i++) {
    codes.push(formatCode(crypto.randomBytes(CODE_BYTES)))
  }
  return codes
}

function formatCode (bytes) {
  const encoded = base32Encode(bytes) // no padding, uppercase A-Z2-7
  // Group as XXXXX-XXXXX-... for readability; length depends on CODE_BYTES.
  return encoded.match(/.{1,5}/g).join('-')
}

function hashRecoveryCode (code) {
  const normalized = normalizeCode(code)
  return crypto.createHash('sha256').update(normalized).digest('hex')
}

function normalizeCode (code) {
  return String(code).toUpperCase().replace(/[^A-Z2-7]/g, '')
}

/**
 * @param {string[]} storedHashes hex sha256 hashes, as produced by hashRecoveryCode
 * @param {string} candidateCode user-entered code
 * @returns {number} index of the matched hash in storedHashes, or -1 if none matched.
 *   Callers MUST remove the matched entry from storage (single use).
 */
function verifyRecoveryCode (storedHashes, candidateCode) {
  const candidateHash = hashRecoveryCode(candidateCode)
  const candidateHashBuf = Buffer.from(candidateHash, 'hex')
  for (let i = 0; i < storedHashes.length; i++) {
    const storedBuf = Buffer.from(storedHashes[i], 'hex')
    if (storedBuf.length === candidateHashBuf.length && crypto.timingSafeEqual(storedBuf, candidateHashBuf)) {
      return i
    }
  }
  return -1
}

export {
  DEFAULT_CODE_COUNT,
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyRecoveryCode
}
