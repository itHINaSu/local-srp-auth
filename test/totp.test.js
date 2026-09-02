import { test } from 'node:test'
import assert from 'node:assert/strict'
import nodeCrypto from 'node:crypto'

import * as totp from '../src/totp/totp.js'
import * as base32 from '../src/totp/base32.js'
import * as recoveryCodes from '../src/totp/recovery-codes.js'

test('base32 round trips arbitrary bytes', () => {
  for (const len of [0, 1, 5, 10, 16, 20, 33]) {
    const bytes = new Uint8Array(nodeCrypto.randomBytes(len))
    const encoded = base32.encode(bytes)
    const decoded = base32.decode(encoded)
    assert.deepEqual([...decoded], [...bytes], `round trip failed for length ${len}`)
  }
})

test('base32 output is uppercase A-Z2-7 only, no padding', () => {
  const encoded = base32.encode(new Uint8Array([1, 2, 3, 4, 5]))
  assert.match(encoded, /^[A-Z2-7]+$/)
})

test('a code generated for "now" verifies against itself', () => {
  const secret = totp.generateSecret()
  const code = totp.totpAt(secret, Date.now())
  const { matched, stepOffset } = totp.verifyTotp(secret, code)
  assert.equal(matched, true)
  assert.equal(stepOffset, 0)
})

test('a code from one step in the future verifies within the default window', () => {
  const secret = totp.generateSecret()
  const futureCode = totp.totpAt(secret, Date.now() + totp.DEFAULT_STEP_SECONDS * 1000)
  const { matched, stepOffset } = totp.verifyTotp(secret, futureCode)
  assert.equal(matched, true)
  assert.equal(stepOffset, 1)
})

test('a code far outside the drift window is rejected', () => {
  const secret = totp.generateSecret()
  const farFutureCode = totp.totpAt(secret, Date.now() + totp.DEFAULT_STEP_SECONDS * 1000 * 10)
  const { matched } = totp.verifyTotp(secret, farFutureCode)
  assert.equal(matched, false)
})

test('a code for a different secret is rejected', () => {
  const secretA = totp.generateSecret()
  const secretB = totp.generateSecret()
  const codeForA = totp.totpAt(secretA, Date.now())
  const { matched } = totp.verifyTotp(secretB, codeForA)
  assert.equal(matched, false)
})

test('malformed codes (wrong length, non-numeric) are rejected without throwing', () => {
  const secret = totp.generateSecret()
  assert.equal(totp.verifyTotp(secret, '12345').matched, false) // too short
  assert.equal(totp.verifyTotp(secret, '1234567').matched, false) // too long
  assert.equal(totp.verifyTotp(secret, 'abcdef').matched, false) // non-numeric
})

test('otpauthUri embeds a valid base32 secret and expected params', () => {
  const secret = totp.generateSecret()
  const uri = totp.otpauthUri({ secretBytes: secret, issuer: 'Acme', accountName: 'alice' })
  assert.match(uri, /^otpauth:\/\/totp\/Acme%3Aalice\?/)
  const params = new URL(uri).searchParams
  assert.equal(params.get('issuer'), 'Acme')
  assert.equal(params.get('algorithm'), 'SHA1')
  assert.equal(params.get('digits'), '6')
  assert.deepEqual([...base32.decode(params.get('secret'))], [...secret])
})

test('recovery codes: generated codes verify once and are then gone', () => {
  const codes = recoveryCodes.generateRecoveryCodes(5)
  assert.equal(codes.length, 5)
  const hashes = codes.map((c) => recoveryCodes.hashRecoveryCode(c))

  const idx = recoveryCodes.verifyRecoveryCode(hashes, codes[2])
  assert.equal(idx, 2)

  // Simulate the caller removing the used code (AuthServer does this).
  const remaining = hashes.slice()
  remaining.splice(idx, 1)

  assert.equal(recoveryCodes.verifyRecoveryCode(remaining, codes[2]), -1) // used code no longer valid
  assert.notEqual(recoveryCodes.verifyRecoveryCode(remaining, codes[0]), -1) // others still are
})

test('recovery code verification is case- and dash-insensitive', () => {
  const codes = recoveryCodes.generateRecoveryCodes(1)
  const hashes = codes.map((c) => recoveryCodes.hashRecoveryCode(c))
  const messy = codes[0].toLowerCase().replace(/-/g, ' ')
  assert.notEqual(recoveryCodes.verifyRecoveryCode(hashes, messy), -1)
})

test('an unrelated string never matches a real recovery code', () => {
  const codes = recoveryCodes.generateRecoveryCodes(3)
  const hashes = codes.map((c) => recoveryCodes.hashRecoveryCode(c))
  assert.equal(recoveryCodes.verifyRecoveryCode(hashes, 'AAAAA-AAAAA'), -1)
})
