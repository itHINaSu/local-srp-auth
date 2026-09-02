// BigInt <-> bytes/hex helpers and modular arithmetic shared by client and
// server SRP code. Pure math, no I/O, works identically in Node and the
// browser (BigInt is a JS-language primitive, not a platform API).

function hexToBigInt (hex) {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`
  return BigInt(`0x${clean}`)
}

function bigIntToHex (n, byteLength) {
  let hex = n.toString(16)
  if (hex.length % 2 !== 0) hex = `0${hex}`
  const targetLen = byteLength ? byteLength * 2 : hex.length
  if (hex.length > targetLen) {
    throw new RangeError(`value does not fit in ${byteLength} bytes`)
  }
  return hex.padStart(targetLen, '0')
}

function bigIntToBytes (n, byteLength) {
  return hexToBytes(bigIntToHex(n, byteLength))
}

function bytesToBigInt (bytes) {
  return hexToBigInt(bytesToHex(bytes))
}

function hexToBytes (hex) {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16)
  }
  return out
}

function bytesToHex (bytes) {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

function concatBytes (...chunks) {
  const total = chunks.reduce((sum, c) => sum + c.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) {
    out.set(c, offset)
    offset += c.length
  }
  return out
}

// Left-pads `bytes` to `byteLength` with zero bytes, as required by SRP's
// PAD() before hashing values into u, k, and the M1/M2 proofs (RFC 5054
// section 2.5.3 / 2.6). A value already at or over the target length is
// returned unchanged (over-length only happens if the protocol produced a
// value >= N, which callers reject separately).
function padBytes (bytes, byteLength) {
  if (bytes.length >= byteLength) return bytes
  const out = new Uint8Array(byteLength)
  out.set(bytes, byteLength - bytes.length)
  return out
}

function modPow (base, exponent, modulus) {
  if (modulus === 1n) return 0n
  let result = 1n
  let b = base % modulus
  let e = exponent
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus
    e >>= 1n
    b = (b * b) % modulus
  }
  return result
}

function mod (a, m) {
  const r = a % m
  return r >= 0n ? r : r + m
}

function randomBigInt (byteLength, randomBytesFn) {
  const bytes = randomBytesFn(byteLength)
  return bytesToBigInt(bytes)
}

function constantTimeEqualBytes (a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export {
  hexToBigInt,
  bigIntToHex,
  bigIntToBytes,
  bytesToBigInt,
  hexToBytes,
  bytesToHex,
  concatBytes,
  padBytes,
  modPow,
  mod,
  randomBigInt,
  constantTimeEqualBytes
}
