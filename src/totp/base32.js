// RFC 4648 base32 (unpadded), the encoding every TOTP authenticator app
// expects for the shared secret in an otpauth:// URI / manual-entry key.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function encode (bytes) {
  let bits = 0
  let value = 0
  let output = ''

  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31]
  }

  return output
}

function decode (base32String) {
  const clean = base32String.toUpperCase().replace(/[^A-Z2-7]/g, '')
  let bits = 0
  let value = 0
  const output = []

  for (const char of clean) {
    const idx = ALPHABET.indexOf(char)
    if (idx === -1) throw new Error(`invalid base32 character: ${char}`)
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }

  return new Uint8Array(output)
}

export { encode, decode }
