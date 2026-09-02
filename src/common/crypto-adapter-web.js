// Browser-side CryptoAdapter (see crypto-adapter-node.js for the Node
// counterpart, and its header comment for why these are two files).
//
// @typedef {object} CryptoAdapter
// @property {(bytes: Uint8Array) => Promise<Uint8Array>} sha256
// @property {(password: Uint8Array, salt: Uint8Array, iterations: number, lengthBytes: number) => Promise<Uint8Array>} pbkdf2Sha256
// @property {(byteLength: number) => Uint8Array} randomBytes

/** @returns {CryptoAdapter} */
export function createWebCryptoAdapter (subtleCrypto, getRandomValuesFn) {
  return {
    async sha256 (bytes) {
      const digest = await subtleCrypto.digest('SHA-256', bytes)
      return new Uint8Array(digest)
    },
    async pbkdf2Sha256 (password, salt, iterations, lengthBytes) {
      const key = await subtleCrypto.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
      const derived = await subtleCrypto.deriveBits(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        key,
        lengthBytes * 8
      )
      return new Uint8Array(derived)
    },
    randomBytes (byteLength) {
      const out = new Uint8Array(byteLength)
      getRandomValuesFn(out)
      return out
    }
  }
}

/**
 * Convenience wrapper around the global `crypto.subtle` / `crypto.getRandomValues`
 * available in every modern browser (and in Node via `globalThis.crypto`,
 * which Node also provides — see the note in README about Node usage of
 * this entry point being possible but not the primary target).
 * @returns {CryptoAdapter}
 */
export function defaultWebCryptoAdapter () {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('window.crypto.subtle is not available in this environment')
  }
  return createWebCryptoAdapter(crypto.subtle, crypto.getRandomValues.bind(crypto))
}
