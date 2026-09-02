// Node-side CryptoAdapter (see crypto-adapter-web.js for the browser
// counterpart). Split into two files, rather than one file that branches
// at runtime, because a static `import 'node:crypto'` at the top of a
// file is an unresolvable specifier in a browser loading this package
// directly via <script type="module"> with no bundler — it would hard
// fail the whole module graph even if the Node branch were never taken.
//
// @typedef {object} CryptoAdapter
// @property {(bytes: Uint8Array) => Promise<Uint8Array>} sha256
// @property {(password: Uint8Array, salt: Uint8Array, iterations: number, lengthBytes: number) => Promise<Uint8Array>} pbkdf2Sha256
// @property {(byteLength: number) => Uint8Array} randomBytes

import crypto from 'node:crypto'

/** @returns {CryptoAdapter} */
export function createNodeCryptoAdapter () {
  return {
    async sha256 (bytes) {
      return new Uint8Array(crypto.createHash('sha256').update(bytes).digest())
    },
    async pbkdf2Sha256 (password, salt, iterations, lengthBytes) {
      return new Promise((resolve, reject) => {
        crypto.pbkdf2(Buffer.from(password), Buffer.from(salt), iterations, lengthBytes, 'sha256', (err, derived) => {
          if (err) reject(err)
          else resolve(new Uint8Array(derived))
        })
      })
    },
    randomBytes (byteLength) {
      return new Uint8Array(crypto.randomBytes(byteLength))
    }
  }
}
