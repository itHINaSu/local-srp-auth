// Rate limiting contract. AuthServer calls consume() before doing
// expensive/attackable work (a login attempt, an MFA guess, ...) and
// treats a thrown RateLimitExceededError as "reject this request," not
// as an internal error — callers map it to HTTP 429 + Retry-After.
//
// Bucket keys are always built from values the caller already controls
// (a submitted username, an mfaToken's resolved uid, an optional
// caller-supplied client key) — never from anything that would leak
// whether an account exists, so this composes cleanly with the
// enumeration-resistance design in server-auth.js: the same username
// string is rate-limited identically whether or not it belongs to a
// real account.

class RateLimitExceededError extends Error {
  constructor (message, retryAfterMs) {
    super(message)
    this.name = 'RateLimitExceededError'
    this.retryAfterMs = retryAfterMs
  }
}

class RateLimiter {
  /**
   * @param {string} bucket a named category, e.g. 'login', 'mfa', 'register', 'bootstrap'
   * @param {string} key the specific thing being limited within that bucket (a username, uid, or client key)
   * @param {{ maxAttempts: number, windowMs: number }} rule
   * @returns {Promise<void>} resolves if under the limit (and records this attempt); throws RateLimitExceededError otherwise
   */
  async consume (bucket, key, rule) { throw new Error('RateLimiter.consume() is not implemented') }
}

export { RateLimiter, RateLimitExceededError }
