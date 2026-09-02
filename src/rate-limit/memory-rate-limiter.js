// Fixed-window in-memory rate limiter — the same "fine for one process,
// not for a fleet" tradeoff as MemoryChallengeStore/MemorySessionStore.
// Multiple server instances behind a load balancer each enforce their
// own independent limit (an attacker distributed across instances gets
// roughly maxAttempts-per-instance, not a shared global cap) — implement
// RateLimiter against Redis or similar if that matters for your
// deployment.

import { RateLimiter, RateLimitExceededError } from './rate-limiter.js'

const SWEEP_EVERY_N_CALLS = 1000

class MemoryRateLimiter extends RateLimiter {
  constructor () {
    super()
    this._entries = new Map() // `${bucket}:${key}` -> { count, windowStart }
    this._callsSinceSweep = 0
  }

  async consume (bucket, key, { maxAttempts, windowMs }) {
    this._maybeSweep()

    const compositeKey = `${bucket}:${key}`
    const now = Date.now()
    const existing = this._entries.get(compositeKey)

    if (!existing || now - existing.windowStart >= windowMs) {
      this._entries.set(compositeKey, { count: 1, windowStart: now })
      return
    }

    if (existing.count >= maxAttempts) {
      const retryAfterMs = existing.windowStart + windowMs - now
      throw new RateLimitExceededError(
        `rate limit exceeded for ${bucket} (${maxAttempts} per ${windowMs}ms)`,
        retryAfterMs
      )
    }

    existing.count += 1
  }

  _maybeSweep () {
    this._callsSinceSweep += 1
    if (this._callsSinceSweep < SWEEP_EVERY_N_CALLS) return
    this._callsSinceSweep = 0

    const now = Date.now()
    for (const [key, entry] of this._entries) {
      // A generous upper bound: no rule's window should realistically
      // exceed a day, so anything older than that is safe to drop even
      // without knowing the specific rule that created it.
      if (now - entry.windowStart > 24 * 60 * 60 * 1000) this._entries.delete(key)
    }
  }
}

export { MemoryRateLimiter }
