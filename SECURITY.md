# Security model

This document exists to be read alongside an internal software
attestation review, not just as marketing copy — it says what this
package actually protects against, what it deliberately leaves to the
integrator, and where the cryptographic choices came from.

## Threat model

| Threat | Protected? | How |
|---|---|---|
| Passive network eavesdropper reads the password | Yes | SRP-6a never transmits the password or any fixed hash of it — only one-time ephemeral values (`A`, `M1`) that don't reveal the password or the verifier. |
| Server database is stolen (verifier leak) | Partially | An attacker gets `(salt, verifier)`, not the password. Recovering the password requires an offline PBKDF2-HMAC-SHA256 search (600,000 iterations by default) per guess — the same class of protection bcrypt/Argon2 give a conventional password hash, applied to SRP's `x`. |
| Active MITM impersonates the server | Yes | The client's `verifyServerProof()` step (M2) fails closed if the party on the other end can't prove it derived the same session key `K`, which requires knowing the real verifier. |
| Replay of a captured login exchange | Yes | `A`/`B` are single-use ephemeral values (fresh random each attempt); the server deletes a challenge after one use (success or failure) via `ChallengeStore`. |
| Renaming a user or a role breaks their credential/permissions | Yes | Usernames and role names are display-only; every crypto and permission check keys off a stable `id` that renaming never touches (tested explicitly — see `test/e2e.test.js` and `test/roles.test.js`). |
| Username enumeration via login attempts | Yes | `beginLogin()` returns a deterministic, indistinguishable-in-shape fake `(uid, salt, verifier)` for a nonexistent username (HMAC-derived from a per-process secret), so response shape and cost are the same either way. |
| Client trusting a forged TOTP/recovery bypass | Yes | MFA verification happens entirely server-side against the stored secret/hashes; the client never sees or influences the comparison. |
| Brute-forcing login attempts / credential stuffing | **No** — integrator's responsibility | This package does not rate-limit or lock out repeated attempts. Add this at your reverse proxy, framework middleware, or `ChallengeStore`/`SessionStore` layer — the right limits are deployment-specific (traffic patterns, existing WAF, etc.), and a wrong guess here would be worse than no guess. |
| CSRF / session-token theft via XSS | **No** — integrator's responsibility | This package issues an opaque session token string and validates it via `getSession()`. It does not choose cookie vs. header transport, `httpOnly`/`SameSite` flags, or CSRF tokens — those are framework- and deployment-specific decisions. |
| Multi-instance / distributed deployment consistency | Partially | `JsonFileUserStore`/`JsonFileRoleStore` are safe for one process (atomic write + in-process write queue) but not for multiple instances writing the same file. `ChallengeStore`/`SessionStore` default to in-memory (lost on restart, not shared across instances) — pass your own Redis-backed (or similar) implementation of those interfaces for a real multi-instance deployment. |
| Timing side channels | Best-effort | Recovery-code and TOTP-secret comparisons use `crypto.timingSafeEqual`. Enumeration resistance (above) addresses the main username-existence timing channel. PBKDF2/modexp costs are inherently data-independent in Node's/the browser's implementations; this package does not add its own variable-time comparisons on secret material. |

## Cryptographic choices, and why

- **SRP-6a, RFC 5054, 3072-bit group by default.** Provides
  password-authenticated key exchange without ever transmitting the
  password or a fixed derivative of it. The group constants (`N`, `g`)
  were not retyped from memory or a single source: they were
  cross-verified byte-for-byte, programmatically, against two
  independent, unrelated open-source packages (`jsrp`, which cites RFC
  5054 directly, and `diffie-hellman`, for the RFC 3526 groups RFC 5054
  reuses for its larger sizes) before being committed — see
  `src/common/groups.js`. 2048-bit and 4096-bit groups also ship for
  environments with different performance/margin needs.
- **PBKDF2-HMAC-SHA256, 600,000 iterations**, to derive `x` (the SRP
  private key) from `(salt, password)`. This is OWASP's 2023 minimum
  recommendation for PBKDF2-HMAC-SHA256. The iteration count is stored
  per-user alongside the verifier, so it can be raised for new
  registrations without invalidating existing accounts (the same
  pattern bcrypt's embedded cost factor uses).
- **x and M1/M2 bind to a stable user `id`, never to the username.**
  This is a deliberate departure from a textbook RFC 5054
  implementation (which mixes the username into `x`) — see the header
  comment in `src/srp/srp-core.js`. It's what makes username renaming
  safe.
- **SHA-256** everywhere except TOTP.
- **HMAC-SHA1 for TOTP** (RFC 6238), deliberately, despite SHA-256 being
  used everywhere else in this package. SHA-1's known weakness is
  collision resistance in its use as a general-purpose hash; that
  attack does not apply to HMAC-SHA1 as a keyed PRF, which is all TOTP
  uses it for. Virtually every real authenticator app (Google
  Authenticator, Authy, 1Password, Apple's built-in one, ...) expects
  SHA-1; using SHA-256 here would silently break compatibility with
  most real MFA devices for no security benefit.
- **Recovery codes are hashed with plain SHA-256, not PBKDF2.** OWASP's
  stretching guidance targets low-entropy, human-chosen secrets against
  offline guessing. Recovery codes are 80-bit, server-generated random
  tokens — stretching would only slow down legitimate verification, not
  an attacker who'd still have to search the same 80-bit space either
  way.
- **No hand-rolled cryptographic primitives, anywhere.** Every hash,
  HMAC, PBKDF2, and random-byte generation call in this package is
  either a Node built-in (`node:crypto`) or a browser built-in
  (`crypto.subtle` / `crypto.getRandomValues`) — see
  `src/common/crypto-adapter-node.js` and
  `src/common/crypto-adapter-web.js`. The only "custom" math in this
  package is the SRP-6a modular-exponentiation protocol logic itself
  (built on JavaScript's native `BigInt`) and RFC 6238's HOTP counter
  arithmetic — both public, specified algorithms, not invented ciphers.
- **Zero runtime dependencies.** There is no third-party package in the
  supply chain to audit, pin, or worry about going malicious in an
  update — everything this package does, it does with what Node and the
  browser already ship.

## Known limitations (by design, not oversight)

- **No rate limiting or account lockout.** See the threat table above —
  this is intentionally left to the deployment layer.
- **No session-transport opinion.** This package returns an opaque
  session token string; how it travels (cookie, header, storage) and
  what CSRF protection wraps it is the integrator's decision.
- **No audit logging.** Login attempts, MFA events, and admin actions
  are not logged by this package. Add logging at the call sites in your
  own route handlers if you need it.
- **`JsonFileUserStore`/`JsonFileRoleStore` are single-instance.** Fine
  for a small deployment; write a database-backed `UserStore`/`RoleStore`
  for anything that needs to scale horizontally.
- **Default `ChallengeStore`/`SessionStore` are in-memory.** Server
  restarts drop in-flight logins and active sessions. Pass your own
  implementation (Redis, a database, etc.) if that's not acceptable for
  your deployment.
- **TOTP secrets are stored in plaintext hex** in whatever `UserStore`
  backend you use (same trust boundary as the verifier — if your
  database is compromised, TOTP secrets are readable). Encrypting
  secrets-at-rest, if your deployment requires it, is a `UserStore`
  concern (encrypt/decrypt in your storage implementation), not
  something this package does on your behalf, since it would require
  this package to also manage an encryption key, which is exactly the
  kind of deployment-specific decision this document keeps deferring to
  the integrator.

## Reporting a concern

This is an internal package without a public disclosure process. Report
concerns directly to whoever maintains the deployment you found the
issue in.
