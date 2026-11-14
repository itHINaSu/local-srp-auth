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
| Brute-forcing login attempts / credential stuffing | Yes, baseline | Login, MFA verification, registration, bootstrap, and invite redemption are all rate-limited by default (`src/rate-limit/`) — keyed by username/uid out of the box (works with zero wiring, and can't be used to enumerate accounts — see below), with an optional additional per-client-key layer (an IP, typically) for callers that supply one. Defaults are conservative starting points (`DEFAULT_RATE_LIMITS` in `server-auth.js`), fully overridable via the `rateLimits` constructor option. The default `MemoryRateLimiter` is per-process — see "Multi-instance" below. |
| CSRF / session-token theft via XSS | Yes, if you use the shipped helpers | `src/session-transport.js` provides HttpOnly session cookies (JS can't read them, so XSS can't exfiltrate them directly) plus double-submit CSRF cookie/header verification. `AuthServer` itself still only deals in an opaque token string — these helpers are opt-in but ready to use, see `examples/node-http/server.js` for the full wiring. |
| Multi-instance / distributed deployment consistency | Partially | `JsonFileUserStore`/`JsonFileRoleStore` are safe for one process (atomic write + in-process write queue) but not for multiple instances writing the same file. `ChallengeStore`/`SessionStore`/`MemoryRateLimiter` default to in-memory (lost on restart, not shared across instances) — pass your own Redis-backed (or similar) implementation of those interfaces for a real multi-instance deployment. |
| Timing side channels | Best-effort | Recovery-code, TOTP-secret, CSRF-token, and SRP proof (M1/M2) comparisons all use `crypto.timingSafeEqual` or an equivalent constant-time byte comparison — see the comments in `srp-server.js`/`srp-client.js` and `session-transport.js`. Enumeration resistance (above) addresses the main username-existence timing channel. PBKDF2/modexp costs are inherently data-independent in Node's/the browser's implementations; this package does not add its own variable-time comparisons on secret material. |
| Attacker deliberately locking a real user out via rate limiting | **Partially — an inherent tradeoff, not a bug** | Because the login rate limit is keyed by the *submitted username string* (required for enumeration resistance, above), an attacker who knows a real username can exhaust that username's budget with wrong-password attempts, denying the real user login for the rest of the window. This is the standard tradeoff every username-keyed rate limiter makes; mitigations (CAPTCHA after N failures, a per-account "notify + allow" exception path, etc.) are application-UX decisions this package doesn't make for you. The per-client-key layer (when a caller supplies one) doesn't have this problem, since an attacker doesn't control the *victim's* IP — but it's optional. |
| Invite / reset token theft from storage | Yes | `InviteManager` stores only `sha256(token)` in the `InviteStore`; the raw 256-bit token exists server-side only in `issue()`'s return value and is never logged (audit events carry `inviteId`/`uid`/`purpose` only). A stolen database or JSON file cannot be replayed into an account takeover. |
| Invite / reset token guessing | Yes | 32 random bytes (256 bits), hash lookup with a constant-time comparison, and `preview`/`redeem` share an `invite` / `inviteClient` rate limit. Every attempt is audited (`invite.failed`). |
| Invite / reset token replay or races | Yes | Single use is enforced by a compare-and-set `InviteStore.markUsed()` before success is reported, so concurrent redeems have exactly one winner; tokens expire (7 days by default), can be revoked, and re-issuing revokes the earlier link for that account and purpose. |
| Invite failure / pending-user enumeration | Yes | Unknown, used, revoked, and expired tokens all return the same generic error from `preview`/`redeem`. A pending user (no credential yet) takes the same fake-credential path in `beginLogin()` as a nonexistent username, and can never complete a login. |
| Leaked reset link bypassing MFA | Yes, by default | A credential-reset link replaces the SRP credential but keeps TOTP unless the issuing admin explicitly set `clearTotp: true`. A reset also destroys the user's existing sessions via `SessionStore.deleteByUid` (a store without it triggers an `invite.sessions_not_revoked` audit event). Apps should deliver tokens in the URL fragment so they stay out of server logs and `Referer` headers; delivery itself is the application's job. |
| Audit log server compromise or tampering | Partially | Shipped log batches are plain newline-delimited JSON with no integrity signing — a compromised or malicious log server sees genuine plaintext audit data (see the log-shipping section below for what each transport does/doesn't encrypt) but can't feed anything back into `AuthServer`; log shipping is one-directional and `ShippingAuditLogger` never trusts a response from a shipper beyond "did `ship()` throw." Local logging (`localLogger`) is unaffected regardless of what happens on the wire. |

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

## Audit log shipping

`ShippingAuditLogger` (`src/audit/shipping-audit-logger.js`) queues
events and, on a timer, hands batches to one or more `LogShipper`
destinations. Local logging (via `localLogger`, `ConsoleAuditLogger` by
default) always happens synchronously with the auth flow regardless of
shipping outcome — an unreachable or slow log server delays shipping or
drops the oldest queued entries once `maxQueueSize` is hit (logged
locally when it happens), it never blocks or breaks logins. Three
shippers ship in the box:

- **TFTP** (`TftpLogShipper`) — pure Node `dgram`, RFC 1350, no
  dependency. TFTP has **no authentication and no encryption**; anyone
  who can reach the server on UDP/69 can write arbitrary files to it.
  That's inherent to the protocol, not this implementation — appropriate
  only for a trusted, isolated management network (this project's own
  domain, network/cell-site equipment provisioning, is a canonical
  example of where that's still normal practice), never the open
  internet.
- **FTP** (`FtpLogShipper`) — pure Node `net`, enough of RFC 959 to log
  in, go passive, and `STOR` one file per flush. No dependency, but also
  **no FTPS/TLS support** — credentials and data travel in the clear,
  same caveat as TFTP. If you need an encrypted transport, use SCP
  instead, or implement `LogShipper` yourself against a TLS-capable
  library.
- **SCP** (`ScpLogShipper`) — shells out to the system's `scp` binary via
  `execFile` (array arguments only, never a shell string — a batch's
  content or a crafted file name cannot be interpreted as a shell
  command; see `test/log-shippers.test.js` for a test that deliberately
  tries). This package does **not** implement SSH itself — doing so would
  mean hand-rolling exactly the kind of cryptographic transport protocol
  this document's "no hand-rolled cryptographic primitives" rule exists
  to prevent. Consequences worth knowing: `scp` must be installed and on
  `PATH`; auth must be key-based and passwordless (an SSH agent or an
  unencrypted identity file — there's no safe non-interactive way to
  hand `scp` a password); and the destination's host key must already be
  trusted (in the invoking user's `known_hosts`) unless you explicitly
  set `allowUnknownHostKey: true`, which disables host-key verification
  and accepts the real MITM risk that implies — off by default,
  deliberately not the path of least resistance.

## Known limitations (by design, not oversight)

- **`JsonFileUserStore`/`JsonFileRoleStore` are single-instance.** Fine
  for a small deployment; write a database-backed `UserStore`/`RoleStore`
  for anything that needs to scale horizontally.
- **Default `ChallengeStore`/`SessionStore`/`RateLimiter` are in-memory.**
  Server restarts drop in-flight logins, active sessions, and rate-limit
  counters; multiple instances behind a load balancer each enforce their
  own independent limits rather than a shared one. Pass your own
  implementation (Redis, a database, etc.) of the relevant interface if
  that's not acceptable for your deployment.
- **No account-lockout escape hatch beyond the rate-limit window
  expiring.** There's no admin "unlock this account now" API, no
  CAPTCHA-after-N-failures step-up, and no email-the-user-a-notice flow
  — see the "attacker deliberately locking a real user out" threat-table
  row above. These are UX/product decisions, not protocol gaps.
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
