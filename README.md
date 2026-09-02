# local-srp-auth

Zero-runtime-dependency authentication: SRP-6a password login (the
password itself, and every fixed hash of it, never crosses the network
in any form), TOTP MFA with recovery codes, pluggable storage, and
usernames/roles that can be renamed without touching a user's login
credential.

Built to be dropped into more than one project without rebuilding
authentication from scratch each time — see "Integrating into a new
project" below.

## Why SRP-6a instead of "hash it and send it"

The common "client-side hashing" pattern — browser computes
`sha256(password)` or `Argon2(password)`, sends *that* to the server
instead of the raw password — still sends a fixed, replayable bearer
credential over the wire. Anyone who captures that hash once can replay
it forever; it's really just a password with extra steps, and its
security still ultimately rests on TLS.

SRP-6a (RFC 5054), a Password-Authenticated Key Exchange (PAKE)
protocol, doesn't have that problem. The client never sends the
password, nor any single fixed derivative of it — only one-time
ephemeral public values (`A`, `M1`) that are cryptographically useless
for authenticating a second time, and from which an eavesdropper cannot
recover the password or the verifier. This holds independent of
transport security — it doesn't depend on TLS to be true, though you
should still run everything over TLS regardless.

See `SECURITY.md` for the full protocol and threat-model writeup.

## What's in the box

- **SRP-6a** login (`src/srp/`) — 3072-bit RFC 5054 group by default
  (2048/4096 also shipped), PBKDF2-HMAC-SHA256 password stretching
  (600,000 iterations, OWASP 2023's minimum), SHA-256 throughout.
- **TOTP MFA** (`src/totp/`) — RFC 6238, HMAC-SHA1 (see `SECURITY.md`
  for why SHA-1 here is correct, not a downgrade), with base32
  otpauth:// URIs for QR enrollment and single-use recovery codes.
- **Roles** (`src/roles/`) — four seed roles (Admin, Privilege 1,
  Privilege 2, Read Only), fully renameable, permissions freely
  editable, referenced everywhere by a stable `id` so a rename never
  breaks anything.
- **Pluggable storage** (`src/storage/`) — `UserStore` / `RoleStore` /
  `ChallengeStore` / `SessionStore` interfaces; in-memory and JSON-file
  reference implementations ship in the box, write your own for a real
  database.
- **First-run bootstrap** (`src/bootstrap.js`) — if no user exists yet,
  a one-time setup token gates creating the first (admin) account.
- **Rate limiting** (`src/rate-limit/`) — every credential-guessing entry
  point (login, MFA verification, registration, bootstrap) is
  rate-limited by default, keyed by username/uid (works with zero
  wiring) with an optional extra layer keyed by a caller-supplied client
  key (an IP, typically) for callers that want it.
- **Session transport** (`src/session-transport.js`) — ready-to-use
  HttpOnly cookie + double-submit CSRF helpers for plain `node:http` (or
  anything with a similar req/res shape). `AuthServer` itself still only
  deals in opaque session-token strings, so this stays optional.
- **Audit logging** (`src/audit/`) — every security-relevant event
  (registration, login success/failure, MFA enroll/verify/disable,
  recovery-code use, session destroy, bootstrap, rate-limit trips) is
  logged, with secrets (passwords, verifiers, TOTP secrets, raw
  tokens/codes) never included — see `SECURITY.md`. Optionally ships
  batches to a remote log server over TFTP, FTP, or SCP
  (`src/audit/shippers/`).
- **Zero runtime dependencies.** Every crypto primitive is a browser
  (`crypto.subtle`) or Node (`node:crypto`) built-in — nothing here is a
  hand-rolled cipher or hash implementation.
- **Native ESM**, no build step. `import` it in Node, or load
  `src/client/index.js` directly as `<script type="module">` in a
  browser — no bundler required (see the caveat about `file://` below).

## Quick start

```bash
node examples/node-http/server.js
```

Prints a one-time setup token, then serves a working demo (plain
`node:http`, no framework) at `http://localhost:8787` — register,
log in, enable MFA, log in with MFA, all through the actual browser
`crypto.subtle` path. Read `examples/node-http/server.js` and
`examples/node-http/public/index.html` as the reference integration.

## Server-side usage

```js
import { AuthServer, Bootstrap, storage } from 'local-srp-auth'

const server = new AuthServer({
  userStore: new storage.JsonFileUserStore('./data/users.json'),
  roleStore: new storage.JsonFileRoleStore('./data/roles.json')
})
await server.ensureDefaultRoles()

const bootstrap = new Bootstrap(server)
if (await bootstrap.needsBootstrap()) {
  const token = await bootstrap.generateSetupToken()
  console.log('Setup token:', token) // surface this however your deployment expects
}

// Wire these into your own HTTP framework's routes. `clientKey` (e.g.
// the request's IP) is optional everywhere it's accepted — omitting it
// still rate-limits by username/uid, it just skips the extra per-source layer.
server.registerUser({ username, salt, verifier, iterations, group, clientKey })
server.beginLogin({ username, clientPublicEphemeral, clientKey })
server.completeLogin({ challengeId, clientProof })
server.verifyMfaTotp({ mfaToken, code, clientKey })
server.beginTotpEnrollment(uid)
server.confirmTotpEnrollment({ pendingToken, code, clientKey })
server.getSession(sessionToken)
server.destroySession(sessionToken)

// Account self-service — see "Changing username/password" below.
server.changeUsername({ uid, newUsername, clientKey })
server.beginPasswordChange({ uid, clientPublicEphemeral, clientKey })
server.completePasswordChange({ uid, challengeId, clientProof, newSalt, newVerifier, mfaCode, keepSessionToken, clientKey })
server.requestPasswordReset({ username, clientKey })   // no-op unless passwordResetEnabled
server.completePasswordReset({ token, newSalt, newVerifier, mfaCode, clientKey })

// Admin-facing — the caller is responsible for checking the requester is
// actually an admin (e.g. via userHasPermission()) before calling these;
// AuthServer itself doesn't know what "admin" means to your app.
server.listUsers()
server.setUserRoles({ uid, roleIds, clientKey })
```

`AuthServer` never sees a password — only what the browser already
reduced it to (a salt and a verifier at registration; ephemeral protocol
values at login). It also never touches HTTP directly: wire its methods
into whatever router/framework your app already uses.

## Browser-side usage

```js
import { SrpRegistration, SrpLoginAttempt, defaultWebCryptoAdapter } from 'local-srp-auth/client'

const adapter = defaultWebCryptoAdapter()

// Registration
const { salt, verifier, iterations, group } = await SrpRegistration.create({ password, adapter })
await fetch('/api/register', { method: 'POST', body: JSON.stringify({ username, salt, verifier, iterations, group }) })

// Login (two round trips)
const client = new SrpLoginAttempt({ adapter })
const { A } = client.start()
const { challengeId, salt: s, B, uid } = await postJson('/api/login/begin', { username, clientPublicEphemeral: A })
const { M1 } = await client.finish({ password, salt: s, serverPublicEphemeral: B, uid })
const { M2, sessionToken } = await postJson('/api/login/complete', { challengeId, clientProof: M1 })
await client.verifyServerProof(M2) // throws if the server can't prove it knows the session key too
```

## Changing username/password

Renaming is a one-call round trip (`server.changeUsername()` — see
"Server-side usage" above); nothing changes on the browser side since the
credential itself isn't touched.

Changing the password re-uses the exact same client classes as login and
registration — `SrpLoginAttempt` to prove the *current* password (so it
never has to cross the network, not even to authorize replacing itself),
then `SrpRegistration.create()` to compute the new (salt, verifier) pair:

```js
// Step 1: prove you know the current password (same shape as login)
const client = new SrpLoginAttempt({ adapter })
const { A } = client.start()
const begin = await postJson('/api/account/password/begin', { clientPublicEphemeral: A })
const { M1 } = await client.finish({ password: currentPassword, salt: begin.salt, serverPublicEphemeral: begin.B, uid: begin.uid })

// Step 2: compute the new credential and send both in one call
const { salt, verifier, iterations, group } = await SrpRegistration.create({ password: newPassword, adapter })
const { M2 } = await postJson('/api/account/password/complete', {
  challengeId: begin.challengeId, clientProof: M1,
  newSalt: salt, newVerifier: verifier, newIterations: iterations, newGroup: group,
  mfaCode // only required if this account has MFA enabled — see below
})
await client.verifyServerProof(M2)
```

If the account has MFA enabled, `completePasswordChange()` (and
`completePasswordReset()`, below) both require a valid `mfaCode` or
`recoveryCode` in addition to the SRP proof — a hijacked-but-not-MFA'd
session, or a compromised inbox in the reset case, shouldn't be able to
silently strip MFA off an account just by changing its password. On
success, every *other* session the account holds is invalidated (pass
`keepSessionToken` — the session the request itself arrived on — so the
browser making the change isn't logged out by its own success).

**Password reset (email-based) is off by default** —
`requestPasswordReset()`/`completePasswordReset()` exist and are fully
functional, but `requestPasswordReset()` is a safe no-op (same
enumeration-safe `{ requested: true }` response either way) unless the
`AuthServer` was constructed with `passwordResetEnabled: true` and a
`passwordResetSender` callback that actually delivers the reset
link/token somewhere (email, typically). Until a deployment wires up its
own email client, there's simply nowhere for the token to go — the
mechanics (single-use, time-limited tokens; MFA-gated completion) are
ready for whenever one exists:

```js
const server = new AuthServer({
  userStore, roleStore,
  passwordResetEnabled: true,
  passwordResetSender: async ({ user, token, expiresAt }) => {
    await yourEmailClient.send(user /* public fields only — no secrets */, `https://your-app/reset?token=${token}`)
  }
})
```

`password` is a local variable that never leaves this scope in any form
— everything sent over the network from this snippet is a one-time
protocol value.

## Integrating into a new project

1. `npm install` this package (or vendor the `src/` directory directly
   — it has no dependencies to manage either way, so vendoring costs you
   nothing but a `git subtree`/copy step).
2. Implement `UserStore`/`RoleStore` for your project's real storage if
   the JSON-file reference implementation isn't enough (see
   `src/storage/storage-interface.js` for the contract).
3. Wire `AuthServer`'s methods into your HTTP framework's routes — see
   `examples/node-http/server.js` for the full route list.
4. Load `local-srp-auth/client` in your frontend — as a bundled import
   if you already have a bundler, or as a direct `<script type="module">`
   if (like this package's own example, and like the
   CellSiteConfigGenerator project this package was built to eventually
   serve) you don't want a build step. Native ESM relative imports
   require an HTTP(S) origin — they will not resolve from a bare
   `file://` URL, the same constraint CellSiteConfigGenerator's own
   README documents for its playbook loading mechanism.
5. Wire up `src/session-transport.js`'s cookie helpers (see
   `examples/node-http/server.js` for the full pattern: set the session
   + CSRF cookies on login success, check the CSRF header on
   state-changing authenticated routes, clear on logout). If your
   deployment has no TLS, pass `secure: false` — see that file's module
   comment for what that tradeoff means; leaving the default `true` on a
   non-TLS deployment means the browser will silently refuse to store
   the cookie at all, not just send it insecurely.
6. If you want a remote audit trail, wrap your logger with
   `ShippingAuditLogger` and pass it one or more shippers (see "Audit log
   shipping" below). Optional — the default `ConsoleAuditLogger` needs no
   configuration.

## Testing

```bash
npm test
```

Runs on Node's built-in test runner (`node:test`) — no test-framework
dependency either. Covers SRP protocol correctness (including rejection
of wrong passwords, tampered proofs, spoofed server proofs, and
identity-binding attacks), TOTP/base32/recovery-code correctness against
drift and malformed input, every storage backend against a shared
behavioral contract, and a full `AuthServer` end-to-end suite (bootstrap,
register, login, MFA enroll/verify, recovery codes, roles, sessions).

The SRP group constants themselves were not retyped from memory: they
were fetched from two independent, unrelated open-source packages (one
citing RFC 5054 directly, the other RFC 3526) and cross-checked
byte-for-byte programmatically before being committed — see the comment
at the top of `src/common/groups.js`.

## Audit log shipping

`ShippingAuditLogger` wraps a local logger (`ConsoleAuditLogger` by
default) and, on a timer, batches queued events out to one or more
`LogShipper` destinations:

```js
import { AuthServer, audit } from 'local-srp-auth'

const logger = new audit.ShippingAuditLogger({
  shippers: [
    new audit.TftpLogShipper({ host: '10.0.0.5' }),        // pure Node dgram, no dependency
    // new audit.FtpLogShipper({ host: '...', user: '...', password: '...', remoteDir: '/logs' }),
    // new audit.ScpLogShipper({ host: '...', user: '...', remoteDir: '/logs', identityFile: '~/.ssh/id_ed25519' }),
  ]
})
logger.start() // begins the periodic flush; no-op if shippers is empty

const server = new AuthServer({ userStore, roleStore, logger })
```

Local logging always happens synchronously with the auth flow; shipping
never does — a slow or unreachable log server delays shipping or drops
the oldest queued entries once a bound is hit, it never blocks or breaks
logins. See `SECURITY.md`'s "Audit log shipping" section for what each
transport does and doesn't protect (TFTP and plain FTP are unencrypted
and unauthenticated by protocol design — appropriate for a trusted
management network, not the open internet; SCP shells out to the
system's `ssh`/`scp` binaries rather than reimplementing SSH, and
requires key-based, passwordless auth already configured on the host).

## What this package deliberately does not do

See `SECURITY.md` for the full list, but briefly: account lockout
beyond rate limiting (a human-in-the-loop unlock flow is
application-specific), and the JSON-file storage backend is
single-instance only (no distributed locking — write your own
`UserStore`/`RoleStore` against a real database for a multi-instance
deployment). Neither is a protocol weakness — they're deployment
concerns this package leaves to the integrator rather than guessing
wrong about your infrastructure.

## License

MIT
