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

// Wire these into your own HTTP framework's routes:
server.registerUser({ username, salt, verifier, iterations, group })
server.beginLogin({ username, clientPublicEphemeral })
server.completeLogin({ challengeId, clientProof })
server.verifyMfaTotp({ mfaToken, code })
server.beginTotpEnrollment(uid)
server.confirmTotpEnrollment({ pendingToken, code })
server.getSession(sessionToken)
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
5. Design your own session-token transport (cookie vs. `Authorization`
   header, CSRF handling, etc.) — this package issues an opaque session
   token and validates it via `getSession()`, but deliberately does not
   prescribe how it travels between browser and server; that's a
   framework-specific decision this package shouldn't make for you.

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

## What this package deliberately does not do

See `SECURITY.md` for the full list, but briefly: no rate limiting or
account lockout (add this at your reverse proxy or framework layer — it
is inherently deployment-specific), no CSRF protection or session
transport (you choose cookies vs. headers), no audit logging, and the
JSON-file storage backend is single-instance only (no distributed
locking). None of these are protocol weaknesses — they're deployment
concerns this package leaves to the integrator rather than guessing
wrong about your infrastructure.

## License

MIT
