# Design: invite & credential-reset tokens ("magic links")

**Status:** implemented (`src/invites.js`, see the test suite in
`test/invites.test.js`). This document remains the design reference;
`README.md` and `SECURITY.md` carry the user-facing documentation.

## Motivation

`Bootstrap` already proves the pattern this package needs more generally: a
random token gates one registration, the password still never leaves the
browser (SRP registration as usual), the token burns on use. But bootstrap is
first-run-only. Downstream projects (Family Listmas is the first) need the
steady-state version:

- An **admin invites a user**: the app hands the invitee a magic link; opening
  it lets them choose a password and activate a pre-created account.
- An **admin resets a credential**: same mechanism against an existing account
  (no email infrastructure ⇒ no self-service reset; the admin is the recovery
  path).

Both are generic enough to belong in this package rather than being rebuilt
per project. Design goals match the package's existing rules: zero
dependencies, storage behind an interface, every guessing surface rate-limited
and audited, no secret ever stored or logged in recoverable form.

## Concepts

### Pending users

A **pending user** is a `UserRecord` whose credential fields are not yet set:
`salt`, `verifier`, `iterations`, `group` are all `null`. It exists so the
application can reference a stable `uid` (relationships, ownership, role
assignment) *before* the person has ever logged in — consistent with this
package's stable-id philosophy.

- New `AuthServer` method:
  `createPendingUser({ username, roleIds = [], clientKey })` → `UserRecord`.
  Validates username uniqueness exactly like `registerUser`, shares its rate
  limit bucket (`register`), and audits as `user.pending_created`.
- `beginLogin()` for a pending user MUST take the existing
  nonexistent-username path (deterministic fake `(uid, salt, B)`), so a
  pending account is indistinguishable from no account to an outside prober.
- `countUsers()` continues to count all users (pending included); bootstrap
  semantics are unaffected because pending users can only be created *after*
  bootstrap by definition (an authenticated admin creates them — enforcing
  *who* may call `createPendingUser` is the application's job, as with every
  other `AuthServer` method).

### Invite records

```
InviteRecord {
  id:         string          // 'invite-' + randomUUID, stable
  tokenHash:  string          // hex sha256 of the raw token; raw token is NEVER stored
  uid:        string          // the user this invite is bound to
  purpose:    'activate' | 'credential-reset'
  createdBy:  string|null     // acting admin's uid, for the audit trail
  createdAt:  string          // ISO
  expiresAt:  string          // ISO
  usedAt:     string|null
  revokedAt:  string|null
}
```

Raw tokens are 32 random bytes (`crypto.randomBytes`), base64url-encoded.
Lookup is by `sha256(token)` — the store never sees the raw token, so a stolen
database/JSON file cannot be replayed into an account takeover.

## New module: `src/invites.js`

```js
class InviteManager {
  constructor (authServer, { inviteStore, defaultTtlMs = 7 * 24 * 60 * 60 * 1000 } = {})

  // purpose 'activate'  : uid must be a pending user
  // purpose 'credential-reset': uid must be an active (credentialed) user
  // Issuing revokes any outstanding unexpired invites for the same
  // (uid, purpose) — exactly one live link per account per purpose.
  async issue ({ uid, purpose, ttlMs, createdBy }) // → { invite, token } — the
      // only moment the raw token exists server-side; return it, forget it.

  // Lets the app greet the invitee before they type anything.
  // Rate-limited ('invite' bucket). On any failure (unknown, expired, used,
  // revoked) returns the SAME generic error — no distinguishing why.
  async preview ({ token, clientKey }) // → { uid, username, purpose, expiresAt }

  // Burns the token and installs the credential, atomically:
  //  - validate: exists by hash, constant-time hash comparison, not used,
  //    not revoked, not expired; same generic error on every failure path.
  //  - 'activate': user must still be pending → updateUser with
  //    salt/verifier/iterations/group.
  //  - 'credential-reset': replace salt/verifier/iterations/group, then
  //    destroy all of the user's sessions (see SessionStore change below).
  //    TOTP is KEPT unless the invite was issued with clearTotp: true
  //    (an issue() option, recorded on the record) — admins use that for
  //    lost-phone recovery; by default a reset link alone must not be able
  //    to strip a second factor.
  //  - mark usedAt before reporting success (single-use even under races:
  //    the store's markUsed must be compare-and-set — see interface note).
  async redeem ({ token, salt, verifier, iterations, group, clientKey }) // → UserRecord

  async revoke (inviteId)
  async listForUser (uid)   // for the app's "outstanding invites" admin UI
}
```

Rate limits: add to `DEFAULT_RATE_LIMITS`:
`invite: { maxAttempts: 10, windowMs: 15 * 60 * 1000 }` and
`inviteClient: { maxAttempts: 30, windowMs: 15 * 60 * 1000 }` — shared by
`preview` and `redeem` (they are the same guessing surface).

Audit events (never include the raw token; `inviteId`/`uid`/`purpose` only):
`invite.issued`, `invite.redeemed`, `invite.revoked`, `invite.failed`
(covers preview and redeem failures, with a non-enumerating `reason` kept
generic in the event details), `invite.sessions_revoked`.

## Storage changes

### New `InviteStore` interface (`src/storage/storage-interface.js`)

```js
class InviteStore {
  async createInvite (invite)                 // → InviteRecord
  async getInviteByTokenHash (tokenHash)      // → InviteRecord|null
  async getInvite (id)                        // → InviteRecord|null
  async markUsed (id, usedAt)                 // → boolean: false if already
                                              //   used/revoked (compare-and-set;
                                              //   this is the single-use guarantee)
  async revokeInvite (id, revokedAt)          // → void (idempotent)
  async listInvitesForUser (uid)              // → InviteRecord[]
}
```

Implement it in both reference backends (`memory-store.js`,
`json-file-store.js`), covered by the shared storage behavioral contract test.

### `SessionStore` addition

Add `async deleteByUid (uid)` to the `SessionStore` interface so
credential-reset can revoke sessions. To stay backward compatible with
existing third-party stores: `InviteManager` feature-detects the method; if
absent it completes the reset but emits audit event
`invite.sessions_not_revoked` so the integrator finds out loudly. Implement
`deleteByUid` in `MemorySessionStore` (iterate entries, matching on the stored
`uid` field).

### `UserRecord` relaxation

Document in the typedef that `salt`/`verifier`/`iterations`/`group` are
`null` while pending. Audit every place `AuthServer` reads `user.verifier`
and route pending users through the fake-user path.

## Security notes (add the gist to SECURITY.md's threat table)

- **Token theft from storage:** only `sha256(token)` at rest; the raw token
  exists in server memory only inside `issue()`'s return path.
- **Token guessing:** 256-bit random + rate limiting + constant-time compare.
- **Enumeration:** preview/redeem failures are uniform; pending users look
  nonexistent to `beginLogin`.
- **Replay/races:** single-use enforced by compare-and-set `markUsed` before
  the success response; re-issuing revokes earlier links.
- **Privilege:** a reset link replaces the credential but keeps MFA by
  default — a leaked link alone cannot bypass a user's second factor unless
  the issuing admin explicitly cleared it.
- **Delivery guidance (document in README):** apps should put the token in the
  URL *fragment* (`/welcome#token=...`) and POST it from the page, so tokens
  stay out of server logs, proxies, and Referer headers. This package does not
  build URLs or send anything — delivery is the application's job.

## Deliberate non-goals

Email/SMS delivery, URL construction, invite UI, multi-use invite codes
("join codes" are a different, weaker primitive — out of scope), and
self-service password reset (no out-of-band channel exists in this package's
world; the admin is the recovery path).

## Tests to write (`test/invites.test.js` + storage contract additions)

1. Full happy paths: pending → issue → preview → redeem → SRP login succeeds
   (activate); active → reset-issue → redeem → old password fails, new works,
   all prior sessions dead (with a store that implements `deleteByUid`).
2. Reuse after redeem fails; redeem after revoke fails; redeem after expiry
   fails; all three return the same error shape/message as an unknown token.
3. Re-issuing revokes the earlier outstanding invite for that (uid, purpose).
4. Pending user: `beginLogin` response indistinguishable from a nonexistent
   username (compare against one); `completeLogin` can never succeed.
5. `clearTotp` honored both ways (default keeps TOTP and the reset user still
   needs MFA to log in).
6. Rate limit trips on preview and redeem; audit events emitted with no token
   material in any of them (assert by scanning logged payloads for the raw
   token and its hash).
7. Concurrent double-redeem race: exactly one wins (exercise `markUsed` CAS).
8. Storage contract: `InviteStore` behavioral suite run against memory and
   json-file backends, like the existing stores.

## Documentation updates when implementing

- `README.md`: new "Invites & credential resets" section (quick start snippet
  mirroring this doc's API), add `InviteStore` to the storage list, note the
  `SessionStore.deleteByUid` addition.
- `SECURITY.md`: threat-table rows for invite-token theft/guessing/replay, and
  the "pending users are indistinguishable" property.
- Export `InviteManager` from `src/index.js`.
