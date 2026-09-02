// Audit logging contract. AuthServer calls log() at every
// security-relevant event — never with a password (which never reaches
// it anyway), a verifier/salt, a TOTP secret, a recovery code, or a raw
// session token (those are logged as a short non-reversible reference
// only — see hashRef() in server-auth.js) — so a log file is safe to
// retain, ship to a SIEM, or hand to an auditor without itself becoming
// a credential store.
//
// Event `type` values this package emits: user.registered,
// user.login.success, user.login.failure, user.login.rate_limited,
// mfa.enrolled, mfa.disabled, mfa.verify.success, mfa.verify.failure,
// mfa.recovery_code.used, mfa.rate_limited, session.destroyed,
// bootstrap.completed, bootstrap.failed, bootstrap.rate_limited.

class AuditLogger {
  /**
   * @param {object} event
   * @param {string} event.type
   * @param {string} event.timestamp ISO 8601
   * @param {string} [event.uid]
   * @param {string} [event.username]
   * @param {string} [event.clientKey] caller-supplied (e.g. IP), if any
   * @param {object} [event.details] event-specific extra fields (never secrets)
   */
  async log (event) { /* no-op base class — extend or use a reference implementation below */ }
}

class ConsoleAuditLogger extends AuditLogger {
  async log (event) {
    console.log(JSON.stringify(event))
  }
}

class NullAuditLogger extends AuditLogger {
  async log () {}
}

export { AuditLogger, ConsoleAuditLogger, NullAuditLogger }
