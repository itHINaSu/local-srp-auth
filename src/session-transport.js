// Cookie-based session transport for plain node:http (or anything that
// exposes similar req.headers / res.setHeader). AuthServer itself never
// imports this — it only deals in opaque session-token strings — so
// this stays optional and Node-http-specific rather than baked into the
// framework-agnostic core. Wire it in from your own route handlers, the
// way examples/node-http/server.js does.
//
// TLS note: the `secure` cookie flag tells the browser "only ever send
// this cookie over HTTPS" — and critically, browsers will refuse to
// *store* a Secure cookie set over plain HTTP at all, not just decline
// to send it. If your deployment doesn't terminate TLS (common for a
// self-hosted internal tool), you MUST pass `secure: false` below or
// the session cookie will silently never work. Defaults to secure:true
// because TLS is the right call whenever it's available — but this is
// a real per-deployment decision, not a hardcoded assumption, and
// running without it means the session cookie travels in the clear
// (readable by anything on the same network path) — same tradeoff
// SECURITY.md documents.

import crypto from 'node:crypto'

const DEFAULT_COOKIE_NAME = 'sid'
const DEFAULT_CSRF_COOKIE_NAME = 'csrf'
const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token'
const DEFAULT_MAX_AGE_SECONDS = 12 * 60 * 60 // matches AuthServer's default sessionTtlMs

/**
 * @typedef {object} CookieOptions
 * @property {boolean} [secure=true] set false for a deployment with no TLS — see module note above
 * @property {'Strict'|'Lax'|'None'} [sameSite='Strict']
 * @property {string} [path='/']
 * @property {number} [maxAgeSeconds]
 * @property {string} [cookieName]
 */

function serializeCookie (name, value, { secure = true, sameSite = 'Strict', path = '/', maxAgeSeconds, httpOnly = true } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`]
  if (httpOnly) parts.push('HttpOnly')
  if (secure) parts.push('Secure')
  if (typeof maxAgeSeconds === 'number') parts.push(`Max-Age=${Math.floor(maxAgeSeconds)}`)
  return parts.join('; ')
}

function parseCookies (cookieHeader) {
  const out = {}
  if (!cookieHeader) return out
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=')
    if (idx === -1) continue
    const key = pair.slice(0, idx).trim()
    const value = pair.slice(idx + 1).trim()
    if (key) out[key] = decodeURIComponent(value)
  }
  return out
}

function appendSetCookie (res, cookieString) {
  const existing = res.getHeader('Set-Cookie')
  if (!existing) {
    res.setHeader('Set-Cookie', [cookieString])
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, cookieString])
  } else {
    res.setHeader('Set-Cookie', [existing, cookieString])
  }
}

/** Sets the session cookie after a successful login. */
function setSessionCookie (res, sessionToken, opts = {}) {
  const cookieName = opts.cookieName || DEFAULT_COOKIE_NAME
  const maxAgeSeconds = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS
  appendSetCookie(res, serializeCookie(cookieName, sessionToken, { ...opts, maxAgeSeconds, httpOnly: true }))
}

/** Clears the session cookie on logout. */
function clearSessionCookie (res, opts = {}) {
  const cookieName = opts.cookieName || DEFAULT_COOKIE_NAME
  appendSetCookie(res, serializeCookie(cookieName, '', { ...opts, maxAgeSeconds: 0, httpOnly: true }))
}

/** Reads the session token out of an incoming request, or null if absent. */
function getSessionToken (req, opts = {}) {
  const cookieName = opts.cookieName || DEFAULT_COOKIE_NAME
  const cookies = parseCookies(req.headers.cookie)
  return cookies[cookieName] || null
}

// ---- CSRF (double-submit cookie pattern) -----------------------------
//
// The session cookie is HttpOnly (JS can't read it, so an XSS payload
// can't exfiltrate it directly) but browsers still attach cookies to
// cross-site requests automatically (that's what SameSite=Strict above
// already blocks for most cases). Double-submit CSRF is defense in
// depth for the SameSite=Lax/None cases some deployments need: the CSRF
// cookie is deliberately NOT HttpOnly so your frontend JS can read it
// and echo it back in a header — a cross-site attacker's browser will
// send the cookie automatically but cannot read its value to put it in
// the header, so a mismatch means the request didn't originate from
// your own page's JS.

function generateCsrfToken () {
  return crypto.randomBytes(32).toString('hex')
}

function setCsrfCookie (res, token, opts = {}) {
  const cookieName = opts.cookieName || DEFAULT_CSRF_COOKIE_NAME
  const maxAgeSeconds = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS
  appendSetCookie(res, serializeCookie(cookieName, token, { ...opts, maxAgeSeconds, httpOnly: false }))
}

/** Returns true if the request's CSRF header matches its CSRF cookie. */
function verifyCsrfToken (req, opts = {}) {
  const cookieName = opts.cookieName || DEFAULT_CSRF_COOKIE_NAME
  const headerName = opts.headerName || DEFAULT_CSRF_HEADER_NAME
  const cookies = parseCookies(req.headers.cookie)
  const cookieValue = cookies[cookieName]
  const headerValue = req.headers[headerName]
  if (!cookieValue || !headerValue || typeof headerValue !== 'string') return false
  const cookieBuf = Buffer.from(cookieValue)
  const headerBuf = Buffer.from(headerValue)
  // Constant-time compare — this is exactly the kind of secret-bearing
  // comparison a data-dependent-time check would turn into a guessable
  // oracle, same reasoning as the SRP proof comparisons in srp-server.js.
  return cookieBuf.length === headerBuf.length && crypto.timingSafeEqual(cookieBuf, headerBuf)
}

export {
  DEFAULT_COOKIE_NAME,
  DEFAULT_CSRF_COOKIE_NAME,
  DEFAULT_CSRF_HEADER_NAME,
  parseCookies,
  serializeCookie,
  setSessionCookie,
  clearSessionCookie,
  getSessionToken,
  generateCsrfToken,
  setCsrfCookie,
  verifyCsrfToken
}
