import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  serializeCookie,
  parseCookies,
  setSessionCookie,
  clearSessionCookie,
  getSessionToken,
  generateCsrfToken,
  setCsrfCookie,
  verifyCsrfToken
} from '../src/session-transport.js'

function fakeResponse () {
  const headers = {}
  return {
    setHeader (name, value) { headers[name] = value },
    getHeader (name) { return headers[name] },
    _headers: headers
  }
}

function fakeRequest ({ cookie, headers = {} } = {}) {
  return { headers: { ...(cookie !== undefined ? { cookie } : {}), ...headers } }
}

test('parseCookies handles multiple cookies, spacing, and URI-encoded values', () => {
  const parsed = parseCookies('a=1; b=hello%20world;c=3')
  assert.deepEqual(parsed, { a: '1', b: 'hello world', c: '3' })
})

test('parseCookies returns {} for an absent header', () => {
  assert.deepEqual(parseCookies(undefined), {})
  assert.deepEqual(parseCookies(''), {})
})

test('serializeCookie: defaults are HttpOnly, Secure, SameSite=Strict, Path=/', () => {
  const cookie = serializeCookie('sid', 'abc123')
  assert.match(cookie, /^sid=abc123/)
  assert.match(cookie, /HttpOnly/)
  assert.match(cookie, /Secure/)
  assert.match(cookie, /SameSite=Strict/)
  assert.match(cookie, /Path=\//)
})

test('serializeCookie: secure:false omits the Secure attribute (the non-TLS deployment case)', () => {
  const cookie = serializeCookie('sid', 'abc123', { secure: false })
  assert.doesNotMatch(cookie, /Secure/)
})

test('serializeCookie: CSRF-style cookie can opt out of HttpOnly so client JS can read it', () => {
  const cookie = serializeCookie('csrf', 'tok', { httpOnly: false })
  assert.doesNotMatch(cookie, /HttpOnly/)
})

test('setSessionCookie appends a Set-Cookie header carrying the session token', () => {
  const res = fakeResponse()
  setSessionCookie(res, 'my-session-token', { secure: false })
  const setCookie = res.getHeader('Set-Cookie')
  assert.equal(setCookie.length, 1)
  assert.match(setCookie[0], /^sid=my-session-token/)
})

test('setSessionCookie appends to, rather than overwrites, an existing Set-Cookie header', () => {
  const res = fakeResponse()
  res.setHeader('Set-Cookie', ['other=1'])
  setSessionCookie(res, 'tok', { secure: false })
  const setCookie = res.getHeader('Set-Cookie')
  assert.equal(setCookie.length, 2)
  assert.equal(setCookie[0], 'other=1')
  assert.match(setCookie[1], /^sid=tok/)
})

test('clearSessionCookie sets Max-Age=0', () => {
  const res = fakeResponse()
  clearSessionCookie(res, { secure: false })
  const setCookie = res.getHeader('Set-Cookie')
  assert.match(setCookie[0], /Max-Age=0/)
})

test('getSessionToken reads the cookie back out of a request', () => {
  const req = fakeRequest({ cookie: 'sid=abc123; other=x' })
  assert.equal(getSessionToken(req), 'abc123')
})

test('getSessionToken returns null when the cookie is absent', () => {
  const req = fakeRequest({ cookie: 'other=x' })
  assert.equal(getSessionToken(req), null)
  assert.equal(getSessionToken(fakeRequest()), null)
})

test('generateCsrfToken produces a long, unique, hex value each call', () => {
  const a = generateCsrfToken()
  const b = generateCsrfToken()
  assert.match(a, /^[0-9a-f]{64}$/)
  assert.notEqual(a, b)
})

test('verifyCsrfToken passes when the header matches the cookie', () => {
  const token = generateCsrfToken()
  const req = fakeRequest({ cookie: `csrf=${token}`, headers: { 'x-csrf-token': token } })
  assert.equal(verifyCsrfToken(req), true)
})

test('verifyCsrfToken fails on a mismatch, and when either side is missing', () => {
  const token = generateCsrfToken()
  assert.equal(verifyCsrfToken(fakeRequest({ cookie: `csrf=${token}`, headers: { 'x-csrf-token': 'wrong' } })), false)
  assert.equal(verifyCsrfToken(fakeRequest({ cookie: `csrf=${token}` })), false) // no header
  assert.equal(verifyCsrfToken(fakeRequest({ headers: { 'x-csrf-token': token } })), false) // no cookie
  assert.equal(verifyCsrfToken(fakeRequest()), false) // neither
})

test('setCsrfCookie is not HttpOnly (must be readable by frontend JS for the double-submit pattern)', () => {
  const res = fakeResponse()
  setCsrfCookie(res, 'tok', { secure: false })
  const setCookie = res.getHeader('Set-Cookie')
  assert.doesNotMatch(setCookie[0], /HttpOnly/)
})
