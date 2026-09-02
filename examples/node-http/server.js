// Minimal end-to-end example: plain node:http (no framework, no
// dependencies) wiring AuthServer to a JSON-file store. Demonstrates the
// full request shape an integration needs: bootstrap, register, login
// (2 round trips), TOTP enrollment + verification, recovery codes,
// logout, cookie-based session transport with CSRF protection,
// client-IP-aware rate limiting, and audit logging.
//
// Run: node examples/node-http/server.js
// Then open http://localhost:8787 in a browser.

import http from 'node:http'
import path from 'node:path'
import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import { AuthServer } from '../../src/server-auth.js'
import { Bootstrap } from '../../src/bootstrap.js'
import { JsonFileUserStore, JsonFileRoleStore } from '../../src/storage/json-file-store.js'
import { RateLimitExceededError } from '../../src/rate-limit/rate-limiter.js'
import {
  setSessionCookie, clearSessionCookie, getSessionToken,
  generateCsrfToken, setCsrfCookie, verifyCsrfToken
} from '../../src/session-transport.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DATA_DIR = path.join(__dirname, 'data')
const PORT = process.env.PORT || 8787

// This demo runs over plain HTTP (no TLS termination here), so the
// session cookie is set with secure:false — see session-transport.js's
// module comment for what that tradeoff means. A production deployment
// behind TLS should not set this.
const COOKIE_SECURE = false

// Audit log shipping is off by default in this demo (no destination
// configured). To try it against a real TFTP/FTP/SCP log server:
//   import { ShippingAuditLogger } from '../../src/audit/shipping-audit-logger.js'
//   import { TftpLogShipper } from '../../src/audit/shippers/tftp-log-shipper.js'
//   const logger = new ShippingAuditLogger({ shippers: [new TftpLogShipper({ host: '10.0.0.5' })] })
//   logger.start()
//   // then pass `logger` into the AuthServer constructor below.

const server = new AuthServer({
  userStore: new JsonFileUserStore(path.join(DATA_DIR, 'users.json')),
  roleStore: new JsonFileRoleStore(path.join(DATA_DIR, 'roles.json'))
})
await server.ensureDefaultRoles()

const bootstrap = new Bootstrap(server)

async function printBootstrapTokenIfNeeded () {
  if (!(await bootstrap.needsBootstrap())) return
  const token = await bootstrap.generateSetupToken()
  console.log('\n' + '='.repeat(72))
  console.log('No users exist yet. Setup token (valid 30 minutes):')
  console.log('  ' + token)
  console.log('Open http://localhost:' + PORT + '/ and paste it into the setup form.')
  console.log('='.repeat(72) + '\n')
}
await printBootstrapTokenIfNeeded()

function clientKeyOf (req) {
  return req.socket.remoteAddress
}

/** Establishes an authenticated session: sets the session cookie and a fresh CSRF cookie. */
function startAuthenticatedSession (res, sessionToken) {
  setSessionCookie(res, sessionToken, { secure: COOKIE_SECURE })
  setCsrfCookie(res, generateCsrfToken(), { secure: COOKIE_SECURE })
}

async function requireSession (req) {
  const token = getSessionToken(req)
  const session = token && (await server.getSession(token))
  if (!session) throw httpError(401, 'not authenticated')
  return session
}

/** CSRF check for state-changing requests made by an already-authenticated browser. */
function requireCsrf (req) {
  if (!verifyCsrfToken(req)) throw httpError(403, 'CSRF check failed')
}

function httpError (statusCode, message) {
  const err = new Error(message)
  err.statusCode = statusCode
  return err
}

const routes = {
  'POST /api/bootstrap/status': async () => ({ needsBootstrap: await bootstrap.needsBootstrap() }),

  'POST /api/bootstrap/complete': async (body, req) => {
    const user = await bootstrap.completeBootstrap({ ...body, clientKey: clientKeyOf(req) })
    return { user }
  },

  'POST /api/register': async (body, req) => {
    const user = await server.registerUser({ ...body, roleIds: ['role-privileged-1'], clientKey: clientKeyOf(req) })
    return { user }
  },

  'POST /api/login/begin': async (body, req) => server.beginLogin({ ...body, clientKey: clientKeyOf(req) }),

  'POST /api/login/complete': async (body, req, res) => {
    const result = await server.completeLogin(body)
    if (!result.mfaRequired) startAuthenticatedSession(res, result.sessionToken)
    // The raw sessionToken never needs to reach the browser's JS at all —
    // it's already in the (HttpOnly) cookie by the time this responds.
    const { sessionToken, ...rest } = result
    return rest
  },

  'POST /api/mfa/totp/verify': async (body, req, res) => {
    const result = await server.verifyMfaTotp({ ...body, clientKey: clientKeyOf(req) })
    startAuthenticatedSession(res, result.sessionToken)
    return {}
  },

  'POST /api/mfa/recovery/verify': async (body, req, res) => {
    const result = await server.verifyMfaRecoveryCode({ ...body, clientKey: clientKeyOf(req) })
    startAuthenticatedSession(res, result.sessionToken)
    return { recoveryCodesRemaining: result.recoveryCodesRemaining }
  },

  'POST /api/mfa/enroll/begin': async (body, req) => {
    const session = await requireSession(req)
    requireCsrf(req)
    return server.beginTotpEnrollment(session.uid)
  },

  'POST /api/mfa/enroll/confirm': async (body, req) => {
    await requireSession(req)
    requireCsrf(req)
    return server.confirmTotpEnrollment({ ...body, clientKey: clientKeyOf(req) })
  },

  'POST /api/mfa/disable': async (body, req) => {
    const session = await requireSession(req)
    requireCsrf(req)
    await server.disableTotp({ uid: session.uid, code: body.code, clientKey: clientKeyOf(req) })
    return {}
  },

  'POST /api/logout': async (body, req, res) => {
    const token = getSessionToken(req)
    if (token) await server.destroySession(token)
    clearSessionCookie(res, { secure: COOKIE_SECURE })
    return {}
  },

  'POST /api/me': async (body, req) => {
    const session = await requireSession(req)
    const user = await server.userStore.getUserById(session.uid)
    return { username: user.username, roleIds: user.roleIds, mfaEnabled: Boolean(user.totp) }
  }
}

const STATIC_DIR = path.join(__dirname, 'public')
const PACKAGE_SRC_DIR = path.join(__dirname, '..', '..', 'src')
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' }

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const routeKey = `${req.method} ${url.pathname}`

  if (routes[routeKey]) {
    try {
      const body = req.method === 'POST' ? await readJsonBody(req) : null
      const result = await routes[routeKey](body, req, res)
      sendJson(res, 200, result ?? {})
    } catch (err) {
      if (err instanceof RateLimitExceededError) {
        res.setHeader('Retry-After', Math.ceil(err.retryAfterMs / 1000))
        sendJson(res, 429, { error: 'too many attempts, try again later' })
      } else {
        sendJson(res, err.statusCode || 400, { error: err.message })
      }
    }
    return
  }

  // Serve the package's own src/ tree under /lib/, so the browser demo can
  // import 'local-srp-auth/client' (and everything it transitively imports)
  // as plain ES modules with zero bundler and zero npm install — exactly
  // the workflow this package is designed to support.
  const isLibRequest = url.pathname.startsWith('/lib/')
  const baseDir = isLibRequest ? PACKAGE_SRC_DIR : STATIC_DIR
  const relPath = isLibRequest ? url.pathname.slice('/lib/'.length) : (url.pathname === '/' ? 'index.html' : url.pathname)
  const filePath = path.join(baseDir, relPath)
  if (!filePath.startsWith(baseDir)) {
    res.writeHead(403).end('forbidden')
    return
  }
  try {
    const content = await fs.readFile(filePath)
    const ext = path.extname(filePath)
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' })
    res.end(content)
  } catch {
    res.writeHead(404).end('not found')
  }
})

async function readJsonBody (req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const raw = Buffer.concat(chunks).toString('utf8')
  return raw ? JSON.parse(raw) : {}
}

function sendJson (res, statusCode, data) {
  const body = JSON.stringify(data)
  res.writeHead(statusCode, { 'Content-Type': 'application/json' })
  res.end(body)
}

httpServer.listen(PORT, () => {
  console.log(`local-srp-auth example running at http://localhost:${PORT}`)
})
