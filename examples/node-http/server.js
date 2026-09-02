// Minimal end-to-end example: plain node:http (no framework, no
// dependencies) wiring AuthServer to a JSON-file store. Demonstrates the
// full request shape an integration needs: bootstrap, register, login
// (2 round trips), TOTP enrollment + verification, recovery codes, and
// session-gated routes.
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

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DATA_DIR = path.join(__dirname, 'data')
const PORT = process.env.PORT || 8787

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

const routes = {
  'POST /api/bootstrap/status': async () => ({ needsBootstrap: await bootstrap.needsBootstrap() }),

  'POST /api/bootstrap/complete': async (body) => {
    const user = await bootstrap.completeBootstrap(body)
    return { user }
  },

  'POST /api/register': async (body) => {
    const user = await server.registerUser({ ...body, roleIds: ['role-privileged-1'] })
    return { user }
  },

  'POST /api/login/begin': async (body) => server.beginLogin(body),

  'POST /api/login/complete': async (body) => server.completeLogin(body),

  'POST /api/mfa/totp/verify': async (body) => server.verifyMfaTotp(body),

  'POST /api/mfa/recovery/verify': async (body) => server.verifyMfaRecoveryCode(body),

  'POST /api/mfa/enroll/begin': async (body, req) => {
    const session = await requireSession(req)
    return server.beginTotpEnrollment(session.uid)
  },

  'POST /api/mfa/enroll/confirm': async (body) => server.confirmTotpEnrollment(body),

  'POST /api/me': async (body, req) => {
    const session = await requireSession(req)
    const user = await server.userStore.getUserById(session.uid)
    return { username: user.username, roleIds: user.roleIds, mfaEnabled: Boolean(user.totp) }
  }
}

async function requireSession (req) {
  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
  const session = token && (await server.getSession(token))
  if (!session) {
    const err = new Error('not authenticated')
    err.statusCode = 401
    throw err
  }
  return session
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
      const result = await routes[routeKey](body, req)
      sendJson(res, 200, result ?? {})
    } catch (err) {
      sendJson(res, err.statusCode || 400, { error: err.message })
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
