// Minimal FTP (RFC 959) log shipper: enough of the protocol to log in,
// switch to binary mode, open a passive-mode data connection, and STOR
// one file per flush. Pure Node `net`, no dependency — this is not a
// general-purpose FTP client (no LIST/RETR/active mode/resume/etc.),
// just what shipping a batch of log lines needs.
//
// Plain FTP sends credentials and data in the clear — same caveat as
// TFTP, see the note in tftp-log-shipper.js. This shipper does not
// implement FTPS/AUTH TLS; if your log server requires an encrypted
// transport, either put it behind a network you already trust FTP's
// plaintext on, use ScpLogShipper instead, or implement the LogShipper
// interface yourself against a TLS-capable FTP library.

import net from 'node:net'
import { LogShipper } from './log-shipper.js'

const DEFAULT_PORT = 21
const DEFAULT_TIMEOUT_MS = 10000

class FtpLogShipper extends LogShipper {
  /**
   * @param {object} opts
   * @param {string} opts.host
   * @param {number} [opts.port=21]
   * @param {string} [opts.user='anonymous']
   * @param {string} [opts.password='anonymous']
   * @param {string} [opts.remoteDir] directory to STOR into, no trailing slash (e.g. '/logs')
   * @param {number} [opts.timeoutMs]
   */
  constructor ({ host, port = DEFAULT_PORT, user = 'anonymous', password = 'anonymous', remoteDir = '', timeoutMs = DEFAULT_TIMEOUT_MS }) {
    super()
    if (!host) throw new Error('FtpLogShipper requires a host')
    this._host = host
    this._port = port
    this._user = user
    this._password = password
    this._remoteDir = remoteDir
    this._timeoutMs = timeoutMs
  }

  async ship (batchText, fileName) {
    const control = new FtpControlConnection(this._host, this._port, this._timeoutMs)
    try {
      await control.connect()
      await control.expect(220)
      await control.command(`USER ${this._user}`, [230, 331])
      const lastCode = control.lastCode
      if (lastCode === 331) await control.command(`PASS ${this._password}`, 230)
      await control.command('TYPE I', 200)

      const pasvResponse = await control.command('PASV', 227)
      const { host: dataHost, port: dataPort } = parsePasvResponse(pasvResponse)

      const remotePath = this._remoteDir ? `${this._remoteDir}/${fileName}` : fileName
      const dataSocket = await connectDataSocket(dataHost, dataPort, this._timeoutMs)

      await control.sendCommandOnly(`STOR ${remotePath}`)
      await control.expect(150) // "about to open data connection"

      await writeAndEnd(dataSocket, Buffer.from(batchText, 'utf8'))
      await control.expect(226) // "transfer complete"

      await control.sendCommandOnly('QUIT')
    } finally {
      control.close()
    }
  }
}

class FtpControlConnection {
  constructor (host, port, timeoutMs) {
    this._host = host
    this._port = port
    this._timeoutMs = timeoutMs
    this._socket = null
    this._buffer = ''
    this._pendingResolvers = []
    this.lastCode = null
  }

  connect () {
    return new Promise((resolve, reject) => {
      this._socket = net.createConnection({ host: this._host, port: this._port })
      const onError = (err) => reject(err)
      this._socket.once('error', onError)
      this._socket.setTimeout(this._timeoutMs, () => {
        this._socket.destroy(new Error(`FTP control connection to ${this._host}:${this._port} timed out`))
      })
      this._socket.once('connect', () => {
        this._socket.removeListener('error', onError)
        this._socket.on('error', (err) => this._rejectAllPending(err))
        this._socket.on('data', (chunk) => this._onData(chunk))
        resolve()
      })
    })
  }

  _onData (chunk) {
    this._buffer += chunk.toString('utf8')
    let lines = this._buffer.split('\r\n')
    this._buffer = lines.pop() // keep any incomplete trailing line

    for (const line of lines) {
      // A final response line for a code is "CODE text" (space); a
      // continuation line of a multi-line response is "CODE-text"
      // (hyphen). We only need to recognize the terminating line.
      const match = line.match(/^(\d{3})([ -])/)
      if (match && match[2] === ' ') {
        const code = Number(match[1])
        this.lastCode = code
        const pending = this._pendingResolvers.shift()
        if (pending) pending.resolve({ code, line })
      }
    }
  }

  _rejectAllPending (err) {
    while (this._pendingResolvers.length) {
      const pending = this._pendingResolvers.shift()
      pending.reject(err)
    }
  }

  _nextResponse () {
    return new Promise((resolve, reject) => {
      this._pendingResolvers.push({ resolve, reject })
    })
  }

  async expect (expectedCode) {
    const { code, line } = await this._nextResponse()
    const expected = Array.isArray(expectedCode) ? expectedCode : [expectedCode]
    if (!expected.includes(code)) {
      throw new Error(`FTP: expected ${expected.join('/')}, got: ${line}`)
    }
    return line
  }

  async command (text, expectedCode) {
    this._socket.write(`${text}\r\n`)
    return this.expect(expectedCode)
  }

  async sendCommandOnly (text) {
    this._socket.write(`${text}\r\n`)
  }

  close () {
    if (this._socket) this._socket.destroy()
  }
}

function connectDataSocket (host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port })
    const onError = (err) => reject(err)
    socket.once('error', onError)
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`FTP data connection to ${host}:${port} timed out`)))
    socket.once('connect', () => {
      socket.removeListener('error', onError)
      resolve(socket)
    })
  })
}

function writeAndEnd (socket, buffer) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.end(buffer, () => {
      socket.removeListener('error', reject)
      resolve()
    })
  })
}

/** Parses "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)." into { host, port }. */
function parsePasvResponse (line) {
  const match = line.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/)
  if (!match) throw new Error(`FTP: could not parse PASV response: ${line}`)
  const [, h1, h2, h3, h4, p1, p2] = match.map(Number)
  return {
    host: `${h1}.${h2}.${h3}.${h4}`,
    port: p1 * 256 + p2
  }
}

export { FtpLogShipper }
