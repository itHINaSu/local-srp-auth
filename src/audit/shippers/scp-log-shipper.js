// SCP log shipper. Unlike TFTP/FTP, SCP runs over SSH — implementing
// the SSH transport (key exchange, host-key verification, cipher
// negotiation, MAC checking) from scratch would mean hand-rolling
// exactly the kind of cryptographic protocol this package's own
// SECURITY.md says never to hand-roll. So this shipper does not
// implement SSH: it shells out to the system's `scp` binary via
// execFile (array arguments only — never a shell string — so nothing in
// a batch's content or file name can be interpreted as a shell command),
// reusing whatever SSH keys/agent/known_hosts the host already trusts.
//
// Requirements this implies, spelled out rather than hidden:
//  - `scp` must be installed and on PATH.
//  - Auth must be key-based and passwordless (an SSH agent, or an
//    unencrypted identity file) — there's no safe, non-interactive way
//    to hand `scp` a password without it appearing in a process listing
//    or an expect-style hack, so this shipper doesn't attempt it.
//  - The destination host's key must already be in the invoking user's
//    known_hosts, UNLESS you explicitly set `allowUnknownHostKey: true`
//    — which disables host-key verification (-o StrictHostKeyChecking=no)
//    and accepts the real MITM risk that implies. Off by default; opt in
//    deliberately, not because it was the path of least resistance to a
//    green test.

import { execFile } from 'node:child_process'
import { writeFile, unlink, mkdtemp } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { LogShipper } from './log-shipper.js'

const DEFAULT_TIMEOUT_MS = 15000

class ScpLogShipper extends LogShipper {
  /**
   * @param {object} opts
   * @param {string} opts.host
   * @param {string} opts.user
   * @param {string} opts.remoteDir directory to copy into (no trailing slash)
   * @param {number} [opts.port=22]
   * @param {string} [opts.identityFile] path to a private key; omit to use the default SSH agent/identity
   * @param {boolean} [opts.allowUnknownHostKey=false] see module note above — real security tradeoff, off by default
   * @param {number} [opts.timeoutMs]
   * @param {string} [opts.scpBinary='scp'] override if `scp` isn't on PATH under that name
   */
  constructor ({ host, user, remoteDir, port = 22, identityFile, allowUnknownHostKey = false, timeoutMs = DEFAULT_TIMEOUT_MS, scpBinary = 'scp' }) {
    super()
    if (!host) throw new Error('ScpLogShipper requires a host')
    if (!user) throw new Error('ScpLogShipper requires a user')
    if (!remoteDir) throw new Error('ScpLogShipper requires a remoteDir')
    this._host = host
    this._user = user
    this._remoteDir = remoteDir
    this._port = port
    this._identityFile = identityFile
    this._allowUnknownHostKey = allowUnknownHostKey
    this._timeoutMs = timeoutMs
    this._scpBinary = scpBinary
  }

  async ship (batchText, fileName) {
    const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-scp-'))
    const localPath = path.join(tmpDir, fileName)
    try {
      await writeFile(localPath, batchText, { mode: 0o600 })
      await this._runScp(localPath)
    } finally {
      await unlink(localPath).catch(() => {})
    }
  }

  _runScp (localPath) {
    const args = ['-P', String(this._port), '-o', 'BatchMode=yes']
    if (this._identityFile) args.push('-i', this._identityFile)
    if (this._allowUnknownHostKey) args.push('-o', 'StrictHostKeyChecking=no')
    args.push(localPath, `${this._user}@${this._host}:${this._remoteDir}/`)

    return new Promise((resolve, reject) => {
      execFile(this._scpBinary, args, { timeout: this._timeoutMs }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`scp failed: ${err.message}${stderr ? ` (stderr: ${stderr.trim()})` : ''}`))
        } else {
          resolve()
        }
      })
    })
  }
}

export { ScpLogShipper }
