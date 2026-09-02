// TFTP (RFC 1350) log shipper. Pure Node `dgram`, no dependency — TFTP
// is a genuinely simple protocol (a handful of opcodes over UDP), unlike
// FTP or SCP, so implementing the wire format directly here is
// reasonable rather than reaching for a library.
//
// TFTP itself has no authentication and no encryption — anyone who can
// reach the server on UDP/69 can write files to it. That's inherent to
// the protocol, not a limitation of this implementation, and is exactly
// why TFTP is normally only used on trusted, isolated management
// networks (this project's own domain — cell site / network equipment
// provisioning — is a canonical example of where that's still common
// practice). Don't point this at a log server reachable from anywhere
// you wouldn't also trust with write access to arbitrary files.
//
// Each flush is written as a new file (WRQ), not appended — TFTP has no
// append operation — so `fileName` should be unique per call (see
// ShippingAuditLogger, which timestamps it).

import dgram from 'node:dgram'
import { LogShipper } from './log-shipper.js'

const OPCODE = { RRQ: 1, WRQ: 2, DATA: 3, ACK: 4, ERROR: 5 }
const BLOCK_SIZE = 512
const DEFAULT_TIMEOUT_MS = 3000
const DEFAULT_MAX_RETRIES = 5

class TftpLogShipper extends LogShipper {
  /**
   * @param {object} opts
   * @param {string} opts.host
   * @param {number} [opts.port=69]
   * @param {number} [opts.timeoutMs]
   * @param {number} [opts.maxRetries]
   */
  constructor ({ host, port = 69, timeoutMs = DEFAULT_TIMEOUT_MS, maxRetries = DEFAULT_MAX_RETRIES }) {
    super()
    if (!host) throw new Error('TftpLogShipper requires a host')
    this._host = host
    this._port = port
    this._timeoutMs = timeoutMs
    this._maxRetries = maxRetries
  }

  async ship (batchText, fileName) {
    const data = Buffer.from(batchText, 'utf8')
    const socket = dgram.createSocket('udp4')
    try {
      await this._transfer(socket, fileName, data)
    } finally {
      socket.close()
    }
  }

  _transfer (socket, fileName, data) {
    return new Promise((resolve, reject) => {
      let remotePort = this._port // updates to the server's ephemeral TID after its first reply
      let block = 0 // block 0 = "waiting for the ACK that grants the WRQ"
      let settled = false
      let retriesLeft = this._maxRetries
      let timer = null

      const finish = (err) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.removeAllListeners('message')
        socket.removeAllListeners('error')
        if (err) reject(err)
        else resolve()
      }

      const currentPacket = () => {
        if (block === 0) return buildWrq(fileName)
        return buildData(block, chunkFor(data, block))
      }

      const sendCurrent = () => {
        const packet = currentPacket()
        socket.send(packet, remotePort, this._host, (err) => { if (err) finish(err) })
        clearTimeout(timer)
        timer = setTimeout(onTimeout, this._timeoutMs)
      }

      const onTimeout = () => {
        if (retriesLeft <= 0) {
          finish(new Error(`TFTP transfer to ${this._host}:${this._port} timed out (no ACK for block ${block})`))
          return
        }
        retriesLeft -= 1
        sendCurrent()
      }

      // Per RFC 1350, a transfer ends on the first DATA block shorter
      // than BLOCK_SIZE — including a zero-length one. So when the
      // payload is an exact multiple of BLOCK_SIZE, one extra empty
      // block is required after the last full one, or the server has no
      // way to know the transfer is complete (it'll just wait forever
      // for a block that's never coming — this was a real bug caught by
      // this file's own tests, not a hypothetical). floor(...)+1 always
      // accounts for that: e.g. 512 bytes -> [512, 0] (2 blocks), 1000
      // bytes -> [512, 488] (2 blocks, second already short), 0 bytes
      // -> [0] (1 block).
      const totalDataBlocks = Math.floor(data.length / BLOCK_SIZE) + 1

      socket.on('error', finish)
      socket.on('message', (msg, rinfo) => {
        if (msg.length < 4) return // too short to be a valid TFTP packet, ignore
        const opcode = msg.readUInt16BE(0)

        if (opcode === OPCODE.ERROR) {
          const errCode = msg.readUInt16BE(2)
          const errMsg = msg.slice(4, msg.indexOf(0, 4) === -1 ? undefined : msg.indexOf(0, 4)).toString('utf8')
          finish(new Error(`TFTP server error ${errCode}: ${errMsg}`))
          return
        }

        if (opcode !== OPCODE.ACK) return // unexpected opcode, ignore and keep waiting
        const ackedBlock = msg.readUInt16BE(2)
        if (ackedBlock !== block) return // stale/duplicate ACK, ignore

        // First reply establishes the server's per-transfer ephemeral port (TID).
        if (block === 0) remotePort = rinfo.port

        if (block >= totalDataBlocks) { finish(); return }

        block = (block + 1) % 65536
        retriesLeft = this._maxRetries
        sendCurrent()
      })

      sendCurrent()
    })
  }
}

function chunkFor (data, block) {
  const start = (block - 1) * BLOCK_SIZE
  return data.subarray(start, start + BLOCK_SIZE)
}

function buildWrq (fileName) {
  const filenameBuf = Buffer.from(fileName, 'ascii')
  const modeBuf = Buffer.from('octet', 'ascii')
  const packet = Buffer.alloc(2 + filenameBuf.length + 1 + modeBuf.length + 1)
  let offset = 0
  packet.writeUInt16BE(OPCODE.WRQ, offset); offset += 2
  filenameBuf.copy(packet, offset); offset += filenameBuf.length
  packet.writeUInt8(0, offset); offset += 1
  modeBuf.copy(packet, offset); offset += modeBuf.length
  packet.writeUInt8(0, offset)
  return packet
}

function buildData (block, chunk) {
  const packet = Buffer.alloc(4 + chunk.length)
  packet.writeUInt16BE(OPCODE.DATA, 0)
  packet.writeUInt16BE(block, 2)
  chunk.copy(packet, 4)
  return packet
}

export { TftpLogShipper }
