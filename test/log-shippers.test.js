import { test } from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'node:dgram'
import net from 'node:net'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { TftpLogShipper } from '../src/audit/shippers/tftp-log-shipper.js'
import { FtpLogShipper } from '../src/audit/shippers/ftp-log-shipper.js'
import { ScpLogShipper } from '../src/audit/shippers/scp-log-shipper.js'
import { ShippingAuditLogger } from '../src/audit/shipping-audit-logger.js'
import { AuditLogger } from '../src/audit/audit-logger.js'

// ---- A minimal in-process TFTP server (RFC 1350), for testing our
// client against real wire behavior instead of mocks. WRQ-only. ----

function startTftpTestServer () {
  const received = new Map() // filename -> Buffer
  const listener = dgram.createSocket('udp4')

  listener.on('message', (msg, rinfo) => {
    const opcode = msg.readUInt16BE(0)
    if (opcode !== 2) return // only handle WRQ
    const nul1 = msg.indexOf(0, 2)
    const filename = msg.slice(2, nul1).toString('ascii')

    const xfer = dgram.createSocket('udp4')
    xfer.bind(0, () => {
      let expectedBlock = 1
      const chunks = []

      const sendAck = (block, then) => {
        const ack = Buffer.alloc(4)
        ack.writeUInt16BE(4, 0)
        ack.writeUInt16BE(block, 2)
        // Must wait for send()'s callback before doing anything that
        // could tear down the socket (like closing it) — closing
        // immediately after a synchronous send() call risks the
        // datagram never actually being flushed to the OS.
        xfer.send(ack, rinfo.port, rinfo.address, () => { if (then) then() })
      }

      xfer.on('message', (dmsg, drinfo) => {
        if (dmsg.readUInt16BE(0) !== 3) return // only DATA
        const block = dmsg.readUInt16BE(2)
        const data = dmsg.subarray(4)

        if (block !== expectedBlock) {
          sendAck((expectedBlock - 1 + 65536) % 65536) // re-ack the last good block
          return
        }

        chunks.push(Buffer.from(data))
        const isFinal = data.length < 512
        sendAck(block, isFinal ? () => xfer.close() : undefined)
        if (isFinal) {
          received.set(filename, Buffer.concat(chunks))
        } else {
          expectedBlock = (expectedBlock + 1) % 65536
        }
      })

      sendAck(0) // grant the WRQ
    })
  })

  return new Promise((resolve) => {
    listener.bind(0, () => resolve({
      port: listener.address().port,
      received,
      close: () => listener.close()
    }))
  })
}

test('TftpLogShipper: ships a small (<512 byte) batch and the server receives it byte-for-byte', async () => {
  const server = await startTftpTestServer()
  try {
    const shipper = new TftpLogShipper({ host: '127.0.0.1', port: server.port, timeoutMs: 500 })
    await shipper.ship('{"type":"user.login.success"}\n', 'batch-1.jsonl')
    assert.equal(server.received.get('batch-1.jsonl').toString('utf8'), '{"type":"user.login.success"}\n')
  } finally {
    server.close()
  }
})

test('TftpLogShipper: ships a multi-block (>512 byte) batch correctly', async () => {
  const server = await startTftpTestServer()
  try {
    const bigText = 'x'.repeat(1500) + '\n'
    const shipper = new TftpLogShipper({ host: '127.0.0.1', port: server.port, timeoutMs: 500 })
    await shipper.ship(bigText, 'batch-2.jsonl')
    assert.equal(server.received.get('batch-2.jsonl').toString('utf8'), bigText)
  } finally {
    server.close()
  }
})

test('TftpLogShipper: a payload that is an EXACT multiple of 512 bytes still terminates (regression test for the empty-final-block bug)', async () => {
  const server = await startTftpTestServer()
  try {
    const exactText = 'y'.repeat(512) // exactly one block, no remainder
    const shipper = new TftpLogShipper({ host: '127.0.0.1', port: server.port, timeoutMs: 500 })
    await shipper.ship(exactText, 'batch-3.jsonl')
    assert.equal(server.received.get('batch-3.jsonl').toString('utf8'), exactText)

    const exact1024 = 'z'.repeat(1024) // two full blocks, still needs a trailing empty one
    await shipper.ship(exact1024, 'batch-4.jsonl')
    assert.equal(server.received.get('batch-4.jsonl').toString('utf8'), exact1024)
  } finally {
    server.close()
  }
})

test('TftpLogShipper: rejects when the server never responds (timeout)', async () => {
  const blackhole = dgram.createSocket('udp4')
  await new Promise((resolve) => blackhole.bind(0, resolve))
  const port = blackhole.address().port
  try {
    const shipper = new TftpLogShipper({ host: '127.0.0.1', port, timeoutMs: 100, maxRetries: 1 })
    await assert.rejects(shipper.ship('data', 'never.jsonl'), /timed out/)
  } finally {
    blackhole.close()
  }
})

// ---- A minimal in-process FTP server (RFC 959): USER/PASS/TYPE/PASV/STOR/QUIT only ----

function startFtpTestServer () {
  const received = new Map()
  const server = net.createServer((socket) => {
    socket.write('220 test FTP ready\r\n')
    let dataServer = null

    socket.on('data', (chunk) => {
      const line = chunk.toString('utf8').trim()
      const [cmd, ...rest] = line.split(' ')
      const arg = rest.join(' ')

      if (cmd === 'USER') socket.write('331 need password\r\n')
      else if (cmd === 'PASS') socket.write('230 logged in\r\n')
      else if (cmd === 'TYPE') socket.write('200 type set\r\n')
      else if (cmd === 'PASV') {
        dataServer = net.createServer((dataSocket) => {
          const chunks = []
          dataSocket.on('data', (c) => chunks.push(c))
          dataSocket.on('end', () => {
            received.set(dataServer._pendingFileName, Buffer.concat(chunks))
          })
        })
        dataServer.listen(0, '127.0.0.1', () => {
          const port = dataServer.address().port
          const p1 = Math.floor(port / 256)
          const p2 = port % 256
          socket.write(`227 Entering Passive Mode (127,0,0,1,${p1},${p2}).\r\n`)
        })
      } else if (cmd === 'STOR') {
        if (dataServer) dataServer._pendingFileName = arg
        socket.write('150 opening data connection\r\n')
        // Real servers send 226 once the data connection closes; a short
        // fixed delay is enough for this test's tiny payloads.
        setTimeout(() => socket.write('226 transfer complete\r\n'), 50)
      } else if (cmd === 'QUIT') {
        socket.write('221 bye\r\n')
        socket.end()
        if (dataServer) dataServer.close()
      }
    })
  })

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      received,
      close: () => server.close()
    }))
  })
}

test('FtpLogShipper: logs in, goes passive, and STORs a batch that the server receives byte-for-byte', async () => {
  const server = await startFtpTestServer()
  try {
    const shipper = new FtpLogShipper({ host: '127.0.0.1', port: server.port, remoteDir: '/logs', timeoutMs: 2000 })
    await shipper.ship('{"type":"mfa.enrolled"}\n', 'batch-1.jsonl')
    assert.equal(server.received.get('/logs/batch-1.jsonl').toString('utf8'), '{"type":"mfa.enrolled"}\n')
  } finally {
    server.close()
  }
})

test('FtpLogShipper: rejects when the control connection refuses login', async () => {
  const server = net.createServer((socket) => {
    socket.write('220 test FTP ready\r\n')
    socket.on('data', (chunk) => {
      if (chunk.toString().startsWith('USER')) socket.write('530 login incorrect\r\n')
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    const shipper = new FtpLogShipper({ host: '127.0.0.1', port: server.address().port, timeoutMs: 2000 })
    await assert.rejects(shipper.ship('data', 'x.jsonl'), /expected 230\/331/)
  } finally {
    server.close()
  }
})

// ---- ScpLogShipper: verify safe argv construction against a fake `scp` ----

async function makeFakeScpBinary (argvLogPath) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-fakescp-'))
  const fakeScpPath = path.join(tmpDir, 'fake-scp.js')
  await fs.writeFile(fakeScpPath, [
    '#!/usr/bin/env node',
    'const fs = require("fs");',
    `fs.writeFileSync(${JSON.stringify(argvLogPath)}, JSON.stringify(process.argv.slice(2)));`,
    'process.exit(0);',
    ''
  ].join('\n'))
  await fs.chmod(fakeScpPath, 0o755)
  return { tmpDir, fakeScpPath }
}

test('ScpLogShipper: invokes the binary with array args (no shell) — a filename with shell metacharacters reaches it as one literal argv entry, and StrictHostKeyChecking is left alone by default', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-fakescp-'))
  const argvLogPath = path.join(tmpDir, 'argv.json')
  const { fakeScpPath } = await makeFakeScpBinary(argvLogPath)

  const shipper = new ScpLogShipper({
    host: 'log-server.internal',
    user: 'auditshipper',
    remoteDir: '/var/log/auth-audit',
    identityFile: '/home/svc/.ssh/id_ed25519',
    scpBinary: fakeScpPath
  })

  // A filename with shell metacharacters — must reach the fake script as
  // ONE literal argv entry, never interpreted, because execFile never
  // invokes a shell.
  const trickyFileName = 'batch-$(rm -rf ~).jsonl; echo pwned.jsonl'
  await shipper.ship('{"type":"test"}\n', trickyFileName)

  const argv = JSON.parse(await fs.readFile(argvLogPath, 'utf8'))
  assert.ok(argv.some((a) => a.endsWith(trickyFileName)), 'the tricky filename must appear as a literal argv entry')
  assert.ok(argv.includes('BatchMode=yes'), 'BatchMode=yes must be present (non-interactive)')
  assert.ok(argv.includes('-i') && argv.includes('/home/svc/.ssh/id_ed25519'), 'identity file must be passed through')
  assert.ok(!argv.includes('StrictHostKeyChecking=no'), 'must NOT disable host-key checking unless explicitly opted in')

  await fs.rm(tmpDir, { recursive: true, force: true })
})

test('ScpLogShipper: allowUnknownHostKey:true adds StrictHostKeyChecking=no to the actual invocation', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'local-srp-auth-fakescp-'))
  const argvLogPath = path.join(tmpDir, 'argv.json')
  const { fakeScpPath } = await makeFakeScpBinary(argvLogPath)

  const shipper = new ScpLogShipper({
    host: 'h', user: 'u', remoteDir: '/d', scpBinary: fakeScpPath, allowUnknownHostKey: true
  })
  await shipper.ship('data', 'x.jsonl')

  const argv = JSON.parse(await fs.readFile(argvLogPath, 'utf8'))
  assert.ok(argv.includes('StrictHostKeyChecking=no'))

  await fs.rm(tmpDir, { recursive: true, force: true })
})

test('ScpLogShipper: constructor options round-trip onto the instance', () => {
  const withFlag = new ScpLogShipper({ host: 'h', user: 'u', remoteDir: '/d', allowUnknownHostKey: true })
  const withoutFlag = new ScpLogShipper({ host: 'h', user: 'u', remoteDir: '/d' })
  assert.equal(withFlag._allowUnknownHostKey, true)
  assert.equal(withoutFlag._allowUnknownHostKey, false)
})

test('ScpLogShipper: requires host, user, and remoteDir', () => {
  assert.throws(() => new ScpLogShipper({ user: 'u', remoteDir: '/d' }), /host/)
  assert.throws(() => new ScpLogShipper({ host: 'h', remoteDir: '/d' }), /user/)
  assert.throws(() => new ScpLogShipper({ host: 'h', user: 'u' }), /remoteDir/)
})

// ---- ShippingAuditLogger: queueing, batching, retry-on-failure ----

class RecordingLocalLogger extends AuditLogger {
  constructor () { super(); this.events = [] }
  async log (event) { this.events.push(event) }
}

class FakeShipper {
  constructor () { this.batches = [] }
  async ship (batchText, fileName) { this.batches.push({ batchText, fileName }) }
}

class FailingShipper {
  async ship () { throw new Error('destination unreachable') }
}

test('ShippingAuditLogger: local logging always happens, independent of shipping', async () => {
  const local = new RecordingLocalLogger()
  const shipping = new ShippingAuditLogger({ localLogger: local, shippers: [] })
  await shipping.log({ type: 'user.login.success' })
  assert.equal(local.events.length, 1)
})

test('ShippingAuditLogger: flush ships the queued batch and clears the queue on success', async () => {
  const shipper = new FakeShipper()
  const shipping = new ShippingAuditLogger({ localLogger: new RecordingLocalLogger(), shippers: [shipper] })
  await shipping.log({ type: 'a' })
  await shipping.log({ type: 'b' })
  await shipping.flush()

  assert.equal(shipper.batches.length, 1)
  const lines = shipper.batches[0].batchText.trim().split('\n').map((l) => JSON.parse(l))
  assert.deepEqual(lines.map((l) => l.type), ['a', 'b'])

  await shipping.flush() // nothing left to ship
  assert.equal(shipper.batches.length, 1)
})

test('ShippingAuditLogger: a failing shipper keeps the batch queued for retry, and logs a shipping.failure locally', async () => {
  const local = new RecordingLocalLogger()
  const shipping = new ShippingAuditLogger({ localLogger: local, shippers: [new FailingShipper()] })
  await shipping.log({ type: 'a' })
  await shipping.flush()

  assert.ok(local.events.some((e) => e.type === 'audit.shipping.failure'))

  // Still queued: a later flush against a working shipper should still succeed.
  const workingShipper = new FakeShipper()
  shipping._shippers = [workingShipper]
  await shipping.flush()
  assert.equal(workingShipper.batches.length, 1)
})

test('ShippingAuditLogger: ships to multiple configured shippers, and one failing does not block the others', async () => {
  const good = new FakeShipper()
  const bad = new FailingShipper()
  const shipping = new ShippingAuditLogger({ localLogger: new RecordingLocalLogger(), shippers: [good, bad] })
  await shipping.log({ type: 'a' })
  await shipping.flush()
  assert.equal(good.batches.length, 1)
})

test('ShippingAuditLogger: queue overflow drops the oldest events and logs a warning locally', async () => {
  const local = new RecordingLocalLogger()
  const shipping = new ShippingAuditLogger({ localLogger: local, shippers: [], maxQueueSize: 3 })
  for (let i = 0; i < 5; i++) await shipping.log({ type: 'x', i })
  assert.equal(shipping._queue.length, 3)
  assert.deepEqual(shipping._queue.map((e) => e.i), [2, 3, 4])
  assert.ok(local.events.some((e) => e.type === 'audit.shipping.queue_overflow'))
})

test('ShippingAuditLogger: start()/stop() is a no-op with no shippers configured (no dangling timer)', () => {
  const shipping = new ShippingAuditLogger({ shippers: [] })
  shipping.start()
  assert.equal(shipping._timer, null)
  shipping.stop() // must not throw
})
