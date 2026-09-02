// Wraps a local AuditLogger (ConsoleAuditLogger by default) and, on an
// interval, batches queued events and hands them to one or more
// LogShipper destinations (TFTP/FTP/SCP, or your own). Local logging
// always happens synchronously with the auth flow; shipping never does
// — it's queued and flushed on a timer, so a slow or unreachable log
// server degrades to "shipping is delayed" or "the queue fills up and
// oldest entries drop," never "logins stop working." That degradation
// path is deliberate: an audit log server should never become a way to
// take down authentication for everyone by taking down or overloading a
// side channel.

import crypto from 'node:crypto'
import { AuditLogger, ConsoleAuditLogger } from './audit-logger.js'

const DEFAULT_FLUSH_INTERVAL_MS = 30 * 1000
const DEFAULT_MAX_BATCH_SIZE = 500
const DEFAULT_MAX_QUEUE_SIZE = 10000

class ShippingAuditLogger extends AuditLogger {
  /**
   * @param {object} opts
   * @param {AuditLogger} [opts.localLogger] logged to synchronously on every event, regardless of shipping outcome
   * @param {import('./shippers/log-shipper').LogShipper[]} [opts.shippers] destinations to ship each batch to; empty by default (shipping is opt-in)
   * @param {number} [opts.flushIntervalMs]
   * @param {number} [opts.maxBatchSize] events per flush, per shipper
   * @param {number} [opts.maxQueueSize] oldest events are dropped (with a local warning) once exceeded, so an unreachable log server can't grow this without bound
   * @param {string} [opts.fileNamePrefix] remote file names are `${fileNamePrefix}-<timestamp>-<random>.jsonl`
   */
  constructor ({
    localLogger = new ConsoleAuditLogger(),
    shippers = [],
    flushIntervalMs = DEFAULT_FLUSH_INTERVAL_MS,
    maxBatchSize = DEFAULT_MAX_BATCH_SIZE,
    maxQueueSize = DEFAULT_MAX_QUEUE_SIZE,
    fileNamePrefix = 'auth-audit'
  } = {}) {
    super()
    this._localLogger = localLogger
    this._shippers = shippers
    this._flushIntervalMs = flushIntervalMs
    this._maxBatchSize = maxBatchSize
    this._maxQueueSize = maxQueueSize
    this._fileNamePrefix = fileNamePrefix
    this._queue = []
    this._timer = null
    this._flushing = false
  }

  async log (event) {
    await this._localLogger.log(event)

    this._queue.push(event)
    if (this._queue.length > this._maxQueueSize) {
      const dropped = this._queue.length - this._maxQueueSize
      this._queue.splice(0, dropped)
      await this._localLogger.log({
        type: 'audit.shipping.queue_overflow',
        timestamp: new Date().toISOString(),
        details: { droppedCount: dropped, maxQueueSize: this._maxQueueSize }
      })
    }
  }

  /** Starts the periodic flush timer. No-op if there are no shippers configured. */
  start () {
    if (this._shippers.length === 0 || this._timer) return
    this._timer = setInterval(() => { this.flush().catch(() => {}) }, this._flushIntervalMs)
    this._timer.unref?.() // never keep the process alive just for this
  }

  stop () {
    if (this._timer) clearInterval(this._timer)
    this._timer = null
  }

  /**
   * Ships up to `maxBatchSize` queued events to every configured
   * shipper. Removes them from the queue if at least one shipper
   * accepted the batch (or if there are no shippers); otherwise leaves
   * them queued for the next flush. Safe to call directly (e.g. before
   * process shutdown) in addition to the periodic timer.
   */
  async flush () {
    if (this._flushing || this._queue.length === 0) return
    this._flushing = true
    try {
      const batch = this._queue.slice(0, this._maxBatchSize)
      if (batch.length === 0) return

      if (this._shippers.length === 0) {
        this._queue.splice(0, batch.length)
        return
      }

      const batchText = batch.map((e) => JSON.stringify(e)).join('\n') + '\n'
      const fileName = `${this._fileNamePrefix}-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(4).toString('hex')}.jsonl`

      const results = await Promise.allSettled(this._shippers.map((shipper) => shipper.ship(batchText, fileName)))
      const anySucceeded = results.some((r) => r.status === 'fulfilled')

      for (const [i, result] of results.entries()) {
        if (result.status === 'rejected') {
          await this._localLogger.log({
            type: 'audit.shipping.failure',
            timestamp: new Date().toISOString(),
            details: { shipperIndex: i, error: String(result.reason?.message || result.reason) }
          })
        }
      }

      if (anySucceeded) this._queue.splice(0, batch.length)
    } finally {
      this._flushing = false
    }
  }
}

export { ShippingAuditLogger }
