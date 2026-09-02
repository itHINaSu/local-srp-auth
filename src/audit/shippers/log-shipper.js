// Log-shipper contract. A shipper's only job is "take this batch of
// already-serialized log lines and get them onto a remote server" — it
// doesn't know about AuditLogger, queuing, retry policy, or batching;
// that's ShippingAuditLogger's job (see ../shipping-audit-logger.js).
// This split is what lets TFTP/FTP/SCP (or a shipper you write yourself)
// all plug into the same queue/retry/backoff machinery instead of each
// reimplementing it.

class LogShipper {
  /**
   * @param {string} batchText newline-delimited JSON, one audit event per line
   * @param {string} fileName suggested remote file name (shippers that
   *   write whole files, like TFTP/FTP/SCP, should use this; a shipper
   *   with real append/streaming semantics can ignore it)
   * @returns {Promise<void>} resolves once the remote server has
   *   acknowledged receipt; throws on any failure (network, auth,
   *   protocol error) so ShippingAuditLogger knows to retry/back off
   *   rather than silently losing the batch.
   */
  async ship (batchText, fileName) { throw new Error('LogShipper.ship() is not implemented') }
}

export { LogShipper }
