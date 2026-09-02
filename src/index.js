// Server-side entry point (`import ... from 'local-srp-auth'`). For the
// browser, import 'local-srp-auth/client' instead — that entry never
// pulls in node:crypto or node:fs.

import { AuthServer, publicUser } from './server-auth.js'
import { Bootstrap } from './bootstrap.js'
import GROUPS from './common/groups.js'
import { createNodeCryptoAdapter } from './common/crypto-adapter-node.js'
import * as roles from './roles/roles.js'
import * as totp from './totp/totp.js'
import * as base32 from './totp/base32.js'
import * as recoveryCodes from './totp/recovery-codes.js'
import { UserStore, RoleStore, ChallengeStore, SessionStore } from './storage/storage-interface.js'
import { MemoryUserStore, MemoryRoleStore, MemoryChallengeStore, MemorySessionStore } from './storage/memory-store.js'
import { JsonFileUserStore, JsonFileRoleStore } from './storage/json-file-store.js'
import { RateLimiter, RateLimitExceededError } from './rate-limit/rate-limiter.js'
import { MemoryRateLimiter } from './rate-limit/memory-rate-limiter.js'
import { AuditLogger, ConsoleAuditLogger, NullAuditLogger } from './audit/audit-logger.js'
import { ShippingAuditLogger } from './audit/shipping-audit-logger.js'
import { LogShipper } from './audit/shippers/log-shipper.js'
import { TftpLogShipper } from './audit/shippers/tftp-log-shipper.js'
import { FtpLogShipper } from './audit/shippers/ftp-log-shipper.js'
import { ScpLogShipper } from './audit/shippers/scp-log-shipper.js'
import * as sessionTransport from './session-transport.js'

const storage = {
  UserStore,
  RoleStore,
  ChallengeStore,
  SessionStore,
  MemoryUserStore,
  MemoryRoleStore,
  MemoryChallengeStore,
  MemorySessionStore,
  JsonFileUserStore,
  JsonFileRoleStore
}

const rateLimit = {
  RateLimiter,
  RateLimitExceededError,
  MemoryRateLimiter
}

const audit = {
  AuditLogger,
  ConsoleAuditLogger,
  NullAuditLogger,
  ShippingAuditLogger,
  LogShipper,
  TftpLogShipper,
  FtpLogShipper,
  ScpLogShipper
}

export {
  AuthServer,
  publicUser,
  Bootstrap,
  GROUPS,
  createNodeCryptoAdapter,
  roles,
  totp,
  base32,
  recoveryCodes,
  storage,
  rateLimit,
  audit,
  sessionTransport
}
