import type { RememberBlock } from '../domain/vault/model.js'
import { REMEMBER_BLOCK_VERSION, REMEMBER_DAY_MS } from '../domain/vault/model.js'
import { rememberActive } from './remember-service.js'

export interface LockoutSnapshot {
  failures: number
  lockedUntil: number
  retryAfterMs: number
  locked: boolean
}

export interface RememberSnapshot {
  days: number
  active: boolean
  issuedAt: number | null
  expiresAt: number | null
}

/** Build a Web-safe lockout view. */
export function lockoutSnapshot(failures: number, lockedUntil: number, now: number = Date.now()): LockoutSnapshot {
  const retryAfterMs = Math.max(0, lockedUntil - now)
  return { failures, lockedUntil, retryAfterMs, locked: retryAfterMs > 0 }
}

/** Select and bound the runtime remember setting over its configured default. */
export function effectiveRememberDays(runtimeDays: number | undefined, configuredDays: number): number {
  const value = runtimeDays ?? configuredDays
  return Number.isInteger(value) && value >= -1 && value <= 30 ? value : 0
}

/** Build a Web-safe remembered-login view. */
export function rememberSnapshot(
  days: number,
  block: RememberBlock | undefined,
  now: number = Date.now(),
): RememberSnapshot {
  const active =
    days !== 0 &&
    block !== void 0 &&
    block.version === REMEMBER_BLOCK_VERSION &&
    block.days === days &&
    rememberActive(block, now)
  return {
    days,
    active,
    issuedAt: block?.issuedAt ?? null,
    expiresAt: block !== void 0 && block.days !== -1 ? block.issuedAt + block.days * REMEMBER_DAY_MS : null,
  }
}
