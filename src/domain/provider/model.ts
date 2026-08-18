/** Public configuration accepted by the encrypted credential provider. */
export interface ProviderConfig {
  path?: string
  dshHome?: string
  allowEnvFallback?: boolean
  passwordEnv?: string
  watch?: boolean
  debounceMs?: number
  rememberDays?: number
  rememberChannel?: 'cookie' | 'header'
  leakGuard?: boolean
  leakMinMaskLength?: number
  leakMaxMaskLength?: number
  maxUnlockAttempts?: number
  lockoutBaseMs?: number
  lockoutMaxMs?: number
}

/** Resolved filesystem and watcher configuration. */
export interface ProviderSpec {
  filename: string
  stateFile: string
  allowEnvFallback: boolean
  passwordEnv: string
  watch: boolean
  debounceMs: number
}

export type NormalizedProviderConfig = ProviderConfig & Required<Omit<ProviderConfig, 'path' | 'dshHome'>>

/** One newly issued remembered-login ticket. */
export interface RememberIssue {
  secret: string
  days: number
  issuedAt: number
  expiresAt: number | null
}

/** Web-facing provider state without credential material. */
export interface ProviderStatus {
  format: 'plain' | 'encrypted'
  unlocked: boolean
  plaintextForbidden: boolean
  remember: { days: number; active: boolean; issuedAt: number | null; expiresAt: number | null }
  lockout: { failures: number; lockedUntil: number; retryAfterMs: number; locked: boolean }
  leakGuard: { enabled: boolean; masks: number }
  rememberChannel: 'cookie' | 'header'
}

export const CREDENTIALS_FILENAME = '.credentials.yaml' as const
export const DEFAULT_PASSWORD_ENV = 'DSH_CREDENTIAL_PASSWORD' as const
