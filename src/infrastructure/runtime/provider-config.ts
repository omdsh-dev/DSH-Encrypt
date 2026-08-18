import type { NormalizedProviderConfig, ProviderConfig, ProviderSpec } from '../../domain/provider/model.js'
import { join, resolve } from 'node:path'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV } from '../../domain/provider/model.js'

/** Apply provider defaults once at the composition boundary. */
export function normalizeProviderConfig(config: ProviderConfig = {}): NormalizedProviderConfig {
  const leakMinMaskLength = boundedInteger(config.leakMinMaskLength, 8, 4, 64)
  const leakMaxMaskLength = Math.max(leakMinMaskLength, boundedInteger(config.leakMaxMaskLength, 256, 16, 1024))
  const lockoutBaseMs = boundedInteger(config.lockoutBaseMs, 30000, 1000, 3_600_000)
  return {
    ...config,
    allowEnvFallback: config.allowEnvFallback ?? true,
    passwordEnv: config.passwordEnv ?? DEFAULT_PASSWORD_ENV,
    watch: config.watch ?? true,
    debounceMs: boundedInteger(config.debounceMs, 100, 0, 60_000),
    rememberDays: boundedInteger(config.rememberDays, 0, -1, 30),
    rememberChannel: config.rememberChannel === 'header' ? 'header' : 'cookie',
    leakGuard: config.leakGuard ?? true,
    leakMinMaskLength,
    leakMaxMaskLength,
    maxUnlockAttempts: boundedInteger(config.maxUnlockAttempts, 5, 1, 32),
    lockoutBaseMs,
    lockoutMaxMs: Math.max(lockoutBaseMs, boundedInteger(config.lockoutMaxMs, 900000, 1000, 86_400_000)),
  }
}

function boundedInteger(value: unknown, fallback: number, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) return fallback
  return Math.min(maximum, Math.max(minimum, value))
}

/** Resolve the credential and runtime-state files from provider config. */
export function resolveSpec(config: ProviderConfig = {}): ProviderSpec {
  const home = resolveDshHome(config.dshHome)
  return {
    filename: resolve(config.path ?? join(home, CREDENTIALS_FILENAME)),
    stateFile: resolve(join(home, '.dsh-encrypt.json')),
    allowEnvFallback: config.allowEnvFallback ?? true,
    passwordEnv: config.passwordEnv ?? DEFAULT_PASSWORD_ENV,
    watch: config.watch ?? true,
    debounceMs: config.debounceMs ?? 100,
  }
}
