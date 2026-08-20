import type { LeakGuard } from './leak-guard.js'
import {
  EncryptController as RuntimeEncryptController,
  resolveSpec as runtimeResolveSpec,
} from './fabric-controller-runtime.js'

// The controller implementation is kept in a compatibility JavaScript module so
// the upstream tsdown declaration pass does not have to infer hundreds of legacy
// lifecycle methods. The public constructor and path helpers remain typed here.

/** Runtime configuration accepted by the Fabric sidecar adapter. */
export interface FabricConfig {
  path?: string
  dshHome?: string
  encryptedPath?: string
  statePath?: string
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
  trustedHosts?: string[]
  fabric?: unknown
  [key: string]: unknown
}

/** Resolved sidecar paths and policy values. */
export interface FabricSpec {
  filename: string
  encryptedFilename: string
  stateFile: string
  [key: string]: unknown
}

interface RememberIssue {
  secret: string
  days: number
  issuedAt: number
  expiresAt: number | null
}

type Invoke = (...args: unknown[]) => unknown

/** Public controller instance surface supplied by the runtime adapter. */
export interface EncryptController {
  config: FabricConfig
  format: 'plain' | 'encrypted'
  unlocked: boolean
  plaintextForbidden: boolean
  leakGuard: LeakGuard
  webInstalled?: boolean
  init: () => Promise<void>
  dispose: () => Promise<void>
  status: () => Promise<Record<string, unknown>>
  afterResolve: (ref: string, result: unknown) => unknown
  afterDescribe: (ref: string, result: unknown) => unknown
  invokeSet: (ref: string, value: string, invoke?: Invoke) => unknown
  invokeUnset: (ref: string, invoke?: Invoke) => unknown
  setPassword: (digest: string) => Promise<Record<string, unknown>>
  changePassword: (oldDigest: string, digest: string) => Promise<Record<string, unknown>>
  unlock: (digest: string) => Promise<Record<string, unknown>>
  unlockWithRemember: (secretText: string) => Promise<Record<string, unknown>>
  setRememberDays: (days: unknown) => Promise<RememberIssue | null>
  issueRemember: () => Promise<RememberIssue | null>
}

type EncryptControllerConstructor = new (ctx: unknown, config?: FabricConfig) => EncryptController

/** Public controller constructor. */
export const EncryptController = RuntimeEncryptController as EncryptControllerConstructor

/** Resolve official and sidecar paths without changing provider ownership. */
export function resolveSpec(config: FabricConfig = {}): FabricSpec {
  return runtimeResolveSpec(config) as FabricSpec
}
