import type { StentConfig } from './fabric-controller.js'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { getStent } from '@oh-my-dsh/stent'
import { assertRuntimeCompat } from './compat.js'
import { EncryptController, resolveSpec } from './fabric-controller.js'
import { PATCH_IDS, PATCH_OPERATIONS, patchStubs, registerStentPatches } from './fabric-handlers.js'
import { loadAndVerifyIntegrity } from './integrity.js'
import { apply as applyWeb } from './web.js'

// The root entry is the thin Stent adapter. Crypto, persistence, lockout and
// redaction live in separate modules so this file never replaces the official
// credentials provider or reimplements its lifecycle.
loadAndVerifyIntegrity(import.meta.url)
assertRuntimeCompat()

export const name: string = 'dsh-encrypt-fabric'
export const inject: readonly ['credentials'] = ['credentials']

/** Configuration for the Stent controller; the official provider uses the same path/dshHome values. */
export const Config: ReturnType<typeof z.object> = z.object({
  path: z.string().default(''),
  dshHome: z.string().default(''),
  encryptedPath: z.string().default(''),
  statePath: z.string().default(''),
  allowEnvFallback: z.boolean().default(true),
  passwordEnv: z.string().default('DSH_CREDENTIAL_PASSWORD'),
  watch: z.boolean().default(true),
  debounceMs: z.number().min(0).default(100),
  rememberDays: z.number().min(-1).max(30).default(0),
  rememberChannel: z.union([z.const('cookie'), z.const('header')]).default('cookie'),
  leakGuard: z.boolean().default(true),
  leakMinMaskLength: z.number().min(4).max(64).default(8),
  leakMaxMaskLength: z.number().min(16).max(1024).default(256),
  maxUnlockAttempts: z.number().min(1).default(5),
  lockoutBaseMs: z.number().min(1000).default(30000),
  lockoutMaxMs: z.number().min(1000).default(900000),
  trustedHosts: z.array(String).default([]),
  // Stent consumes this raw descriptor block before plugin apply; retaining it
  // in the row schema prevents a strict config codec from dropping metadata.
  stent: z.any(),
})

/**
 * Mount the sidecar controller and register trusted Stent handlers on this
 * plugin fiber. Plain dsh skips this Stent-required row; no replacement
 * credentials provider is mounted here.
 */
export async function apply(ctx: Context, config: StentConfig = {}): Promise<void> {
  const controller = new EncryptController(ctx, config)
  await controller.init()
  ctx.provide('dshEncrypt', controller)
  ctx.effect(() => () => controller.dispose(), 'dsh-encrypt: controller')
  const stent = getStent(ctx)
  registerStentPatches(stent, controller)
  const installWeb = (webCtx: Context): void => {
    if (controller.webInstalled === true) return
    controller.webInstalled = true
    const webContext = { ...webCtx, credentials: controller } as unknown as Parameters<typeof applyWeb>[0]
    applyWeb(webContext, config)
  }
  ctx.inject(['webServer'], installWeb)
  ctx.inject(['httpServer'], installWeb)
}

export { EncryptController, PATCH_IDS, PATCH_OPERATIONS, patchStubs, registerStentPatches, resolveSpec }
