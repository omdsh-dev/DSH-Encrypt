// @ts-nocheck
import z from "@deepseek-ai/schemastery";
import { getFabric } from "@oh-my-dsh/cordis-fabric";
import { loadAndVerifyIntegrity } from "./integrity.js";
import { assertRuntimeCompat } from "./compat.js";
import { apply as applyWeb } from "./web.js";
import { EncryptController, resolveSpec } from "./fabric-controller.js";
import { PATCH_IDS, PATCH_OPERATIONS, patchStubs, registerFabricPatches } from "./fabric-handlers.js";

// The root entry is the thin Fabric adapter. Crypto, persistence, lockout and
// redaction live in separate modules so this file never replaces the official
// credentials provider or reimplements its lifecycle.
loadAndVerifyIntegrity(import.meta.url);
assertRuntimeCompat();

export const name = "dsh-encrypt-fabric";
export const inject = ["credentials"];

/** Configuration for the Fabric controller; the official provider uses the same path/dshHome values. */
export const Config = z.object({
  path: z.string().default(""),
  dshHome: z.string().default(""),
  encryptedPath: z.string().default(""),
  statePath: z.string().default(""),
  allowEnvFallback: z.boolean().default(true),
  passwordEnv: z.string().default("DSH_CREDENTIAL_PASSWORD"),
  watch: z.boolean().default(true),
  debounceMs: z.number().min(0).default(100),
  rememberDays: z.number().min(-1).max(30).default(0),
  leakGuard: z.boolean().default(true),
  leakMinMaskLength: z.number().min(4).max(64).default(8),
  leakMaxMaskLength: z.number().min(16).max(1024).default(256),
  maxUnlockAttempts: z.number().min(1).default(5),
  lockoutBaseMs: z.number().min(1000).default(30000),
  lockoutMaxMs: z.number().min(1000).default(900000),
  trustedHosts: z.array(String).default([]),
  // Fabric consumes this raw descriptor block before plugin apply; retaining it
  // in the row schema prevents a strict config codec from dropping metadata.
  fabric: z.any(),
});

/**
 * Mount the sidecar controller and register trusted Fabric handlers on this
 * plugin fiber. Plain dsh skips this Fabric-required row; no replacement
 * credentials provider is mounted here.
 */
export async function apply(ctx, config = {}) {
  const controller = new EncryptController(ctx, config);
  await controller.init();
  ctx.provide("dshEncrypt", controller);
  ctx.effect(() => () => controller.dispose(), "dsh-encrypt: controller");
  const fabric = getFabric(ctx);
  registerFabricPatches(fabric, controller);
  const installWeb = (webCtx) => {
    if (controller.webInstalled === true) return;
    controller.webInstalled = true;
    applyWeb({ ...webCtx, credentials: controller }, config);
  };
  ctx.inject(["webServer"], installWeb);
  ctx.inject(["httpServer"], installWeb);
}

export {
  EncryptController,
  PATCH_IDS,
  PATCH_OPERATIONS,
  patchStubs,
  registerFabricPatches,
  resolveSpec,
};
