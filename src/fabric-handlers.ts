import type { LeakGuard } from './leak-guard.js'
import type { HttpHandler, UpgradeRoute } from './transport/http/model.js'
import { redactingHttpHandler, redactingUpgradeRoute } from './web.js'

/** Stable ids shared by cordis.patch.yml and runtime registration. */
export const PATCH_IDS: Readonly<{
  credentialsResolve: 'dsh-encrypt/credentials-resolve'
  credentialsDescribe: 'dsh-encrypt/credentials-describe'
  credentialsSet: 'dsh-encrypt/credentials-set'
  credentialsUnset: 'dsh-encrypt/credentials-unset'
  webserverHttpRegister: 'dsh-encrypt/webserver-http-register'
  webserverUpgradeRegister: 'dsh-encrypt/webserver-upgrade-register'
}> = Object.freeze({
  credentialsResolve: 'dsh-encrypt/credentials-resolve',
  credentialsDescribe: 'dsh-encrypt/credentials-describe',
  credentialsSet: 'dsh-encrypt/credentials-set',
  credentialsUnset: 'dsh-encrypt/credentials-unset',
  webserverHttpRegister: 'dsh-encrypt/webserver-http-register',
  webserverUpgradeRegister: 'dsh-encrypt/webserver-upgrade-register',
})

export const PATCH_OPERATIONS: Readonly<{
  credentialsResolve: 'after'
  credentialsDescribe: 'after'
  credentialsSet: 'around'
  credentialsUnset: 'around'
  webserverHttpRegister: 'before'
  webserverUpgradeRegister: 'before'
}> = Object.freeze({
  credentialsResolve: 'after',
  credentialsDescribe: 'after',
  credentialsSet: 'around',
  credentialsUnset: 'around',
  webserverHttpRegister: 'before',
  webserverUpgradeRegister: 'before',
})

type PatchOperation = (typeof PATCH_OPERATIONS)[keyof typeof PATCH_OPERATIONS]
type FunctionKind = 'Async' | 'Sync'

interface PatchTarget {
  module: string
  versionRange: string
  filePaths: string[]
  functionQuery: {
    methodName: string
    kind: FunctionKind
  }
}

export interface PatchStub {
  id: string
  required: boolean
  target: PatchTarget
  operation: PatchOperation
}

interface FabricCall {
  arguments: unknown[]
  result?: unknown
}

type Invoke = (...args: unknown[]) => unknown

type FabricHandler = (call: FabricCall, invoke?: Invoke) => unknown

interface FabricRegistry {
  register: (descriptor: PatchStub & { handler: FabricHandler }) => unknown
}

interface FabricController {
  leakGuard: LeakGuard
  afterResolve: (ref: string, result: unknown) => unknown
  afterDescribe: (ref: string, result: unknown) => unknown
  invokeSet: (ref: string, value: string, invoke: Invoke | undefined) => unknown
  invokeUnset: (ref: string, invoke: Invoke | undefined) => unknown
}

const LOCAL_TARGET: PatchTarget = {
  module: '@deepseek-ai/dsh-credentials-local',
  // Covers the rc.6 package currently used by this plugin and the source/lib
  // launch forms used by fabric-dsh. Tighten this range when the host API is
  // published under a new incompatible major/minor.
  versionRange: '>=0.0.1-0 <0.2.0',
  filePaths: ['src/index.ts', 'lib/index.js'],
  functionQuery: { methodName: '', kind: 'Async' },
}

const WEBSERVER_TARGET: PatchTarget = {
  module: '@deepseek-ai/dsh-host-webserver',
  versionRange: '>=0.0.1-0 <0.2.0',
  filePaths: ['src/index.ts', 'lib/index.js'],
  functionQuery: { methodName: '', kind: 'Sync' },
}

function methodTarget(base: PatchTarget, methodName: string, kind: FunctionKind): PatchTarget {
  return { ...base, functionQuery: { methodName, kind } }
}

/** Declarative descriptors emitted into the bundle profile layer. */
export function patchStubs(): PatchStub[] {
  return [
    {
      id: PATCH_IDS.credentialsResolve,
      required: true,
      target: methodTarget(LOCAL_TARGET, 'resolve', 'Async'),
      operation: PATCH_OPERATIONS.credentialsResolve,
    },
    {
      id: PATCH_IDS.credentialsDescribe,
      required: true,
      target: methodTarget(LOCAL_TARGET, 'describe', 'Async'),
      operation: PATCH_OPERATIONS.credentialsDescribe,
    },
    {
      id: PATCH_IDS.credentialsSet,
      required: true,
      target: methodTarget(LOCAL_TARGET, 'set', 'Async'),
      operation: PATCH_OPERATIONS.credentialsSet,
    },
    {
      id: PATCH_IDS.credentialsUnset,
      required: true,
      target: methodTarget(LOCAL_TARGET, 'unset', 'Async'),
      operation: PATCH_OPERATIONS.credentialsUnset,
    },
    {
      id: PATCH_IDS.webserverHttpRegister,
      required: false,
      target: methodTarget(WEBSERVER_TARGET, 'register', 'Sync'),
      operation: PATCH_OPERATIONS.webserverHttpRegister,
    },
    {
      id: PATCH_IDS.webserverUpgradeRegister,
      required: false,
      target: methodTarget(WEBSERVER_TARGET, 'registerUpgrade', 'Sync'),
      operation: PATCH_OPERATIONS.webserverUpgradeRegister,
    },
  ]
}

/**
 * Register trusted handlers on the current plugin fiber. The YAML/profile
 * carries only patch metadata; executable behavior is assembled here.
 */
export function registerFabricPatches(fabric: FabricRegistry, controller: FabricController): PatchStub[] {
  const descriptors = patchStubs()
  const byId = new Map(descriptors.map(patch => [patch.id, patch]))
  const register = (id: string, handler: FabricHandler): void => {
    const descriptor = byId.get(id)
    if (descriptor === undefined) throw new Error(`dsh-encrypt: missing Fabric descriptor ${id}`)
    fabric.register({ ...descriptor, handler })
  }

  register(PATCH_IDS.credentialsResolve, call => {
    const ref = call.arguments[0] as string
    return controller.afterResolve(ref, call.result)
  })
  register(PATCH_IDS.credentialsDescribe, call => {
    const ref = call.arguments[0] as string
    return controller.afterDescribe(ref, call.result)
  })
  register(PATCH_IDS.credentialsSet, (call, invoke) => {
    const ref = call.arguments[0] as string
    const value = call.arguments[1] as string
    return controller.invokeSet(ref, value, invoke)
  })
  register(PATCH_IDS.credentialsUnset, (call, invoke) => {
    const ref = call.arguments[0] as string
    return controller.invokeUnset(ref, invoke)
  })
  register(PATCH_IDS.webserverHttpRegister, call => {
    const route = call.arguments[0] as { handler?: unknown } & Record<string, unknown>
    if (typeof route?.handler === 'function') {
      call.arguments[0] = {
        ...route,
        handler: redactingHttpHandler(route.handler as HttpHandler, controller.leakGuard),
      }
    }
  })
  register(PATCH_IDS.webserverUpgradeRegister, call => {
    const route = call.arguments[0] as UpgradeRoute
    if (typeof route?.handler === 'function') call.arguments[0] = redactingUpgradeRoute(route, controller.leakGuard)
  })

  return descriptors
}

export { LOCAL_TARGET, WEBSERVER_TARGET }
