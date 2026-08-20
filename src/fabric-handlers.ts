// @ts-nocheck
import {
  redactingHttpHandler,
  redactingUpgradeRoute,
} from "./web.js";

/** Stable ids shared by cordis.patch.yml and runtime registration. */
export const PATCH_IDS = Object.freeze({
  credentialsResolve: "dsh-encrypt/credentials-resolve",
  credentialsDescribe: "dsh-encrypt/credentials-describe",
  credentialsSet: "dsh-encrypt/credentials-set",
  credentialsUnset: "dsh-encrypt/credentials-unset",
  webserverHttpRegister: "dsh-encrypt/webserver-http-register",
  webserverUpgradeRegister: "dsh-encrypt/webserver-upgrade-register",
});

export const PATCH_OPERATIONS = Object.freeze({
  credentialsResolve: "after",
  credentialsDescribe: "after",
  credentialsSet: "around",
  credentialsUnset: "around",
  webserverHttpRegister: "before",
  webserverUpgradeRegister: "before",
});

const LOCAL_TARGET = {
  module: "@deepseek-ai/dsh-credentials-local",
  // Covers the rc.6 package currently used by this plugin and the source/lib
  // launch forms used by fabric-dsh. Tighten this range when the host API is
  // published under a new incompatible major/minor.
  versionRange: ">=0.0.1-0 <0.2.0",
  filePaths: ["src/index.ts", "lib/index.js"],
};

const WEBSERVER_TARGET = {
  module: "@deepseek-ai/dsh-host-webserver",
  versionRange: ">=0.0.1-0 <0.2.0",
  filePaths: ["src/index.ts", "lib/index.js"],
};

function methodTarget(base, methodName, kind) {
  return { ...base, functionQuery: { methodName, kind } };
}

/** Declarative descriptors emitted into the bundle profile layer. */
export function patchStubs() {
  return [
    {
      id: PATCH_IDS.credentialsResolve,
      required: true,
      target: methodTarget(LOCAL_TARGET, "resolve", "Async"),
      operation: PATCH_OPERATIONS.credentialsResolve,
    },
    {
      id: PATCH_IDS.credentialsDescribe,
      required: true,
      target: methodTarget(LOCAL_TARGET, "describe", "Async"),
      operation: PATCH_OPERATIONS.credentialsDescribe,
    },
    {
      id: PATCH_IDS.credentialsSet,
      required: true,
      target: methodTarget(LOCAL_TARGET, "set", "Async"),
      operation: PATCH_OPERATIONS.credentialsSet,
    },
    {
      id: PATCH_IDS.credentialsUnset,
      required: true,
      target: methodTarget(LOCAL_TARGET, "unset", "Async"),
      operation: PATCH_OPERATIONS.credentialsUnset,
    },
    {
      id: PATCH_IDS.webserverHttpRegister,
      required: false,
      target: methodTarget(WEBSERVER_TARGET, "register", "Sync"),
      operation: PATCH_OPERATIONS.webserverHttpRegister,
    },
    {
      id: PATCH_IDS.webserverUpgradeRegister,
      required: false,
      target: methodTarget(WEBSERVER_TARGET, "registerUpgrade", "Sync"),
      operation: PATCH_OPERATIONS.webserverUpgradeRegister,
    },
  ];
}

/**
 * Register trusted handlers on the current plugin fiber. The YAML/profile
 * carries only patch metadata; executable behavior is assembled here.
 */
export function registerFabricPatches(fabric, controller) {
  const descriptors = patchStubs();
  const byId = new Map(descriptors.map((patch) => [patch.id, patch]));
  const register = (id, handler) => fabric.register({ ...byId.get(id), handler });

  register(PATCH_IDS.credentialsResolve, (call) => {
    const ref = call.arguments[0];
    return controller.afterResolve(ref, call.result);
  });
  register(PATCH_IDS.credentialsDescribe, (call) => {
    const ref = call.arguments[0];
    return controller.afterDescribe(ref, call.result);
  });
  register(PATCH_IDS.credentialsSet, (call, invoke) => {
    return controller.invokeSet(call.arguments[0], call.arguments[1], invoke);
  });
  register(PATCH_IDS.credentialsUnset, (call, invoke) => {
    return controller.invokeUnset(call.arguments[0], invoke);
  });
  register(PATCH_IDS.webserverHttpRegister, (call) => {
    const route = call.arguments[0];
    if (route?.handler !== void 0) {
      call.arguments[0] = {
        ...route,
        handler: redactingHttpHandler(route.handler, controller.leakGuard),
      };
    }
  });
  register(PATCH_IDS.webserverUpgradeRegister, (call) => {
    const route = call.arguments[0];
    if (route?.handler !== void 0) call.arguments[0] = redactingUpgradeRoute(route, controller.leakGuard);
  });

  return descriptors;
}

export { LOCAL_TARGET, WEBSERVER_TARGET };
