// @ts-nocheck
import { watch } from "chokidar";
import { mkdir, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { withFileLock, writeFileAtomic } from "@deepseek-ai/dsh-atomic-write";
import { canonicalizeWatchPath, resolveDshHome } from "@deepseek-ai/dsh-home-paths";
import { launchEnvironmentOf } from "@deepseek-ai/dsh-launch-environment";
import { credentialRef } from "@deepseek-ai/dsh-credentials";
import {
  LEGACY_KDF,
  REMEMBER_DAY_MS,
  VAULT_KDF,
  VaultError,
  createRememberBlock,
  decryptEntry,
  decryptEntryBuffer,
  detectCredentialStore,
  encryptCredentialStore,
  encryptEntry,
  isDigest,
  parseEncryptedStore,
  recoverKeyFromRemember,
  rememberActive,
  serializeEncryptedStore,
  sha3_256Hex,
  unlockEncryptedStore,
  verifyPasswordDigest,
  zeroizeBuffer,
} from "./vault.js";
import { LeakGuard } from "./leak-guard.js";
import { formatLockoutMessage, isLockedOut, recordLockoutFailure } from "./lockout.js";
import { encryptedMarker, isEncryptedMarker, parsePlainEntries } from "./plain.js";

const CREDENTIALS_FILENAME = ".credentials.yaml";
const DEFAULT_PASSWORD_ENV = "DSH_CREDENTIAL_PASSWORD";
const GROUP_OTHER_BITS = 0o077;

/**
 * Resolve the files owned by the Fabric controller. The official provider
 * keeps owning `.credentials.yaml`; the controller owns only the encrypted
 * sidecar and its runtime state.
 */
export function resolveSpec(config = {}) {
  const home = resolveDshHome(config.dshHome || void 0);
  const filename = resolve(config.path || join(home, CREDENTIALS_FILENAME));
  const encryptedFilename = resolve(config.encryptedPath || (
    basename(filename) === CREDENTIALS_FILENAME
      ? join(dirname(filename), ".credentials.encrypt.yaml")
      : `${filename}.encrypt`
  ));
  return {
    filename,
    encryptedFilename,
    stateFile: resolve(config.statePath || join(home, ".dsh-encrypt.json")),
    allowEnvFallback: config.allowEnvFallback ?? true,
    passwordEnv: config.passwordEnv ?? DEFAULT_PASSWORD_ENV,
    watch: config.watch ?? true,
    debounceMs: config.debounceMs ?? 100,
    rememberDays: config.rememberDays ?? 0,
    leakGuard: config.leakGuard ?? true,
    leakMinMaskLength: config.leakMinMaskLength ?? 8,
    leakMaxMaskLength: config.leakMaxMaskLength ?? 256,
    maxUnlockAttempts: config.maxUnlockAttempts ?? 5,
    lockoutBaseMs: config.lockoutBaseMs ?? 30000,
    lockoutMaxMs: config.lockoutMaxMs ?? 900000,
  };
}

/** The sidecar is a secret-bearing file and must be owner-readable only. */
export async function assertOwnerOnly(filename) {
  try {
    const mode = (await stat(filename)).mode;
    if (process.platform !== "win32" && (mode & GROUP_OTHER_BITS) !== 0) {
      throw new Error(`dsh-encrypt: ${filename} is readable beyond its owner (mode ${(mode & 0o777).toString(8)}); run "chmod 600 ${filename}" before starting again`);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    // Keep the same path-canonicalization behavior as credentials-local for a
    // missing file, while allowing the sidecar itself to be created later.
    await canonicalizeWatchPath(filename);
  }
}

function isENOENT(error) {
  return error?.code === "ENOENT";
}

async function readOptional(filename) {
  try {
    return await readFile(filename, "utf8");
  } catch (error) {
    if (isENOENT(error)) return void 0;
    throw error;
  }
}

function changedRefs(previous, next) {
  return [...new Set([...previous.keys(), ...next.keys()])].filter((ref) => previous.get(ref) !== next.get(ref));
}

/**
 * Runtime owner for the encrypted sidecar. It contains no Fabric registration
 * code: handlers call this object, and its lifecycle is scoped by the plugin
 * that provided it.
 */
export class EncryptController {
  constructor(ctx, config = {}) {
    this.ctx = ctx;
    this.config = config;
    const providerPath = ctx.credentials?.spec?.filename;
    this.spec = resolveSpec({ ...config, path: config.path || providerPath });
    this.format = "plain";
    this.unlocked = true;
    this.key = void 0;
    this.salt = void 0;
    this.params = void 0;
    this.kdf = VAULT_KDF;
    this.entries = new Map();
    this.text = void 0;
    this.markerText = void 0;
    this.remember = void 0;
    this.stateRememberDays = void 0;
    this.stateEncrypted = false;
    this.plaintextForbidden = false;
    this.operations = Promise.resolve();
    this.closed = false;
    this.watcher = void 0;
    this.leakGuard = new LeakGuard({
      enabled: this.spec.leakGuard,
      minMaskLength: this.spec.leakMinMaskLength,
      maxMaskLength: this.spec.leakMaxMaskLength,
    });
    this.unlockFailures = 0;
    this.unlockLockedUntil = 0;
  }

  /** Load the sidecar and start only the sidecar/marker watcher. */
  async init() {
    await this.loadStateFile();
    await assertOwnerOnly(this.spec.encryptedFilename);
    const primary = await readOptional(this.spec.filename);
    const sidecar = await readOptional(this.spec.encryptedFilename);

    // A pre-Fabric single-file vault cannot be safely migrated after the
    // official provider has initialized. Fail closed with an explicit action;
    // a future migration command can perform the move before dsh starts.
    if (sidecar === void 0 && primary !== void 0 && detectCredentialStore(primary) === "encrypted") {
      throw new VaultError("VAULT_MIGRATION_REQUIRED", `the legacy encrypted ${this.spec.filename} must be migrated to ${this.spec.encryptedFilename} before starting Fabric dsh-encrypt`);
    }
    if (sidecar !== void 0) {
      if (primary !== void 0 && !isEncryptedMarker(primary)) {
        const plain = parsePlainEntries(primary, this.spec.filename);
        if (plain.size > 0) {
          throw new VaultError("VAULT_INVALID", `${this.spec.filename} contains plaintext while the encrypted sidecar is active; restore the encrypted marker before starting`);
        }
        await this.writeMarker();
      } else if (primary === void 0) {
        await this.writeMarker();
      }
      this.attachParsed(sidecar);
      this.format = "encrypted";
      this.unlocked = false;
      this.markerText = (await readOptional(this.spec.filename)) ?? encryptedMarker(this.spec.encryptedFilename);
      this.stateEncrypted = true;
      await this.persistState();
      await this.refreshOfficial();
      const ambient = this.ambientPassword();
      if (ambient !== void 0) {
        const unlocked = await unlockEncryptedStore(sidecar, sha3_256Hex(ambient));
        this.applyUnlock(unlocked);
        if (unlocked.kdf === LEGACY_KDF) await this.upgradeKdf(sha3_256Hex(ambient));
      }
    } else {
      if (primary !== void 0 && isEncryptedMarker(primary)) {
        throw new VaultError("VAULT_INVALID", `the encrypted marker exists but ${this.spec.encryptedFilename} is missing`);
      }
      if (this.stateEncrypted === true) {
        throw new VaultError("VAULT_MIGRATION_REQUIRED", `the encrypted state for ${this.spec.filename} has no sidecar; migrate the legacy vault before starting`);
      }
      this.format = "plain";
      this.unlocked = true;
    }
    if (this.spec.watch) this.startWatcher();
    return this;
  }

  startWatcher() {
    this.watcher = watch([this.spec.filename, this.spec.encryptedFilename], {
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: this.spec.debounceMs,
        pollInterval: Math.max(1, Math.min(this.spec.debounceMs, 10)),
      },
    });
    this.watcher.on("all", () => {
      if (!this.closed) this.queueRefresh();
    });
    this.watcher.on("ready", () => {
      if (!this.closed) this.queueRefresh();
    });
    this.watcher.on("error", (error) => {
      this.ctx.logger.warn("dsh-encrypt: sidecar watcher error");
      this.ctx.logger.warn(error);
    });
  }

  async dispose() {
    this.closed = true;
    if (this.watcher !== void 0) await this.watcher.close();
    await this.operations;
    this.dropKey();
    this.entries.clear();
    this.text = void 0;
    this.markerText = void 0;
  }

  isClosed() {
    return this.closed;
  }

  isEncrypted() {
    return this.format === "encrypted";
  }

  /** The source-side state used by the WebUI, never including secrets. */
  status() {
    return Promise.resolve({
      format: this.format,
      unlocked: this.unlocked,
      plaintextForbidden: this.plaintextForbidden,
      remember: this.rememberState(),
      lockout: this.lockoutSnapshot(),
      leakGuard: {
        enabled: this.spec.leakGuard,
        masks: this.leakGuard.size(),
      },
    });
  }

  /** Observe an official result, then supply a sidecar result on a miss. */
  afterResolve(ref, result) {
    if (!this.spec.allowEnvFallback && result?.source !== "file") result = void 0;
    if (result?.value !== void 0) this.leakGuard.add(result.value, ref);
    if (this.format !== "encrypted") return result;
    if (result?.source === "file") {
      this.plaintextForbidden = true;
      throw new VaultError("VAULT_INVALID", `the official credentials file ${this.spec.filename} is not the encrypted marker`);
    }
    if (result !== void 0) return result;
    const record = this.entries.get(ref);
    if (record === void 0) return void 0;
    if (!this.unlocked || this.key === void 0) {
      throw new VaultError("VAULT_LOCKED", `the encrypted credential store is locked; unlock it in Settings → 加密安全 (or export ${this.spec.passwordEnv})`);
    }
    const value = decryptEntry(this.key, ref, record);
    this.leakGuard.add(value, ref);
    return { value, source: "file" };
  }

  /** Add masking for official sources and expose encrypted metadata. */
  afterDescribe(ref, result) {
    if (!this.spec.allowEnvFallback && result?.source !== "file") result = void 0;
    if (this.format !== "encrypted") return result ?? { configured: false, writable: true };
    if (result?.source === "file") {
      this.plaintextForbidden = true;
      throw new VaultError("VAULT_INVALID", `the official credentials file ${this.spec.filename} is not the encrypted marker`);
    }
    if (result !== void 0 && !(result.configured === false && result.source === void 0 && this.entries.has(ref))) return result;
    if (!this.entries.has(ref)) return result ?? { configured: false, writable: true };
    if (!this.unlocked) return { configured: false, source: "locked", writable: false };
    return { configured: true, source: "file", writable: true };
  }

  /** Around handler target for the official provider's asynchronous set. */
  async invokeSet(ref, value, invoke) {
    if (this.format !== "encrypted") return invoke();
    credentialRef(ref);
    this.assertUnshadowed(ref, "set");
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`dsh-encrypt: an empty value cannot be stored for "${ref}"; use unset`);
    }
    return this.writeEncrypted(ref, value);
  }

  /** Around handler target for the official provider's asynchronous unset. */
  async invokeUnset(ref, invoke) {
    if (this.format !== "encrypted") return invoke();
    credentialRef(ref);
    this.assertUnshadowed(ref, "unset");
    return this.writeEncrypted(ref, void 0);
  }

  async setPassword(digest) {
    if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
    if (this.format === "encrypted") throw new VaultError("VAULT_ALREADY_ENCRYPTED", "the credential store already has a password; use changePassword");
    return this.enqueue(async () => {
      await mkdir(dirname(this.spec.filename), { recursive: true, mode: 0o700 });
      return withFileLock(this.spec.filename, async () => {
        const text = await readOptional(this.spec.filename);
        const plaintexts = text === void 0 ? new Map() : parsePlainEntries(text, this.spec.filename);
        const created = await encryptCredentialStore(plaintexts, digest);
        plaintexts.clear();
        await mkdir(dirname(this.spec.encryptedFilename), { recursive: true, mode: 0o700 });
        await writeFileAtomic(this.spec.encryptedFilename, created.text, { mode: 0o600, dirMode: 0o700 });
        await writeFileAtomic(this.spec.filename, encryptedMarker(this.spec.encryptedFilename), { mode: 0o600, dirMode: 0o700 });
        this.format = "encrypted";
        this.stateEncrypted = true;
        this.plaintextForbidden = false;
        this.text = created.text;
        this.markerText = encryptedMarker(this.spec.encryptedFilename);
        this.key = created.key;
        this.entries = created.entries;
        this.salt = created.salt;
        this.params = created.params;
        this.kdf = VAULT_KDF;
        this.remember = void 0;
        this.unlocked = true;
        this.leakGuard.clear();
        await this.refreshOfficial();
        await this.persistState();
        return { unlocked: true, migrated: true };
      });
    });
  }

  async changePassword(oldDigest, digest) {
    if (!isDigest(oldDigest) || !isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the current and new password digests must be 64 lowercase hex characters (SHA3-256 of the password)");
    this.assertUnlocked("change the password");
    return this.enqueue(async () => withFileLock(this.spec.encryptedFilename, async () => {
      await this.reconcileFromDisk();
      this.assertUnlocked("change the password");
      await verifyPasswordDigest(this.text, oldDigest);
      const plaintexts = new Map();
      for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
      const created = await encryptCredentialStore(plaintexts, digest);
      plaintexts.clear();
      await writeFileAtomic(this.spec.encryptedFilename, created.text, { mode: 0o600, dirMode: 0o700 });
      this.dropKey();
      this.text = created.text;
      this.entries = created.entries;
      this.salt = created.salt;
      this.params = created.params;
      this.kdf = VAULT_KDF;
      this.key = created.key;
      this.unlocked = true;
      this.remember = void 0;
      this.leakGuard.clear();
      return { unlocked: true };
    }));
  }

  async unlock(digest) {
    if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
    if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
    if (this.unlocked) return { unlocked: true };
    this.assertUnlockAllowed();
    await this.reconcileFromDisk();
    let unlocked;
    try {
      unlocked = await unlockEncryptedStore(this.text, digest);
    } catch (error) {
      if (error instanceof VaultError && error.code === "PASSWORD_WRONG") await this.recordUnlockFailure();
      throw error;
    }
    this.applyUnlock(unlocked);
    if (unlocked.kdf === LEGACY_KDF) await this.upgradeKdf(digest);
    await this.clearUnlockFailures();
    return { unlocked: true };
  }

  async unlockWithRemember(secretText) {
    if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
    if (this.unlocked) return { unlocked: true };
    await this.reconcileFromDisk();
    this.applyUnlock(recoverKeyFromRemember(this.text, secretText));
    return { unlocked: true };
  }

  async upgradeKdf(digest) {
    return withFileLock(this.spec.encryptedFilename, async () => {
      await this.reconcileFromDisk();
      this.assertUnlocked("upgrade the credential store KDF");
      const plaintexts = new Map();
      for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
      const created = await encryptCredentialStore(plaintexts, digest);
      plaintexts.clear();
      await writeFileAtomic(this.spec.encryptedFilename, created.text, { mode: 0o600, dirMode: 0o700 });
      this.dropKey();
      this.text = created.text;
      this.entries = created.entries;
      this.salt = created.salt;
      this.params = created.params;
      this.kdf = VAULT_KDF;
      this.key = created.key;
      this.unlocked = true;
      this.remember = void 0;
      this.ctx.logger.warn("dsh-encrypt: legacy sidecar KDF was upgraded");
    });
  }

  async writeEncrypted(ref, value) {
    if (this.closed) throw new Error("dsh-encrypt is disposed");
    if (value !== void 0 && (typeof value !== "string" || value.length === 0)) throw new Error(`dsh-encrypt: an empty value cannot be stored for "${ref}"; use unset`);
    return this.enqueue(async () => withFileLock(this.spec.encryptedFilename, async () => {
      await this.reconcileFromDisk();
      this.assertUnlocked("store credentials");
      const previous = this.entries.get(ref);
      if (value === void 0 && previous === void 0) return;
      const next = new Map(this.entries);
      if (value === void 0) next.delete(ref);
      else next.set(ref, encryptEntry(this.key, ref, value));
      const nextText = serializeEncryptedStore(next, this.key, this.salt, this.params, this.remember, this.kdf);
      await writeFileAtomic(this.spec.encryptedFilename, nextText, { mode: 0o600, dirMode: 0o700 });
      this.text = nextText;
      this.entries = next;
      if (value !== void 0) this.leakGuard.add(value, ref);
      this.publishUpdated(ref);
    }));
  }

  assertUnshadowed(ref, verb) {
    try {
      const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ["process"]);
      if (entry?.value) throw new Error(`dsh-encrypt: "${ref}" is supplied read-only by the launching environment, so ${verb} would be shadowed; unset it in the shell you start dsh from instead`);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("dsh-encrypt:")) throw error;
      if (process.env[ref]) throw new Error(`dsh-encrypt: "${ref}" is supplied read-only by the launching environment, so ${verb} would be shadowed; unset it in the shell you start dsh from instead`);
    }
  }

  assertUnlocked(verb) {
    if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", `cannot ${verb}: the credential store has no password`);
    if (!this.unlocked || this.key === void 0) throw new VaultError("VAULT_LOCKED", `cannot ${verb}: the credential store is locked; unlock it in Settings → 加密安全`);
  }

  enqueue(operation) {
    const task = this.operations.then(operation);
    this.operations = task.then(() => void 0, () => void 0);
    return task;
  }

  queueRefresh() {
    void this.enqueue(() => this.refresh()).catch((error) => {
      this.ctx.logger.error("dsh-encrypt: sidecar reload failed");
      this.ctx.logger.error(error);
    });
  }

  async refresh() {
    if (this.closed) return;
    await this.reconcileFromDisk();
  }

  async reconcileFromDisk() {
    await assertOwnerOnly(this.spec.filename);
    await assertOwnerOnly(this.spec.encryptedFilename);
    const sidecar = await readOptional(this.spec.encryptedFilename);
    const marker = await readOptional(this.spec.filename);
    if (this.format !== "encrypted") {
      if (sidecar === void 0) return;
      if (marker !== void 0 && !isEncryptedMarker(marker)) {
        const plain = parsePlainEntries(marker, this.spec.filename);
        if (plain.size > 0) {
          this.plaintextForbidden = true;
          throw new VaultError("VAULT_INVALID", `${this.spec.filename} contains plaintext while the encrypted sidecar is active`);
        }
        await this.writeMarker();
      } else if (marker === void 0) {
        await this.writeMarker();
      }
      const parsed = parseEncryptedStore(sidecar);
      this.attachParsed(sidecar, parsed);
      this.format = "encrypted";
      this.unlocked = false;
      this.markerText = (await readOptional(this.spec.filename)) ?? encryptedMarker(this.spec.encryptedFilename);
      this.stateEncrypted = true;
      await this.refreshOfficial();
      return;
    }
    if (sidecar === void 0) {
      this.dropKey();
      throw new VaultError("VAULT_CORRUPTED", `the encrypted sidecar ${this.spec.encryptedFilename} disappeared; keeping the last trusted snapshot`);
    }
    if (marker === void 0 || !isEncryptedMarker(marker)) {
      this.plaintextForbidden = true;
      this.dropKey();
      throw new VaultError("VAULT_INVALID", `the official credentials file ${this.spec.filename} is not the encrypted marker`);
    }
    this.plaintextForbidden = false;
    if (sidecar === this.text && marker === this.markerText) return;
    const previous = this.entries;
    const parsed = parseEncryptedStore(sidecar);
    this.attachParsed(sidecar, parsed);
    this.markerText = marker;
    this.dropKey();
    for (const ref of changedRefs(previous, this.entries)) this.publishUpdated(ref);
  }

  attachParsed(text, parsed = parseEncryptedStore(text)) {
    this.text = text;
    this.entries = parsed.entries;
    this.salt = parsed.salt;
    this.params = parsed.params;
    this.kdf = parsed.kdf;
    this.remember = parsed.remember;
  }

  applyUnlock(unlocked) {
    this.key = unlocked.key;
    this.entries = unlocked.entries;
    this.salt = unlocked.salt;
    this.params = unlocked.params;
    this.kdf = unlocked.kdf ?? VAULT_KDF;
    this.remember = unlocked.remember;
    this.format = "encrypted";
    this.unlocked = true;
    this.plaintextForbidden = false;
    this.leakGuard.clear();
  }

  dropKey() {
    if (this.key !== void 0) {
      zeroizeBuffer(this.key);
      this.key = void 0;
    }
    this.unlocked = this.format === "plain";
    this.leakGuard.clear();
  }

  async setRememberDays(days) {
    if (!Number.isInteger(days) || days < -1 || days > 30) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be an integer from -1 through 30");
    this.stateRememberDays = days;
    await this.persistState();
    if (this.format !== "encrypted") return null;
    if (this.remember !== void 0) {
      this.assertUnlocked("change remembered-login settings");
      await this.enqueue(async () => withFileLock(this.spec.encryptedFilename, async () => {
        await this.reconcileFromDisk();
        this.assertUnlocked("change remembered-login settings");
        const text = serializeEncryptedStore(this.entries, this.key, this.salt, this.params, void 0, this.kdf);
        await writeFileAtomic(this.spec.encryptedFilename, text, { mode: 0o600, dirMode: 0o700 });
        this.text = text;
        this.remember = void 0;
      }));
    }
    if (days !== 0 && this.unlocked && this.key !== void 0) return this.persistRemember(days);
    return null;
  }

  async issueRemember() {
    if (this.effectiveDays() === 0 || this.format !== "encrypted" || !this.unlocked || this.key === void 0) return null;
    return this.enqueue(async () => {
      await this.reconcileFromDisk();
      if (this.effectiveDays() === 0 || !this.unlocked || this.key === void 0) return null;
      return this.persistRemember(this.effectiveDays());
    });
  }

  async persistRemember(days) {
    let issued;
    await withFileLock(this.spec.encryptedFilename, async () => {
      await this.reconcileFromDisk();
      this.assertUnlocked("issue remembered-login ticket");
      const created = createRememberBlock(this.key, days);
      const text = serializeEncryptedStore(this.entries, this.key, this.salt, this.params, created.block, this.kdf);
      await writeFileAtomic(this.spec.encryptedFilename, text, { mode: 0o600, dirMode: 0o700 });
      this.text = text;
      this.remember = created.block;
      issued = {
        secret: created.secret,
        days,
        issuedAt: created.block.issuedAt,
        expiresAt: days === -1 ? null : created.block.issuedAt + days * REMEMBER_DAY_MS,
      };
    });
    return issued;
  }

  effectiveDays() {
    const value = this.stateRememberDays ?? this.spec.rememberDays;
    return Number.isInteger(value) && value >= -1 && value <= 30 ? value : 0;
  }

  rememberState() {
    const days = this.effectiveDays();
    const block = this.remember;
    return {
      days,
      active: block !== void 0 && rememberActive(block, Date.now()),
      issuedAt: block?.issuedAt ?? null,
      expiresAt: block !== void 0 && block.days !== -1 ? block.issuedAt + block.days * REMEMBER_DAY_MS : null,
    };
  }

  lockoutSnapshot(now = Date.now()) {
    const retryAfterMs = Math.max(0, this.unlockLockedUntil - now);
    return { failures: this.unlockFailures, lockedUntil: this.unlockLockedUntil, retryAfterMs, locked: retryAfterMs > 0 };
  }

  assertUnlockAllowed(now = Date.now()) {
    if (isLockedOut(this.unlockLockedUntil, now)) throw new VaultError("TOO_MANY_ATTEMPTS", formatLockoutMessage(this.unlockLockedUntil - now), { retryAfterMs: Math.max(0, this.unlockLockedUntil - now) });
  }

  async recordUnlockFailure() {
    const next = recordLockoutFailure({ failures: this.unlockFailures, lockedUntil: this.unlockLockedUntil }, {
      maxAttempts: this.spec.maxUnlockAttempts,
      lockoutBaseMs: this.spec.lockoutBaseMs,
      lockoutMaxMs: this.spec.lockoutMaxMs,
    });
    this.unlockFailures = next.failures;
    this.unlockLockedUntil = next.lockedUntil;
    await this.persistState();
    this.ctx.logger.warn("dsh-encrypt: unlock failed (attempt %d); %s", next.failures, next.retryAfterMs > 0 ? `locked out for ${Math.max(1, Math.ceil(next.retryAfterMs / 1000))}s` : "retry allowed");
  }

  async clearUnlockFailures() {
    if (this.unlockFailures === 0 && this.unlockLockedUntil === 0) return;
    this.unlockFailures = 0;
    this.unlockLockedUntil = 0;
    await this.persistState();
  }

  async loadStateFile() {
    await assertOwnerOnly(this.spec.stateFile);
    let doc;
    try {
      doc = JSON.parse(await readFile(this.spec.stateFile, "utf8"));
    } catch (error) {
      if (isENOENT(error)) return;
      this.ctx.logger.error("dsh-encrypt: cannot read state file %s", this.spec.stateFile);
      this.ctx.logger.error(error);
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} cannot be read`);
    }
    if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} must contain a JSON object`);
    }
    if (doc.rememberDays !== void 0 && (!Number.isInteger(doc.rememberDays) || doc.rememberDays < -1 || doc.rememberDays > 30)) {
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} has an invalid rememberDays value`);
    }
    if (doc.encrypted !== void 0 && doc.encrypted !== true) {
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} has an invalid encrypted value`);
    }
    if (doc.unlockFailures !== void 0 && (!Number.isInteger(doc.unlockFailures) || doc.unlockFailures < 0)) {
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} has an invalid unlockFailures value`);
    }
    if (doc.unlockLockedUntil !== void 0 && (!Number.isFinite(doc.unlockLockedUntil) || doc.unlockLockedUntil < 0)) {
      throw new VaultError("STATE_INVALID", `the dsh-encrypt state file ${this.spec.stateFile} has an invalid unlockLockedUntil value`);
    }
    if (doc.rememberDays !== void 0) this.stateRememberDays = doc.rememberDays;
    if (doc.encrypted === true) this.stateEncrypted = true;
    if (doc.unlockFailures !== void 0) this.unlockFailures = doc.unlockFailures;
    if (doc.unlockLockedUntil !== void 0) this.unlockLockedUntil = doc.unlockLockedUntil;
  }

  async persistState() {
    try {
      await mkdir(dirname(this.spec.stateFile), { recursive: true, mode: 0o700 });
      const doc = {};
      if (Number.isInteger(this.stateRememberDays) && this.stateRememberDays >= -1 && this.stateRememberDays <= 30) doc.rememberDays = this.stateRememberDays;
      if (this.stateEncrypted || this.format === "encrypted") doc.encrypted = true;
      if (this.unlockFailures > 0) doc.unlockFailures = this.unlockFailures;
      if (this.unlockLockedUntil > 0) doc.unlockLockedUntil = this.unlockLockedUntil;
      await writeFileAtomic(this.spec.stateFile, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600, dirMode: 0o700 });
    } catch (error) {
      this.ctx.logger.error("dsh-encrypt: cannot write state file %s", this.spec.stateFile);
      this.ctx.logger.error(error);
      throw error;
    }
  }

  ambientPassword() {
    try {
      const entry = launchEnvironmentOf(this.ctx).get(this.spec.passwordEnv);
      if (entry?.value) return entry.value;
    } catch {
      // Unit contexts may not mount the launch-environment service.
    }
    return process.env[this.spec.passwordEnv] || void 0;
  }

  async writeMarker() {
    const text = encryptedMarker(this.spec.encryptedFilename);
    await mkdir(dirname(this.spec.filename), { recursive: true, mode: 0o700 });
    await writeFileAtomic(this.spec.filename, text, { mode: 0o600, dirMode: 0o700 });
    this.markerText = text;
  }

  async refreshOfficial() {
    const provider = this.ctx.credentials;
    if (typeof provider?.refresh === "function") {
      await provider.refresh();
    } else if (typeof provider?.queueRefresh === "function") {
      provider.queueRefresh();
    }
  }

  publishUpdated(ref) {
    const safe = credentialRef(ref);
    const provider = this.ctx.credentials;
    if (typeof provider?.notifyUpdated === "function") {
      provider.notifyUpdated(safe);
      return;
    }
    this.ctx.emit?.("credentials/updated", safe);
  }

  /** Exposed for tests and the optional WebUI redaction adapter. */
  withUnlockedBuffer(ref, fn) {
    return (async () => {
      const hit = this.afterResolve(ref, void 0);
      if (hit === void 0) return fn(void 0);
      const buffer = this.format === "encrypted" && this.key !== void 0
        ? decryptEntryBuffer(this.key, ref, this.entries.get(ref))
        : Buffer.from(hit.value, "utf8");
      try {
        return await fn(buffer);
      } finally {
        zeroizeBuffer(buffer);
      }
    })();
  }
}

export { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV };
