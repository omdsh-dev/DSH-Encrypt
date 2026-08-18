import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";
import { watch } from "chokidar";
import { mkdir, readFile, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { Document, parseDocument as parseYaml } from "yaml";
import { withFileLock, writeFileAtomic } from "@deepseek-ai/dsh-atomic-write";
import { canonicalizeWatchPath, resolveDshHome } from "@deepseek-ai/dsh-home-paths";
import { launchEnvironmentOf } from "@deepseek-ai/dsh-launch-environment";
import { CredentialProvider, credentialRef } from "@deepseek-ai/dsh-credentials";
import { VaultError, REMEMBER_DAY_MS, VAULT_KDF, LEGACY_KDF, createRememberBlock, decryptEntry, decryptEntryBuffer, detectCredentialStore, encryptCredentialStore, encryptEntry, isDigest, parseEncryptedStore, recoverKeyFromRemember, rememberActive, serializeEncryptedStore, sha3_256Hex, unlockEncryptedStore, verifyPasswordDigest, zeroizeBuffer } from "./vault.js";
import { LeakGuard } from "./leak-guard.js";
import { formatLockoutMessage, isLockedOut, recordLockoutFailure } from "./lockout.js";
import { loadAndVerifyIntegrity } from "./integrity.js";
import { assertRuntimeCompat } from "./compat.js";

// Fail-closed shipped-code integrity check: any byte difference from the
// build-time SHA3-256 manifest refuses to load this provider row before it
// can serve or decrypt anything (see ./integrity.js for the honest limits).
loadAndVerifyIntegrity(import.meta.url);
// Runtime compatibility check: a dsh release outside the supported line
// refuses to load with a clear UNSUPPORTED_DSH error instead of failing
// somewhere inside the seams (see ./compat.js for the policy).
assertRuntimeCompat();
//#region lib/types/index.js
/**
 * dsh-encrypt — single-file, WebUI-managed encrypted credentials.
 *
 * One file, `$DSH_HOME/.credentials.yaml`, carries the credentials in two
 * forms:
 *
 * ```text
 * no password set (default, drop-in identical to dsh-credentials-local):
 *   OPENCODE_GO_API_KEY: sk-…                    ← plaintext YAML mapping
 *
 * after a password is set in Settings → 加密安全:
 *   { "format": "dsh-encrypt-credentials",      ← the same file's contents
 *     "kdf": "scrypt", "salt": …, "verifier": …, replaced by an encrypted
 *     "entries": { REF: { data, sha3 } }, … }     JSON document (SHA3-256
 *                                                  fingerprints + GCM tags)
 * ```
 *
 * State machine:
 *
 * ```text
 *             set-password                    (restart)            unlock
 *  plain ──────────────────► encrypted+unlocked ──────► encrypted+locked ──► unlocked
 *                                 ▲                                        │
 *                                 └──────────── change-password ───────────┘
 * ```
 *
 * While locked the provider activates normally (the web server stays up),
 * `resolve` throws `VAULT_LOCKED` and `describe` reports `source: "locked"` —
 * the Settings page is the unlock surface. Credentials are decrypted per
 * model request; plaintext is never cached between operations.
 *
 * Password APIs: `status()` / `unlock(digest)` / `setPassword(digest)` /
 * `changePassword(oldDigest, digest)`, also exposed to the browser
 * as `/api/credentials.{status,unlock,set-password,change-password,config}`
 * (exact routes behind the Host trust fence, served while a webServer
 * service exists; headless compositions simply have no HTTP surface).
 * `$DSH_CREDENTIAL_PASSWORD` unlocks a locked store at startup for automation.
 * @module dsh-encrypt
 */
/** Basename of the credential file inside the harness home. */
const CREDENTIALS_FILENAME = ".credentials.yaml";
/** Default environment variable carrying the unlock password. */
const DEFAULT_PASSWORD_ENV = "DSH_CREDENTIAL_PASSWORD";
/** Permission bits outside the owner; a credential file must have none of them. */
const GROUP_OTHER_BITS = 63;
/**
 * Resolve the runtime spec from plugin config.
 * @param config - raw plugin config.
 * @returns resolved file location and watch behavior.
 */
function resolveSpec(config) {
	return {
		filename: resolve(config.path ?? join(resolveDshHome(config.dshHome), CREDENTIALS_FILENAME)),
		stateFile: resolve(join(resolveDshHome(config.dshHome), ".dsh-encrypt.json")),
		allowEnvFallback: config.allowEnvFallback ?? true,
		passwordEnv: config.passwordEnv ?? DEFAULT_PASSWORD_ENV,
		watch: config.watch ?? true,
		debounceMs: config.debounceMs ?? 100
	};
}
/**
 * Reject a credential file other OS users can read, before its contents are
 * read at all — the plain form holds live secrets. POSIX only; Windows has no
 * mode to inspect, so the check is skipped there and protection is whatever
 * the create/replace APIs and the OS ACL express.
 * @param filename - absolute path of the file.
 */
async function assertOwnerOnly(filename) {
	let mode;
	try {
		mode = (await stat(filename)).mode;
	} catch (error) {
		if (!isENOENT(error)) throw error;
		await canonicalizeWatchPath(filename);
		return;
	}
	/* v8 ignore next */
	if (process.platform === "win32") return;
	if ((mode & GROUP_OTHER_BITS) === 0) return;
	throw new Error(`dsh-encrypt: ${filename} is readable beyond its owner (mode ${(mode & 511).toString(8)}); run "chmod 600 ${filename}" before starting again`);
}
/** Whether a filesystem error means absence. */
function isENOENT(error) {
	return error?.code === "ENOENT";
}
/**
 * Parse the plain form: a strict mapping of `CredentialRef` to non-empty
 * string, exactly the shape dsh-credentials-local serves. Rejects a mapping
 * that is not one, because a silently ignored entry reads as "the key I
 * stored has no effect".
 * @param text - the file text.
 * @param filename - quoted in errors.
 * @returns the entries keyed by reference.
 */
function parsePlainEntries(text, filename) {
	const document = parseYaml(text, { prettyErrors: true, uniqueKeys: true });
	if (document.errors.length > 0) throw new Error(`dsh-encrypt: invalid document at ${filename}: ${document.errors.map((error) => {
		const at = error.linePos?.[0];
		return `${error.code}${at === void 0 ? "" : ` at line ${String(at.line)}, column ${String(at.col)}`}`;
	}).join("; ")}`);
	const root = document.toJS() ?? {};
	if (typeof root !== "object" || root === null || Array.isArray(root)) throw new TypeError(`dsh-encrypt: ${filename} must be a mapping of credential reference to value`);
	const entries = /* @__PURE__ */ new Map();
	for (const [key, value] of Object.entries(root)) {
		credentialRef(key);
		if (typeof value !== "string") throw new TypeError(`dsh-encrypt: the value for "${key}" in ${filename} must be a string`);
		if (value.length === 0) throw new Error(`dsh-encrypt: the value for "${key}" in ${filename} is empty; remove the key instead`);
		entries.set(key, value);
	}
	return entries;
}
/**
 * Render the next plain-form text with one reference set or deleted. Editing
 * the parsed document rather than rebuilding it keeps comments and the
 * formatting of every untouched entry; an absent document starts a fresh one.
 * @param text - the current text, `undefined` while the file is absent.
 * @param ref - the reference to write.
 * @param value - the new value, or `undefined` to delete the key.
 * @returns the text to persist.
 */
function renderPlainDocument(text, ref, value) {
	const document = text === void 0 ? new Document({}) : parseYaml(text);
	if (value === void 0) document.deleteIn([ref]);
	else document.setIn([ref], value);
	return document.toString();
}
/** Whether one credential changed between two snapshots (for the updated event). */
function refChanged(prev, next, ref) {
	return prev.get(ref) !== next.get(ref);
}
/**
 * Single-file encrypted credentials provider with a WebUI-managed password.
 */
var EncryptedCredentialProvider = class extends CredentialProvider {
	config;
	static Config = z.object({
		path: z.string(),
		dshHome: z.string(),
		allowEnvFallback: z.boolean().default(true),
		passwordEnv: z.string().default(DEFAULT_PASSWORD_ENV),
		watch: z.boolean().default(true),
		debounceMs: z.number().min(0).default(100),
		rememberDays: z.number().min(-1).max(30).default(0),
		/** Channel carrying the remembered-login ticket: the HttpOnly cookie (default) or the localStorage-backed header (XSS-readable; only for cookie-storage-quirky WebViews). */
		rememberChannel: z.union([z.const("cookie"), z.const("header")]).default("cookie"),
		/** Master switch for the credential leak guard (output redaction). */
		leakGuard: z.boolean().default(true),
		/** Values shorter than this are never masked (avoids prose mangling). */
		leakMinMaskLength: z.number().min(4).max(64).default(8),
		/** Values longer than this are never masked (stream lookback window). */
		leakMaxMaskLength: z.number().min(16).max(1024).default(256),
		/** Consecutive failed unlocks before the first lockout window. */
		maxUnlockAttempts: z.number().min(1).default(5),
		/** First lockout window in milliseconds (exponential from here). */
		lockoutBaseMs: z.number().min(1000).default(30000),
		/** Lockout window ceiling in milliseconds. */
		lockoutMaxMs: z.number().min(1000).default(900000)
	});
	spec;
	/** Current on-disk form: `plain` while no password is set. */
	format = "plain";
	/** Whether the encrypted form is currently unlocked (always true in plain form). */
	unlocked = true;
	/** The derived key while unlocked; zeroized on lock/dispose. */
	key;
	/** KDF salt and cost parameters of the current encrypted document. */
	salt;
	params;
	/** KDF of the current encrypted document: "argon2id" or legacy "scrypt". */
	kdf = VAULT_KDF;
	/**
	 * The in-memory snapshot: plaintext values in the plain form, ciphertext
	 * records in the encrypted form. Never both, never plaintext alongside a
	 * lockable key.
	 */
	entries = /* @__PURE__ */ new Map();
	/**
	 * Raw text of the last read or persisted document; `undefined` while the
	 * file is absent. Watcher events whose content equals this cache are
	 * no-ops, which is also the self-write suppression.
	 */
	text;
	/** Current remembered-login block from the encrypted document, if any. */
	remember;
	/** Runtime-overridden remembered-login window from the state file. */
	stateRememberDays;
	/** The ciphertext-only policy flag persisted in the state file. */
	stateEncrypted;
	/** True while the file holds plaintext against the ciphertext-only policy. */
	refusePlain = false;
	/** Single exclusive operation chain; settled tail, like credentials-local. */
	operations = Promise.resolve();
	/** Set at dispose: refuse new writes and let in-flight work no-op. */
	closed = false;
	/** Leak guard: masks resolved credential values in output streams. */
	leakGuard;
	/** Consecutive failed unlock attempts (persisted in the state file). */
	unlockFailures = 0;
	/** Epoch ms until which unlocks are refused (persisted in the state file). */
	unlockLockedUntil = 0;
	isClosed() {
		return this.closed;
	}
	constructor(ctx, config) {
		super(ctx);
		// Surface a same-line rc drift of the dsh runtime as a warning (the
		// module-level guard already refused hard mismatches).
		const compat = assertRuntimeCompat();
		if (compat.verdict?.level === "warn") ctx.logger.warn("dsh-encrypt: " + compat.verdict.reason);
		this.config = config;
		this.spec = resolveSpec(config);
		this.leakGuard = new LeakGuard({
			enabled: config.leakGuard,
			minMaskLength: config.leakMinMaskLength,
			maxMaskLength: config.leakMaxMaskLength
		});
	}
	// ── unlock lockout (online brute-force defense) ─────────────────────────

	/** The WebUI-facing lockout snapshot (never secret-bearing). */
	lockoutSnapshot(now = Date.now()) {
		const retryAfterMs = Math.max(0, this.unlockLockedUntil - now);
		return {
			failures: this.unlockFailures,
			lockedUntil: this.unlockLockedUntil,
			retryAfterMs,
			locked: retryAfterMs > 0
		};
	}
	/** Reject an unlock attempt while the lockout window is active. */
	assertUnlockAllowed(now = Date.now()) {
		if (isLockedOut(this.unlockLockedUntil, now)) throw new VaultError("TOO_MANY_ATTEMPTS", formatLockoutMessage(this.unlockLockedUntil - now), { retryAfterMs: Math.max(0, this.unlockLockedUntil - now) });
	}
	/** Count one failed unlock and (re-)arm the exponential window. */
	async recordUnlockFailure() {
		const next = recordLockoutFailure({ failures: this.unlockFailures, lockedUntil: this.unlockLockedUntil }, {
			maxAttempts: this.config.maxUnlockAttempts,
			lockoutBaseMs: this.config.lockoutBaseMs,
			lockoutMaxMs: this.config.lockoutMaxMs
		});
		this.unlockFailures = next.failures;
		this.unlockLockedUntil = next.lockedUntil;
		await this.persistState();
		this.ctx.logger.warn("dsh-encrypt: unlock failed (attempt %d); %s", next.failures, next.retryAfterMs > 0 ? `locked out for ${Math.max(1, Math.ceil(next.retryAfterMs / 1000))}s` : "retry allowed");
	}
	/** Reset the failure counter after a successful unlock. */
	async clearUnlockFailures() {
		if (this.unlockFailures === 0 && this.unlockLockedUntil === 0) return;
		this.unlockFailures = 0;
		this.unlockLockedUntil = 0;
		await this.persistState();
	}
	/**
	 * Reconcile the leak guard's mask set with the current vault state:
	 * plain form registers every entry value; a locked vault (or a refused
	 * plaintext file) clears the set; an encrypted+unlocked vault keeps the
	 * incrementally resolved values registered by resolve().
	 */
	syncGuard() {
		if (!this.config.leakGuard) {
			this.leakGuard.clear();
			return;
		}
		if (this.refusePlain || (this.format === "encrypted" && !this.unlocked)) {
			this.leakGuard.clear();
			return;
		}
		if (this.format === "plain") this.leakGuard.rebuild([...this.entries.values()]);
	}
	/** The inherited-environment value for a reference, or `undefined` when empty or unset. */
	inherited(ref) {
		if (!this.spec.allowEnvFallback) return void 0;
		const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ["process"]);
		return entry !== void 0 && entry.value.length > 0 ? entry.value : void 0;
	}
	/** The read-only `.env` fallback — below the managed file, never above it. */
	dotenvFallback(ref) {
		if (!this.spec.allowEnvFallback) return void 0;
		const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ["project-env", "user-env"]);
		return entry !== void 0 && entry.value.length > 0 ? entry : void 0;
	}
	async *[Service.init]() {
		yield async () => {
			this.closed = true;
			await this.operations;
			this.dropKey();
			this.entries.clear();
			this.text = void 0;
		};
		try {
			await assertOwnerOnly(this.spec.filename);
			await this.loadStateFile();
			await this.loadInitial();
			if (!this.spec.watch) return;
			const watcher = watch(await canonicalizeWatchPath(this.spec.filename), {
				ignoreInitial: true,
				awaitWriteFinish: {
					stabilityThreshold: this.spec.debounceMs,
					pollInterval: Math.max(1, Math.min(this.spec.debounceMs, 10))
				}
			});
			watcher.on("all", () => {
				if (this.closed) return;
				this.queueRefresh();
			});
			watcher.on("ready", () => {
				if (this.closed) return;
				this.queueRefresh();
			});
			watcher.on("error", (error) => {
				this.ctx.logger.warn("dsh-encrypt: watcher error on %s", this.spec.filename);
				this.ctx.logger.warn(error);
			});
			yield async () => {
				this.closed = true;
				await watcher.close();
				await this.operations;
				this.dropKey();
			};
		} catch (error) {
			this.dropKey();
			throw error;
		}
	}
	/** Zeroize and release the derived key (lock). */
	dropKey() {
		if (this.key !== void 0) {
			zeroizeBuffer(this.key);
			this.key = void 0;
		}
		this.unlocked = this.format === "plain";
		this.leakGuard.clear();
	}
	/**
	 * Boot read: an absent file is an empty plain store. A present encrypted
	 * store must pass its SHA3-256 integrity checks before activation; it then
	 * boots LOCKED (unless `$DSH_CREDENTIAL_PASSWORD` supplies the password —
	 * a supplied-but-wrong password fails activation, never boots locked).
	 */
	async loadInitial() {
		let text;
		try {
			text = await readFile(this.spec.filename, "utf8");
		} catch (error) {
			if (!isENOENT(error)) throw error;
			this.format = "plain";
			this.unlocked = true;
			this.entries = /* @__PURE__ */ new Map();
			return;
		}
		if (detectCredentialStore(text) === "encrypted") {
			const parsed = parseEncryptedStore(text);
			this.format = "encrypted";
			this.salt = parsed.salt;
			this.params = parsed.params;
			this.kdf = parsed.kdf;
			this.entries = parsed.entries;
			this.remember = parsed.remember;
			this.text = text;
			this.unlocked = false;
			// Migrate stores encrypted by older versions: arm the
			// ciphertext-only policy the first time an encrypted document
			// is booted, so the state file records it for every later boot.
			if (this.stateEncrypted !== true) {
				this.stateEncrypted = true;
				await this.persistState();
			}
			const ambient = launchEnvironmentOf(this.ctx).get(this.spec.passwordEnv);
			if (ambient !== void 0 && ambient.value.length > 0) {
				const digest = sha3_256Hex(ambient.value);
				const unlocked = await unlockEncryptedStore(text, digest);
				this.applyUnlock(unlocked);
				// A legacy scrypt vault unlocked at boot upgrades to Argon2id in
				// place right away (the remembered-login block dies with it).
				if (unlocked.kdf === LEGACY_KDF) await this.upgradeKdf(digest);
				await this.revokeRememberIfDisabled();
			}
			return;
		}
		this.format = "plain";
		this.unlocked = true;
		this.entries = parsePlainEntries(text, this.spec.filename);
		this.text = text;
		this.syncGuard();
		if (this.stateEncrypted === true) {
			this.refusePlain = true;
			this.ctx.logger.error("dsh-encrypt: %s holds PLAINTEXT credentials while ciphertext is required; credential resolution is refused until the password is set again", this.spec.filename);
		}
	}
	/** Apply an unlock result to the snapshot (used by boot env unlock and the API). */
	applyUnlock(unlocked) {
		this.key = unlocked.key;
		this.entries = unlocked.entries;
		this.salt = unlocked.salt;
		this.params = unlocked.params;
		this.kdf = unlocked.kdf ?? VAULT_KDF;
		this.remember = unlocked.remember;
		this.unlocked = true;
		// A fresh unlock starts with an empty mask set: values enter the leak
		// guard only as resolve() actually hands them out.
		this.leakGuard.clear();
	}
	/**
	 * Resolve one reference per operation: plaintext value, or a decrypted
	 * transient value while unlocked. Never cached between operations.
	 * @param ref - the reference to resolve.
	 * @returns value and source, or `undefined` while unconfigured.
	 */
	resolve(ref) {
		if (this.refusePlain) return Promise.reject(new VaultError("VAULT_INVALID", "the credential file was replaced with plaintext while ciphertext is required; set the password again in Settings → 加密安全 to re-encrypt it"));
		const inherited = this.inherited(ref);
		if (inherited !== void 0) {
			this.leakGuard.add(inherited, ref);
			return Promise.resolve({
				value: inherited,
				source: "env"
			});
		}
		const record = this.entries.get(ref);
		if (record !== void 0) {
			try {
				if (this.format === "encrypted") {
					if (!this.unlocked) return Promise.reject(new VaultError("VAULT_LOCKED", `the credential store is locked; unlock it in Settings → 加密安全 (or export ${this.spec.passwordEnv})`));
					const value = decryptEntry(this.key, ref, record);
					this.leakGuard.add(value, ref);
					return Promise.resolve({ value, source: "file" });
				}
				this.leakGuard.add(record, ref);
				return Promise.resolve({ value: record, source: "file" });
			} catch (error) {
				return Promise.reject(error);
			}
		}
		const fallback = this.dotenvFallback(ref);
		if (fallback !== void 0) {
			this.leakGuard.add(fallback.value, ref);
			return Promise.resolve({
				value: fallback.value,
				source: fallback.source
			});
		}
		return Promise.resolve(void 0);
	}
	/**
	 * Run `fn` with one reference temporarily unlocked. The plaintext argument
	 * lives for the callback and is dropped with it.
	 * @param ref - the reference to unlock.
	 * @param fn - the consumer; receives the plaintext or `undefined` while unconfigured.
	 * @returns the callback's result.
	 */
	async withUnlocked(ref, fn) {
		const hit = await this.resolve(ref);
		return fn(hit === void 0 ? void 0 : hit.value);
	}
	/**
	 * Burn-after-read variant: run `fn` with the plaintext as a mutable
	 * Buffer and zeroize it in a finally block once the callback settles.
	 * JavaScript strings are immutable, so the string seam above can only
	 * drop references — this buffer copy is the erasure-capable path.
	 * @param ref - the reference to unlock.
	 * @param fn - the consumer; receives the plaintext buffer or `undefined`.
	 * @returns the callback's result.
	 */
	async withUnlockedBuffer(ref, fn) {
		const hit = await this.resolve(ref);
		if (hit === void 0) return fn(void 0);
		let buffer;
		if (this.format === "encrypted" && this.key !== void 0) {
			buffer = decryptEntryBuffer(this.key, ref, this.entries.get(ref));
		} else {
			buffer = Buffer.from(hit.value, "utf8");
		}
		try {
			return await fn(buffer);
		} finally {
			zeroizeBuffer(buffer);
		}
	}
	/** The WebUI-facing snapshot: form, lock state, remembered-login, lockout and leak-guard state. */
	status() {
		return Promise.resolve({
			format: this.format,
			unlocked: this.unlocked,
			plaintextForbidden: this.refusePlain,
			remember: this.rememberState(),
			lockout: this.lockoutSnapshot(),
			leakGuard: {
				enabled: this.config.leakGuard,
				masks: this.leakGuard.size()
			},
			rememberChannel: this.config.rememberChannel
		});
	}
	/**
	 * Unlock the encrypted store with the password's SHA3-256 digest (the
	 * WebUI derives it; the raw password never reaches this process).
	 * @param digest - the lowercase hex SHA3-256 digest of the password.
	 */
	async unlock(digest) {
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
		if (this.unlocked) return {
			unlocked: true
		};
		this.assertUnlockAllowed();
		await this.reconcileFromDisk();
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store no longer has a password (the file was changed externally)");
		if (this.unlocked) return {
			unlocked: true
		};
		let unlocked;
		try {
			unlocked = await unlockEncryptedStore(this.text, digest);
		} catch (error) {
			if (error instanceof VaultError && error.code === "PASSWORD_WRONG") await this.recordUnlockFailure();
			throw error;
		}
		this.applyUnlock(unlocked);
		// A legacy scrypt (v2) vault upgrades to Argon2id in place on its
		// first successful password unlock; the remembered-login block (which
		// wrapped the old key) dies with it.
		if (unlocked.kdf === LEGACY_KDF) await this.upgradeKdf(digest);
		await this.clearUnlockFailures();
		await this.revokeRememberIfDisabled();
		return {
			unlocked: true
		};
	}
	/**
	 * Re-encrypt a legacy scrypt (v2) store into the Argon2id (v3) format
	 * after a password unlock: every entry is decrypted under the legacy key
	 * and re-encrypted under a fresh Argon2id salt/key derived from the same
	 * digest, then the document is replaced in place. The legacy key is
	 * zeroized; a remembered-login block wrapping it is dropped.
	 * @param digest - lowercase hex SHA3-256 digest of the password.
	 */
	async upgradeKdf(digest) {
		const plaintexts = new Map();
		for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
		const created = await encryptCredentialStore(plaintexts, digest);
		plaintexts.clear();
		await withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			if (!this.unlocked || this.key === void 0) throw new VaultError("VAULT_LOCKED", "the credential store locked while upgrading its KDF; unlock it again");
			await writeFileAtomic(this.spec.filename, created.text, { mode: 384, dirMode: 448 });
			this.text = created.text;
			this.entries = created.entries;
			this.salt = created.salt;
			this.params = created.params;
			this.remember = void 0;
			this.dropKey();
			this.key = created.key;
			this.kdf = VAULT_KDF;
			this.unlocked = true;
			this.leakGuard.clear();
			this.ctx.logger.warn("dsh-encrypt: legacy scrypt store upgraded to argon2id in place");
		});
	}
	/**
	 * Set the first password: the file's plaintext contents are replaced by
	 * the encrypted document in place, and the provider stays unlocked. Any
	 * previous remembered-login block dies with the old plain form.
	 * @param digest - lowercase hex SHA3-256 digest of the new password.
	 */
	async setPassword(digest) {
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (this.format === "encrypted") throw new VaultError("VAULT_ALREADY_ENCRYPTED", "the credential store already has a password; use changePassword");
		return this.passwordTransition(async () => {
			const plaintexts = this.entries;
			const created = await encryptCredentialStore(plaintexts, digest);
			await writeFileAtomic(this.spec.filename, created.text, { mode: 384, dirMode: 448 });
			this.text = created.text;
			this.format = "encrypted";
			this.unlocked = true;
			this.entries = created.entries;
			this.salt = created.salt;
			this.params = created.params;
			this.kdf = VAULT_KDF;
			this.key = created.key;
			this.remember = void 0;
			this.refusePlain = false;
			this.stateEncrypted = true;
			// The plain values just moved into ciphertext: stale masks must not
			// linger; values re-enter the guard one by one as they resolve.
			this.leakGuard.clear();
			await this.persistState();
		});
	}
	/**
	 * Change the password of the encrypted store (must be unlocked). The
	 * caller must prove knowledge of the CURRENT password: `oldDigest` is
	 * verified against the AEAD verifier before anything is re-encrypted, so
	 * a merely unlocked store is not enough to take it over. Every entry is
	 * then re-encrypted under the new derived key, and the old
	 * remembered-login block dies with the old key. A wrong `oldDigest`
	 * counts as a failed unlock (lockout); a correct one clears the counter.
	 * @param {string} oldDigest - lowercase hex SHA3-256 digest of the current password.
	 * @param {string} digest - lowercase hex SHA3-256 digest of the new password.
	 */
	async changePassword(oldDigest, digest) {
		if (!isDigest(oldDigest)) throw new VaultError("PASSWORD_INVALID", "the current password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the new password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
		this.assertUnlocked("change the password");
		// The lockout window gates password changes exactly like it gates
		// unlocks: a wrong oldDigest counts toward the same counter, so the
		// change-password route must not become an unlimited guessing oracle.
		this.assertUnlockAllowed();
		return this.passwordTransition(async () => {
			this.assertUnlocked("change the password");
			this.assertUnlockAllowed();
			try {
				await verifyPasswordDigest(this.text, oldDigest);
			} catch (error) {
				if (error instanceof VaultError && error.code === "PASSWORD_WRONG") await this.recordUnlockFailure();
				throw error;
			}
			const plaintexts = new Map();
			for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
			const created = await encryptCredentialStore(plaintexts, digest);
			plaintexts.clear();
			await writeFileAtomic(this.spec.filename, created.text, { mode: 384, dirMode: 448 });
			this.text = created.text;
			this.entries = created.entries;
			this.salt = created.salt;
			this.params = created.params;
			this.dropKey();
			this.key = created.key;
			this.kdf = VAULT_KDF;
			this.unlocked = true;
			this.remember = void 0;
			await this.clearUnlockFailures();
		});
	}
	/** Assert the encrypted store is unlocked before a password transition. */
	assertUnlocked(verb) {
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", `cannot ${verb}: the credential store has no password`);
		if (!this.unlocked) throw new VaultError("VAULT_LOCKED", `cannot ${verb}: the credential store is locked; unlock it in Settings → 加密安全`);
	}
	/** Shared queue+lock+reconcile wrapper for password transitions. */
	passwordTransition(operation) {
		if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the queued password transition ran");
			await mkdir(dirname(this.spec.filename), { recursive: true, mode: 448 });
			return withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				return operation();
			});
		});
	}
	describe(ref) {
		if (this.refusePlain) return Promise.resolve({
			configured: false,
			source: "locked",
			writable: false
		});
		if (this.inherited(ref) !== void 0) return Promise.resolve({
			configured: true,
			source: "env",
			writable: false
		});
		if (this.format === "encrypted" && !this.unlocked) return Promise.resolve({
			configured: false,
			source: "locked",
			writable: false
		});
		if (this.entries.get(ref) !== void 0) return Promise.resolve({
			configured: true,
			source: "file",
			writable: true
		});
		const fallback = this.dotenvFallback(ref);
		if (fallback !== void 0) return Promise.resolve({
			configured: true,
			source: fallback.source,
			writable: true
		});
		return Promise.resolve({
			configured: false,
			writable: true
		});
	}
	async set(ref, value) {
		if (value.length === 0) throw new Error(`dsh-encrypt: an empty value cannot be stored for "${ref}"; use unset`);
		await this.write(ref, value);
	}
	async unset(ref) {
		await this.write(ref, void 0);
	}
	/** Queue one exclusive document operation behind every earlier one. */
	enqueue(operation) {
		const task = this.operations.then(operation);
		this.operations = task.then(() => void 0, () => void 0);
		return task;
	}
	/** Queue a reload; only an invariant violation escaping the fan-out can reject it. */
	queueRefresh() {
		this.enqueue(() => this.refresh()).catch((error) => {
			this.ctx.logger.error("dsh-encrypt: reload commit failed at %s", this.spec.filename);
			this.ctx.logger.error(error);
		});
	}
	/** Queue one entry edit; entry checks reject early, the queue re-judges them at run time. */
	async write(ref, value) {
		const verb = value === void 0 ? "unset" : "set";
		if (this.refusePlain) throw new VaultError("VAULT_INVALID", "credential writes are refused while the credential file is plaintext; set the password again in Settings → 加密安全 to re-encrypt it");
		if (this.isClosed()) throw new Error(`dsh-encrypt is disposed: cannot ${verb} "${ref}"`);
		this.assertUnshadowed(ref, verb);
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error(`dsh-encrypt was disposed before the queued "${ref}" ${verb} ran`);
			this.assertUnshadowed(ref, verb);
			await mkdir(dirname(this.spec.filename), { recursive: true, mode: 448 });
			await withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				const existing = this.entries.get(ref);
				if (value === void 0 && existing === void 0) return;
				if (this.format === "encrypted") {
					if (!this.unlocked) throw new VaultError("VAULT_LOCKED", "the credential store is locked; unlock it in Settings → 加密安全 before storing credentials");
					const next = new Map(this.entries);
					if (value === void 0) next.delete(ref);
					else next.set(ref, encryptEntry(this.key, ref, value));
					const nextText = serializeEncryptedStore(next, this.key, this.salt, this.params, this.remember, this.kdf);
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, { mode: 384, dirMode: 448 });
					this.text = nextText;
					this.entries = next;
					if (value !== void 0) this.leakGuard.add(value, ref);
				} else {
					const nextText = renderPlainDocument(this.text, ref, value);
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, { mode: 384, dirMode: 448 });
					this.text = nextText;
					if (value === void 0) this.entries.delete(ref);
					else this.entries.set(ref, value);
					this.syncGuard();
				}
				this.notifyUpdated(ref);
			});
		});
	}
	/**
	 * Reject a write the inherited environment would shadow into apparent
	 * no-effect. Only that layer can shadow a write.
	 */
	assertUnshadowed(ref, verb) {
		if (this.inherited(ref) !== void 0) throw new Error(`dsh-encrypt: "${ref}" is supplied read-only by the launching environment, so ${verb} would be shadowed; unset it in the shell you start dsh from instead`);
	}
	/**
	 * Re-read the document after a watcher event. Unchanged content (including
	 * this provider's own writes) is a no-op; an unreadable or corrupt
	 * document keeps the last good snapshot and warns — a live hot-reload must
	 * never take the process down.
	 */
	async refresh() {
		if (this.closed) return;
		try {
			await this.reconcileFromDisk();
		} catch (error) {
			this.ctx.logger.warn("dsh-encrypt: reload failed at %s; keeping the last good document", this.spec.filename);
			this.ctx.logger.warn(error);
		}
	}
	/**
	 * Compare the on-disk text against the cache and publish any difference
	 * into the seam. Absence publishes the empty plain store; an unreadable or
	 * invalid document throws, so each caller picks its policy. An external
	 * form switch (plain→encrypted or back) is adopted: a newly encrypted file
	 * boots locked, a decrypted one clears the key.
	 */
	async reconcileFromDisk() {
		await assertOwnerOnly(this.spec.filename);
		let text;
		try {
			text = await readFile(this.spec.filename, "utf8");
		} catch (error) {
			if (!isENOENT(error)) throw error;
			text = void 0;
		}
		if (text === this.text || this.isClosed()) return;
		if (text === void 0) {
			this.text = void 0;
			this.format = "plain";
			this.entries = /* @__PURE__ */ new Map();
			this.remember = void 0;
			this.dropKey();
			this.unlocked = true;
			return;
		}
		if (detectCredentialStore(text) === "encrypted") {
			const parsed = parseEncryptedStore(text);
			this.text = text;
			this.format = "encrypted";
			this.entries = parsed.entries;
			this.salt = parsed.salt;
			this.params = parsed.params;
			this.kdf = parsed.kdf;
			this.remember = parsed.remember;
			this.dropKey();
			return;
		}
		const next = parsePlainEntries(text, this.spec.filename);
		if (this.stateEncrypted === true) {
			// Ciphertext-only policy: never serve plaintext. While unlocked,
			// the external plaintext edit is re-encrypted in place immediately;
			// while locked, the last good encrypted snapshot is kept.
			if (this.unlocked && this.key !== void 0) {
				const records = new Map();
				for (const [ref, value] of next) records.set(ref, encryptEntry(this.key, ref, value));
				const cipher = serializeEncryptedStore(records, this.key, this.salt, this.params, this.remember, this.kdf);
				await writeFileAtomic(this.spec.filename, cipher, { mode: 384, dirMode: 448 });
				this.text = cipher;
				this.format = "encrypted";
				this.entries = records;
				this.unlocked = true;
				this.leakGuard.clear();
				this.ctx.logger.warn("dsh-encrypt: external plaintext edit at %s was re-encrypted in place (ciphertext-only policy)", this.spec.filename);
				return;
			}
			this.leakGuard.clear();
			this.ctx.logger.error("dsh-encrypt: refusing to adopt plaintext at %s while locked; keeping the last good encrypted snapshot", this.spec.filename);
			return;
		}
		const changed = [];
		for (const ref of new Set([...this.entries.keys(), ...next.keys()])) if (refChanged(this.entries, next, ref)) changed.push(credentialRef(ref));
		this.text = text;
		this.format = "plain";
		this.entries = next;
		this.remember = void 0;
		this.dropKey();
		this.unlocked = true;
		this.syncGuard();
		for (const ref of changed) this.notifyUpdated(ref);
	}
	// ── remembered-login window (localhost-only; the browser surface lives in ./web.js) ──

	/** The effective remembered-login window: runtime state file over patch config. */
	effectiveDays() {
		const value = this.stateRememberDays ?? this.config.rememberDays ?? 0;
		return Number.isInteger(value) && value >= -1 && value <= 30 ? value : 0;
	}

	/** The WebUI-facing remembered-login snapshot. */
	rememberState() {
		const days = this.effectiveDays();
		const block = this.remember;
		const active = block !== void 0 && rememberActive(block, Date.now());
		return {
			days,
			active,
			issuedAt: block !== void 0 ? block.issuedAt : null,
			expiresAt: block !== void 0 && block.days !== -1 ? block.issuedAt + block.days * REMEMBER_DAY_MS : null
		};
	}

	/** Load the runtime state file ({ rememberDays }) if present and valid. */
	async loadStateFile() {
		let doc;
		try {
			doc = JSON.parse(await readFile(this.spec.stateFile, "utf8"));
		} catch (error) {
			if (!isENOENT(error)) this.ctx.logger.warn("dsh-encrypt: cannot read state file %s: %s", this.spec.stateFile, error instanceof Error ? error.message : String(error));
			return;
		}
		if (typeof doc === "object" && doc !== null && !Array.isArray(doc)) {
			if (Number.isInteger(doc.rememberDays) && doc.rememberDays >= -1 && doc.rememberDays <= 30) this.stateRememberDays = doc.rememberDays;
			else this.ctx.logger.warn("dsh-encrypt: ignoring invalid rememberDays in %s", this.spec.stateFile);
			if (doc.encrypted === true) this.stateEncrypted = true;
			if (Number.isInteger(doc.unlockFailures) && doc.unlockFailures >= 0) this.unlockFailures = doc.unlockFailures;
			if (Number.isFinite(doc.unlockLockedUntil) && doc.unlockLockedUntil >= 0) this.unlockLockedUntil = doc.unlockLockedUntil;
		}
	}

	/**
	 * Write the runtime state file: the remembered-login window plus the
	 * ciphertext-only policy flag. Never throws — state persistence must not
	 * break credential operations.
	 */
	async persistState() {
		try {
			await mkdir(dirname(this.spec.stateFile), { recursive: true, mode: 448 });
			const doc = {};
			const days = this.stateRememberDays;
			if (Number.isInteger(days) && days >= -1 && days <= 30) doc.rememberDays = days;
			if (this.stateEncrypted === true) doc.encrypted = true;
			if (this.unlockFailures > 0) doc.unlockFailures = this.unlockFailures;
			if (this.unlockLockedUntil > 0) doc.unlockLockedUntil = this.unlockLockedUntil;
			await writeFileAtomic(this.spec.stateFile, `${JSON.stringify(doc, null, 2)}\n`, { mode: 384, dirMode: 448 });
		} catch (error) {
			this.ctx.logger.warn("dsh-encrypt: cannot write state file %s: %s", this.spec.stateFile, error instanceof Error ? error.message : String(error));
		}
	}

	/**
	 * Change the remembered-login window (0 = every time, 1..30 days, -1 =
	 * forever). Persists in the runtime state file and invalidates any stored
	 * block; when the store is currently unlocked a fresh ticket is issued
	 * immediately under the new window.
	 * @param {number} days - the new window.
	 * @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
	 */
	async setRememberDays(days) {
		if (!Number.isInteger(days) || days < -1 || days > 30) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be an integer from -1 (forever) through 30, or 0 to require the password every time");
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt is disposed");
			this.stateRememberDays = days;
			await this.persistState();
			if (this.format !== "encrypted") return null;
			await withFileLock(this.spec.filename, async () => {
				await this.reconcileFromDisk();
				// Rewriting the store needs the key: while locked, defer the block
				// revocation to the next unlock (revokeRememberIfDisabled) instead
				// of crashing on the missing key.
				if (this.remember !== void 0 && this.key !== void 0 && this.unlocked) {
					const text = serializeEncryptedStore(this.entries, this.key, this.salt, this.params, void 0, this.kdf);
					await writeFileAtomic(this.spec.filename, text, { mode: 384, dirMode: 448 });
					this.text = text;
					this.remember = void 0;
				}
			});
			if (days !== 0 && this.unlocked && this.key !== void 0) return this.persistRemember(days);
			return null;
		});
	}

	/**
	 * Issue a remembered-login ticket wrapping the current master key. No-op
	 * unless the store is encrypted, unlocked, and the window is non-zero.
	 * @returns {Promise<{ secret: string, days: number, issuedAt: number, expiresAt: number|null }|null>}
	 */
	async issueRemember() {
		if (this.effectiveDays() === 0 || this.format !== "encrypted" || !this.unlocked || this.key === void 0) return null;
		return this.enqueue(async () => {
			if (this.isClosed()) throw new Error("dsh-encrypt was disposed before the remembered-login issue ran");
			if (this.effectiveDays() === 0 || this.format !== "encrypted" || !this.unlocked || this.key === void 0) return null;
			await this.reconcileFromDisk();
			return this.persistRemember(this.effectiveDays());
		});
	}

	/** Rewrite the store with a fresh remember block and return the ticket. */
	async persistRemember(days) {
		let issued;
		await withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			const created = createRememberBlock(this.key, days);
			const text = serializeEncryptedStore(this.entries, this.key, this.salt, this.params, created.block, this.kdf);
			await writeFileAtomic(this.spec.filename, text, { mode: 384, dirMode: 448 });
			this.text = text;
			this.remember = created.block;
			issued = { secret: created.secret, days, issuedAt: created.block.issuedAt, expiresAt: days === -1 ? null : created.block.issuedAt + days * REMEMBER_DAY_MS };
		});
		return issued;
	}

	/**
	 * Unlock with the browser-held remembered-login ticket. Fails with
	 * REMEMBER_EXPIRED / REMEMBER_INVALID when the ticket is stale or does
	 * not match — the web layer then falls back to the password form.
	 * @param {string} secretText - the base64url ticket.
	 */
	async unlockWithRemember(secretText) {
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
		if (this.unlocked) return {
			unlocked: true
		};
		await this.reconcileFromDisk();
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store no longer has a password (the file was changed externally)");
		if (this.unlocked) return {
			unlocked: true
		};
		this.applyUnlock(recoverKeyFromRemember(this.text, secretText));
		this.ctx.logger.info("dsh-encrypt: unlocked with the remembered-login ticket");
		await this.revokeRememberIfDisabled();
		return {
			unlocked: true
		};
	}

	/**
	 * Drop a persisted remembered-login block the runtime window no longer
	 * allows (the slider moved to 0 while the store was locked, when the
	 * block could not be rewritten without the key). Runs right after a
	 * password or ticket unlock; a no-op when nothing is stale.
	 */
	async revokeRememberIfDisabled() {
		if (this.remember === void 0 || this.effectiveDays() !== 0 || !this.unlocked || this.key === void 0) return;
		await withFileLock(this.spec.filename, async () => {
			await this.reconcileFromDisk();
			if (this.remember === void 0 || this.effectiveDays() !== 0 || !this.unlocked || this.key === void 0) return;
			const text = serializeEncryptedStore(this.entries, this.key, this.salt, this.params, void 0, this.kdf);
			await writeFileAtomic(this.spec.filename, text, { mode: 384, dirMode: 448 });
			this.text = text;
			this.remember = void 0;
			this.ctx.logger.info("dsh-encrypt: revoked a remembered-login block the current window no longer allows");
		});
	}

	// ── password operations end here; the browser surface lives in ./web.js ──
};
//#endregion
export { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV, EncryptedCredentialProvider, EncryptedCredentialProvider as default, VaultError, assertOwnerOnly, parsePlainEntries, renderPlainDocument, resolveSpec };
