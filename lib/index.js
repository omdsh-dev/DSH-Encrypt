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
import { VaultError, SCRYPT_N, SCRYPT_P, SCRYPT_R, decryptEntry, detectCredentialStore, encryptCredentialStore, encryptEntry, parseEncryptedStore, serializeEncryptedStore, unlockEncryptedStore, zeroizeBuffer } from "./vault.js";
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
 *    ▲                            │  ▲                                        │
 *    └────── clear-password ──────┘  └──────────── change-password ───────────┘
 * ```
 *
 * While locked the provider activates normally (the web server stays up),
 * `resolve` throws `VAULT_LOCKED` and `describe` reports `source: "locked"` —
 * the Settings page is the unlock surface. Credentials are decrypted per
 * model request; plaintext is never cached between operations.
 *
 * Password APIs: `status()` / `unlock(password)` / `setPassword(password)` /
 * `changePassword(password)` / `clearPassword()`, also exposed to the browser
 * as `/api/credentials.{status,unlock,set-password,change-password,clear-password}`
 * (exact routes, served while a webServer service exists; headless
 * compositions simply have no HTTP surface). `$DSH_CREDENTIAL_PASSWORD`
 * unlocks a locked store at startup for automation.
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
		debounceMs: z.number().min(0).default(100)
	});
	spec;
	/** Current on-disk form: `plain` while no password is set. */
	format = "plain";
	/** Whether the encrypted form is currently unlocked (always true in plain form). */
	unlocked = true;
	/** The derived key while unlocked; zeroized on lock/dispose. */
	key;
	/** scrypt salt and cost parameters of the current encrypted document. */
	salt;
	params;
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
	/** Single exclusive operation chain; settled tail, like credentials-local. */
	operations = Promise.resolve();
	/** Set at dispose: refuse new writes and let in-flight work no-op. */
	closed = false;
	isClosed() {
		return this.closed;
	}
	constructor(ctx, config) {
		super(ctx);
		this.config = config;
		this.spec = resolveSpec(config);
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
			this.entries = parsed.entries;
			this.text = text;
			this.unlocked = false;
			const ambient = launchEnvironmentOf(this.ctx).get(this.spec.passwordEnv);
			if (ambient !== void 0 && ambient.value.length > 0) {
				await this.applyUnlock(await unlockEncryptedStore(text, ambient.value));
			}
			return;
		}
		this.format = "plain";
		this.unlocked = true;
		this.entries = parsePlainEntries(text, this.spec.filename);
		this.text = text;
	}
	/** Apply an unlock result to the snapshot (used by boot env unlock and the API). */
	applyUnlock(unlocked) {
		this.key = unlocked.key;
		this.entries = unlocked.entries;
		this.salt = unlocked.salt;
		this.params = unlocked.params;
		this.unlocked = true;
	}
	/**
	 * Resolve one reference per operation: plaintext value, or a decrypted
	 * transient value while unlocked. Never cached between operations.
	 * @param ref - the reference to resolve.
	 * @returns value and source, or `undefined` while unconfigured.
	 */
	resolve(ref) {
		const inherited = this.inherited(ref);
		if (inherited !== void 0) return Promise.resolve({
			value: inherited,
			source: "env"
		});
		const record = this.entries.get(ref);
		if (record !== void 0) {
			try {
				if (this.format === "encrypted") {
					if (!this.unlocked) return Promise.reject(new VaultError("VAULT_LOCKED", `the credential store is locked; unlock it in Settings → 加密安全 (or export ${this.spec.passwordEnv})`));
					const value = decryptEntry(this.key, ref, record);
					return Promise.resolve({ value, source: "file" });
				}
				return Promise.resolve({ value: record, source: "file" });
			} catch (error) {
				return Promise.reject(error);
			}
		}
		const fallback = this.dotenvFallback(ref);
		if (fallback !== void 0) return Promise.resolve({
			value: fallback.value,
			source: fallback.source
		});
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
	/** The WebUI-facing snapshot: form and lock state. */
	status() {
		return Promise.resolve({
			format: this.format,
			unlocked: this.unlocked
		});
	}
	/**
	 * Unlock the encrypted store with the user's password.
	 * @param password - the password to check.
	 */
	async unlock(password) {
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store has no password; nothing to unlock");
		if (this.unlocked) return {
			unlocked: true
		};
		await this.reconcileFromDisk();
		if (this.format !== "encrypted") throw new VaultError("VAULT_NOT_ENCRYPTED", "the credential store no longer has a password (the file was changed externally)");
		if (this.unlocked) return {
			unlocked: true
		};
		this.applyUnlock(await unlockEncryptedStore(this.text, password));
		return {
			unlocked: true
		};
	}
	/**
	 * Set the first password: the file's plaintext contents are replaced by
	 * the encrypted document in place, and the provider stays unlocked.
	 * @param password - the new non-empty password.
	 */
	async setPassword(password) {
		if (this.format === "encrypted") throw new VaultError("VAULT_ALREADY_ENCRYPTED", "the credential store already has a password; use changePassword");
		return this.passwordTransition(async () => {
			const plaintexts = this.entries;
			const created = await encryptCredentialStore(plaintexts, password);
			await writeFileAtomic(this.spec.filename, created.text, { mode: 384, dirMode: 448 });
			this.text = created.text;
			this.format = "encrypted";
			this.unlocked = true;
			this.entries = created.entries;
			this.salt = created.salt;
			this.params = { n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P };
			this.key = created.key;
		});
	}
	/**
	 * Change the password of the encrypted store (must be unlocked). Every
	 * entry is re-encrypted under the new derived key.
	 * @param password - the new non-empty password.
	 */
	async changePassword(password) {
		this.assertUnlocked("change the password");
		return this.passwordTransition(async () => {
			const plaintexts = new Map();
			for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
			const created = await encryptCredentialStore(plaintexts, password);
			await writeFileAtomic(this.spec.filename, created.text, { mode: 384, dirMode: 448 });
			this.text = created.text;
			this.entries = created.entries;
			this.salt = created.salt;
			this.dropKey();
			this.key = created.key;
			this.unlocked = true;
		});
	}
	/**
	 * Remove the password (must be unlocked): every entry is decrypted and the
	 * file returns to the plaintext YAML form. The key is zeroized.
	 */
	async clearPassword() {
		this.assertUnlocked("remove the password");
		return this.passwordTransition(async () => {
			const plaintexts = new Map();
			for (const [ref, record] of this.entries) plaintexts.set(ref, decryptEntry(this.key, ref, record));
			const rendered = this.renderPlainFromMap(plaintexts);
			await writeFileAtomic(this.spec.filename, rendered, { mode: 384, dirMode: 448 });
			this.text = rendered;
			this.format = "plain";
			this.entries = plaintexts;
			this.dropKey();
			this.unlocked = true;
		});
	}
	/** Render the plain form from a full entries map. */
	renderPlainFromMap(entries) {
		const document = new Document({});
		for (const [ref, value] of entries) document.setIn([ref], value);
		return document.toString();
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
					const nextText = serializeEncryptedStore(next, this.key, this.salt, this.params);
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, { mode: 384, dirMode: 448 });
					this.text = nextText;
					this.entries = next;
				} else {
					const nextText = renderPlainDocument(this.text, ref, value);
					if (nextText === this.text) return;
					await writeFileAtomic(this.spec.filename, nextText, { mode: 384, dirMode: 448 });
					this.text = nextText;
					if (value === void 0) this.entries.delete(ref);
					else this.entries.set(ref, value);
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
			this.dropKey();
			return;
		}
		const next = parsePlainEntries(text, this.spec.filename);
		const changed = [];
		for (const ref of new Set([...this.entries.keys(), ...next.keys()])) if (refChanged(this.entries, next, ref)) changed.push(credentialRef(ref));
		this.text = text;
		this.format = "plain";
		this.entries = next;
		this.dropKey();
		this.unlocked = true;
		for (const ref of changed) this.notifyUpdated(ref);
	}
	// ── password operations end here; the browser surface lives in ./web.js ──
};
//#endregion
export { CREDENTIALS_FILENAME, DEFAULT_PASSWORD_ENV, EncryptedCredentialProvider, EncryptedCredentialProvider as default, VaultError, assertOwnerOnly, parsePlainEntries, renderPlainDocument, resolveSpec };
