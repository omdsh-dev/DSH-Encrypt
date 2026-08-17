/**
 * Encrypted credential vault core — the pure, dependency-free crypto layer of
 * `dsh-encrypt`.
 *
 * ## Threat model and guarantees
 *
 * Every secret is stored as AES-256-GCM ciphertext and is held in memory only
 * as ciphertext. Plaintext exists for the lifetime of one decryption call: a
 * caller requests it, uses it, and the reference dies — the provider never
 * caches plaintext between operations.
 *
 * Integrity is checked twice, both with SHA3-256:
 *
 * 1. **Entry-level**: each record carries `sha3(data)` where `data` is the
 *    base64url(nonce ‖ ciphertext ‖ GCM tag) blob. `verifyEntryRecord()`
 *    compares the stored fingerprint against the blob before any decryption,
 *    so a bit-rotten or truncated store is reported as `VAULT_CORRUPTED` with
 *    the offending reference named — without ever touching the key.
 * 2. **Document-level**: the document carries `sha3(canonical-entries-block)`,
 *    so adding, removing, or swapping whole entries (or replacing the file
 *    with an older version) fails the check as well.
 *
 * The GCM authentication tag is the third, cryptographic, layer: a ciphertext
 * that was tampered with AND had its SHA3 fingerprints recomputed still fails
 * `aes-256-gcm` tag verification and is reported as `VAULT_KEY_MISMATCH` (the
 * same report as a wrong master key — the two are indistinguishable by design,
 * which is the honest answer for an AEAD).
 *
 * The reference name is bound into the ciphertext as GCM AAD, so swapping the
 * record of `OPENCODE_GO_API_KEY` into the slot of `DEEPSEEK_API_KEY` fails
 * authentication instead of silently returning the other entry's secret.
 *
 * ## Honest limits
 *
 * - JavaScript strings are immutable: a decrypted value cannot be zeroized.
 *   The guarantee offered here is *no persistence, no caching, no logging*,
 *   and reference death at the end of the operation — not memory erasure.
 * - The master key (KEK) must be readable as bytes to decrypt anything, so it
 *   lives in memory as a `Buffer` for the process lifetime and IS zeroized on
 *   provider disposal (`zeroizeBuffer`). Protect it with the OS account and
 *   the `0600` key file.
 *
 * ## Password-derived keys
 *
 * The master key is stretched from the password's SHA3-256 digest with
 * **Argon2id** (`@node-rs/argon2`, 64 MiB / 3 passes / 1 lane — OWASP
 * aligned) plus a random 16-byte salt, and proven against an AEAD verifier
 * record on every unlock (`PASSWORD_WRONG` on mismatch). The password
 * itself never crosses the wire and is never stored — the WebUI derives the
 * digest, the server only ever sees the digest. Forgetting the password
 * means wiping the vault; nothing else can recover it, by design.
 *
 * Version-2 documents (scrypt KDF, dsh-encrypt ≤ 0.1.0-rc.8) still parse
 * and unlock with their own stored scrypt parameters, and are transparently
 * re-encrypted into the Argon2id format on the next password unlock.
 *
 * @module dsh-encrypt/vault
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from "node:crypto";
import { promisify } from "node:util";
import { Algorithm as Argon2Algorithm, hashRaw as argon2HashRaw } from "@node-rs/argon2";

const scryptAsync = promisify(scrypt);

/** Document schema version. v3 stretches the password digest with Argon2id. */
export const VAULT_VERSION = 3;
/** Algorithm identifier persisted in the document and asserted on parse. */
export const VAULT_ALGORITHM = "aes-256-gcm+sha3-256";
/** KDF marker written by v3 documents (Argon2id). */
export const VAULT_KDF = "argon2id";
/** KDF marker of legacy v2 documents (scrypt); parsed and upgraded on unlock. */
export const LEGACY_KDF = "scrypt";
/** KDF input marker: the KDF stretches the lowercase hex SHA3-256 digest. */
export const VAULT_KDF_INPUT = "sha3-256-password";
/** Master key size in bytes (AES-256). */
export const MASTER_KEY_BYTES = 32;
/** GCM nonce size in bytes. */
export const NONCE_BYTES = 12;
/** GCM authentication tag size in bytes. */
export const TAG_BYTES = 16;
/** Argon2id default memory cost in KiB (64 MiB). */
export const ARGON2_MEMORY_KIB = 65536;
/** Argon2id default time cost (passes). */
export const ARGON2_TIME = 3;
/** Argon2id default parallelism (lanes). */
export const ARGON2_PARALLELISM = 1;
/** Argon2id memory ceiling accepted from a document (256 MiB — hostile-parameter guard). */
export const ARGON2_MAX_MEMORY_KIB = 262144;
/** Argon2id time-cost ceiling accepted from a document (CPU-exhaustion guard). */
export const ARGON2_MAX_TIME = 64;
/** Argon2id parallelism ceiling accepted from a document. */
export const ARGON2_MAX_PARALLELISM = 32;
/** Legacy scrypt cost parameters (v2 documents carry their own; defaults for tests). */
export const SCRYPT_N = 131072;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
/** Legacy scrypt memory ceiling in bytes; 128 * N * r needs 128 MiB plus overhead. */
export const SCRYPT_MAXMEM = 256 * 1024 * 1024;
/** Password salt size in bytes. */
export const PASSWORD_SALT_BYTES = 16;
/** Milliseconds in one remembered-login day window. */
export const REMEMBER_DAY_MS = 86400000;

/** Lowercase hex SHA3-256 of a UTF-8 text (server-side digest helper). */
export function sha3_256Hex(text) {
	return createHash("sha3-256").update(text, "utf8").digest("hex");
}

/** Whether a text is a valid lowercase hex SHA3-256 digest. */
export function isDigest(value) {
	return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}
/** The fixed reference the key-file verifier record is stored under. */
export const KEY_FILE_VERIFIER_REF = "DSH_CREDENTIAL_MASTER_VERIFIER";
/** Fixed plaintext the key-file verifier encrypts; it is not a secret. */
const KEY_FILE_VERIFIER_TEXT = "dsh-encrypt master-key verifier";

/**
 * Vault failure with a stable machine-readable `code`. Messages never contain
 * plaintext, ciphertext, key material, or the offending document body.
 */
export class VaultError extends Error {
	code;
	/**
	 * @param {string} code - stable machine-readable error code.
	 * @param {string} message - human-readable message (never secret-bearing).
	 * @param {Record<string, unknown>} [details] - optional machine-readable
	 *   fields merged onto the error (e.g. retryAfterMs for TOO_MANY_ATTEMPTS).
	 */
	constructor(code, message, details) {
		super(`dsh-encrypt: ${message}`);
		this.name = "VaultError";
		this.code = code;
		if (details !== void 0 && details !== null && typeof details === "object") Object.assign(this, details);
	}
}

/** Reference names a record may be stored under (mirrors the credential seam). */
const REF_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** One persisted record: the ciphertext blob and its SHA3-256 fingerprint. */
/**
 * @typedef {Object} EntryRecord
 * @property {string} data - base64url(nonce ‖ ciphertext ‖ tag).
 * @property {string} sha3 - hex SHA3-256 of `data`.
 */

/** Non-cryptographic plain-object check (arrays fail on purpose). */
function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Zeroize a key buffer. Call on disposal; callers must not use the buffer
 * afterwards.
 * @param {Buffer} buffer - the buffer to erase.
 */
export function zeroizeBuffer(buffer) {
	buffer.fill(0);
}

/** Generate a fresh 256-bit master key. */
export function generateMasterKey() {
	return randomBytes(MASTER_KEY_BYTES);
}

/** Encode a master key as base64url text for the key file / env var. */
export function encodeMasterKey(key) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	return key.toString("base64url");
}

/**
 * Parse a master key from user-supplied text. Accepts the key-file format
 * (base64url) and bare hex (64 hex digits); surrounding whitespace is trimmed
 * silently because a padded pasted key has one unambiguous reading.
 * @param {string} text - the raw text.
 * @returns {Buffer} the 32-byte key.
 */
export function parseMasterKey(text) {
	if (typeof text !== "string") throw new VaultError("MASTER_KEY_INVALID", "the master key must be text (base64url or 64 hex digits)");
	const value = text.trim();
	if (value.length === 0) throw new VaultError("MASTER_KEY_INVALID", "the master key is empty");
	let key;
	if (/^[0-9a-fA-F]{64}$/.test(value)) key = Buffer.from(value, "hex");
	else {
		try {
			key = Buffer.from(value, "base64url");
		} catch {
			throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
		}
		// base64url decoding is lenient about trailing garbage-free length; re-encode
		// to prove the text really encoded exactly the key bytes.
		if (key.toString("base64url").replace(/=+$/u, "") !== value.replace(/=+$/u, "")) throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
	}
	if (key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", `the master key must decode to ${MASTER_KEY_BYTES} bytes, got ${key.length}`);
	return key;
}

/** Generate a fresh 16-byte salt for a password-derived master key. */
export function generatePasswordSalt() {
	return randomBytes(PASSWORD_SALT_BYTES);
}

/**
 * Derive a 32-byte master key from the SHA3-256 digest of a user-chosen
 * password. Only the digest (64 lowercase hex characters) is accepted: the
 * browser derives it from the password, so the raw password never reaches
 * this process. The digest itself is never stored or logged; only the salt
 * and an AEAD verifier are persisted.
 *
 * The default KDF is Argon2id via `@node-rs/argon2`; the legacy scrypt
 * path remains for version-2 documents until they are upgraded.
 * @param {string} digest - the lowercase hex SHA3-256 digest of the password.
 * @param {Buffer} salt - the persisted salt.
 * @param {Object} [params] - cost parameters for the selected KDF.
 * @param {string} [kdf] - `"argon2id"` (default) or the legacy `"scrypt"`.
 * @returns {Promise<Buffer>} the 32-byte key.
 */
export async function deriveMasterKey(digest, salt, params = argon2Defaults(), kdf = VAULT_KDF) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (kdf === LEGACY_KDF) return deriveScryptKey(digest, salt, params);
	if (kdf === VAULT_KDF) return deriveArgon2idKey(digest, salt, params);
	throw new VaultError("MASTER_KEY_INVALID", `unsupported kdf ${String(kdf)}`);
}

/** Default Argon2id cost parameters (64 MiB, 3 passes, 1 lane). */
export function argon2Defaults() {
	return { m: ARGON2_MEMORY_KIB, t: ARGON2_TIME, p: ARGON2_PARALLELISM };
}

/**
 * Derive the key with Argon2id (`@node-rs/argon2`). The digest is passed as
 * the password bytes; memory is capped so a hostile document cannot demand
 * unbounded RAM.
 * @param {string} digest - lowercase hex SHA3-256 digest of the password.
 * @param {Buffer} salt - the persisted salt.
 * @param {{ m: number, t: number, p: number }} params - memory (KiB), time, parallelism.
 * @returns {Promise<Buffer>} the 32-byte key.
 */
export async function deriveArgon2idKey(digest, salt, params) {
	if (!Number.isInteger(params.m) || params.m < 8 || params.m > ARGON2_MAX_MEMORY_KIB) throw new VaultError("MASTER_KEY_INVALID", `argon2id memory cost must be an integer from 8 through ${ARGON2_MAX_MEMORY_KIB} KiB`);
	if (!Number.isInteger(params.t) || params.t < 1 || params.t > ARGON2_MAX_TIME) throw new VaultError("MASTER_KEY_INVALID", `argon2id time cost must be an integer from 1 through ${ARGON2_MAX_TIME}`);
	if (!Number.isInteger(params.p) || params.p < 1 || params.p > ARGON2_MAX_PARALLELISM) throw new VaultError("MASTER_KEY_INVALID", `argon2id parallelism must be an integer from 1 through ${ARGON2_MAX_PARALLELISM}`);
	// hashRaw returns exactly outputLen bytes (the `hash` entry
	// returns the PHC-encoded string in argon2 v2, which is not a key).
	const raw = await argon2HashRaw(Buffer.from(digest, "utf8"), {
		algorithm: Argon2Algorithm.Argon2id,
		salt,
		outputLen: MASTER_KEY_BYTES,
		memoryCost: params.m,
		timeCost: params.t,
		parallelism: params.p
	});
	const key = Buffer.from(raw);
	if (key.length < MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "argon2id produced fewer than 32 bytes");
	return key.subarray(0, MASTER_KEY_BYTES);
}

/**
 * Legacy scrypt derivation for version-2 documents (dsh-encrypt ≤ 0.1.0-rc.8).
 * Kept only so an existing v2 vault can still be unlocked and upgraded.
 * @param {string} digest - lowercase hex SHA3-256 digest of the password.
 * @param {Buffer} salt - the persisted salt.
 * @param {{ n: number, r: number, p: number }} params - scrypt cost parameters.
 * @returns {Promise<Buffer>} the 32-byte key.
 */
export async function deriveScryptKey(digest, salt, params) {
	if (!Number.isInteger(params.n) || !Number.isInteger(params.r) || !Number.isInteger(params.p) || params.n <= 0 || params.r <= 0 || params.p <= 0) throw new VaultError("MASTER_KEY_INVALID", "scrypt parameters must be positive integers");
	return scryptAsync(digest, salt, MASTER_KEY_BYTES, { N: params.n, r: params.r, p: params.p, maxmem: SCRYPT_MAXMEM });
}

/**
 * Serialize a password-protected key file: Argon2id parameters, the salt,
 * and an AEAD verifier the password is checked against. Contains neither the
 * password nor the derived key. (A standalone helper kept for API
 * compatibility — the credential store itself is the v3 document format.)
 * @param {Buffer} key - the derived 32-byte key.
 * @param {Buffer} salt - the salt the key was derived from.
 * @param {{ m: number, t: number, p: number }} [params] - the Argon2id cost parameters used.
 * @returns {string} the key-file text.
 */
export function createPasswordKeyFile(key, salt, params = argon2Defaults()) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	const doc = {
		version: 1,
		kdf: VAULT_KDF,
		m: params.m,
		t: params.t,
		p: params.p,
		salt: salt.toString("base64url"),
		verifier: encryptEntry(key, KEY_FILE_VERIFIER_REF, KEY_FILE_VERIFIER_TEXT)
	};
	return `${JSON.stringify(doc, null, 2)}\n`;
}

/** Whether a key-file text uses the password format rather than a raw key. */
export function isPasswordKeyFile(text) {
	try {
		const doc = JSON.parse(text);
		return isRecord(doc) && (doc.kdf === VAULT_KDF || doc.kdf === LEGACY_KDF);
	} catch {
		return false;
	}
}

/**
 * Parse a password key file and check the password against its AEAD
 * verifier. A wrong password derives a wrong key, so the verifier decrypt
 * fails and is reported as `PASSWORD_WRONG` — before any vault entry is
 * touched, so the caller can tell "wrong password" apart from "corrupt
 * vault". Argon2id files stretch the password bytes directly; legacy scrypt
 * files keep their stored parameters.
 * @param {string} text - the key-file text.
 * @param {string} password - the password to check.
 * @returns {Promise<Buffer>} the verified 32-byte key.
 */
export async function parsePasswordKeyFile(text, password) {
	let doc;
	try {
		doc = JSON.parse(text);
	} catch {
		throw new VaultError("MASTER_KEY_INVALID", "the key file is neither a legacy raw key nor a password key file");
	}
	if (!isRecord(doc) || typeof doc.salt !== "string") throw new VaultError("MASTER_KEY_INVALID", "unsupported password key-file format");
	const salt = Buffer.from(doc.salt, "base64url");
	let key;
	if (doc.kdf === LEGACY_KDF) {
		const params = { n: doc.n, r: doc.r, p: doc.p };
		key = await deriveScryptKey(password, salt, params);
	} else if (doc.kdf === VAULT_KDF) {
		const params = { m: doc.m, t: doc.t, p: doc.p };
		key = await deriveArgon2idKey(password, salt, params);
	} else {
		throw new VaultError("MASTER_KEY_INVALID", `unsupported password key-file kdf ${JSON.stringify(doc.kdf)}`);
	}
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, doc.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password does not match this master-key file");
		throw error;
	}
	return key;
}

/**
 * Validate one record shape and its entry-level SHA3-256 fingerprint.
 * @param {string} ref - the reference owning the record (named in errors).
 * @param {unknown} record - the persisted value.
 */
export function verifyEntryRecord(ref, record) {
	if (!isRecord(record) || typeof record.data !== "string" || typeof record.sha3 !== "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" must map to { data, sha3 } strings`);
	const actual = createHash("sha3-256").update(record.data, "utf8").digest("hex");
	if (actual !== record.sha3) throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" failed its SHA3-256 integrity check: the stored ciphertext does not match its fingerprint`);
}

/** Compute the entry-level SHA3-256 fingerprint of one ciphertext blob. */
function fingerprint(data) {
	return createHash("sha3-256").update(data, "utf8").digest("hex");
}

/**
 * Encrypt one secret into a persisted record. The reference is bound as GCM
 * AAD; a fresh random nonce is drawn per call, so encrypting the same value
 * twice yields different ciphertext.
 * @param {Buffer} key - the 32-byte master key.
 * @param {string} ref - the reference this secret is stored under.
 * @param {string} plaintext - the non-empty secret value.
 * @returns {EntryRecord} the record to persist.
 */
export function encryptEntry(key, ref, plaintext) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!REF_PATTERN.test(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	if (typeof plaintext !== "string" || plaintext.length === 0) throw new VaultError("VAULT_INVALID", `the plaintext for "${ref}" must be a non-empty string`);
	const nonce = randomBytes(NONCE_BYTES);
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	cipher.setAAD(Buffer.from(ref, "utf8"));
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	const data = Buffer.concat([nonce, ciphertext, tag]).toString("base64url");
	return { data, sha3: fingerprint(data) };
}

/**
 * Decrypt one record into a mutable plaintext Buffer for burn-after-read
 * consumers. Entry integrity is verified first (SHA3-256), then GCM
 * authentication. Callers MUST zeroize the returned buffer when done — or
 * prefer the provider's `withUnlockedBuffer` seam, which burns it in a
 * finally block.
 * @param {Buffer} key - the 32-byte master key.
 * @param {string} ref - the reference the record is stored under (GCM AAD).
 * @param {unknown} record - the persisted record.
 * @returns {Buffer} the plaintext.
 */
export function decryptEntryBuffer(key, ref, record) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!REF_PATTERN.test(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	verifyEntryRecord(ref, record);
	let blob;
	try {
		blob = Buffer.from(record.data, "base64url");
	} catch {
		throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" is not valid base64url`);
	}
	if (blob.length <= NONCE_BYTES + TAG_BYTES) throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" is truncated`);
	const nonce = blob.subarray(0, NONCE_BYTES);
	const tag = blob.subarray(blob.length - TAG_BYTES);
	const ciphertext = blob.subarray(NONCE_BYTES, blob.length - TAG_BYTES);
	try {
		const decipher = createDecipheriv("aes-256-gcm", key, nonce);
		decipher.setAAD(Buffer.from(ref, "utf8"));
		decipher.setAuthTag(tag);
		return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	} catch {
		throw new VaultError("VAULT_KEY_MISMATCH", `entry "${ref}" failed AES-256-GCM authentication: the master key does not match this document, or the ciphertext was replaced`);
	}
}

/**
 * Decrypt one record into its plaintext string (the official seam shape).
 * The intermediate plaintext Buffer is zeroized before the string is
 * returned — the string itself is an immutable copy JavaScript cannot wipe,
 * so callers must drop it after use (see `withUnlockedBuffer` for an
 * erasure-capable path).
 * @param {Buffer} key - the 32-byte master key.
 * @param {string} ref - the reference the record is stored under (GCM AAD).
 * @param {unknown} record - the persisted record.
 * @returns {string} the plaintext.
 */
export function decryptEntry(key, ref, record) {
	const plain = decryptEntryBuffer(key, ref, record);
	const text = plain.toString("utf8");
	zeroizeBuffer(plain);
	return text;
}

/** Sort a plain object's keys and return the canonical deep copy. */
function canonicalEntries(entries) {
	const sorted = {};
	for (const ref of Object.keys(entries).sort()) sorted[ref] = entries[ref];
	return sorted;
}

/** Serialize the sorted entries block exactly as the document fingerprint covers it. */
function entriesBlock(entries) {
	return JSON.stringify(canonicalEntries(entries));
}

/**
 * Serialize a complete vault document from an entries map. Output is stable
 * for equal content regardless of insertion order (keys are sorted), so the
 * document-level SHA3-256 comparison is meaningful across writes.
 * @param {Map<string, EntryRecord>} entries - records keyed by reference.
 * @returns {string} the document text.
 */
export function serializeDocument(entries) {
	const canonical = canonicalEntries(Object.fromEntries(entries));
	const block = JSON.stringify(canonical);
	const doc = {
		version: VAULT_VERSION,
		algorithm: VAULT_ALGORITHM,
		sha3: createHash("sha3-256").update(block, "utf8").digest("hex"),
		entries: canonical
	};
	return `${JSON.stringify(doc, null, 2)}\n`;
}

/**
 * Parse and fully verify a vault document: structure, document-level
 * SHA3-256, and every entry-level SHA3-256 fingerprint. This is the startup
 * and hot-reload check — a store that exists but cannot be trusted must never
 * be treated as "no credentials stored".
 * @param {string} text - the raw document text.
 * @returns {{ entries: Map<string, EntryRecord>, documentSha3: string }} the verified entries.
 */
export function parseDocument(text) {
	let doc;
	try {
		doc = JSON.parse(text);
	} catch {
		throw new VaultError("VAULT_INVALID", "the vault document is not valid JSON");
	}
	if (!isRecord(doc)) throw new VaultError("VAULT_INVALID", "the vault document must be a JSON object");
	if (doc.version !== VAULT_VERSION) throw new VaultError("VAULT_INVALID", `unsupported vault version ${JSON.stringify(doc.version)} (expected ${VAULT_VERSION})`);
	if (doc.algorithm !== VAULT_ALGORITHM) throw new VaultError("VAULT_INVALID", `unsupported vault algorithm ${JSON.stringify(doc.algorithm)} (expected ${VAULT_ALGORITHM})`);
	if (!isRecord(doc.entries)) throw new VaultError("VAULT_INVALID", "the vault document needs an entries object");
	if (typeof doc.sha3 !== "string") throw new VaultError("VAULT_INVALID", "the vault document needs a sha3 fingerprint");
	// Structural checks run before the document fingerprint: a malformed
	// document is INVALID, not CORRUPTED — the hash can only be compared once
	// the entries block is known to have the shape it covers.
	for (const [ref, record] of Object.entries(doc.entries)) {
		if (!REF_PATTERN.test(ref)) throw new VaultError("VAULT_INVALID", `entry key "${ref}" is not a credential reference`);
		if (!isRecord(record) || typeof record.data !== "string" || typeof record.sha3 !== "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" must map to { data, sha3 } strings`);
	}
	const block = entriesBlock(doc.entries);
	const actual = createHash("sha3-256").update(block, "utf8").digest("hex");
	if (actual !== doc.sha3) throw new VaultError("VAULT_CORRUPTED", "the vault document failed its SHA3-256 integrity check: entries were added, removed, swapped, or altered");
	const entries = new Map();
	for (const [ref, record] of Object.entries(doc.entries)) {
		verifyEntryRecord(ref, record);
		entries.set(ref, record);
	}
	return { entries, documentSha3: actual };
}

/** Convenience alias: parse a document and throw away the entries. */
export function verifyDocument(text) {
	parseDocument(text);
}

// ── single-file encrypted credential store ─────────────────────────────────
//
// The WebUI-friendly on-disk shape: ONE file (`$DSH_HOME/.credentials.yaml`)
// carries the credentials in two forms:
//
//   plain form     — a strict `Ref: value` YAML mapping while no password is
//                    set (drop-in identical to dsh-credentials-local).
//   encrypted form — the same file's contents replaced by a JSON document:
//
//   {
//     "format": "dsh-encrypt-credentials",
//     "version": 2, "algorithm": "aes-256-gcm+sha3-256",
//     "kdf": "scrypt", "kdfInput": "sha3-256-password",
//     "n": ..., "r": ..., "p": ...,
//     "salt": "<base64url>",
//     "verifier": { "data": ..., "sha3": ... },   ← AEAD digest check
//     "remember": {                                ← absent until a
//       "salt": "<base64url>",                       localhost remembered
//       "issuedAt": <unix ms>,                      login is issued
//       "days": 7 | -1,
//       "cipher": { "data": ..., "sha3": ... }      ← KEK wrapped under the
//     },                                              browser-held ticket
//     "entries": { REF: { data, sha3 }, ... },
//     "sha3": "<document fingerprint>"
//   }
//
// The document fingerprint covers every field except `sha3` itself, so
// tampering with the salt, the cost parameters, or the verifier fails
// `VAULT_CORRUPTED` before any key is derived; a wrong password survives the
// fingerprint (it changes no field) and is caught by the verifier AEAD as
// `PASSWORD_WRONG`. The password itself is never stored.

/** Format marker persisted in the encrypted store document. */
export const ENCRYPTED_STORE_FORMAT = "dsh-encrypt-credentials";
/** Field order the document fingerprint is computed over (stable across parse). */
const STORE_FIELDS = ["format", "version", "algorithm", "kdf", "kdfInput", "n", "r", "m", "t", "p", "salt", "verifier", "remember", "entries"];

/**
 * Whether a credential file's text is the encrypted form. An empty or
 * non-JSON text is the plain form; a JSON document carrying the format
 * marker is the encrypted form.
 * @param {string} text - the raw file text.
 * @returns {"encrypted" | "plain"} the detected form.
 */
export function detectCredentialStore(text) {
	const trimmed = text.trim();
	if (trimmed.length === 0) return "plain";
	try {
		const doc = JSON.parse(trimmed);
		if (isRecord(doc) && doc.format === ENCRYPTED_STORE_FORMAT) return "encrypted";
	} catch {}
	return "plain";
}

/** Rebuild the fingerprint target from a parsed document in the canonical field order. */
function fingerprintTarget(doc) {
	const target = {};
	for (const field of STORE_FIELDS) if (doc[field] !== void 0) target[field] = doc[field];
	return target;
}

/**
 * Serialize the encrypted credential-store document. Records are already
 * encrypted under `key`; the key additionally encrypts the fixed verifier so
 * a password digest can be checked without touching any credential. An
 * optional `remember` block (created by `createRememberBlock`) wraps the key
 * for localhost remembered logins.
 *
 * Writes the current v3 Argon2id format by default; passing
 * `kdf = LEGACY_KDF` re-serializes a still-legacy (scrypt) store, e.g.
 * after a remembered-login unlock that never saw the password digest.
 * @param {Map<string, EntryRecord>} records - ciphertext records keyed by reference.
 * @param {Buffer} key - the derived 32-byte key.
 * @param {Buffer} salt - the persisted KDF salt.
 * @param {Object} [params] - the cost parameters used (Argon2id m/t/p, or legacy n/r/p).
 * @param {Object} [remember] - optional remembered-login block.
 * @param {string} [kdf] - `"argon2id"` (default) or `"scrypt"` for a legacy re-serialization.
 * @returns {string} the document text.
 */
export function serializeEncryptedStore(records, key, salt, params = argon2Defaults(), remember, kdf = VAULT_KDF) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (remember !== void 0) validateRememberBlock(remember);
	if (kdf !== VAULT_KDF && kdf !== LEGACY_KDF) throw new VaultError("MASTER_KEY_INVALID", `unsupported store kdf ${String(kdf)}`);
	const doc = {
		format: ENCRYPTED_STORE_FORMAT,
		// Legacy scrypt stores keep the v2 version marker so parsers never see
		// a v3 document carrying a non-Argon2id KDF.
		version: kdf === LEGACY_KDF ? 2 : VAULT_VERSION,
		algorithm: VAULT_ALGORITHM,
		kdf,
		kdfInput: VAULT_KDF_INPUT,
		salt: salt.toString("base64url"),
		verifier: encryptEntry(key, KEY_FILE_VERIFIER_REF, KEY_FILE_VERIFIER_TEXT),
		entries: canonicalEntries(Object.fromEntries(records))
	};
	if (kdf === LEGACY_KDF) {
		doc.n = params.n;
		doc.r = params.r;
		doc.p = params.p;
	} else {
		doc.m = params.m;
		doc.t = params.t;
		doc.p = params.p;
	}
	if (remember !== void 0) doc.remember = remember;
	doc.sha3 = createHash("sha3-256").update(JSON.stringify(fingerprintTarget(doc)), "utf8").digest("hex");
	return `${JSON.stringify(doc, null, 2)}\n`;
}

/**
 * Parse and fully verify an encrypted credential-store document: structure,
 * document-level SHA3-256 over every non-fingerprint field, and every
 * entry-level SHA3-256. No key is needed — this is the startup and hot-reload
 * integrity check, distinct from unlocking. Version-2 documents (legacy
 * scrypt KDF) parse alongside the current Argon2id format.
 * @param {string} text - the raw document text.
 * @returns {{ salt: Buffer, params: Object, kdf: string, verifier: EntryRecord, entries: Map<string, EntryRecord>, remember: Object|undefined, documentSha3: string }}
 */
export function parseEncryptedStore(text) {
	let doc;
	try {
		doc = JSON.parse(text);
	} catch {
		throw new VaultError("VAULT_INVALID", "the encrypted credential store is not valid JSON");
	}
	if (!isRecord(doc) || doc.format !== ENCRYPTED_STORE_FORMAT) throw new VaultError("VAULT_INVALID", `the document is not a ${ENCRYPTED_STORE_FORMAT} store`);
	if (doc.version === 1) throw new VaultError("VAULT_INVALID", "unsupported store version 1; a store encrypted by dsh-encrypt ≤ 0.1.0-rc.6 must be unlocked and returned to plaintext with that version first");
	if (doc.version !== 2 && doc.version !== VAULT_VERSION) throw new VaultError("VAULT_INVALID", `unsupported store version ${JSON.stringify(doc.version)} (expected ${VAULT_VERSION}, or 2 for a legacy scrypt store)`);
	if (doc.algorithm !== VAULT_ALGORITHM) throw new VaultError("VAULT_INVALID", `unsupported store algorithm ${JSON.stringify(doc.algorithm)}`);
	if (doc.kdfInput !== VAULT_KDF_INPUT) throw new VaultError("VAULT_INVALID", `unsupported kdf input ${JSON.stringify(doc.kdfInput)} (expected ${VAULT_KDF_INPUT})`);
	let kdf;
	let params;
	if (doc.kdf === LEGACY_KDF) {
		if (doc.version !== 2) throw new VaultError("VAULT_INVALID", "a scrypt store must carry version 2");
		if (!Number.isInteger(doc.n) || !Number.isInteger(doc.r) || !Number.isInteger(doc.p) || doc.n <= 0 || doc.r <= 0 || doc.p <= 0) throw new VaultError("VAULT_INVALID", "the store needs positive scrypt cost parameters");
		kdf = LEGACY_KDF;
		params = { n: doc.n, r: doc.r, p: doc.p };
	} else if (doc.kdf === VAULT_KDF) {
		if (doc.version !== VAULT_VERSION) throw new VaultError("VAULT_INVALID", "an argon2id store must carry the current version");
		if (!Number.isInteger(doc.m) || doc.m < 8 || doc.m > ARGON2_MAX_MEMORY_KIB) throw new VaultError("VAULT_INVALID", `the store needs an argon2id memory cost from 8 through ${ARGON2_MAX_MEMORY_KIB} KiB`);
		if (!Number.isInteger(doc.t) || doc.t < 1 || doc.t > ARGON2_MAX_TIME) throw new VaultError("VAULT_INVALID", `the store needs an argon2id time cost from 1 through ${ARGON2_MAX_TIME}`);
		if (!Number.isInteger(doc.p) || doc.p < 1 || doc.p > ARGON2_MAX_PARALLELISM) throw new VaultError("VAULT_INVALID", `the store needs argon2id parallelism from 1 through ${ARGON2_MAX_PARALLELISM}`);
		kdf = VAULT_KDF;
		params = { m: doc.m, t: doc.t, p: doc.p };
	} else {
		throw new VaultError("VAULT_INVALID", `unsupported store kdf ${JSON.stringify(doc.kdf)}`);
	}
	if (typeof doc.salt !== "string" || doc.salt.length === 0) throw new VaultError("VAULT_INVALID", "the store needs a salt");
	if (!isRecord(doc.entries)) throw new VaultError("VAULT_INVALID", "the store needs an entries object");
	if (typeof doc.sha3 !== "string") throw new VaultError("VAULT_INVALID", "the store needs a sha3 fingerprint");
	// Structural checks first: INVALID for shape errors, CORRUPTED for hash misses.
	if (!isRecord(doc.verifier) || typeof doc.verifier.data !== "string" || typeof doc.verifier.sha3 !== "string") throw new VaultError("VAULT_INVALID", "the store needs a { data, sha3 } verifier");
	if (doc.remember !== void 0 && doc.remember !== null) {
		validateRememberBlock(doc.remember);
		verifyEntryRecord(REMEMBER_KEY_REF, doc.remember.cipher);
	}
	for (const [ref, record] of Object.entries(doc.entries)) {
		if (!REF_PATTERN.test(ref)) throw new VaultError("VAULT_INVALID", `entry key "${ref}" is not a credential reference`);
		if (!isRecord(record) || typeof record.data !== "string" || typeof record.sha3 !== "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" must map to { data, sha3 } strings`);
	}
	const actual = createHash("sha3-256").update(JSON.stringify(fingerprintTarget(doc)), "utf8").digest("hex");
	if (actual !== doc.sha3) throw new VaultError("VAULT_CORRUPTED", "the encrypted credential store failed its SHA3-256 integrity check: its header or entries were altered");
	const entries = new Map();
	verifyEntryRecord(KEY_FILE_VERIFIER_REF, doc.verifier);
	for (const [ref, record] of Object.entries(doc.entries)) {
		verifyEntryRecord(ref, record);
		entries.set(ref, record);
	}
	return {
		salt: Buffer.from(doc.salt, "base64url"),
		params,
		kdf,
		verifier: doc.verifier,
		entries,
		remember: doc.remember ?? void 0,
		documentSha3: actual
	};
}

/**
 * Derive the master key for a store document and prove it against the
 * AEAD verifier. Shared by unlocking and by the password-change check;
 * a wrong digest is reported as `PASSWORD_WRONG` before any entry is
 * touched, and a non-digest input as `PASSWORD_INVALID`.
 * @param {string} text - the raw document text.
 * @param {string} digest - the lowercase hex SHA3-256 digest of the password.
 * @returns {Promise<{ key: Buffer, parsed: Object }>} the verified key and parsed document.
 */
async function deriveVerifiedKey(text, digest) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
	const parsed = parseEncryptedStore(text);
	const key = await deriveMasterKey(digest, parsed.salt, parsed.params, parsed.kdf);
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password digest does not match this credential store");
		throw error;
	}
	return { key, parsed };
}

/**
 * Unlock an encrypted credential store with the password's SHA3-256 digest:
 * derive the key, check it against the AEAD verifier (`PASSWORD_WRONG` on
 * mismatch), and hand back the key plus the ciphertext entries. Entries are
 * decrypted per operation by the caller — plaintext never sits in the
 * unlocked snapshot.
 * @param {string} text - the raw document text.
 * @param {string} digest - the lowercase hex SHA3-256 digest of the password.
 * @returns {Promise<{ key: Buffer, entries: Map<string, EntryRecord>, salt: Buffer, params: Object, kdf: string, remember: Object|undefined }>}
 */
export async function unlockEncryptedStore(text, digest) {
	const { key, parsed } = await deriveVerifiedKey(text, digest);
	return { key, entries: parsed.entries, salt: parsed.salt, params: parsed.params, kdf: parsed.kdf, remember: parsed.remember };
}

/**
 * Verify a password digest against a store document without unlocking it:
 * the derived key is proven against the AEAD verifier and immediately
 * zeroized. Password changes call this so the caller must prove knowledge
 * of the current password before the store is re-encrypted.
 * @param {string} text - the raw document text.
 * @param {string} digest - the lowercase hex SHA3-256 digest of the password.
 * @returns {Promise<void>} resolves on a match; throws `PASSWORD_WRONG` otherwise.
 */
export async function verifyPasswordDigest(text, digest) {
	const { key } = await deriveVerifiedKey(text, digest);
	zeroizeBuffer(key);
}

/**
 * Encrypt a full plaintext credential map under a brand-new password digest:
 * draws the salt, derives the key, encrypts every entry, and serializes the
 * encrypted store. The plaintext map is not retained or logged.
 * @param {Map<string, string>} plaintexts - credentials keyed by reference.
 * @param {string} digest - lowercase hex SHA3-256 digest of the new password.
 * @param {{ m: number, t: number, p: number }} [params] - Argon2id cost overrides (tests; production uses the defaults).
 * @returns {Promise<{ text: string, key: Buffer, entries: Map<string, EntryRecord>, salt: Buffer, params: Object }>} the document text, the derived key (zeroize when done), the ciphertext entries, and the KDF salt/params.
 */
export async function encryptCredentialStore(plaintexts, digest, params = argon2Defaults()) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
	const salt = generatePasswordSalt();
	const key = await deriveArgon2idKey(digest, salt, params);
	const records = new Map();
	for (const [ref, value] of plaintexts) {
		if (!REF_PATTERN.test(ref)) throw new VaultError("VAULT_INVALID", `entry key "${ref}" is not a credential reference`);
		if (typeof value !== "string" || value.length === 0) throw new VaultError("VAULT_INVALID", `entry "${ref}" must be a non-empty string`);
		records.set(ref, encryptEntry(key, ref, value));
	}
	return { text: serializeEncryptedStore(records, key, salt, params, void 0, VAULT_KDF), key, entries: records, salt, params };
}

// ── remembered logins (localhost-only, WebUI-managed) ──────────────────────
//
// The browser keeps a high-entropy 256-bit ticket (an HttpOnly cookie the
// server never persists in plain form); the store document carries the same
// ticket's salt and an AEAD-wrapped copy of the master key. Presenting the
// ticket recovers the key without the password for the configured window
// (`days` days, or forever when `days === -1`). The web layer refuses this
// path for non-localhost requests; the password digest remains the only way
// to unlock from anywhere else.

/** GCM AAD reference for the wrapped master key inside the remember block. */
export const REMEMBER_KEY_REF = "remember_key";
/** Fixed domain separator for the ticket-key derivation. */
const REMEMBER_TICKET_DOMAIN = "dsh-encrypt-remember-ticket";

/**
 * Validate one remembered-login block's shape. Never called on undefined.
 * @param {unknown} remember - the persisted block.
 */
function validateRememberBlock(remember) {
	if (!isRecord(remember)) throw new VaultError("VAULT_INVALID", "the store's remember block must be a JSON object");
	if (typeof remember.salt !== "string" || remember.salt.length === 0) throw new VaultError("VAULT_INVALID", "the remember block needs a salt");
	if (!Number.isFinite(remember.issuedAt) || remember.issuedAt < 0) throw new VaultError("VAULT_INVALID", "the remember block needs a non-negative issuedAt");
	if (!Number.isInteger(remember.days) || (remember.days !== -1 && (remember.days < 1 || remember.days > 30))) throw new VaultError("VAULT_INVALID", "the remember block needs days in 1..30 or -1 (forever)");
	if (!isRecord(remember.cipher) || typeof remember.cipher.data !== "string" || typeof remember.cipher.sha3 !== "string") throw new VaultError("VAULT_INVALID", "the remember block needs a { data, sha3 } cipher");
}

/**
 * Whether a remembered-login block is still inside its window at `now`.
 * @param {Object} remember - a validated remember block.
 * @param {number} now - the current unix ms timestamp.
 * @returns {boolean} true while the block may still be presented.
 */
export function rememberActive(remember, now = Date.now()) {
	if (remember.days === -1) return true;
	return now - remember.issuedAt <= remember.days * REMEMBER_DAY_MS;
}

/** Decode the browser-held ticket text into its 32 secret bytes. */
function parseRememberSecret(secretText) {
	if (typeof secretText !== "string" || secretText.length === 0) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is empty");
	let secret;
	try {
		secret = Buffer.from(secretText, "base64url");
	} catch {
		throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is not valid base64url");
	}
	if (secret.length !== MASTER_KEY_BYTES) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket must decode to 32 bytes");
	return secret;
}

/**
 * Derive the ticket key from the remember salt and the browser-held secret.
 * The secret is high-entropy, so one SHA3-256 is enough stretching.
 * @param {Buffer} salt - the block's salt.
 * @param {Buffer} secret - the browser-held 32-byte ticket.
 * @returns {Buffer} a 32-byte key.
 */
function ticketKey(salt, secret) {
	return createHash("sha3-256").update(Buffer.concat([Buffer.from(REMEMBER_TICKET_DOMAIN, "utf8"), salt, secret])).digest();
}

/**
 * Create a remembered-login block: a fresh 32-byte ticket whose derived key
 * AEAD-wraps the master key. The ticket is returned to the caller (the web
 * layer puts it in an HttpOnly cookie) and is never persisted in plain form.
 * @param {Buffer} key - the current 32-byte master key.
 * @param {number} days - the window in days (1..30), or -1 for forever.
 * @param {number} [now] - issue timestamp (unix ms).
 * @returns {{ block: Object, secret: string }} the block to persist and the base64url ticket.
 */
export function createRememberBlock(key, days, now = Date.now()) {
	if (!Buffer.isBuffer(key) || key.length !== MASTER_KEY_BYTES) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Number.isInteger(days) || (days !== -1 && (days < 1 || days > 30))) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be 1..30 or -1 (forever)");
	const salt = generatePasswordSalt();
	const secret = randomBytes(MASTER_KEY_BYTES);
	const cipher = encryptEntry(ticketKey(salt, secret), REMEMBER_KEY_REF, encodeMasterKey(key));
	return {
		block: { salt: salt.toString("base64url"), issuedAt: now, days, cipher },
		secret: secret.toString("base64url")
	};
}

/**
 * Recover the master key from the browser-held ticket: verify the block's
 * integrity and window, unwrap the key, and re-authenticate it against the
 * store's AEAD verifier so a tampered ticket or block fails as
 * `REMEMBER_INVALID` — never as a silently wrong key.
 * @param {string} text - the raw encrypted-store document text.
 * @param {string} secretText - the base64url ticket from the cookie.
 * @returns {{ key: Buffer, entries: Map<string, EntryRecord>, salt: Buffer, params: Object, remember: Object }}
 */
export function recoverKeyFromRemember(text, secretText) {
	const parsed = parseEncryptedStore(text);
	if (parsed.remember === void 0) throw new VaultError("REMEMBER_INVALID", "this credential store has no remembered login");
	if (!rememberActive(parsed.remember)) throw new VaultError("REMEMBER_EXPIRED", "the remembered login has expired; enter the password again");
	const secret = parseRememberSecret(secretText);
	let key;
	try {
		key = parseMasterKey(decryptEntry(ticketKey(Buffer.from(parsed.remember.salt, "base64url"), secret), REMEMBER_KEY_REF, parsed.remember.cipher));
	} catch (error) {
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket does not match this credential store");
		throw error;
	}
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket does not match this credential store");
		throw error;
	}
	return { key, entries: parsed.entries, salt: parsed.salt, params: parsed.params, kdf: parsed.kdf, remember: parsed.remember };
}
