import { a as isPlainRecord, i as isCredentialReference, n as isAsciiHex, r as isAsciiLowerHex, s as trimTrailingCharacter } from "./primitives-CDfnkTeX.js";
import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from "node:crypto";
import { hashRaw } from "@node-rs/argon2";
import { check, finite, integer, literal, maxValue, minValue, nonEmpty, nullable, number, optional, pipe, record, safeParse, strictObject, string, union, unknown } from "valibot";
//#region src/domain/vault/model.ts
/** Stable domain constants and types for encrypted credential documents. */
/** Document schema version. v3 stretches the password digest with Argon2id. */
const VAULT_VERSION = 3;
/** Algorithm identifier persisted in the document and asserted on parse. */
const VAULT_ALGORITHM = "aes-256-gcm+sha3-256";
/** KDF marker written by v3 documents. */
const VAULT_KDF = "argon2id";
/** KDF marker of legacy v2 documents. */
const LEGACY_KDF = "scrypt";
/** KDF input marker persisted in encrypted stores. */
const VAULT_KDF_INPUT = "sha3-256-password";
/** Format marker persisted in encrypted stores. */
const ENCRYPTED_STORE_FORMAT = "dsh-encrypt-credentials";
/** Fixed reference for a key verifier record. */
const KEY_FILE_VERIFIER_REF = "DSH_CREDENTIAL_MASTER_VERIFIER";
/** Fixed reference for the wrapped master key inside a remember block. */
const REMEMBER_KEY_REF = "remember_key";
const MASTER_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const PASSWORD_SALT_BYTES = 16;
const REMEMBER_DAY_MS = 864e5;
const ARGON2_MEMORY_KIB = 65536;
const ARGON2_TIME = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_MAX_MEMORY_KIB = 65536;
const ARGON2_MAX_TIME = 3;
const ARGON2_MAX_PARALLELISM = 1;
const SCRYPT_N = 131072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 268435456;
const SCRYPT_MAX_N = 131072;
/** Vault failure with a stable machine-readable code. */
var VaultError = class extends Error {
	code;
	constructor(code, message, details) {
		super(`dsh-encrypt: ${message}`);
		this.name = "VaultError";
		this.code = code;
		if (details !== void 0 && details !== null && typeof details === "object") Object.assign(this, details);
	}
};
//#endregion
//#region src/domain/vault/schemas.ts
const nonEmptyStringSchema = pipe(string(), nonEmpty());
const credentialReferenceSchema = pipe(string(), check(isCredentialReference));
const scryptNSchema = pipe(number(), integer(), minValue(2), maxValue(SCRYPT_MAX_N));
const scryptRSchema = pipe(number(), integer(), minValue(1), maxValue(8));
const scryptPSchema = pipe(number(), integer(), minValue(1), maxValue(1));
const entryRecordSchema = strictObject({
	data: string(),
	sha3: string()
});
const entriesSchema = record(credentialReferenceSchema, entryRecordSchema);
const rememberDaysSchema = union([literal(-1), pipe(number(), integer(), minValue(1), maxValue(30))]);
const rememberBlockSchema = strictObject({
	version: optional(literal(2)),
	salt: nonEmptyStringSchema,
	issuedAt: pipe(number(), finite(), minValue(0)),
	days: rememberDaysSchema,
	cipher: entryRecordSchema
});
const vaultDocumentSchema = strictObject({
	version: literal(3),
	algorithm: literal(VAULT_ALGORITHM),
	sha3: string(),
	entries: entriesSchema
});
const encryptedStoreBaseEntries = {
	format: literal(ENCRYPTED_STORE_FORMAT),
	algorithm: literal(VAULT_ALGORITHM),
	kdfInput: literal(VAULT_KDF_INPUT),
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema,
	remember: optional(nullable(rememberBlockSchema)),
	entries: entriesSchema,
	sha3: string()
};
const legacyEncryptedStoreSchema = strictObject({
	...encryptedStoreBaseEntries,
	version: literal(2),
	kdf: literal(LEGACY_KDF),
	n: scryptNSchema,
	r: scryptRSchema,
	m: optional(unknown()),
	t: optional(unknown()),
	p: scryptPSchema
});
const argon2EncryptedStoreSchema = strictObject({
	...encryptedStoreBaseEntries,
	version: literal(3),
	kdf: literal(VAULT_KDF),
	m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
	t: pipe(number(), integer(), minValue(1), maxValue(3)),
	n: optional(unknown()),
	r: optional(unknown()),
	p: pipe(number(), integer(), minValue(1), maxValue(1))
});
const encryptedStoreSchema = union([legacyEncryptedStoreSchema, argon2EncryptedStoreSchema]);
const passwordKeyFileSchema = union([strictObject({
	version: number(),
	kdf: literal(VAULT_KDF),
	m: pipe(number(), integer(), minValue(8), maxValue(ARGON2_MAX_MEMORY_KIB)),
	t: pipe(number(), integer(), minValue(1), maxValue(3)),
	p: pipe(number(), integer(), minValue(1), maxValue(1)),
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema
}), strictObject({
	version: number(),
	kdf: literal(LEGACY_KDF),
	n: scryptNSchema,
	r: scryptRSchema,
	p: scryptPSchema,
	salt: nonEmptyStringSchema,
	verifier: entryRecordSchema
})]);
function result(parsed) {
	return parsed.success ? {
		success: true,
		output: parsed.output
	} : { success: false };
}
/** Validate the legacy standalone vault-document shape. */
function validateVaultDocumentShape(input) {
	return result(safeParse(vaultDocumentSchema, input));
}
/** Validate the current or legacy encrypted credential-store shape. */
function validateEncryptedStoreShape(input) {
	return result(safeParse(encryptedStoreSchema, input));
}
/** Validate a password key-file shape. */
function validatePasswordKeyFileShape(input) {
	return result(safeParse(passwordKeyFileSchema, input));
}
/** Validate a remember block without accepting unknown fields. */
function validateRememberBlockShape(input) {
	return result(safeParse(rememberBlockSchema, input));
}
//#endregion
//#region src/infrastructure/crypto/vault-crypto.ts
const KEY_FILE_VERIFIER_TEXT = "dsh-encrypt master-key verifier";
/** Lowercase hex SHA3-256 of a UTF-8 text. */
function sha3_256Hex(text) {
	return createHash("sha3-256").update(text, "utf8").digest("hex");
}
/** Whether a text is a valid lowercase hex SHA3-256 digest. */
function isDigest(value) {
	return isAsciiLowerHex(value, 64);
}
/** Erase a mutable key buffer. */
function zeroizeBuffer(buffer) {
	buffer.fill(0);
}
/** Generate a fresh 256-bit master key. */
function generateMasterKey() {
	return randomBytes(32);
}
/** Encode a master key as base64url. */
function encodeMasterKey(key) {
	assertMasterKey(key);
	return key.toString("base64url");
}
/** Parse a base64url or hexadecimal master key. */
function parseMasterKey(text) {
	if (typeof text !== "string") throw new VaultError("MASTER_KEY_INVALID", "the master key must be text (base64url or 64 hex digits)");
	const value = text.trim();
	if (value.length === 0) throw new VaultError("MASTER_KEY_INVALID", "the master key is empty");
	let key;
	if (isAsciiHex(value, 64)) key = Buffer.from(value, "hex");
	else {
		try {
			key = Buffer.from(value, "base64url");
		} catch {
			throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
		}
		if (trimTrailingCharacter(key.toString("base64url"), "=") !== trimTrailingCharacter(value, "=")) throw new VaultError("MASTER_KEY_INVALID", "the master key is neither 64 hex digits nor base64url");
	}
	if (key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", `the master key must decode to 32 bytes, got ${key.length}`);
	return key;
}
/** Generate a fresh salt for password-key derivation. */
function generatePasswordSalt() {
	return randomBytes(16);
}
/** Default Argon2id parameters. */
function argon2Defaults() {
	return {
		m: ARGON2_MEMORY_KIB,
		t: 3,
		p: 1
	};
}
/** Derive a master key with the selected document KDF. */
async function deriveMasterKey(digest, salt, params = argon2Defaults(), kdf = VAULT_KDF) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (kdf === "scrypt") return deriveScryptKey(digest, salt, params);
	if (kdf === "argon2id") return deriveArgon2idKey(digest, salt, params);
	throw new VaultError("MASTER_KEY_INVALID", `unsupported kdf ${String(kdf)}`);
}
/** Derive a key with Argon2id under bounded resource parameters. */
async function deriveArgon2idKey(digest, salt, params) {
	if (!Number.isInteger(params.m) || params.m < 8 || params.m > 65536) throw new VaultError("MASTER_KEY_INVALID", `argon2id memory cost must be an integer from 8 through ${ARGON2_MAX_MEMORY_KIB} KiB`);
	if (!Number.isInteger(params.t) || params.t < 1 || params.t > 3) throw new VaultError("MASTER_KEY_INVALID", `argon2id time cost must be an integer from 1 through 3`);
	if (!Number.isInteger(params.p) || params.p < 1 || params.p > 1) throw new VaultError("MASTER_KEY_INVALID", `argon2id parallelism must be an integer from 1 through 1`);
	const raw = await hashRaw(Buffer.from(digest, "utf8"), {
		algorithm: 2,
		salt,
		outputLen: 32,
		memoryCost: params.m,
		timeCost: params.t,
		parallelism: params.p
	});
	const key = Buffer.from(raw);
	if (key.length < 32) throw new VaultError("MASTER_KEY_INVALID", "argon2id produced fewer than 32 bytes");
	return key.subarray(0, 32);
}
/** Derive a legacy version-2 document key with scrypt. */
async function deriveScryptKey(digest, salt, params) {
	if (!Number.isInteger(params.n) || !Number.isInteger(params.r) || !Number.isInteger(params.p) || params.n < 2 || params.n > 131072 || !Number.isInteger(Math.log2(params.n)) || params.r < 1 || params.r > 8 || params.p < 1 || params.p > 1) throw new VaultError("MASTER_KEY_INVALID", "scrypt parameters exceed the supported resource bounds");
	return new Promise((resolve, reject) => {
		scrypt(digest, salt, 32, {
			N: params.n,
			r: params.r,
			p: params.p,
			maxmem: SCRYPT_MAXMEM
		}, (error, key) => {
			if (error !== null) reject(error);
			else resolve(key);
		});
	});
}
/** Encrypt the fixed key-verifier plaintext. */
function createKeyVerifier(key) {
	return encryptEntry(key, KEY_FILE_VERIFIER_REF, KEY_FILE_VERIFIER_TEXT);
}
/** Serialize the standalone password-key file kept for API compatibility. */
function createPasswordKeyFile(key, salt, params = argon2Defaults()) {
	assertMasterKey(key);
	const document = {
		version: 1,
		kdf: VAULT_KDF,
		m: params.m,
		t: params.t,
		p: params.p,
		salt: salt.toString("base64url"),
		verifier: createKeyVerifier(key)
	};
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Whether text is a supported standalone password-key file. */
function isPasswordKeyFile(text) {
	try {
		return validatePasswordKeyFileShape(JSON.parse(text)).success;
	} catch {
		return false;
	}
}
/** Parse a standalone password-key file and authenticate its password. */
async function parsePasswordKeyFile(text, password) {
	let document;
	try {
		document = JSON.parse(text);
	} catch {
		throw new VaultError("MASTER_KEY_INVALID", "the key file is neither a legacy raw key nor a password key file");
	}
	const validated = validatePasswordKeyFileShape(document);
	if (!validated.success || validated.output === void 0) throw new VaultError("MASTER_KEY_INVALID", "unsupported password key-file format");
	const keyFile = validated.output;
	const salt = Buffer.from(keyFile.salt, "base64url");
	const key = keyFile.kdf === "scrypt" ? await deriveScryptKey(password, salt, {
		n: keyFile.n,
		r: keyFile.r,
		p: keyFile.p
	}) : await deriveArgon2idKey(password, salt, {
		m: keyFile.m,
		t: keyFile.t,
		p: keyFile.p
	});
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, keyFile.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password does not match this master-key file");
		throw error;
	}
	return key;
}
/** Validate an entry record and its SHA3-256 fingerprint. */
function verifyEntryRecord(ref, record) {
	if (!isPlainRecord(record) || typeof record.data !== "string" || typeof record.sha3 !== "string") throw new VaultError("VAULT_INVALID", `entry "${ref}" must map to { data, sha3 } strings`);
	if (fingerprint(record.data) !== record.sha3) throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" failed its SHA3-256 integrity check: the stored ciphertext does not match its fingerprint`);
}
/** Encrypt one secret and bind it to its credential reference with GCM AAD. */
function encryptEntry(key, ref, plaintext) {
	assertMasterKey(key);
	if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	if (typeof plaintext !== "string" || plaintext.length === 0) throw new VaultError("VAULT_INVALID", `the plaintext for "${ref}" must be a non-empty string`);
	const nonce = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	cipher.setAAD(Buffer.from(ref, "utf8"));
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	const data = Buffer.concat([
		nonce,
		ciphertext,
		tag
	]).toString("base64url");
	return {
		data,
		sha3: fingerprint(data)
	};
}
/** Decrypt one entry into an erasure-capable buffer. */
function decryptEntryBuffer(key, ref, record) {
	assertMasterKey(key);
	if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `reference "${ref}" is not a credential reference`);
	verifyEntryRecord(ref, record);
	let blob;
	try {
		blob = Buffer.from(record.data, "base64url");
	} catch {
		throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" is not valid base64url`);
	}
	if (blob.length <= 28) throw new VaultError("VAULT_CORRUPTED", `entry "${ref}" is truncated`);
	const nonce = blob.subarray(0, 12);
	const tag = blob.subarray(blob.length - 16);
	const ciphertext = blob.subarray(12, blob.length - 16);
	try {
		const decipher = createDecipheriv("aes-256-gcm", key, nonce);
		decipher.setAAD(Buffer.from(ref, "utf8"));
		decipher.setAuthTag(tag);
		return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	} catch {
		throw new VaultError("VAULT_KEY_MISMATCH", `entry "${ref}" failed AES-256-GCM authentication: the master key does not match this document, or the ciphertext was replaced`);
	}
}
/** Decrypt one entry into an immutable string and erase its intermediate buffer. */
function decryptEntry(key, ref, record) {
	const plain = decryptEntryBuffer(key, ref, record);
	const text = plain.toString("utf8");
	zeroizeBuffer(plain);
	return text;
}
function assertMasterKey(key) {
	if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
}
function fingerprint(data) {
	return createHash("sha3-256").update(data, "utf8").digest("hex");
}
//#endregion
//#region src/infrastructure/persistence/vault-document.ts
const STORE_FIELDS = [
	"format",
	"version",
	"algorithm",
	"kdf",
	"kdfInput",
	"n",
	"r",
	"m",
	"t",
	"p",
	"salt",
	"verifier",
	"remember",
	"entries"
];
/** Serialize the legacy standalone vault-document shape. */
function serializeDocument(entries) {
	const canonical = canonicalEntries(Object.fromEntries(entries));
	const block = JSON.stringify(canonical);
	const document = {
		version: 3,
		algorithm: VAULT_ALGORITHM,
		sha3: hashText(block),
		entries: canonical
	};
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Parse and verify the legacy standalone vault-document shape. */
function parseDocument(text) {
	const validated = validateVaultDocumentShape(parseJson(text, "the vault document is not valid JSON"));
	if (!validated.success || validated.output === void 0) throw new VaultError("VAULT_INVALID", "the vault document does not match the supported schema");
	const document = validated.output;
	const actual = hashText(JSON.stringify(canonicalEntries(document.entries)));
	if (actual !== document.sha3) throw new VaultError("VAULT_CORRUPTED", "the vault document failed its SHA3-256 integrity check: entries were added, removed, swapped, or altered");
	return {
		entries: verifiedEntries(document.entries),
		documentSha3: actual
	};
}
/** Verify a standalone vault document and discard its parsed entries. */
function verifyDocument(text) {
	parseDocument(text);
}
/** Detect whether credential text carries the encrypted-store marker. */
function detectCredentialStore(text) {
	const trimmed = text.trim();
	if (trimmed.length === 0) return "plain";
	try {
		const document = JSON.parse(trimmed);
		return isPlainRecord(document) && document.format === "dsh-encrypt-credentials" ? "encrypted" : "plain";
	} catch {
		return "plain";
	}
}
/** Serialize a current or legacy encrypted credential store. */
function serializeEncryptedStore(records, key, salt, params = argon2Defaults(), remember, kdf = VAULT_KDF) {
	if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Buffer.isBuffer(salt) || salt.length === 0) throw new VaultError("MASTER_KEY_INVALID", "a password salt must be a non-empty buffer");
	if (remember !== void 0 && !validateRememberBlockShape(remember).success) throw new VaultError("VAULT_INVALID", "the store's remember block does not match the supported schema");
	if (kdf !== "argon2id" && kdf !== "scrypt") throw new VaultError("MASTER_KEY_INVALID", `unsupported store kdf ${String(kdf)}`);
	const document = {
		format: ENCRYPTED_STORE_FORMAT,
		version: kdf === "scrypt" ? 2 : 3,
		algorithm: VAULT_ALGORITHM,
		kdf,
		kdfInput: VAULT_KDF_INPUT,
		salt: salt.toString("base64url"),
		verifier: createKeyVerifier(key),
		entries: canonicalEntries(Object.fromEntries(records))
	};
	if (kdf === "scrypt") {
		const legacy = params;
		document.n = legacy.n;
		document.r = legacy.r;
		document.p = legacy.p;
	} else {
		const current = params;
		document.m = current.m;
		document.t = current.t;
		document.p = current.p;
	}
	if (remember !== void 0) document.remember = remember;
	document.sha3 = hashText(JSON.stringify(fingerprintTarget(document)));
	return `${JSON.stringify(document, null, 2)}\n`;
}
/** Parse and verify a current or legacy encrypted credential store. */
function parseEncryptedStore(text) {
	const input = parseJson(text, "the encrypted credential store is not valid JSON");
	if (!isPlainRecord(input) || input.format !== "dsh-encrypt-credentials") throw new VaultError("VAULT_INVALID", `the document is not a ${ENCRYPTED_STORE_FORMAT} store`);
	if (input.version === 1) throw new VaultError("VAULT_INVALID", "unsupported store version 1; a store encrypted by dsh-encrypt ≤ 0.1.0-rc.6 must be unlocked and returned to plaintext with that version first");
	const validated = validateEncryptedStoreShape(input);
	if (!validated.success || validated.output === void 0) throw new VaultError("VAULT_INVALID", "the encrypted credential store does not match the supported schema");
	return buildParsedStore(validated.output);
}
function buildParsedStore(store) {
	const actual = hashText(JSON.stringify(fingerprintTarget(store)));
	if (actual !== store.sha3) throw new VaultError("VAULT_CORRUPTED", "the encrypted credential store failed its SHA3-256 integrity check: its header or entries were altered");
	const remember = store.remember ?? void 0;
	if (remember !== void 0) verifyEntryRecord(REMEMBER_KEY_REF, remember.cipher);
	verifyEntryRecord(KEY_FILE_VERIFIER_REF, store.verifier);
	return {
		salt: Buffer.from(store.salt, "base64url"),
		params: store.kdf === "scrypt" ? {
			n: store.n,
			r: store.r,
			p: store.p
		} : {
			m: store.m,
			t: store.t,
			p: store.p
		},
		kdf: store.kdf,
		verifier: store.verifier,
		entries: verifiedEntries(store.entries),
		remember,
		documentSha3: actual
	};
}
function canonicalEntries(entries) {
	const sorted = {};
	for (const ref of Object.keys(entries).sort()) {
		const record = entries[ref];
		if (record === void 0) throw new VaultError("VAULT_INVALID", `entry "${ref}" is missing`);
		sorted[ref] = record;
	}
	return sorted;
}
function verifiedEntries(records) {
	const entries = /* @__PURE__ */ new Map();
	for (const [ref, record] of Object.entries(records)) {
		verifyEntryRecord(ref, record);
		entries.set(ref, record);
	}
	return entries;
}
function fingerprintTarget(document) {
	const target = {};
	for (const field of STORE_FIELDS) if (document[field] !== void 0) target[field] = document[field];
	return target;
}
function hashText(text) {
	return createHash("sha3-256").update(text, "utf8").digest("hex");
}
function parseJson(text, message) {
	try {
		return JSON.parse(text);
	} catch {
		throw new VaultError("VAULT_INVALID", message);
	}
}
//#endregion
//#region src/application/remember-service.ts
const REMEMBER_TICKET_DOMAIN = "dsh-encrypt-remember-ticket";
/** Whether a remembered-login block remains inside its configured window. */
function rememberActive(remember, now = Date.now()) {
	if (remember.issuedAt > now) return false;
	return remember.days === -1 || now - remember.issuedAt <= remember.days * 864e5;
}
/** Wrap a master key under a fresh browser-held remembered-login ticket. */
function createRememberBlock(key, days, now = Date.now()) {
	if (!Buffer.isBuffer(key) || key.length !== 32) throw new VaultError("MASTER_KEY_INVALID", "a master key must be a 32-byte buffer");
	if (!Number.isInteger(days) || days !== -1 && (days < 1 || days > 30)) throw new VaultError("PASSWORD_INVALID", "remembered-login days must be 1..30 or -1 (forever)");
	const salt = generatePasswordSalt();
	const secret = randomBytes(32);
	const blockBase = {
		version: 2,
		salt: salt.toString("base64url"),
		issuedAt: now,
		days
	};
	const wrappingKey = ticketKey(salt, secret);
	try {
		const cipher = encryptEntry(wrappingKey, rememberKeyReference(blockBase), encodeMasterKey(key));
		return {
			block: {
				...blockBase,
				cipher
			},
			secret: secret.toString("base64url")
		};
	} finally {
		zeroizeBuffer(wrappingKey);
		zeroizeBuffer(secret);
	}
}
/** Recover and authenticate a master key from a remembered-login ticket. */
function recoverKeyFromRemember(text, secretText) {
	const parsed = parseEncryptedStore(text);
	if (parsed.remember === void 0) throw new VaultError("REMEMBER_INVALID", "this credential store has no remembered login");
	if (parsed.remember.version !== 2) throw new VaultError("REMEMBER_INVALID", "the remembered login uses an expired ticket format");
	if (!rememberActive(parsed.remember)) throw new VaultError("REMEMBER_EXPIRED", "the remembered login has expired; enter the password again");
	const secret = parseRememberSecret(secretText);
	let key;
	let wrappingKey;
	try {
		wrappingKey = ticketKey(Buffer.from(parsed.remember.salt, "base64url"), secret);
		key = parseMasterKey(decryptEntry(wrappingKey, rememberKeyReference(parsed.remember), parsed.remember.cipher));
	} catch (error) {
		throwRememberInvalid(error);
	} finally {
		if (wrappingKey !== void 0) zeroizeBuffer(wrappingKey);
		zeroizeBuffer(secret);
	}
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		throwRememberInvalid(error);
	}
	return {
		key,
		entries: parsed.entries,
		salt: parsed.salt,
		params: parsed.params,
		kdf: parsed.kdf,
		remember: parsed.remember
	};
}
function parseRememberSecret(secretText) {
	if (typeof secretText !== "string" || secretText.length === 0) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is empty");
	let secret;
	try {
		secret = Buffer.from(secretText, "base64url");
	} catch {
		throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket is not valid base64url");
	}
	if (secret.length !== 32) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket must decode to 32 bytes");
	return secret;
}
function ticketKey(salt, secret) {
	return createHash("sha3-256").update(Buffer.concat([
		Buffer.from(REMEMBER_TICKET_DOMAIN, "utf8"),
		salt,
		secret
	])).digest();
}
/** Bind every expiry-policy field to the GCM tag through a credential-safe AAD reference. */
function rememberKeyReference(remember) {
	const metadata = JSON.stringify({
		version: remember.version,
		salt: remember.salt,
		issuedAt: remember.issuedAt,
		days: remember.days
	});
	return `${REMEMBER_KEY_REF}_${createHash("sha3-256").update(metadata, "utf8").digest("hex")}`;
}
function throwRememberInvalid(error) {
	if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("REMEMBER_INVALID", "the remembered-login ticket does not match this credential store");
	throw error;
}
//#endregion
//#region src/application/password-service.ts
/** Unlock an encrypted store and return only the state required by consumers. */
async function unlockEncryptedStore(text, digest) {
	const { key, parsed } = await deriveVerifiedKey(text, digest);
	return {
		key,
		entries: parsed.entries,
		salt: parsed.salt,
		params: parsed.params,
		kdf: parsed.kdf,
		remember: parsed.remember
	};
}
/** Authenticate a password digest and immediately erase the derived key. */
async function verifyPasswordDigest(text, digest) {
	const { key } = await deriveVerifiedKey(text, digest);
	zeroizeBuffer(key);
}
/** Encrypt a complete plaintext credential map under a new password digest. */
async function encryptCredentialStore(plaintexts, digest, params = argon2Defaults()) {
	assertPasswordDigest(digest);
	const salt = generatePasswordSalt();
	const key = await deriveArgon2idKey(digest, salt, params);
	const entries = /* @__PURE__ */ new Map();
	for (const [ref, value] of plaintexts) {
		if (!isCredentialReference(ref)) throw new VaultError("VAULT_INVALID", `entry key "${ref}" is not a credential reference`);
		if (typeof value !== "string" || value.length === 0) throw new VaultError("VAULT_INVALID", `entry "${ref}" must be a non-empty string`);
		entries.set(ref, encryptEntry(key, ref, value));
	}
	return {
		text: serializeEncryptedStore(entries, key, salt, params, void 0, VAULT_KDF),
		key,
		entries,
		salt,
		params
	};
}
async function deriveVerifiedKey(text, digest) {
	assertPasswordDigest(digest);
	const parsed = parseEncryptedStore(text);
	const key = await deriveMasterKey(digest, parsed.salt, parsed.params, parsed.kdf);
	try {
		decryptEntry(key, KEY_FILE_VERIFIER_REF, parsed.verifier);
	} catch (error) {
		zeroizeBuffer(key);
		if (error instanceof VaultError && (error.code === "VAULT_KEY_MISMATCH" || error.code === "VAULT_CORRUPTED")) throw new VaultError("PASSWORD_WRONG", "the password digest does not match this credential store");
		throw error;
	}
	return {
		key,
		parsed
	};
}
function assertPasswordDigest(digest) {
	if (!isDigest(digest)) throw new VaultError("PASSWORD_INVALID", "the password digest must be 64 lowercase hex characters (SHA3-256 of the password)");
}
//#endregion
export { VAULT_VERSION as $, zeroizeBuffer as A, MASTER_KEY_BYTES as B, generatePasswordSalt as C, parsePasswordKeyFile as D, parseMasterKey as E, ARGON2_PARALLELISM as F, SCRYPT_MAXMEM as G, PASSWORD_SALT_BYTES as H, ARGON2_TIME as I, SCRYPT_R as J, SCRYPT_N as K, ENCRYPTED_STORE_FORMAT as L, ARGON2_MAX_PARALLELISM as M, ARGON2_MAX_TIME as N, sha3_256Hex as O, ARGON2_MEMORY_KIB as P, VAULT_KDF_INPUT as Q, KEY_FILE_VERIFIER_REF as R, generateMasterKey as S, isPasswordKeyFile as T, REMEMBER_DAY_MS as U, NONCE_BYTES as V, REMEMBER_KEY_REF as W, VAULT_ALGORITHM as X, TAG_BYTES as Y, VAULT_KDF as Z, deriveArgon2idKey as _, recoverKeyFromRemember as a, encodeMasterKey as b, parseDocument as c, serializeEncryptedStore as d, VaultError as et, verifyDocument as f, decryptEntryBuffer as g, decryptEntry as h, createRememberBlock as i, ARGON2_MAX_MEMORY_KIB as j, verifyEntryRecord as k, parseEncryptedStore as l, createPasswordKeyFile as m, unlockEncryptedStore as n, rememberActive as o, argon2Defaults as p, SCRYPT_P as q, verifyPasswordDigest as r, detectCredentialStore as s, encryptCredentialStore as t, serializeDocument as u, deriveMasterKey as v, isDigest as w, encryptEntry as x, deriveScryptKey as y, LEGACY_KDF as z };

//# sourceMappingURL=vault-By6rgT8b.js.map