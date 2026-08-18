//#region src/domain/vault/model.d.ts
/** Stable domain constants and types for encrypted credential documents. */
/** Document schema version. v3 stretches the password digest with Argon2id. */
declare const VAULT_VERSION: 3;
/** Algorithm identifier persisted in the document and asserted on parse. */
declare const VAULT_ALGORITHM: "aes-256-gcm+sha3-256";
/** KDF marker written by v3 documents. */
declare const VAULT_KDF: "argon2id";
/** KDF marker of legacy v2 documents. */
declare const LEGACY_KDF: "scrypt";
/** KDF input marker persisted in encrypted stores. */
declare const VAULT_KDF_INPUT: "sha3-256-password";
/** Format marker persisted in encrypted stores. */
declare const ENCRYPTED_STORE_FORMAT: "dsh-encrypt-credentials";
/** Fixed reference for a key verifier record. */
declare const KEY_FILE_VERIFIER_REF: "DSH_CREDENTIAL_MASTER_VERIFIER";
/** Fixed reference for the wrapped master key inside a remember block. */
declare const REMEMBER_KEY_REF: "remember_key";
/** Current remembered-login block format. Version 2 authenticates its policy metadata. */
declare const REMEMBER_BLOCK_VERSION: 2;
declare const MASTER_KEY_BYTES: 32;
declare const NONCE_BYTES: 12;
declare const TAG_BYTES: 16;
declare const PASSWORD_SALT_BYTES: 16;
declare const REMEMBER_DAY_MS: 86400000;
declare const ARGON2_MEMORY_KIB: 65536;
declare const ARGON2_TIME: 3;
declare const ARGON2_PARALLELISM: 1;
declare const ARGON2_MAX_MEMORY_KIB: 65536;
declare const ARGON2_MAX_TIME: 3;
declare const ARGON2_MAX_PARALLELISM: 1;
declare const SCRYPT_N: 131072;
declare const SCRYPT_R: 8;
declare const SCRYPT_P: 1;
declare const SCRYPT_MAXMEM: number;
interface EntryRecord {
  data: string;
  sha3: string;
}
interface Argon2Params {
  m: number;
  t: number;
  p: number;
}
interface ScryptParams {
  n: number;
  r: number;
  p: number;
}
type KdfParams = Argon2Params | ScryptParams;
type KdfName = typeof VAULT_KDF | typeof LEGACY_KDF;
interface RememberBlock {
  /** Absent only on legacy blocks, which password unlock can replace but ticket unlock refuses. */
  version?: typeof REMEMBER_BLOCK_VERSION | undefined;
  salt: string;
  issuedAt: number;
  days: number;
  cipher: EntryRecord;
}
interface ParsedEncryptedStore {
  salt: Buffer;
  params: KdfParams;
  kdf: KdfName;
  verifier: EntryRecord;
  entries: Map<string, EntryRecord>;
  remember?: RememberBlock | undefined;
  documentSha3: string;
}
/** Vault failure with a stable machine-readable code. */
declare class VaultError extends Error {
  code: string;
  constructor(code: string, message: string, details?: Record<string, unknown>);
}
//#endregion
//#region src/infrastructure/crypto/vault-crypto.d.ts
/** Lowercase hex SHA3-256 of a UTF-8 text. */
declare function sha3_256Hex(text: string): string;
/** Whether a text is a valid lowercase hex SHA3-256 digest. */
declare function isDigest(value: unknown): value is string;
/** Erase a mutable key buffer. */
declare function zeroizeBuffer(buffer: Buffer): void;
/** Generate a fresh 256-bit master key. */
declare function generateMasterKey(): Buffer;
/** Encode a master key as base64url. */
declare function encodeMasterKey(key: Buffer): string;
/** Parse a base64url or hexadecimal master key. */
declare function parseMasterKey(text: string): Buffer;
/** Generate a fresh salt for password-key derivation. */
declare function generatePasswordSalt(): Buffer;
/** Default Argon2id parameters. */
declare function argon2Defaults(): Argon2Params;
/** Derive a master key with the selected document KDF. */
declare function deriveMasterKey(digest: string, salt: Buffer, params?: KdfParams, kdf?: KdfName): Promise<Buffer>;
/** Derive a key with Argon2id under bounded resource parameters. */
declare function deriveArgon2idKey(digest: string, salt: Buffer, params: Argon2Params): Promise<Buffer>;
/** Derive a legacy version-2 document key with scrypt. */
declare function deriveScryptKey(digest: string, salt: Buffer, params: ScryptParams): Promise<Buffer>;
/** Serialize the standalone password-key file kept for API compatibility. */
declare function createPasswordKeyFile(key: Buffer, salt: Buffer, params?: Argon2Params): string;
/** Whether text is a supported standalone password-key file. */
declare function isPasswordKeyFile(text: string): boolean;
/** Parse a standalone password-key file and authenticate its password. */
declare function parsePasswordKeyFile(text: string, password: string): Promise<Buffer>;
/** Validate an entry record and its SHA3-256 fingerprint. */
declare function verifyEntryRecord(ref: string, record: unknown): asserts record is EntryRecord;
/** Encrypt one secret and bind it to its credential reference with GCM AAD. */
declare function encryptEntry(key: Buffer, ref: string, plaintext: string): EntryRecord;
/** Decrypt one entry into an erasure-capable buffer. */
declare function decryptEntryBuffer(key: Buffer, ref: string, record: unknown): Buffer;
/** Decrypt one entry into an immutable string and erase its intermediate buffer. */
declare function decryptEntry(key: Buffer, ref: string, record: unknown): string;
//#endregion
//#region src/infrastructure/persistence/vault-document.d.ts
/** Serialize the legacy standalone vault-document shape. */
declare function serializeDocument(entries: Map<string, EntryRecord>): string;
/** Parse and verify the legacy standalone vault-document shape. */
declare function parseDocument(text: string): {
  entries: Map<string, EntryRecord>;
  documentSha3: string;
};
/** Verify a standalone vault document and discard its parsed entries. */
declare function verifyDocument(text: string): void;
/** Detect whether credential text carries the encrypted-store marker. */
declare function detectCredentialStore(text: string): "encrypted" | "plain";
/** Serialize a current or legacy encrypted credential store. */
declare function serializeEncryptedStore(records: Map<string, EntryRecord>, key: Buffer, salt: Buffer, params?: KdfParams, remember?: RememberBlock, kdf?: KdfName): string;
/** Parse and verify a current or legacy encrypted credential store. */
declare function parseEncryptedStore(text: string): ParsedEncryptedStore;
//#endregion
//#region src/application/password-service.d.ts
interface EncryptedStoreCreation {
  text: string;
  key: Buffer;
  entries: Map<string, EntryRecord>;
  salt: Buffer;
  params: Argon2Params;
}
/** Unlock an encrypted store and return only the state required by consumers. */
declare function unlockEncryptedStore(text: string, digest: string): Promise<Omit<ParsedEncryptedStore, "verifier" | "documentSha3"> & {
  key: Buffer;
}>;
/** Authenticate a password digest and immediately erase the derived key. */
declare function verifyPasswordDigest(text: string, digest: string): Promise<void>;
/** Encrypt a complete plaintext credential map under a new password digest. */
declare function encryptCredentialStore(plaintexts: Map<string, string>, digest: string, params?: Argon2Params): Promise<EncryptedStoreCreation>;
//#endregion
//#region src/application/remember-service.d.ts
/** Whether a remembered-login block remains inside its configured window. */
declare function rememberActive(remember: RememberBlock, now?: number): boolean;
/** Wrap a master key under a fresh browser-held remembered-login ticket. */
declare function createRememberBlock(key: Buffer, days: number, now?: number): {
  block: RememberBlock;
  secret: string;
};
/** Recover and authenticate a master key from a remembered-login ticket. */
declare function recoverKeyFromRemember(text: string, secretText: string): Omit<ParsedEncryptedStore, "verifier" | "documentSha3"> & {
  key: Buffer;
  remember: RememberBlock;
};
//#endregion
export { SCRYPT_N as $, verifyEntryRecord as A, EntryRecord as B, generateMasterKey as C, parseMasterKey as D, isPasswordKeyFile as E, ARGON2_MEMORY_KIB as F, MASTER_KEY_BYTES as G, KdfName as H, ARGON2_PARALLELISM as I, ParsedEncryptedStore as J, NONCE_BYTES as K, ARGON2_TIME as L, ARGON2_MAX_MEMORY_KIB as M, ARGON2_MAX_PARALLELISM as N, parsePasswordKeyFile as O, ARGON2_MAX_TIME as P, SCRYPT_MAXMEM as Q, Argon2Params as R, encryptEntry as S, isDigest as T, KdfParams as U, KEY_FILE_VERIFIER_REF as V, LEGACY_KDF as W, REMEMBER_KEY_REF as X, REMEMBER_DAY_MS as Y, RememberBlock as Z, decryptEntryBuffer as _, encryptCredentialStore as a, VAULT_KDF as at, deriveScryptKey as b, detectCredentialStore as c, VaultError as ct, serializeDocument as d, SCRYPT_P as et, serializeEncryptedStore as f, decryptEntry as g, createPasswordKeyFile as h, EncryptedStoreCreation as i, VAULT_ALGORITHM as it, zeroizeBuffer as j, sha3_256Hex as k, parseDocument as l, argon2Defaults as m, recoverKeyFromRemember as n, ScryptParams as nt, unlockEncryptedStore as o, VAULT_KDF_INPUT as ot, verifyDocument as p, PASSWORD_SALT_BYTES as q, rememberActive as r, TAG_BYTES as rt, verifyPasswordDigest as s, VAULT_VERSION as st, createRememberBlock as t, SCRYPT_R as tt, parseEncryptedStore as u, deriveArgon2idKey as v, generatePasswordSalt as w, encodeMasterKey as x, deriveMasterKey as y, ENCRYPTED_STORE_FORMAT as z };
//# sourceMappingURL=vault-BwiX-hzp.d.ts.map