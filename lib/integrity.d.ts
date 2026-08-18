//#region src/integrity.d.ts
/** Manifest format marker. */
declare const INTEGRITY_FORMAT = "dsh-encrypt-integrity";
/** Manifest schema version. */
declare const INTEGRITY_VERSION = 1;
/** Manifest filename, shipped inside lib/. */
declare const MANIFEST_FILE = "integrity-manifest.json";
interface IntegrityManifest {
  format: string;
  version: number;
  files: Record<string, string>;
}
interface IntegrityVerdict {
  ok: boolean;
  mismatches: string[];
}
/**
 * Canonicalize file bytes before hashing: strip a UTF-8 BOM and fold CRLF /
 * lone CR line endings to LF. Both manifest generation and runtime
 * verification hash through this function, so a git checkout on any platform
 * (LF or CRLF) verifies against the same manifest.
 * @param {Buffer} bytes - the raw file bytes.
 * @returns {Buffer} the canonical bytes.
 */
declare function normalizeForHashing(bytes: Buffer): Buffer;
/** SHA3-256 hex digest of one file's canonicalized bytes. */
declare function sha3File(path: string): string;
/**
 * Build a manifest over the given relative file paths (keys are stored in
 * sorted order so the JSON is stable across platforms).
 * @param {string} baseDir - the package root the relative paths resolve from.
 * @param {string[]} relFiles - relative file paths to cover.
 * @returns {{ format: string, version: number, files: Record<string, string> }} the manifest.
 */
declare function computeIntegrityManifest(baseDir: string, relFiles: string[]): IntegrityManifest;
/**
 * Verify a manifest against the files on disk.
 * @param {string} baseDir - the installed package root.
 * @param {unknown} manifest - the parsed manifest document.
 * @param {{ fail?: boolean }} [options] - fail=true throws on mismatch.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
declare function verifyIntegrityManifest(baseDir: string, manifest: unknown, options?: {
  fail?: boolean;
}): IntegrityVerdict;
/**
 * Load the manifest shipped next to this module and verify it against the
 * installed tree. Called at import time by the provider and web rows — a
 * mismatch throws before the plugin can activate (fail-closed).
 * @param {string} importMetaUrl - the importing module's import.meta.url.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
declare function loadAndVerifyIntegrity(importMetaUrl: string): IntegrityVerdict;
//#endregion
export { INTEGRITY_FORMAT, INTEGRITY_VERSION, IntegrityManifest, IntegrityVerdict, MANIFEST_FILE, computeIntegrityManifest, loadAndVerifyIntegrity, normalizeForHashing, sha3File, verifyIntegrityManifest };
//# sourceMappingURL=integrity.d.ts.map