/**
 * Shipped-code integrity self-check — the tamper-detection layer of
 * dsh-encrypt's anti-reverse-engineering / anti-tampering defense.
 *
 * The package ships a manifest ({@link MANIFEST_FILE}) holding the SHA3-256
 * of every shipped JavaScript file and of cordis.patch.yml, generated at
 * build/pack time by `npm run integrity` (scripts/gen-integrity.mjs).
 * At import time the provider row re-hashes each listed file and refuses to
 * load — fail-closed — when any byte differs: a patched, truncated, or
 * substituted plugin never starts silently, and the WebUI panel bundle
 * (lib/client.js) is covered by the host-side check before it is ever
 * served.
 *
 * Honest limits: the manifest itself is a shipped file, so an attacker who
 * can rewrite the installed plugin directory can also regenerate it. The
 * check catches tampering that does not regenerate the manifest (runtime
 * patching of an installed copy, truncation, accidental corruption, supply
 * chain substitution) and forces any legitimate rebuild to pass through
 * `npm run integrity` first. It is detection and fail-closed refusal —
 * not obfuscation and not a trust root; the cryptographic trust root remains
 * the user's password.
 * @module dsh-encrypt/integrity
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Manifest format marker. */
export const INTEGRITY_FORMAT = "dsh-encrypt-integrity";
/** Manifest schema version. */
export const INTEGRITY_VERSION = 1;
/** Manifest filename, shipped inside lib/. */
export const MANIFEST_FILE = "integrity-manifest.json";

/** SHA3-256 hex digest of one file's bytes. */
export function sha3File(path) {
	return createHash("sha3-256").update(readFileSync(path)).digest("hex");
}

/**
 * Build a manifest over the given relative file paths (keys are stored in
 * sorted order so the JSON is stable across platforms).
 * @param {string} baseDir - the package root the relative paths resolve from.
 * @param {string[]} relFiles - relative file paths to cover.
 * @returns {{ format: string, version: number, files: Record<string, string> }} the manifest.
 */
export function computeIntegrityManifest(baseDir, relFiles) {
	const files = {};
	for (const rel of [...relFiles].sort()) files[rel] = sha3File(join(baseDir, rel));
	return { format: INTEGRITY_FORMAT, version: INTEGRITY_VERSION, files };
}

/**
 * Verify a manifest against the files on disk.
 * @param {string} baseDir - the installed package root.
 * @param {unknown} manifest - the parsed manifest document.
 * @param {{ fail?: boolean }} [options] - fail=true throws on mismatch.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
export function verifyIntegrityManifest(baseDir, manifest, options = {}) {
	const fail = options.fail ?? true;
	const mismatches = [];
	const valid = manifest !== null && typeof manifest === "object" && manifest.format === INTEGRITY_FORMAT && manifest.version === INTEGRITY_VERSION && manifest.files !== null && typeof manifest.files === "object" && !Array.isArray(manifest.files);
	if (!valid) {
		mismatches.push(MANIFEST_FILE + " itself is missing or not a dsh-encrypt integrity manifest");
	} else {
		for (const [rel, expected] of Object.entries(manifest.files)) {
			let actual;
			try {
				actual = sha3File(join(baseDir, rel));
			} catch {
				actual = "<unreadable-or-missing>";
			}
			if (actual !== expected) mismatches.push(rel + ": expected " + String(expected) + ", got " + actual);
		}
	}
	if (mismatches.length > 0 && fail) {
		const error = new Error('dsh-encrypt: shipped-code integrity check FAILED — refusing to load tampered or incomplete files. If this tree was rebuilt legitimately, run "npm run integrity" to regenerate the manifest.\n  - ' + mismatches.join("\n  - "));
		error.code = "INTEGRITY_FAILED";
		throw error;
	}
	return { ok: mismatches.length === 0, mismatches };
}

/**
 * Load the manifest shipped next to this module and verify it against the
 * installed tree. Called at import time by the provider and web rows — a
 * mismatch throws before the plugin can activate (fail-closed).
 * @param {string} importMetaUrl - the importing module's import.meta.url.
 * @returns {{ ok: boolean, mismatches: string[] }} the verdict.
 */
export function loadAndVerifyIntegrity(importMetaUrl) {
	// The manifest ships inside lib/ (read from the module's own directory),
	// but its keys are package-relative ("lib/index.js", "cordis.patch.yml"):
	// verification runs against the package ROOT, one level above lib/.
	const moduleDir = dirname(fileURLToPath(importMetaUrl));
	const baseDir = resolve(moduleDir, "..");
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(join(moduleDir, MANIFEST_FILE), "utf8"));
	} catch (error) {
		if (error?.code === "ENOENT") {
			const missing = new Error('dsh-encrypt: ' + MANIFEST_FILE + ' is missing from the installed plugin; run "npm run integrity" to generate it');
			missing.code = "INTEGRITY_FAILED";
			throw missing;
		}
		throw error;
	}
	return verifyIntegrityManifest(baseDir, manifest);
}
