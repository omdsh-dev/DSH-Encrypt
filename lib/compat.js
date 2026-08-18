/**
 * Runtime compatibility guard — the "fail loudly, never mysteriously" layer
 * of dsh-encrypt's decoupling from the dsh runtime.
 *
 * The plugin is a cordis plugin: it must run against the same cordis /
 * dsh-* seam copies the runtime composes. Its own dependency tree is pinned
 * exactly (package.json) and locked (package-lock.json), so the plugin side
 * is deterministic. The runtime side drifts only when the dsh package is
 * updated deliberately (see the pinned dshenv runtime), and this guard makes
 * that drift explicit:
 *
 *   - same 0.1.x line, same rc  -> ok (validated combination)
 *   - same 0.1.x line, other rc -> warn (likely compatible; run the tests)
 *   - other major.minor line    -> UNSUPPORTED_DSH, plugin refuses to load
 *
 * The running dsh version is discovered from the process entry point
 * (process.argv[1] is the @deepseek-ai/dsh lib/bin.js when launched through
 * dsh; in tests/embeds it is something else and the check is skipped).
 * @module dsh-encrypt/compat
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** The dsh release this plugin was built and validated against. */
export const VALIDATED_DSH = "0.1.0-rc.7";
/** Human-readable supported line, for error messages. */
export const SUPPORTED_DSH_LINE = "0.1.x";

/**
 * Find the running dsh runtime version from the process entry point.
 * @param {string[]} argv - the process argv (injectable for tests).
 * @returns {{ path: string, version: string }|null} the runtime, or null when
 *   this process was not launched through the dsh CLI (tests, embeds).
 */
export function detectDshRuntime(argv = process.argv) {
	const entry = argv?.[1];
	if (typeof entry !== "string" || entry.length === 0) return null;
	const binDir = dirname(entry);
	try {
		const doc = JSON.parse(readFileSync(join(binDir, "..", "package.json"), "utf8"));
		if (typeof doc?.name === "string" && doc.name === "@deepseek-ai/dsh" && typeof doc.version === "string") {
			return { path: join(binDir, "..", "package.json"), version: doc.version };
		}
	} catch {
		return null;
	}
	return null;
}

/** Parse a semver-ish version into its numeric line. */
export function parseVersionLine(version) {
	const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(String(version ?? ""));
	if (match === null) return null;
	return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), prerelease: match[4] ?? null };
}

/**
 * Classify one runtime version against the validated release.
 * @param {string} version - the running dsh version.
 * @param {string} [supported] - the validated release (default {@link VALIDATED_DSH}).
 * @returns {{ level: "ok"|"warn"|"fail", reason: string }} the verdict.
 */
export function classifyRuntimeVersion(version, supported = VALIDATED_DSH) {
	const actual = parseVersionLine(version);
	const expected = parseVersionLine(supported);
	if (actual === null || expected === null) return { level: "fail", reason: "unparseable dsh version " + version };
	if (actual.major !== expected.major || actual.minor !== expected.minor) {
		return { level: "fail", reason: "dsh " + version + " is outside the supported " + expected.major + "." + expected.minor + ".x line" };
	}
	if (version !== supported) return { level: "warn", reason: "dsh " + version + " differs from the validated " + supported + "; run the dsh-encrypt test suite before trusting this combination" };
	return { level: "ok", reason: "dsh " + version + " is the validated runtime" };
}

/**
 * Assert the running dsh runtime is supported; throws UNSUPPORTED_DSH on a
 * hard line mismatch (fail-closed, before the plugin can activate). A
 * same-line rc drift is reported as a warning verdict for the caller to log.
 * @param {string[]} [argv] - process argv (injectable for tests).
 * @returns {{ runtime: { path: string, version: string }|null, verdict: { level: string, reason: string } }}
 */
export function assertRuntimeCompat(argv = process.argv) {
	const runtime = detectDshRuntime(argv);
	if (runtime === null) return { runtime: null, verdict: { level: "ok", reason: "no dsh runtime detected (tests/embed)" } };
	const verdict = classifyRuntimeVersion(runtime.version);
	if (verdict.level === "fail") {
		const error = new Error(
			"dsh-encrypt: dsh " + runtime.version + " is NOT supported (validated against " + VALIDATED_DSH +
			", supported line " + SUPPORTED_DSH_LINE + "). Pin dsh to the supported line (see the pinned dshenv runtime) " +
			"or upgrade dsh-encrypt to a release matching this dsh."
		);
		error.code = "UNSUPPORTED_DSH";
		throw error;
	}
	return { runtime, verdict };
}
