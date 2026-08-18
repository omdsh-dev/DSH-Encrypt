//#region src/compat.d.ts
/** The dsh release this plugin was built and validated against. */
declare const VALIDATED_DSH = "0.1.0-rc.7";
/** Human-readable supported line, for error messages. */
declare const SUPPORTED_DSH_LINE = "0.1.x";
interface DshRuntime {
  path: string;
  version: string;
}
interface VersionLine {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}
interface CompatibilityVerdict {
  level: "ok" | "warn" | "fail";
  reason: string;
}
/**
 * Find the running dsh runtime version from the process entry point.
 * @param {string[]} argv - the process argv (injectable for tests).
 * @returns {{ path: string, version: string }|null} the runtime, or null when
 *   this process was not launched through the dsh CLI (tests, embeds).
 */
declare function detectDshRuntime(argv?: string[]): DshRuntime | null;
/** Parse a semver-ish version into its numeric line. */
declare function parseVersionLine(version: string): VersionLine | null;
/**
 * Classify one runtime version against the validated release.
 * @param {string} version - the running dsh version.
 * @param {string} [supported] - the validated release (default {@link VALIDATED_DSH}).
 * @returns {{ level: "ok"|"warn"|"fail", reason: string }} the verdict.
 */
declare function classifyRuntimeVersion(version: string, supported?: string): CompatibilityVerdict;
/**
 * Assert the running dsh runtime is supported; throws UNSUPPORTED_DSH on a
 * hard line mismatch (fail-closed, before the plugin can activate). A
 * same-line rc drift is reported as a warning verdict for the caller to log.
 * @param {string[]} [argv] - process argv (injectable for tests).
 * @returns {{ runtime: { path: string, version: string }|null, verdict: { level: string, reason: string } }}
 */
declare function assertRuntimeCompat(argv?: string[]): {
  runtime: DshRuntime | null;
  verdict: CompatibilityVerdict;
};
//#endregion
export { CompatibilityVerdict, DshRuntime, SUPPORTED_DSH_LINE, VALIDATED_DSH, VersionLine, assertRuntimeCompat, classifyRuntimeVersion, detectDshRuntime, parseVersionLine };
//# sourceMappingURL=compat.d.ts.map