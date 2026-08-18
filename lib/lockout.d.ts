//#region src/lockout.d.ts
/**
 * Unlock-attempt lockout policy — the pure, dependency-free policy layer of
 * dsh-encrypt's online brute-force defense.
 *
 * Consecutive failed password unlocks (PASSWORD_WRONG) increment a persisted
 * counter. Once \`maxAttempts\` is reached, further attempts are rejected
 * with \`TOO_MANY_ATTEMPTS\` for an exponentially growing window:
 *
 *   delay = min(lockoutBaseMs * 2^(failures - maxAttempts), lockoutMaxMs)
 *
 * Every failure past the threshold re-arms and doubles the window; a
 * successful unlock resets the counter. The counter and deadline persist in
 * the state file, so restarting the process does not reset them.
 *
 * Honest limits: the state file is editable by the same OS user who owns the
 * vault, and offline ciphertext brute force is bounded by scrypt cost — this
 * policy only slows ONLINE guessing through the unlock surface.
 * @module dsh-encrypt/lockout
 */
/** Default consecutive failures before the first lockout window. */
declare const DEFAULT_MAX_ATTEMPTS = 5;
/** Default first lockout window (30 s). */
declare const DEFAULT_LOCKOUT_BASE_MS = 3e4;
/** Default lockout window ceiling (15 min). */
declare const DEFAULT_LOCKOUT_MAX_MS = 9e5;
interface LockoutState {
  failures: number;
  lockedUntil: number;
}
interface LockoutConfig {
  maxAttempts: number;
  lockoutBaseMs: number;
  lockoutMaxMs: number;
}
interface LockoutResult extends LockoutState {
  retryAfterMs: number;
}
/**
 * Remaining lockout time at \`now\`, clamped to zero.
 * @param {number} lockedUntil - epoch ms until which unlocks are refused.
 * @param {number} [now] - the reference time.
 * @returns {number} remaining ms.
 */
declare function lockoutRetryAfterMs(lockedUntil: number, now?: number): number;
/**
 * Whether unlocks are currently refused.
 * @param {number} lockedUntil - epoch ms until which unlocks are refused.
 * @param {number} [now] - the reference time.
 * @returns {boolean} true while locked out.
 */
declare function isLockedOut(lockedUntil: number, now?: number): boolean;
/**
 * Record one failed unlock attempt and return the next lockout state. The
 * failure counter grows on every call; once it reaches \`maxAttempts\`,
 * each failure (re-)arms an exponentially growing window:
 *
 *   delay = min(lockoutBaseMs * 2^(failures - maxAttempts), lockoutMaxMs)
 *
 * An already-active window is never shortened by a later failure (the
 * deadline only moves forward).
 * @param {{ failures: number, lockedUntil: number }} state - the previous state.
 * @param {{ maxAttempts: number, lockoutBaseMs: number, lockoutMaxMs: number }} config - the policy.
 * @param {number} [now] - the reference time.
 * @returns {{ failures: number, lockedUntil: number, retryAfterMs: number }} the next state.
 */
declare function recordLockoutFailure(state: LockoutState, config: LockoutConfig, now?: number): LockoutResult;
/**
 * Human-readable lockout message for the WebUI / API surface. Never carries
 * key material or credential values.
 * @param {number} retryAfterMs - remaining lockout ms.
 * @returns {string} the message.
 */
declare function formatLockoutMessage(retryAfterMs: number): string;
//#endregion
export { DEFAULT_LOCKOUT_BASE_MS, DEFAULT_LOCKOUT_MAX_MS, DEFAULT_MAX_ATTEMPTS, LockoutConfig, LockoutResult, LockoutState, formatLockoutMessage, isLockedOut, lockoutRetryAfterMs, recordLockoutFailure };
//# sourceMappingURL=lockout.d.ts.map