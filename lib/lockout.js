//#region src/lockout.ts
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
const DEFAULT_MAX_ATTEMPTS = 5;
/** Default first lockout window (30 s). */
const DEFAULT_LOCKOUT_BASE_MS = 3e4;
/** Default lockout window ceiling (15 min). */
const DEFAULT_LOCKOUT_MAX_MS = 9e5;
/**
* Remaining lockout time at \`now\`, clamped to zero.
* @param {number} lockedUntil - epoch ms until which unlocks are refused.
* @param {number} [now] - the reference time.
* @returns {number} remaining ms.
*/
function lockoutRetryAfterMs(lockedUntil, now = Date.now()) {
	if (!Number.isFinite(lockedUntil) || lockedUntil <= 0) return 0;
	return Math.max(0, lockedUntil - now);
}
/**
* Whether unlocks are currently refused.
* @param {number} lockedUntil - epoch ms until which unlocks are refused.
* @param {number} [now] - the reference time.
* @returns {boolean} true while locked out.
*/
function isLockedOut(lockedUntil, now = Date.now()) {
	return lockoutRetryAfterMs(lockedUntil, now) > 0;
}
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
function recordLockoutFailure(state, config, now = Date.now()) {
	const maxAttempts = Number.isInteger(config?.maxAttempts) && config.maxAttempts > 0 ? config.maxAttempts : 5;
	const baseMs = Number.isFinite(config?.lockoutBaseMs) && config.lockoutBaseMs > 0 ? config.lockoutBaseMs : DEFAULT_LOCKOUT_BASE_MS;
	const maxMs = Number.isFinite(config?.lockoutMaxMs) && config.lockoutMaxMs > 0 ? config.lockoutMaxMs : DEFAULT_LOCKOUT_MAX_MS;
	const failures = (Number.isInteger(state?.failures) && state.failures >= 0 ? state.failures : 0) + 1;
	let lockedUntil = Number.isFinite(state?.lockedUntil) ? Math.max(0, state.lockedUntil) : 0;
	if (failures >= maxAttempts) {
		const exponent = Math.min(failures - maxAttempts, 30);
		const delay = Math.min(baseMs * 2 ** exponent, maxMs);
		lockedUntil = Math.max(lockedUntil, now + delay);
	}
	return {
		failures,
		lockedUntil,
		retryAfterMs: Math.max(0, lockedUntil - now)
	};
}
/**
* Human-readable lockout message for the WebUI / API surface. Never carries
* key material or credential values.
* @param {number} retryAfterMs - remaining lockout ms.
* @returns {string} the message.
*/
function formatLockoutMessage(retryAfterMs) {
	const seconds = Math.max(1, Math.ceil(retryAfterMs / 1e3));
	return `too many failed unlock attempts; retry in ${seconds} second${seconds === 1 ? "" : "s"}`;
}
//#endregion
export { DEFAULT_LOCKOUT_BASE_MS, DEFAULT_LOCKOUT_MAX_MS, DEFAULT_MAX_ATTEMPTS, formatLockoutMessage, isLockedOut, lockoutRetryAfterMs, recordLockoutFailure };

//# sourceMappingURL=lockout.js.map