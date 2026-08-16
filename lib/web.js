/**
 * Browser-facing password surface of dsh-encrypt: exact HTTP routes over the
 * webServer service, dispatching to the `credentials` provider's password
 * operations. A separate composition row (`dsh-encrypt/web`) keeps the core
 * provider free of a webServer dependency, so headless compositions load the
 * provider without this surface.
 *
 * Authentication model:
 * - The browser never sends the raw password. It derives the lowercase hex
 *   SHA3-256 digest and POSTs `{ digest }`; the provider stretches the
 *   digest with scrypt and checks it against the AEAD verifier.
 * - Password modification (set / change / clear) and the remembered-login
 *   window are localhost-only: any other remote address is rejected with
 *   LOCAL_ONLY before the operation runs.
 * - Remembered logins: on a successful localhost password unlock the server
 *   issues a 256-bit ticket in an HttpOnly, SameSite=Strict cookie and
 *   persists only an AEAD-wrapped copy of the key in the store document.
 *   Localhost requests presenting the ticket skip the password form for the
 *   configured window; non-localhost requests never use it.
 *
 * Routes (POST application/json only — the same cross-site write fence the
 * official /api uses; response: `{ ok, value }` or `{ ok: false, code,
 * message }`, messages never carrying the password or any key material):
 *
 *   /api/credentials.status            → state + local + remember snapshot
 *                                         (attempts ticket unlock locally)
 *   /api/credentials.unlock            { digest }        → password unlock
 *   /api/credentials.set-password      { digest }        → localhost only
 *   /api/credentials.change-password   { digest }        → localhost only
 *   /api/credentials.clear-password    { }               → localhost only
 *   /api/credentials.config            { action, rememberDays } → get/set
 *
 * @module dsh-encrypt/web
 */
import { VaultError } from "./vault.js";

export const name = "dsh-encrypt-web";
export const inject = ["webServer", "credentials"];

/** Cookie carrying the browser-held remembered-login ticket. */
export const REMEMBER_COOKIE = "dsh-encrypt-remember";
/** Cookie max-age for a forever remembered login (100 years in seconds). */
const FOREVER_MAX_AGE = 3153600000;

/** Whether a request came from the loopback interface (the only trusted origin). */
export function isLocalRequest(req) {
	const addr = req?.socket?.remoteAddress ?? req?.connection?.remoteAddress ?? "";
	return addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1" || addr === "::ffff:7f00:1";
}

/** Read the remembered-login ticket from the request cookies, if present. */
export function readRememberCookie(req) {
	const header = req?.headers?.cookie;
	if (typeof header !== "string" || header.length === 0) return void 0;
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) continue;
		const key = part.slice(0, eq).trim();
		if (key === REMEMBER_COOKIE) return part.slice(eq + 1).trim();
	}
	return void 0;
}

/** Build the Set-Cookie header issuing a remembered login. */
export function rememberCookieHeader(secret, days) {
	const maxAge = days === -1 ? FOREVER_MAX_AGE : Math.max(0, Math.floor(days * 86400));
	return `${REMEMBER_COOKIE}=${secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

/** Build the Set-Cookie header clearing a remembered login. */
export function clearRememberCookieHeader() {
	return `${REMEMBER_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

/** Reject a non-localhost caller before a password modification runs. */
function assertLocal(req) {
	if (!isLocalRequest(req)) throw new VaultError("LOCAL_ONLY", "password changes and remembered-login settings are only allowed from localhost");
}

/** Wrap one password operation into a JSON HTTP handler with the write fence. */
function jsonHandler(operation) {
	return async (req, res) => {
		/** Cookie to attach to the response; the last assignment wins. */
		const cookies = {
			value: void 0,
			set(header) {
				cookies.value = header;
			},
			clear() {
				cookies.value = clearRememberCookieHeader();
			}
		};
		const write = (status, body) => {
			const headers = { "content-type": "application/json" };
			if (cookies.value !== void 0) {
				headers["set-cookie"] = cookies.value;
				if (typeof res.setHeader === "function") res.setHeader("Set-Cookie", cookies.value);
			}
			res.writeHead(status, headers);
			res.end(JSON.stringify(body));
		};
		if (req.method !== "POST") return write(405, { ok: false, code: "method-not-allowed", message: "POST required" });
		const mediaType = String(req.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase();
		if (mediaType !== "application/json") return write(415, { ok: false, code: "unsupported-media", message: "content type must be application/json" });
		let raw = "";
		for await (const chunk of req) raw += chunk;
		let payload = {};
		try {
			payload = raw.length > 0 ? JSON.parse(raw) : {};
		} catch {
			return write(400, { ok: false, code: "bad-request", message: "body is not JSON" });
		}
		try {
			const value = await operation(payload, req, cookies);
			return write(200, { ok: true, value: value === void 0 ? {} : value });
		} catch (error) {
			const code = typeof error?.code === "string" ? error.code : "internal";
			const message = error instanceof Error ? error.message : String(error);
			return write(400, { ok: false, code, message });
		}
	};
}

export function apply(ctx) {
	const routes = [
		{
			path: "/api/credentials.status",
			operation: async (_payload, req, cookies) => {
				const local = isLocalRequest(req);
				if (local) {
					const ticket = readRememberCookie(req);
					if (ticket !== void 0) {
						try {
							await ctx.credentials.unlockWithRemember(ticket);
						} catch (error) {
							if (error?.code === "REMEMBER_EXPIRED") cookies.clear();
							else if (error?.code !== "REMEMBER_INVALID" && error?.code !== "VAULT_NOT_ENCRYPTED") throw error;
						}
					}
				}
				const status = await ctx.credentials.status();
				return { ...status, local };
			}
		},
		{
			path: "/api/credentials.unlock",
			operation: async (payload, req, cookies) => {
				const value = await ctx.credentials.unlock(String(payload.digest ?? ""));
				const local = isLocalRequest(req);
				let remembered = false;
				let expiresAt = null;
				if (local) {
					const issued = await ctx.credentials.issueRemember();
					if (issued !== null) {
						cookies.set(rememberCookieHeader(issued.secret, issued.days));
						remembered = true;
						expiresAt = issued.expiresAt;
					}
				}
				return { ...value, local, remembered, expiresAt };
			}
		},
		{
			path: "/api/credentials.set-password",
			operation: async (payload, req, cookies) => {
				assertLocal(req);
				const value = await ctx.credentials.setPassword(String(payload.digest ?? ""));
				const issued = await ctx.credentials.issueRemember();
				let expiresAt = null;
				if (issued !== null) {
					cookies.set(rememberCookieHeader(issued.secret, issued.days));
					expiresAt = issued.expiresAt;
				}
				return { ...value, local: true, remembered: issued !== null, expiresAt };
			}
		},
		{
			path: "/api/credentials.change-password",
			operation: async (payload, req, cookies) => {
				assertLocal(req);
				cookies.clear();
				const value = await ctx.credentials.changePassword(String(payload.digest ?? ""));
				const issued = await ctx.credentials.issueRemember();
				let expiresAt = null;
				if (issued !== null) {
					cookies.set(rememberCookieHeader(issued.secret, issued.days));
					expiresAt = issued.expiresAt;
				}
				return { ...value, local: true, remembered: issued !== null, expiresAt };
			}
		},
		{
			path: "/api/credentials.clear-password",
			operation: async (_payload, req, cookies) => {
				assertLocal(req);
				cookies.clear();
				const value = await ctx.credentials.clearPassword();
				return { ...value, local: true };
			}
		},
		{
			path: "/api/credentials.config",
			operation: async (payload, req, cookies) => {
				if (payload?.action === "set") {
					assertLocal(req);
					const issued = await ctx.credentials.setRememberDays(payload.rememberDays);
					if (issued !== null) cookies.set(rememberCookieHeader(issued.secret, issued.days));
					else cookies.clear();
				}
				const status = await ctx.credentials.status();
				return { ...status, local: isLocalRequest(req) };
			}
		}
	];
	for (const { path, operation } of routes) {
		ctx.effect(() => ctx.webServer.register({ kind: "exact", path, handler: jsonHandler(operation) }), `dsh-encrypt: ${path}`);
	}
}
