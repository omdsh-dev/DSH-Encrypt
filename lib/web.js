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
import { WsFrameFilter } from "./leak-guard.js";
import { loadAndVerifyIntegrity } from "./integrity.js";

// Fail-closed shipped-code integrity check (see ./integrity.js); the web row
// re-verifies even though the provider row already did, so a web-only
// composition cannot slip past a tampered lib/ tree either.
loadAndVerifyIntegrity(import.meta.url);

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

/**
 * Read the remembered-login ticket from the explicit request header the
 * WebUI attaches (localStorage-backed, immune to cookie-storage quirks).
 */
export function readRememberHeader(req) {
	const header = req?.headers?.["x-dsh-encrypt-remember"];
	if (typeof header !== "string" || header.length === 0) return void 0;
	return header.trim();
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

// ── leak-guard output redaction (prompt-injection / exfiltration defense) ──
//
// While the vault is unlocked, the credentials provider registers the
// plaintext of every credential it resolves in its LeakGuard. This row wraps
// the web server's route tables so every response body — the /api fetch RPC
// surface (session history, tool results, model text) and the WebSocket
// event downlinks (streaming deltas) — passes through the guard before it
// reaches the browser: a credential value a compromised prompt tricked the
// model into echoing is replaced with a redaction marker before it leaves
// the host.
//
// Honest limits: only resolved values are masked; binary WebSocket frames and
// the static fallback are not scanned; and the marker substitution cannot
// stop a model that exfiltrates a secret through a tool call (web_search,
// bash, …). This layer closes the echo/leak-in-output surface, not the
// tool-use surface.

/**
 * Wrap one HTTP route handler so everything it writes is redacted through
 * the guard. No-op (bare passthrough) when the guard is disabled or holds no
 * secrets, so locked vaults pay nothing.
 * @param {(req: unknown, res: unknown) => unknown} handler - the route handler.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped handler.
 */
export function redactingHttpHandler(handler, guard) {
	return async (req, res) => {
		if (!guard?.enabled || guard.size() === 0 || typeof res?.write !== "function" || typeof res?.end !== "function") return handler(req, res);
		const stream = guard.stream();
		const originalWrite = res.write.bind(res);
		const originalEnd = res.end.bind(res);
		res.write = (chunk, encoding, callback) => {
			const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
			const enc = typeof encoding === "string" ? encoding : void 0;
			if (chunk === void 0 || chunk === null) {
				if (cb !== void 0) cb();
				return true;
			}
			const pieces = stream.push(chunk);
			for (const piece of pieces) originalWrite(piece, enc);
			if (cb !== void 0) cb();
			return true;
		};
		res.end = (chunk, encoding, callback) => {
			const cb = typeof encoding === "function" ? encoding : typeof callback === "function" ? callback : void 0;
			const enc = typeof encoding === "string" ? encoding : void 0;
			const tail = stream.flush();
			if (chunk !== void 0 && chunk !== null) {
				const pieces = stream.push(chunk);
				const last = pieces.length > 0 ? pieces[pieces.length - 1] + tail : tail;
				for (const piece of pieces.slice(0, -1)) originalWrite(piece, enc);
				originalEnd(last, enc);
			} else {
				if (tail.length > 0) originalWrite(tail, enc);
				originalEnd();
			}
			if (cb !== void 0) cb();
			return res;
		};
		try {
			await handler(req, res);
		} finally {
			res.write = originalWrite;
			res.end = originalEnd;
		}
	};
}

/**
 * Patch a raw upgrade socket so that, once the 101 handshake response has
 * been written, every outgoing WebSocket frame passes through the guard
 * (text frames only; the downlink server sends unmasked, uncompressed
 * frames, see {@link WsFrameFilter}). The handshake response itself is
 * buffered only until its header terminator arrives, then forwarded intact.
 * @param {import("node:net").Socket} socket - the raw socket.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 */
export function armSocketRedaction(socket, guard) {
	if (!guard?.enabled || guard.size() === 0 || typeof socket?.write !== "function") return;
	const original = socket.write.bind(socket);
	let filter = null;
	let pre = Buffer.alloc(0);
	let dead = false;
	socket.write = function (chunk, encoding, callback) {
		const cb = typeof encoding === "function" ? encoding : callback;
		const enc = typeof encoding === "string" ? encoding : "utf8";
		const buf = Buffer.isBuffer(chunk) ? chunk : typeof chunk === "string" ? Buffer.from(chunk, enc) : Buffer.from(chunk);
		if (filter === null && !dead) {
			pre = Buffer.concat([pre, buf]);
			const terminator = pre.indexOf("\r\n\r\n");
			if (terminator !== -1) {
				const isUpgrade = pre.subarray(0, terminator).toString("latin1").startsWith("HTTP/1.1 101");
				if (isUpgrade) {
					original(pre.subarray(0, terminator + 4), enc);
					filter = new WsFrameFilter((text) => guard.mask(text));
					const rest = pre.subarray(terminator + 4);
					pre = Buffer.alloc(0);
					for (const piece of filter.push(rest)) original(piece, enc);
					if (cb !== void 0) cb();
					return true;
				}
				dead = true;
			} else if (pre.length > 4096) {
				dead = true;
			}
			if (dead) {
				original(pre, enc);
				pre = Buffer.alloc(0);
				if (cb !== void 0) cb();
				return true;
			}
			if (cb !== void 0) cb();
			return true;
		}
		if (dead) return original(chunk, encoding, callback);
		for (const piece of filter.push(chunk)) original(piece, enc);
		if (cb !== void 0) cb();
		return true;
	};
}

/**
 * Wrap one upgrade route handler so its socket frames are redacted after the
 * handshake completes.
 * @param {Object} route - the registered upgrade route.
 * @param {import("./leak-guard.js").LeakGuard} guard - the provider's guard.
 * @returns the wrapped route.
 */
export function redactingUpgradeRoute(route, guard) {
	const handler = route.handler;
	return {
		...route,
		handler: (req, socket, head) => {
			armSocketRedaction(socket, guard);
			return handler(req, socket, head);
		}
	};
}

/**
 * Install response redaction over the web server's route tables: existing
 * routes are wrapped in place and future registrations are wrapped on insert
 * (the Proxy set trap), covering the /api prefix owned by client-connection
 * and any route registered later. Returns a disposer restoring the original
 * tables.
 * @param {unknown} ctx - the row context.
 * @returns {() => void} the disposer.
 */
export function installLeakRedaction(ctx) {
	const guard = ctx.credentials?.leakGuard;
	const webServer = ctx.webServer;
	if (!guard || typeof webServer?.exact?.set !== "function" || typeof webServer?.prefixes?.set !== "function") return () => {};
	const wrapHttp = (route) => ({ ...route, handler: redactingHttpHandler(route.handler, guard) });
	const wrapUpgrade = (route) => redactingUpgradeRoute(route, guard);
	const proxyTable = (table, wrap) => new Proxy(table, {
		get(target, key) {
			if (key === "set") return (path, route) => target.set(path, wrap(route));
			// Methods extracted from a proxy lose their receiver: bind them to
			// the raw Map so get/has/entries/forEach keep working through the
			// proxy (the WebServer service calls this.exact.get/set/has).
			const value = Reflect.get(target, key);
			return typeof value === "function" ? value.bind(target) : value;
		}
	});
	const originalExact = webServer.exact;
	const originalPrefixes = webServer.prefixes;
	const originalUpgrades = webServer.upgrades;
	for (const [path, route] of [...webServer.exact]) webServer.exact.set(path, wrapHttp(route));
	for (const [path, route] of [...webServer.prefixes]) webServer.prefixes.set(path, wrapHttp(route));
	if (typeof webServer?.upgrades?.set === "function") for (const [path, route] of [...webServer.upgrades]) webServer.upgrades.set(path, wrapUpgrade(route));
	webServer.exact = proxyTable(originalExact, wrapHttp);
	webServer.prefixes = proxyTable(originalPrefixes, wrapHttp);
	if (typeof originalUpgrades?.set === "function") webServer.upgrades = proxyTable(originalUpgrades, wrapUpgrade);
	return () => {
		if (webServer.exact !== originalExact) webServer.exact = originalExact;
		if (webServer.prefixes !== originalPrefixes) webServer.prefixes = originalPrefixes;
		if (webServer.upgrades !== originalUpgrades) webServer.upgrades = originalUpgrades;
	};
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
		const write = (status, body, extraHeaders) => {
			const headers = { "content-type": "application/json", ...extraHeaders };
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
			if (code === "TOO_MANY_ATTEMPTS") {
				const retryAfterSeconds = Math.max(1, Math.ceil((typeof error?.retryAfterMs === "number" ? error.retryAfterMs : 0) / 1000));
				return write(429, { ok: false, code, message, retryAfterMs: retryAfterSeconds * 1000 }, { "retry-after": String(retryAfterSeconds) });
			}
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
				let ticketRejected = false;
				if (local) {
					const ticket = readRememberHeader(req) ?? readRememberCookie(req);
					if (ticket !== void 0) {
						try {
							await ctx.credentials.unlockWithRemember(ticket);
						} catch (error) {
							if (error?.code === "REMEMBER_EXPIRED" || error?.code === "REMEMBER_INVALID") {
								cookies.clear();
								ticketRejected = true;
							} else if (error?.code !== "VAULT_NOT_ENCRYPTED") throw error;
						}
					}
				}
				const status = await ctx.credentials.status();
				return { ...status, local, ticketRejected };
			}
		},
		{
			path: "/api/credentials.unlock",
			operation: async (payload, req, cookies) => {
				const value = await ctx.credentials.unlock(String(payload.digest ?? ""));
				const local = isLocalRequest(req);
				let remembered = false;
				let expiresAt = null;
				let issued = null;
				if (local) {
					issued = await ctx.credentials.issueRemember();
					if (issued !== null) {
						cookies.set(rememberCookieHeader(issued.secret, issued.days));
						remembered = true;
						expiresAt = issued.expiresAt;
					}
				}
				return { ...value, local, remembered, expiresAt, ticket: issued?.secret ?? void 0 };
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
				return { ...value, local: true, remembered: issued !== null, expiresAt, ticket: issued?.secret ?? void 0 };
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
				return { ...value, local: true, remembered: issued !== null, expiresAt, ticket: issued?.secret ?? void 0 };
			}
		},

		{
			path: "/api/credentials.config",
			operation: async (payload, req, cookies) => {
				let ticket;
				if (payload?.action === "set") {
					assertLocal(req);
					const issued = await ctx.credentials.setRememberDays(payload.rememberDays);
					if (issued !== null) {
						cookies.set(rememberCookieHeader(issued.secret, issued.days));
						ticket = issued.secret;
					} else {
						cookies.clear();
					}
				}
				const status = await ctx.credentials.status();
				return { ...status, local: isLocalRequest(req), ticket };
			}
		}
	];
	for (const { path, operation } of routes) {
		ctx.effect(() => ctx.webServer.register({ kind: "exact", path, handler: jsonHandler(operation) }), `dsh-encrypt: ${path}`);
	}
}
