/**
 * Browser-facing password surface of dsh-encrypt: exact HTTP routes over the
 * webServer service, dispatching to the `credentials` provider's password
 * operations. A separate composition row (`dsh-encrypt/web`) keeps the core
 * provider free of a webServer dependency, so headless compositions load the
 * provider without this surface.
 *
 * Routes (POST application/json only — the same cross-site write fence the
 * official /api uses; response: `{ ok, value }` or `{ ok: false, code,
 * message }`, messages never carrying the password or any key material):
 *
 *   /api/credentials.status            → { format: "plain"|"encrypted", unlocked }
 *   /api/credentials.unlock            { password }      → unlock the store
 *   /api/credentials.set-password      { password }      → plain → encrypted
 *   /api/credentials.change-password   { password }      → re-encrypt (unlocked)
 *   /api/credentials.clear-password    { }               → encrypted → plain (unlocked)
 *
 * @module dsh-encrypt/web
 */
export const name = "dsh-encrypt-web";
export const inject = ["webServer", "credentials"];

/** Wrap one password operation into a JSON HTTP handler with the write fence. */
function jsonHandler(operation) {
	return async (req, res) => {
		const write = (status, body) => {
			res.writeHead(status, { "content-type": "application/json" });
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
			const value = await operation(payload);
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
		{ path: "/api/credentials.status", operation: (_payload) => ctx.credentials.status() },
		{ path: "/api/credentials.unlock", operation: (payload) => ctx.credentials.unlock(String(payload.password ?? "")) },
		{ path: "/api/credentials.set-password", operation: (payload) => ctx.credentials.setPassword(String(payload.password ?? "")) },
		{ path: "/api/credentials.change-password", operation: (payload) => ctx.credentials.changePassword(String(payload.password ?? "")) },
		{ path: "/api/credentials.clear-password", operation: (_payload) => ctx.credentials.clearPassword() }
	];
	for (const { path, operation } of routes) {
		ctx.effect(() => ctx.webServer.register({ kind: "exact", path, handler: jsonHandler(operation) }), `dsh-encrypt: ${path}`);
	}
}
