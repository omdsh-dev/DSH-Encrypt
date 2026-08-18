//#region src/trust.d.ts
/** Whether a normalized URL hostname names the local loopback authority. */
declare function isLoopbackHostname(hostname: string): boolean;
/** Normalized URL of a Host-header authority, or undefined when unparsable. */
declare function parseAuthority(authority: string): URL | undefined;
/** Canonical form of a parsed authority: hostname, plus :port when explicit. */
declare function canonicalAuthority(entry: string, entryUrl: URL): string;
/**
 * Assert one configured trustedHosts entry is a bare authority (host or
 * host:port) in canonical form; anything parsing would silently rewrite is
 * refused loudly at startup, never ignored until a request 403s.
 */
declare function assertTrustedAuthority(entry: string): void;
/**
 * Whether a Node HTTP request carries a trusted authority: loopback or
 * configured trusted Host, no cross-site fetch marker, same-origin Origin.
 * @param {unknown} req - node:http IncomingMessage (lowercase header keys).
 * @param {string[]} trustedHosts - non-loopback authorities this deployment serves.
 * @returns {boolean} true when the request may be served.
 */
declare function isTrustedRequest(req: unknown, trustedHosts?: string[]): boolean;
/** Whether a request's Host names the loopback interface alone. */
declare function isLoopbackRequest(req: unknown): boolean;
/**
 * Whether a request's socket genuinely arrived from the loopback interface.
 * This is the anti-spoof counterpart of the Host fence: non-browser clients
 * CAN forge a loopback Host, so password mutations additionally require the
 * connection itself to be loopback (see web.isLocalRequest). A DNS-rebinding
 * page passes this check too (its socket IS loopback) — that shape is caught
 * by the Host fence, so the two checks complement each other.
 * @param {unknown} req - node:http IncomingMessage.
 * @returns {boolean} true when the connection came from loopback.
 */
declare function isLoopbackSocket(req: unknown): boolean;
//#endregion
export { assertTrustedAuthority, canonicalAuthority, isLoopbackHostname, isLoopbackRequest, isLoopbackSocket, isTrustedRequest, parseAuthority };
//# sourceMappingURL=trust.d.ts.map