/**
 * Request-trust fence for dsh-encrypt's web routes — the plugin-local
 * equivalent of the core /api fence (isTrustedApiRequest in
 * @deepseek-ai/dsh-client-connection), which the plugin's exact routes
 * never pass through: they are registered directly on the webServer and
 * would otherwise be reachable from any origin a browser can steer at the
 * loopback socket, DNS-rebinding pages included.
 *
 * The fence judges the request by its **Host header**, never by the socket's
 * remote address: a rebound request genuinely arrives from 127.0.0.1 while
 * its Host names the attacker's domain, and Host is the one header a browser
 * cannot forge (forbidden header). Non-browser clients can spoof Host, so
 * this fence is a confused-deputy defense for browsers, not authentication —
 * the unlock lockout stays the online-guessing defense.
 *
 * Semantics mirror the core fence exactly:
 * - the Host must parse as a bare authority;
 * - its hostname must be loopback (localhost, [::1], or any IPv4 in 127/8)
 *   or match a configured trustedHosts authority (a port-less entry matches
 *   any port; an explicit port matches exactly);
 * - Sec-Fetch-Site: cross-site is rejected;
 * - an attached Origin must be same-origin with the Host.
 *
 * @module dsh-encrypt/trust
 */
import { isIP } from 'node:net'

interface RequestLike {
  headers?: Record<string, string | string[] | undefined>
  socket?: { remoteAddress?: string }
  connection?: { remoteAddress?: string }
}

function requestLike(value: unknown): RequestLike {
  return typeof value === 'object' && value !== null ? value : {}
}

/** Whether a normalized URL hostname names the local loopback authority. */
export function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true
  return isIP(hostname) === 4 && hostname.startsWith('127.')
}

/** Normalized URL of a Host-header authority, or undefined when unparsable. */
export function parseAuthority(authority: string): URL | undefined {
  try {
    return new URL(`http://${authority}`)
  } catch {
    return void 0
  }
}

/** Canonical form of a parsed authority: hostname, plus :port when explicit. */
export function canonicalAuthority(entry: string, entryUrl: URL): string {
  const port = entryUrl.port !== '' ? entryUrl.port : new URL(`https://${entry}`).port
  return port === '' ? entryUrl.hostname : `${entryUrl.hostname}:${port}`
}

/**
 * Assert one configured trustedHosts entry is a bare authority (host or
 * host:port) in canonical form; anything parsing would silently rewrite is
 * refused loudly at startup, never ignored until a request 403s.
 */
export function assertTrustedAuthority(entry: string): void {
  const entryUrl = parseAuthority(entry)
  if (entryUrl !== void 0 && canonicalAuthority(entry, entryUrl) === entry.toLowerCase()) return
  throw new Error(`dsh-encrypt: trustedHosts entry ${JSON.stringify(entry)} is not a bare host[:port] authority`)
}

/** Whether one trustedHosts entry authorizes a parsed request Host. */
function isTrustedAuthority(hostUrl: URL, trustedHosts: string[]): boolean {
  return trustedHosts.some(entry => {
    const entryUrl = parseAuthority(entry)
    if (entryUrl === void 0) return false
    return canonicalAuthority(entry, entryUrl) === entryUrl.hostname
      ? entryUrl.hostname === hostUrl.hostname
      : entryUrl.host === hostUrl.host
  })
}

/**
 * Whether a Node HTTP request carries a trusted authority: loopback or
 * configured trusted Host, no cross-site fetch marker, same-origin Origin.
 * @param {unknown} req - node:http IncomingMessage (lowercase header keys).
 * @param {string[]} trustedHosts - non-loopback authorities this deployment serves.
 * @returns {boolean} true when the request may be served.
 */
export function isTrustedRequest(req: unknown, trustedHosts: string[] = []): boolean {
  const request = requestLike(req)
  const host = request.headers?.host
  if (typeof host !== 'string' || host.length === 0) return false
  const hostUrl = parseAuthority(host)
  if (hostUrl === void 0) return false
  if (!isLoopbackHostname(hostUrl.hostname) && !isTrustedAuthority(hostUrl, trustedHosts)) return false
  if (request.headers?.['sec-fetch-site'] === 'cross-site') return false
  const origin = request.headers?.origin
  if (origin === void 0) return true
  if (typeof origin !== 'string') return false
  try {
    return new URL(origin).host === hostUrl.host
  } catch {
    return false
  }
}

/** Whether a request's Host names the loopback interface alone. */
export function isLoopbackRequest(req: unknown): boolean {
  return isTrustedRequest(req, [])
}

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
export function isLoopbackSocket(req: unknown): boolean {
  const request = requestLike(req)
  if (
    request.headers?.forwarded !== void 0 ||
    request.headers?.['x-forwarded-for'] !== void 0 ||
    request.headers?.['x-forwarded-host'] !== void 0 ||
    request.headers?.['x-real-ip'] !== void 0
  ) {
    return false
  }
  const addr = request.socket?.remoteAddress ?? request.connection?.remoteAddress ?? ''
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1' || addr === '::ffff:7f00:1'
}
