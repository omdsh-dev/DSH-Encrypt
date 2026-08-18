import type { HttpRequestLike } from './model.js'
import { VaultError } from '../../domain/vault/model.js'

const MAX_BODY_BYTES = 4 * 1024
const BODY_TIMEOUT_MS = 10_000

/** Read and parse one small credential-route JSON body under fixed resource limits. */
export async function readCredentialJsonBody(req: HttpRequestLike): Promise<unknown> {
  let raw = ''
  let bytes = 0
  let timedOut = false
  const bodyTimeout = setTimeout(() => {
    timedOut = true
    req.destroy?.(new Error('dsh-encrypt: credential request body timed out'))
  }, BODY_TIMEOUT_MS)
  bodyTimeout.unref()
  try {
    for await (const chunk of req) {
      bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length
      if (bytes > MAX_BODY_BYTES) {
        throw new VaultError('PAYLOAD_TOO_LARGE', 'credential request body exceeds 4 KiB')
      }
      raw += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
    }
  } catch (error) {
    if (timedOut) throw new VaultError('REQUEST_TIMEOUT', 'credential request body timed out')
    throw error
  } finally {
    clearTimeout(bodyTimeout)
  }
  if (raw.length === 0) return {}
  try {
    return JSON.parse(raw) as unknown
  } catch {
    throw new VaultError('BAD_REQUEST', 'credential request body is not valid JSON')
  }
}
