import { parsePlainEntries } from './infrastructure/persistence/plain-credential-document.js'

const ENCRYPTED_MARKER_PATTERN = /^# dsh-encrypt: encrypted sidecar$/mu
const PATH_SEPARATOR_PATTERN = /[\\/]/u

/** Marker written into the official credentials file while the sidecar is active. */
export const ENCRYPTED_MARKER =
  '# dsh-encrypt: encrypted sidecar\n# Credential values are stored in .credentials.encrypt.yaml.\n'

/**
 * Parse the official plaintext document for the one-time plain-to-encrypted
 * transition. This helper owns no watcher or write lifecycle.
 * @param text - the YAML document.
 * @param filename - the path used in diagnostics.
 * @returns plaintext credential entries.
 */
export { parsePlainEntries }

/** Whether the official file is the comment-only encrypted shadow marker. */
export function isEncryptedMarker(text: unknown): boolean {
  if (typeof text !== 'string' || !ENCRYPTED_MARKER_PATTERN.test(text)) return false
  // The marker must remain a comment-only YAML document; plaintext entries
  // alongside it would violate the sidecar's fail-closed state.
  return parsePlainEntries(text, '.credentials.yaml').size === 0
}

/** Build the marker with the actual sidecar basename for custom paths. */
export function encryptedMarker(sidecarPath: string): string {
  const basename = String(sidecarPath).split(PATH_SEPARATOR_PATTERN).pop() || '.credentials.encrypt.yaml'
  return `# dsh-encrypt: encrypted sidecar\n# Credential values are stored in ${basename}.\n`
}
