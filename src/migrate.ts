import { mkdir, readFile, stat } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { withFileLock, writeFileAtomic } from '@deepseek-ai/dsh-atomic-write'
import { canonicalizeWatchPath } from '@deepseek-ai/dsh-home-paths'
import { encryptedMarker } from './plain.js'
import { detectCredentialStore, parseEncryptedStore } from './vault.js'

const GROUP_OTHER_BITS = 0o077

export interface MigrationOptions {
  path?: string
  encryptedPath?: string
}

function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}

async function assertOwnerOnly(filename: string): Promise<void> {
  try {
    const mode = (await stat(filename)).mode
    if (process.platform !== 'win32' && (mode & GROUP_OTHER_BITS) !== 0) {
      throw new Error(
        `dsh-encrypt: ${filename} is readable beyond its owner (mode ${(mode & 0o777).toString(8)}); run "chmod 600 ${filename}" before migrating`,
      )
    }
  } catch (error) {
    if (!isNotFound(error)) throw error
    await canonicalizeWatchPath(filename)
  }
}

/**
 * Move the pre-Fabric single-file encrypted document into the sidecar layout.
 * This operation does not unlock or decrypt anything; it only verifies the
 * document structure, writes the ciphertext first, then replaces the official
 * file with the comment-only marker.
 */
export async function migrateLegacySidecar(
  options: MigrationOptions = {},
): Promise<{ filename: string; sidecar: string }> {
  if (typeof options.path !== 'string' || options.path.length === 0)
    throw new TypeError('dsh-encrypt: migration requires a legacy credentials path')
  const filename = resolve(options.path)
  const sidecar = resolve(
    options.encryptedPath ??
      (basename(filename) === '.credentials.yaml'
        ? `${dirname(filename)}/.credentials.encrypt.yaml`
        : `${filename}.encrypt`),
  )
  await assertOwnerOnly(filename)
  return withFileLock(filename, async () => {
    await assertOwnerOnly(filename)
    const text = await readFile(filename, 'utf8')
    if (detectCredentialStore(text) !== 'encrypted')
      throw new Error(`dsh-encrypt: ${filename} is not a legacy encrypted store`)
    parseEncryptedStore(text)
    try {
      const sidecarStat = await stat(sidecar)
      if (process.platform !== 'win32' && (sidecarStat.mode & GROUP_OTHER_BITS) !== 0) {
        throw new Error(`dsh-encrypt: existing sidecar ${sidecar} is readable beyond its owner`)
      }
      throw new Error(`dsh-encrypt: refusing to overwrite existing sidecar ${sidecar}`)
    } catch (error) {
      if (!isNotFound(error)) throw error
    }
    await mkdir(dirname(sidecar), { recursive: true, mode: 0o700 })
    await writeFileAtomic(sidecar, text, { mode: 0o600, dirMode: 0o700 })
    await writeFileAtomic(filename, encryptedMarker(sidecar), { mode: 0o600, dirMode: 0o700 })
    return { filename, sidecar }
  })
}
