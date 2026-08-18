import type { Stats } from 'node:fs'
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { dirname } from 'node:path'
import { canonicalizeWatchPath } from '@deepseek-ai/dsh-home-paths'

const GROUP_OTHER_BITS = 0o077
const GROUP_OTHER_WRITE_BITS = 0o022

/** Reject unsafe file types, ownership and POSIX permissions without following links. */
export async function assertOwnerOnly(filename: string): Promise<void> {
  await assertSecureParent(filename)
  let info: Stats
  try {
    info = await lstat(filename)
  } catch (error) {
    if (!isENOENT(error)) throw error
    await canonicalizeWatchPath(filename)
    return
  }
  assertSafeFileInfo(filename, info)
}

/** Read one protected UTF-8 file through a no-follow descriptor. */
export async function readOwnerOnlyText(filename: string): Promise<string> {
  await assertOwnerOnly(filename)
  const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW
  const handle = await open(filename, constants.O_RDONLY | constants.O_NONBLOCK | noFollow)
  try {
    assertSafeFileInfo(filename, await handle.stat())
    return await handle.readFile({ encoding: 'utf8' })
  } finally {
    await handle.close()
  }
}

function assertSafeFileInfo(filename: string, info: Stats): void {
  if (info.isSymbolicLink()) throw new Error(`dsh-encrypt: ${filename} must not be a symbolic link`)
  if (!info.isFile()) throw new Error(`dsh-encrypt: ${filename} must be a regular file`)
  if (process.platform === 'win32') return
  assertCurrentOwner(filename, info)
  if ((info.mode & GROUP_OTHER_BITS) !== 0) {
    throw new Error(
      `dsh-encrypt: ${filename} is accessible beyond its owner (mode ${(info.mode & 0o777).toString(8)}); run "chmod 600 ${filename}" before starting again`,
    )
  }
}

async function assertSecureParent(filename: string): Promise<void> {
  const parent = dirname(filename)
  let info: Stats
  try {
    info = await lstat(parent)
  } catch (error) {
    if (isENOENT(error)) return
    throw error
  }
  if (info.isSymbolicLink()) throw new Error(`dsh-encrypt: credential directory ${parent} must not be a symbolic link`)
  if (!info.isDirectory()) throw new Error(`dsh-encrypt: credential directory ${parent} must be a directory`)
  if (process.platform === 'win32') return
  assertCurrentOwner(parent, info)
  if ((info.mode & GROUP_OTHER_WRITE_BITS) !== 0) {
    throw new Error(
      `dsh-encrypt: credential directory ${parent} is writable beyond its owner (mode ${(info.mode & 0o777).toString(8)})`,
    )
  }
}

function assertCurrentOwner(filename: string, info: Stats): void {
  const getuid = process.getuid
  if (typeof getuid !== 'function') return
  if (info.uid !== getuid()) {
    throw new Error(`dsh-encrypt: ${filename} is not owned by the current user`)
  }
}

/** Whether a filesystem error reports an absent file. */
export function isENOENT(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === 'ENOENT'
}
