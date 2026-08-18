import type { IntegrityManifest } from '../lib/integrity.js'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { MANIFEST_FILE, verifyIntegrityManifest } from '../lib/integrity.js'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outputDirectory = join(root, 'lib')

function collectFiles(directory: string): string[] {
  const files: string[] = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...collectFiles(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

describe('build integrity manifest', () => {
  it('covers every generated file and verifies their contents', () => {
    const manifest = JSON.parse(readFileSync(join(outputDirectory, MANIFEST_FILE), 'utf8')) as IntegrityManifest
    const expectedFiles = collectFiles(outputDirectory)
      .map(path => relative(root, path).split(sep).join('/'))
      .filter(path => path !== `lib/${MANIFEST_FILE}`)
    expectedFiles.push('cordis.patch.yml')

    expect(Object.keys(manifest.files).sort()).toEqual(expectedFiles.sort())
    expect(verifyIntegrityManifest(root, manifest, { fail: false })).toEqual({
      ok: true,
      mismatches: [],
    })
  })
})
