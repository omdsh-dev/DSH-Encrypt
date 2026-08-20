import type { TsdownPlugin } from 'tsdown'
import { readdirSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { defineConfig } from 'tsdown'

const root = resolve(dirname(fileURLToPath(import.meta.url)))
const outputDirectory = join(root, 'lib')

interface IntegrityManifest {
  format: string
  version: number
  files: Record<string, string>
}

interface IntegrityModule {
  MANIFEST_FILE: string
  computeIntegrityManifest: (baseDir: string, relativeFiles: string[]) => IntegrityManifest
}

function collectFiles(directory: string): string[] {
  const files: string[] = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...collectFiles(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

function integrityManifestPlugin(): TsdownPlugin {
  return {
    name: 'dsh-encrypt-integrity-manifest',
    async writeBundle(): Promise<void> {
      // tsdown only generates dts for the `es` format; the IIFE client half
      // gets a static declaration (the browser module has no exports).
      writeFileSync(join(outputDirectory, 'client.d.ts'), 'export {}\n')
      const moduleUrl = pathToFileURL(join(outputDirectory, 'integrity.js'))
      const integrity = (await import(moduleUrl.href)) as IntegrityModule
      const relativeFiles = collectFiles(outputDirectory)
        .map(path => relative(root, path).split(sep).join('/'))
        .filter(path => path !== `lib/${integrity.MANIFEST_FILE}`)
      relativeFiles.push('cordis.patch.yml')
      const manifest = integrity.computeIntegrityManifest(root, relativeFiles)
      writeFileSync(join(outputDirectory, integrity.MANIFEST_FILE), `${JSON.stringify(manifest, null, 2)}\n`)
      console.log(`dsh-encrypt: integrity manifest written for ${relativeFiles.length} shipped files`)
    },
  }
}

// Browser half: emits a classic script (IIFE) instead of ESM — the
// client-modules loader injects bundles as <script> tags, where an `export`
// statement is a parse error and the __ModuleLoader__.load registration
// never runs. Run after the node build:
// `pnpm build` = `tsdown && tsdown -c tsdown.client.config.ts`.
export default defineConfig({
  entry: {
    client: 'src/client.ts',
  },
  clean: false,
  dts: {
    generator: 'oxc',
  },
  fixedExtension: false,
  format: 'iife',
  outDir: 'lib',
  outputOptions: {
    entryFileNames: 'client.js',
  },
  platform: 'browser',
  plugins: [integrityManifestPlugin()],
  sourcemap: true,
  target: 'es2022',
  tsconfig: 'tsconfig.build.json',
})
