import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { patchStubs } from '../lib/fabric-handlers.js'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const patchFile = resolve(root, 'cordis.patch.yml')
const document = parse(await readFile(patchFile, 'utf8'))
const row = document.flatMap(operation => operation?.insert ?? []).find(entry => entry?.id === 'dsh-encrypt-fabric')
if (row === void 0) throw new Error('dsh-encrypt: cordis.patch.yml is missing dsh-encrypt-fabric')
if (row.disabled !== true) throw new Error('dsh-encrypt: dsh-encrypt-fabric must remain disabled outside stent-dsh')
const expected = patchStubs().map(({ id, required, target, operation }) => ({ id, required, target, operation }))
const actual = row.config?.stent?.patches
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  throw new Error('dsh-encrypt: cordis.patch.yml Stent descriptors drift from lib/fabric-handlers.js')
}
if (document.some(operation => operation?.id === 'credentials' && operation.disabled === true)) {
  throw new Error('dsh-encrypt: cordis.patch.yml must not disable the official credentials row')
}
console.log(`dsh-encrypt: verified ${expected.length} Stent descriptors and official credentials row`)
