import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { EncryptController, PATCH_IDS, PATCH_OPERATIONS, patchStubs, resolveSpec } from '../lib/fabric-entry.js'
import { encryptedMarker, isEncryptedMarker, parsePlainEntries } from '../lib/plain.js'
import { assertTrustedAuthority, isLoopbackRequest, isLoopbackSocket, isTrustedRequest } from '../lib/trust.js'
import { sha3_256Hex } from '../lib/vault.js'

function context() {
  const updates: string[] = []
  return {
    credentials: {
      notifyUpdated(ref: string) {
        updates.push(ref)
      },
    },
    updates,
    logger: {
      warn() {},
      error() {},
    },
    emit() {},
  }
}

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-encrypt-fabric-'))
  return {
    dir,
    path: join(dir, '.credentials.yaml'),
    encryptedPath: join(dir, '.credentials.encrypt.yaml'),
    statePath: join(dir, '.dsh-encrypt.json'),
  }
}

it('patch stubs keep hook metadata separate from the controller', () => {
  const stubs = patchStubs()
  expect(stubs.map(({ id }) => id)).toEqual(Object.values(PATCH_IDS))
  for (const patch of stubs) {
    const key = Object.keys(PATCH_IDS).find(key => PATCH_IDS[key as keyof typeof PATCH_IDS] === patch.id)
    expect(patch.operation).toBe(PATCH_OPERATIONS[key as keyof typeof PATCH_OPERATIONS])
  }
  expect(stubs.find(patch => patch.id === PATCH_IDS.credentialsResolve)?.target.functionQuery.kind).toBe('Async')
  expect(stubs.find(patch => patch.id === PATCH_IDS.credentialsDescribe)?.target.functionQuery.kind).toBe('Async')
  expect(stubs.filter(patch => patch.required)).toHaveLength(4)
  expect(stubs.filter(patch => !patch.required)).toHaveLength(2)
  expect(
    stubs.some(
      patch =>
        patch.target.module === '@deepseek-ai/dsh-credentials-local' &&
        patch.target.functionQuery.methodName === 'parseCredentialsDocument',
    ),
  ).toBe(false)
})

it('web trust fence requires a trusted Host and loopback socket for local mutations', () => {
  const local = { headers: { host: 'localhost:3199' }, socket: { remoteAddress: '127.0.0.1' } }
  expect(isTrustedRequest(local)).toBe(true)
  expect(isLoopbackRequest(local)).toBe(true)
  expect(isLoopbackSocket(local)).toBe(true)
  expect(isTrustedRequest({ headers: { host: 'attacker.example' }, socket: { remoteAddress: '127.0.0.1' } })).toBe(
    false,
  )
  expect(
    isTrustedRequest({ headers: { host: 'app.example' }, socket: { remoteAddress: '10.0.0.4' } }, ['app.example']),
  ).toBe(true)
  expect(isLoopbackSocket({ socket: { remoteAddress: '10.0.0.4' } })).toBe(false)
  expect(() => assertTrustedAuthority('app.example:443')).not.toThrow()
  expect(() => assertTrustedAuthority('https://app.example')).toThrow()
})

it('resolveSpec derives a sidecar without changing the official path', () => {
  const spec = resolveSpec({ path: '/tmp/example/.credentials.yaml', statePath: '/tmp/state.json' })
  expect(spec.filename).toBe('/tmp/example/.credentials.yaml')
  expect(spec.encryptedFilename).toBe('/tmp/example/.credentials.encrypt.yaml')
  expect(spec.stateFile).toBe('/tmp/state.json')
})

it('plain parser and marker are independent of Fabric hooks', () => {
  const entries = parsePlainEntries('# note\nA_KEY: value\n', '/tmp/credentials.yaml')
  expect([...entries]).toEqual([['A_KEY', 'value']])
  const marker = encryptedMarker('/tmp/.credentials.encrypt.yaml')
  expect(isEncryptedMarker(marker)).toBe(true)
  expect([...parsePlainEntries(marker, '/tmp/.credentials.yaml')]).toEqual([])
})

it('the controller encrypts a sidecar while the official file becomes a shadow marker', async () => {
  const f = await fixture()
  try {
    await writeFile(f.path, 'A_KEY: plaintext-secret\n', { mode: 0o600 })
    const controller = new EncryptController(context(), { ...f, watch: false })
    await controller.init()
    expect(controller.format).toBe('plain')
    await controller.setPassword(sha3_256Hex('correct horse'))
    expect(controller.format).toBe('encrypted')
    expect(controller.unlocked).toBe(true)
    expect(isEncryptedMarker(await readFile(f.path, 'utf8'))).toBe(true)
    expect((await readFile(f.encryptedPath, 'utf8')).includes('plaintext-secret')).toBe(false)
    expect(controller.afterResolve('A_KEY', undefined)).toEqual({ value: 'plaintext-secret', source: 'file' })
    await controller.dispose()
  } finally {
    await rm(f.dir, { recursive: true, force: true })
  }
})

it('a fresh controller boots locked and resolves only after unlock', async () => {
  const f = await fixture()
  try {
    await writeFile(f.path, 'A_KEY: plaintext-secret\n', { mode: 0o600 })
    const first = new EncryptController(context(), { ...f, watch: false })
    await first.init()
    await first.setPassword(sha3_256Hex('correct horse'))
    await first.dispose()

    const second = new EncryptController(context(), { ...f, watch: false })
    await second.init()
    expect(second.unlocked).toBe(false)
    expect(() => second.afterResolve('A_KEY', undefined)).toThrowError(
      expect.objectContaining({ code: 'VAULT_LOCKED' }),
    )
    await second.unlock(sha3_256Hex('correct horse'))
    await expect(second.changePassword(sha3_256Hex('wrong horse'), sha3_256Hex('new horse'))).rejects.toMatchObject({
      code: 'PASSWORD_WRONG',
    })
    expect(second.afterResolve('A_KEY', undefined)).toEqual({ value: 'plaintext-secret', source: 'file' })
    await second.invokeSet('B_KEY', 'second-secret', () => {
      throw new Error('official provider must not run in encrypted mode')
    })
    expect(second.afterResolve('B_KEY', undefined)).toEqual({ value: 'second-secret', source: 'file' })
    await second.dispose()
  } finally {
    await rm(f.dir, { recursive: true, force: true })
  }
})

it('corrupt state fails closed instead of resetting lockout', async () => {
  const f = await fixture()
  try {
    await writeFile(f.statePath, '{\n', { mode: 0o600 })
    const controller = new EncryptController(context(), { ...f, watch: false })
    await expect(controller.init()).rejects.toMatchObject({ code: 'STATE_INVALID' })
  } finally {
    await rm(f.dir, { recursive: true, force: true })
  }
})
