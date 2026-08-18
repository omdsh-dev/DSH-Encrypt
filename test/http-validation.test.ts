import type { HttpRequestLike } from '../src/transport/http/model.js'
import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { readCredentialJsonBody } from '../src/transport/http/request-body.js'
import {
  parseChangePasswordRequest,
  parseConfigRequest,
  parseDigestRequest,
  parseEmptyRequest,
} from '../src/transport/http/request-schemas.js'
import { VaultError } from '../src/vault.js'

const DIGEST = 'a'.repeat(64)

function requestBody(...chunks: string[]): HttpRequestLike {
  return {
    headers: {},
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk
    },
  }
}

describe('hTTP request schemas', () => {
  it('accepts exact supported request shapes', () => {
    assert.deepEqual(parseEmptyRequest({}), {})
    assert.deepEqual(parseDigestRequest({ digest: DIGEST }), { digest: DIGEST })
    assert.deepEqual(parseChangePasswordRequest({ oldDigest: DIGEST, digest: DIGEST }), {
      oldDigest: DIGEST,
      digest: DIGEST,
    })
    assert.deepEqual(parseConfigRequest({}), {})
    assert.deepEqual(parseConfigRequest({ action: 'get' }), { action: 'get' })
    assert.deepEqual(parseConfigRequest({ action: 'set', rememberDays: -1 }), { action: 'set', rememberDays: -1 })
  })

  it('rejects coercion, uppercase digests, unknown fields, and invalid day ranges', () => {
    const invalid = [
      () => parseDigestRequest({ digest: 1 }),
      () => parseDigestRequest({ digest: DIGEST.toUpperCase() }),
      () => parseDigestRequest({ digest: DIGEST, extra: true }),
      () => parseConfigRequest({ action: 'set', rememberDays: 31 }),
    ]
    for (const operation of invalid) {
      assert.throws(operation, error => error instanceof VaultError && error.code === 'BAD_REQUEST')
    }
  })

  it('reads empty and chunked JSON bodies', async () => {
    assert.deepEqual(await readCredentialJsonBody(requestBody()), {})
    assert.deepEqual(await readCredentialJsonBody(requestBody('{"digest":', `"${DIGEST}"}`)), {
      digest: DIGEST,
    })
  })

  it('rejects malformed JSON bodies', async () => {
    await assert.rejects(
      readCredentialJsonBody(requestBody('{')),
      error => error instanceof VaultError && error.code === 'BAD_REQUEST',
    )
  })

  it('rejects bodies larger than 4 KiB', async () => {
    await assert.rejects(
      readCredentialJsonBody(requestBody('x'.repeat(4 * 1024 + 1))),
      error => error instanceof VaultError && error.code === 'PAYLOAD_TOO_LARGE',
    )
  })
})
