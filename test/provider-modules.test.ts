import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { OperationQueue } from '../src/application/operation-queue.js'
import {
  parseProviderRuntimeState,
  serializeProviderRuntimeState,
} from '../src/infrastructure/persistence/provider-state.js'

describe('provider operation queue', () => {
  it('serializes tasks and isolates a rejected task from later work', async () => {
    const queue = new OperationQueue()
    const order: number[] = []
    const first = queue.run(async () => {
      await Promise.resolve()
      order.push(1)
      throw new Error('expected failure')
    })
    const second = queue.run(() => {
      order.push(2)
      return 'done'
    })
    await assert.rejects(first, /expected failure/)
    assert.equal(await second, 'done')
    await queue.idle()
    assert.deepEqual(order, [1, 2])
  })
})

describe('provider runtime state validation', () => {
  it('keeps valid fields when a sibling field is invalid', () => {
    const parsed = parseProviderRuntimeState({
      rememberDays: 7,
      encrypted: true,
      unlockFailures: -1,
      unlockLockedUntil: 1234,
    })
    assert.deepEqual(parsed.state, { rememberDays: 7, encrypted: true, unlockLockedUntil: 1234 })
    assert.deepEqual(parsed.invalidFields, ['unlockFailures'])
  })

  it('serializes only meaningful validated values', () => {
    assert.equal(
      serializeProviderRuntimeState({ rememberDays: 0, encrypted: true, unlockFailures: 0, unlockLockedUntil: 0 }),
      '{\n  "rememberDays": 0,\n  "encrypted": true\n}\n',
    )
  })
})
