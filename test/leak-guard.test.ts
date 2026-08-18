import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { LeakGuard, REDACTION_MARKER } from '../src/leak-guard.js'
import { LiteralMatcher } from '../src/security/redaction/literal-matcher.js'

describe('literal credential matching', () => {
  it('selects the earliest and longest non-overlapping literal', () => {
    const matcher = new LiteralMatcher(['secret', 'secret-long', 'cret-lo'])
    assert.deepEqual(matcher.find('x secret-long y secret'), [
      { start: 2, end: 13, value: 'secret-long' },
      { start: 16, end: 22, value: 'secret' },
    ])
  })

  it('treats punctuation as ordinary literal characters', () => {
    const matcher = new LiteralMatcher(['a.*+?[]{}'])
    assert.deepEqual(matcher.find('before a.*+?[]{} after'), [{ start: 7, end: 16, value: 'a.*+?[]{}' }])
  })
})

describe('leak guard', () => {
  it('masks repeated and overlapping values while retaining reference metadata', () => {
    const guard = new LeakGuard({ minMaskLength: 4, maxMaskLength: 64 })
    guard.add('secret', 'SHORT')
    guard.add('secret-long', 'LONG')
    guard.add('secret-long', 'ALIAS')
    const result = guard.scan('secret-long / secret')
    assert.equal(result.text, `${REDACTION_MARKER} / ${REDACTION_MARKER}`)
    assert.equal(result.matched, 2)
    assert.deepEqual(result.refs, ['LONG', 'ALIAS', 'SHORT'])
  })

  it('masks split secrets and refreshes values registered after the stream opens', () => {
    const guard = new LeakGuard({ minMaskLength: 4, maxMaskLength: 16 })
    guard.add('密钥-abcdef', 'UNICODE')
    const stream = guard.stream()
    guard.add('later-secret', 'LATER')
    const bytes = Buffer.from('start 密钥-abcdef end', 'utf8')
    const split = bytes.indexOf(Buffer.from('钥')) + 1
    const output = [
      ...stream.push(bytes.subarray(0, split)),
      ...stream.push(bytes.subarray(split)),
      stream.flush(),
    ].join('')
    assert.equal(output, `start ${REDACTION_MARKER} end`)
    assert.equal(stream.matched, 1)
    assert.deepEqual(stream.refs, ['UNICODE'])
    assert.equal(stream.push('later-secret').join('') + stream.flush(), REDACTION_MARKER)
  })

  it('honors length limits and the disabled switch', () => {
    const guard = new LeakGuard({ enabled: false, minMaskLength: 4, maxMaskLength: 8 })
    assert.equal(guard.add('abc'), false)
    assert.equal(guard.add('123456789'), false)
    assert.equal(guard.add('secret'), true)
    assert.equal(guard.mask('secret'), 'secret')
  })
})
