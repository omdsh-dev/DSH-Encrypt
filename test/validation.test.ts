import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import {
  isAsciiDigits,
  isAsciiHex,
  isAsciiLowerHex,
  isCredentialReference,
  normalizeLineEndings,
  trimTrailingCharacter,
} from '../src/shared/validation/primitives.js'

describe('validation primitives', () => {
  it('validates decimal and hexadecimal strings without regular expressions', () => {
    assert.equal(isAsciiDigits('012345'), true)
    assert.equal(isAsciiDigits(''), false)
    assert.equal(isAsciiDigits('12a'), false)
    assert.equal(isAsciiHex('Aa09ff', 6), true)
    assert.equal(isAsciiHex('xz', 2), false)
    assert.equal(isAsciiLowerHex('aa09ff', 6), true)
    assert.equal(isAsciiLowerHex('AA09FF', 6), false)
  })

  it('validates credential references with an explicit character grammar', () => {
    assert.equal(isCredentialReference('DEEPSEEK_API_KEY'), true)
    assert.equal(isCredentialReference('_private2'), true)
    assert.equal(isCredentialReference('9INVALID'), false)
    assert.equal(isCredentialReference('HAS-DASH'), false)
  })

  it('normalizes line endings and strips only the requested trailing character', () => {
    assert.equal(normalizeLineEndings('a\r\nb\rc\n'), 'a\nb\nc\n')
    assert.equal(trimTrailingCharacter('abc===', '='), 'abc')
    assert.equal(trimTrailingCharacter('abc', '='), 'abc')
  })
})
