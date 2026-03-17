import { describe, it, expect } from 'vitest'
import { canonicalize } from './canonicalize.js'

describe('canonicalize (JCS RFC 8785)', () => {
  it('sorts object keys lexicographically', () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}')
  })

  it('is stable regardless of insertion order', () => {
    const x = canonicalize({ z: 'last', a: 'first', m: 'mid' })
    const y = canonicalize({ m: 'mid', z: 'last', a: 'first' })
    expect(x).toBe(y)
  })

  it('handles nested objects recursively', () => {
    const result = canonicalize({ b: { d: 4, c: 3 }, a: 1 })
    expect(result).toBe('{"a":1,"b":{"c":3,"d":4}}')
  })

  it('handles arrays without reordering elements', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]')
  })

  it('handles null, booleans, numbers', () => {
    expect(canonicalize(null)).toBe('null')
    expect(canonicalize(true)).toBe('true')
    expect(canonicalize(42)).toBe('42')
  })

  it('produces the same bytes for equivalent objects — critical for signature stability', () => {
    const token = { version: '1', permissions: ['read'], issuer: 'did:amap:x:1:abc' }
    const tokenCopy = { issuer: 'did:amap:x:1:abc', version: '1', permissions: ['read'] }
    expect(canonicalize(token)).toBe(canonicalize(tokenCopy))
  })

  it('handles arrays of objects with unsorted keys', () => {
    const result = canonicalize([{ b: 2, a: 1 }, { d: 4, c: 3 }])
    expect(result).toBe('[{"a":1,"b":2},{"c":3,"d":4}]')
  })

  it('handles empty object and empty array', () => {
    expect(canonicalize({})).toBe('{}')
    expect(canonicalize([])).toBe('[]')
  })

  it('handles strings with special characters', () => {
    expect(canonicalize('hello')).toBe('"hello"')
    expect(canonicalize('say "hi"')).toBe('"say \\"hi\\""')
  })

  it('handles deeply nested objects up to the depth limit', () => {
    // Build a 32-level deep object — should succeed
    let nested: unknown = 'leaf'
    for (let i = 0; i < 32; i++) nested = { v: nested }
    expect(() => canonicalize(nested)).not.toThrow()
  })

  it('throws RangeError when nesting exceeds 32 levels', () => {
    // Build a 33-level deep object — should throw
    let nested: unknown = 'leaf'
    for (let i = 0; i < 33; i++) nested = { v: nested }
    expect(() => canonicalize(nested)).toThrow(RangeError)
    expect(() => canonicalize(nested)).toThrow('maximum depth')
  })
})
