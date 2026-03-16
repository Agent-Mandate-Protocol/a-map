import { describe, it, expect } from 'vitest'
import { sha256hex, sha256ofObject } from './hash.js'

describe('crypto/hash.ts', () => {
  describe('sha256hex()', () => {
    it('returns the correct SHA-256 hex for a string', () => {
      // echo -n "hello" | shasum -a 256
      const expected = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
      expect(sha256hex('hello')).toBe(expected)
    })

    it('returns the correct SHA-256 hex for a Buffer', () => {
      const input = Buffer.from('hello', 'utf8')
      const expected = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
      expect(sha256hex(input)).toBe(expected)
    })

    it('returns the correct SHA-256 hex for an empty string', () => {
      // echo -n "" | shasum -a 256
      const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      expect(sha256hex('')).toBe(expected)
    })
  })

  describe('sha256ofObject()', () => {
    it('returns the same hash for objects with different key order (JCS)', () => {
      const obj1 = { b: 2, a: 1 }
      const obj2 = { a: 1, b: 2 }
      
      const hash1 = sha256ofObject(obj1)
      const hash2 = sha256ofObject(obj2)
      
      expect(hash1).toBe(hash2)
      // JCS of {a:1,b:2} is '{"a":1,"b":2}'
      // echo -n '{"a":1,"b":2}' | shasum -a 256
      expect(hash1).toBe('43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777')
    })

    it('returns different hashes for different objects', () => {
      const obj1 = { a: 1 }
      const obj2 = { a: 2 }
      expect(sha256ofObject(obj1)).not.toBe(sha256ofObject(obj2))
    })
  })
})
