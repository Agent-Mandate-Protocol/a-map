import { describe, it, expect } from 'vitest'
import { signCanonical, verifySignature } from './sign.js'
import { keygen } from './keygen.js'
import { canonicalize } from './canonicalize.js'

describe('signCanonical + verifySignature', () => {
  it('produces a valid signature that verifies', () => {
    const { publicKey, privateKey } = keygen()
    const message = canonicalize({ hello: 'world', n: 42 })
    const sig = signCanonical(privateKey, message)
    expect(verifySignature(publicKey, message, sig)).toBe(true)
  })

  it('rejects a tampered message', () => {
    const { publicKey, privateKey } = keygen()
    const message = canonicalize({ hello: 'world' })
    const sig = signCanonical(privateKey, message)
    expect(verifySignature(publicKey, canonicalize({ hello: 'TAMPERED' }), sig)).toBe(false)
  })

  it('rejects a signature from a different key', () => {
    const a = keygen()
    const b = keygen()
    const message = canonicalize({ data: 1 })
    const sig = signCanonical(a.privateKey, message)
    expect(verifySignature(b.publicKey, message, sig)).toBe(false)
  })

  it('returns false for a malformed signature string', () => {
    const { publicKey } = keygen()
    expect(verifySignature(publicKey, '{}', 'not-a-valid-sig')).toBe(false)
  })

  it('signature is base64url-encoded (no padding, no +/=)', () => {
    const { privateKey } = keygen()
    const sig = signCanonical(privateKey, '{}')
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('{ b: 2, a: 1 } and { a: 1, b: 2 } produce the same signature (JCS key-order invariance)', () => {
    const { publicKey, privateKey } = keygen()

    // Sign each object independently — JCS canonicalises both to '{"a":1,"b":2}'
    const sigBA = signCanonical(privateKey, canonicalize({ b: 2, a: 1 }))
    const sigAB = signCanonical(privateKey, canonicalize({ a: 1, b: 2 }))

    // Same canonical bytes → same signature
    expect(sigBA).toBe(sigAB)

    // Either signature verifies against either key order
    expect(verifySignature(publicKey, canonicalize({ b: 2, a: 1 }), sigAB)).toBe(true)
    expect(verifySignature(publicKey, canonicalize({ a: 1, b: 2 }), sigBA)).toBe(true)
  })
})
