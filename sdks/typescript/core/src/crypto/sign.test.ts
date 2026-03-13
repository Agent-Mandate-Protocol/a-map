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
})
