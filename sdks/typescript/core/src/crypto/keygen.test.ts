import { describe, it, expect } from 'vitest'
import { keygen } from './keygen.js'

describe('keygen', () => {
  it('returns publicKey and privateKey strings', () => {
    const kp = keygen()
    expect(typeof kp.publicKey).toBe('string')
    expect(typeof kp.privateKey).toBe('string')
  })

  it('produces base64url-encoded keys (no padding, no +/=)', () => {
    const kp = keygen()
    expect(kp.publicKey).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(kp.privateKey).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('generates a different keypair each time', () => {
    const a = keygen()
    const b = keygen()
    expect(a.publicKey).not.toBe(b.publicKey)
    expect(a.privateKey).not.toBe(b.privateKey)
  })
})
