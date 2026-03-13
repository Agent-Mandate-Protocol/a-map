import { describe, it, expect } from 'vitest'
import { computeDID } from './did.js'
import { keygen } from './keygen.js'

describe('computeDID', () => {
  it('is deterministic — same key always produces the same DID', () => {
    const { publicKey } = keygen()
    const did1 = computeDID('my-agent', '1.0.0', publicKey)
    const did2 = computeDID('my-agent', '1.0.0', publicKey)
    expect(did1).toBe(did2)
  })

  it('produces different DIDs for different keys', () => {
    const a = keygen()
    const b = keygen()
    expect(computeDID('agent', '1.0', a.publicKey)).not.toBe(computeDID('agent', '1.0', b.publicKey))
  })

  it('follows the did:amap:{name}:{version}:{fingerprint} format', () => {
    const { publicKey } = keygen()
    const did = computeDID('my-agent', '1.0.0', publicKey)
    expect(did).toMatch(/^did:amap:[a-z0-9-]+:[a-z0-9.-]+:[a-f0-9]{32}$/)
  })

  it('sanitizes special characters in name and version', () => {
    const { publicKey } = keygen()
    const did = computeDID('My Agent!', '1.0.0', publicKey)
    expect(did).toMatch(/^did:amap:my-agent-:/)
  })

  it('fingerprint changes when the key changes', () => {
    const a = keygen()
    const b = keygen()
    const didA = computeDID('agent', '1.0', a.publicKey)
    const didB = computeDID('agent', '1.0', b.publicKey)
    const fingerprintA = didA.split(':')[4]
    const fingerprintB = didB.split(':')[4]
    expect(fingerprintA).not.toBe(fingerprintB)
  })
})
