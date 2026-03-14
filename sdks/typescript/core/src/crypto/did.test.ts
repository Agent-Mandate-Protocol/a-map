import { describe, it, expect } from 'vitest'
import { computeDID } from './did.js'
import { keygen } from './keygen.js'

describe('computeDID', () => {
  it('is deterministic — same key always produces the same DID', () => {
    const { publicKey } = keygen()
    const did1 = computeDID({ type: 'agent', name: 'my-agent', version: '1.0.0', publicKey })
    const did2 = computeDID({ type: 'agent', name: 'my-agent', version: '1.0.0', publicKey })
    expect(did1).toBe(did2)
  })

  it('produces different DIDs for different keys', () => {
    const a = keygen()
    const b = keygen()
    expect(
      computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: a.publicKey }),
    ).not.toBe(
      computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: b.publicKey }),
    )
  })

  it('agent format: did:amap:agent:{name}:{version}:{fingerprint}', () => {
    const { publicKey } = keygen()
    const did = computeDID({ type: 'agent', name: 'my-agent', version: '1.0.0', publicKey })
    expect(did).toMatch(/^did:amap:agent:[a-z0-9-]+:[a-z0-9.-]+:[A-Za-z0-9_-]{8}$/)
  })

  it('human format: did:amap:human:{name}:{fingerprint}', () => {
    const { publicKey } = keygen()
    const did = computeDID({ type: 'human', name: 'alice', publicKey })
    expect(did).toMatch(/^did:amap:human:[a-z0-9-]+:[A-Za-z0-9_-]{8}$/)
  })

  it('sanitizes special characters in name', () => {
    const { publicKey } = keygen()
    const did = computeDID({ type: 'agent', name: 'My Agent!', version: '1.0.0', publicKey })
    expect(did).toMatch(/^did:amap:agent:my-agent-:/)
  })

  it('fingerprint is 8 base64url characters', () => {
    const { publicKey } = keygen()
    const did = computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey })
    const parts = did.split(':')
    const fingerprint = parts[parts.length - 1]!
    expect(fingerprint).toHaveLength(8)
    expect(fingerprint).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('fingerprint changes when the key changes', () => {
    const a = keygen()
    const b = keygen()
    const didA = computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: a.publicKey })
    const didB = computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: b.publicKey })
    const fpA = didA.split(':').pop()
    const fpB = didB.split(':').pop()
    expect(fpA).not.toBe(fpB)
  })
})
