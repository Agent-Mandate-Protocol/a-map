import { describe, it, expect } from 'vitest'
import { LocalRegistryClient } from './registry.js'

describe('LocalRegistryClient', () => {
  it('resolves known DIDs', async () => {
    const registry = new LocalRegistryClient(new Map([['did:amap:a:1:xyz', 'pubkey']]))
    expect(await registry.resolve('did:amap:a:1:xyz')).toBe('pubkey')
  })

  it('returns null for unknown DIDs', async () => {
    const registry = new LocalRegistryClient(new Map())
    expect(await registry.resolve('did:amap:unknown:1:xyz')).toBeNull()
  })

  it('returns false for isRevoked when no revocation set', async () => {
    const registry = new LocalRegistryClient(new Map([['did:amap:a:1:xyz', 'pubkey']]))
    expect(await registry.isRevoked('did:amap:a:1:xyz')).toBe(false)
  })

  it('returns true for isRevoked when DID is in revocation set', async () => {
    const revoked = new Set(['did:amap:a:1:xyz'])
    const registry = new LocalRegistryClient(new Map([['did:amap:a:1:xyz', 'pubkey']]), revoked)
    expect(await registry.isRevoked('did:amap:a:1:xyz')).toBe(true)
  })
})
