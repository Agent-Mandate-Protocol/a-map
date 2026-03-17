import { describe, it, expect, vi } from 'vitest'
import { amap } from '../index.js'
import { LocalKeyResolver, HostedRegistryClient } from './registry.js'

describe('LocalKeyResolver', () => {
  it('resolves known DIDs', async () => {
    const resolver = new LocalKeyResolver(new Map([['did:amap:agent:a:1.0:xyz12345', 'pubkey']]))
    expect(await resolver.resolve('did:amap:agent:a:1.0:xyz12345')).toBe('pubkey')
  })

  it('returns null for unknown DIDs', async () => {
    const resolver = new LocalKeyResolver(new Map())
    expect(await resolver.resolve('did:amap:agent:unknown:1.0:xyz12345')).toBeNull()
  })
})

describe('HostedRegistryClient — DID fingerprint verification', () => {
  it('returns the public key when fingerprint matches', async () => {
    const { publicKey } = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name: 'test', version: '1.0', publicKey })

    vi.stubGlobal('fetch', async () => ({
      ok: true,
      json: async () => ({ publicKey }),
    }))

    const client = new HostedRegistryClient('https://registry.example.com')
    const resolved = await client.resolve(did)
    expect(resolved).toBe(publicKey)

    vi.unstubAllGlobals()
  })

  it('returns null when registry returns a key whose fingerprint does not match the DID', async () => {
    const { publicKey: legitimateKey } = amap.keygen()
    const { publicKey: attackerKey } = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name: 'test', version: '1.0', publicKey: legitimateKey })

    // Registry (compromised or MITM'd) returns the attacker's key for the legitimate DID
    vi.stubGlobal('fetch', async () => ({
      ok: true,
      json: async () => ({ publicKey: attackerKey }),
    }))

    const client = new HostedRegistryClient('https://registry.example.com')
    const resolved = await client.resolve(did)
    expect(resolved).toBeNull()

    vi.unstubAllGlobals()
  })

  it('returns null when registry returns a non-ok response', async () => {
    vi.stubGlobal('fetch', async () => ({ ok: false }))

    const client = new HostedRegistryClient('https://registry.example.com')
    expect(await client.resolve('did:amap:agent:test:1.0:xxxxxxxx')).toBeNull()

    vi.unstubAllGlobals()
  })
})
