import { describe, it, expect } from 'vitest'
import { LocalKeyResolver } from './registry.js'

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
