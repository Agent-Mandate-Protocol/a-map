import { describe, it, expect } from 'vitest'
import { createAgentJson } from './agent-json.js'

describe('createAgentJson()', () => {
  it('always sets amap: "1.0"', () => {
    const manifest = createAgentJson({ did: 'did:amap:test:1.0:abc' })
    expect(manifest.amap).toBe('1.0')
  })

  it('defaults requiresDelegationChain to true', () => {
    const manifest = createAgentJson({ did: 'did:amap:test:1.0:abc' })
    expect(manifest.requiresDelegationChain).toBe(true)
  })

  it('allows requiresDelegationChain to be overridden to false', () => {
    const manifest = createAgentJson({ did: 'did:amap:test:1.0:abc', requiresDelegationChain: false })
    expect(manifest.requiresDelegationChain).toBe(false)
  })

  it('passes through requiredPermissions', () => {
    const manifest = createAgentJson({
      did: 'did:amap:email:1.0:xyz',
      requiredPermissions: ['email:read', 'email:send'],
    })
    expect(manifest.requiredPermissions).toEqual(['email:read', 'email:send'])
  })

  it('passes through constraints', () => {
    const manifest = createAgentJson({
      did: 'did:amap:email:1.0:xyz',
      constraints: { maxCalls: 100, maxSpend: 10 },
    })
    expect(manifest.constraints?.maxCalls).toBe(100)
    expect(manifest.constraints?.maxSpend).toBe(10)
  })

  it('passes through optional metadata fields', () => {
    const manifest = createAgentJson({
      did: 'did:amap:email:1.0:xyz',
      name: 'Acme Email API',
      description: 'Send and receive emails.',
      contact: 'security@acme.com',
      registryUrl: 'https://registry.agentmandateprotocol.dev',
      publicKey: 'MCowBQYDK2VdAyEA...',
      docsUrl: 'https://docs.acme.com/amap',
    })
    expect(manifest.name).toBe('Acme Email API')
    expect(manifest.description).toBe('Send and receive emails.')
    expect(manifest.contact).toBe('security@acme.com')
    expect(manifest.registryUrl).toBe('https://registry.agentmandateprotocol.dev')
    expect(manifest.publicKey).toBe('MCowBQYDK2VdAyEA...')
    expect(manifest.docsUrl).toBe('https://docs.acme.com/amap')
  })

  it('passes through extension fields', () => {
    const manifest = createAgentJson({
      did: 'did:amap:test:1.0:abc',
      'x-custom-field': 'custom-value',
    })
    expect(manifest['x-custom-field']).toBe('custom-value')
  })

  it('returns an object with exactly the right shape for minimal usage', () => {
    const manifest = createAgentJson({ did: 'did:amap:minimal:1.0:abc' })
    expect(manifest).toEqual({
      amap: '1.0',
      requiresDelegationChain: true,
      did: 'did:amap:minimal:1.0:abc',
    })
  })

  it('caller-supplied requiresDelegationChain: true is preserved (not doubled)', () => {
    const manifest = createAgentJson({ did: 'did:amap:test:1.0:abc', requiresDelegationChain: true })
    expect(manifest.requiresDelegationChain).toBe(true)
  })
})
