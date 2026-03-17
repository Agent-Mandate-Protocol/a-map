import { describe, it, expect } from 'vitest'
import { amap, LocalKeyResolver, InMemoryNonceStore } from '../index.js'
import { verifyRequest } from './verify-request.js'

describe('api/verify-request.ts', () => {
  const aliceKeys = amap.keygen()
  const agentKeys = amap.keygen()
  const aliceDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: aliceKeys.publicKey })
  const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })
  const keyResolver = new LocalKeyResolver(new Map([
    [aliceDid, aliceKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ]))

  it('throws STALE_REQUEST if timestamp is missing', async () => {
    const mandate = await amap.issue({
      principal: aliceDid,
      delegate: agentDid,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: aliceKeys.privateKey,
    })
    const headers = amap.signRequest({
      mandateChain: [mandate],
      method: 'GET',
      path: '/test',
      privateKey: agentKeys.privateKey,
    })
    delete (headers as any)['X-AMAP-Timestamp']

    await expect(verifyRequest({
      headers,
      method: 'GET',
      path: '/test',
      keyResolver,
    })).rejects.toThrow(expect.objectContaining({ code: 'STALE_REQUEST' }))
  })

  it('throws STALE_REQUEST if timestamp is outside 5 minute window', async () => {
    const mandate = await amap.issue({
      principal: aliceDid,
      delegate: agentDid,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: aliceKeys.privateKey,
    })
    const headers = amap.signRequest({
      mandateChain: [mandate],
      method: 'GET',
      path: '/test',
      privateKey: agentKeys.privateKey,
    })
    // 10 minutes ago
    headers['X-AMAP-Timestamp'] = new Date(Date.now() - 10 * 60 * 1000).toISOString()

    await expect(verifyRequest({
      headers,
      method: 'GET',
      path: '/test',
      keyResolver,
    })).rejects.toThrow(expect.objectContaining({ code: 'STALE_REQUEST' }))
  })

  it('throws BROKEN_CHAIN if mandate header is missing', async () => {
    const headers = {
      'X-AMAP-Timestamp': new Date().toISOString(),
      'X-AMAP-Nonce': '123',
      'X-AMAP-Agent-DID': agentDid,
      'X-AMAP-Signature': 'sig',
    }

    await expect(verifyRequest({
      headers,
      method: 'GET',
      path: '/test',
      keyResolver,
    })).rejects.toThrow(expect.objectContaining({ code: 'BROKEN_CHAIN' }))
  })

  it('throws NONCE_REPLAYED if nonce is replayed', async () => {
    const nonceStore = new InMemoryNonceStore()
    const mandate = await amap.issue({
      principal: aliceDid,
      delegate: agentDid,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: aliceKeys.privateKey,
    })
    const headers = amap.signRequest({
      mandateChain: [mandate],
      method: 'GET',
      path: '/test',
      privateKey: agentKeys.privateKey,
    })

    // First call succeeds
    await verifyRequest({
      headers: { ...headers },
      method: 'GET',
      path: '/test',
      keyResolver,
      nonceStore,
    })

    // Second call with same nonce fails
    await expect(verifyRequest({
      headers: { ...headers },
      method: 'GET',
      path: '/test',
      keyResolver,
      nonceStore,
    })).rejects.toThrow(expect.objectContaining({ code: 'NONCE_REPLAYED' }))
  })

  it('passes a fixed 10-minute TTL to the nonce store regardless of token lifetime', async () => {
    const capturedTtls: number[] = []
    const capturingNonceStore = {
      async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
        capturedTtls.push(ttlMs)
        return true
      },
    }

    // Issue a token with a very long lifetime (24h)
    const mandate = await amap.issue({
      principal: aliceDid,
      delegate: agentDid,
      permissions: ['read'],
      expiresIn: '24h',
      privateKey: aliceKeys.privateKey,
    })
    const headers = amap.signRequest({
      mandateChain: [mandate],
      method: 'GET',
      path: '/test',
      privateKey: agentKeys.privateKey,
    })

    await verifyRequest({
      headers,
      method: 'GET',
      path: '/test',
      keyResolver,
      nonceStore: capturingNonceStore,
    })

    expect(capturedTtls).toHaveLength(1)
    // Must be exactly 2 × 5 minutes = 600_000 ms, not the ~86_400_000 ms token lifetime
    expect(capturedTtls[0]).toBe(10 * 60 * 1000)
  })

  it('throws INVALID_REQUEST_SIGNATURE if method or path mismatch', async () => {
    const mandate = await amap.issue({
      principal: aliceDid,
      delegate: agentDid,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: aliceKeys.privateKey,
    })
    const headers = amap.signRequest({
      mandateChain: [mandate],
      method: 'GET',
      path: '/test',
      privateKey: agentKeys.privateKey,
    })

    await expect(verifyRequest({
      headers,
      method: 'POST', // Mismatch
      path: '/test',
      keyResolver,
    })).rejects.toThrow(expect.objectContaining({ code: 'INVALID_REQUEST_SIGNATURE' }))

    await expect(verifyRequest({
      headers,
      method: 'GET',
      path: '/wrong-path', // Mismatch
      keyResolver,
    })).rejects.toThrow(expect.objectContaining({ code: 'INVALID_REQUEST_SIGNATURE' }))
  })
})
