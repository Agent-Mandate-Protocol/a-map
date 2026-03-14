import { describe, it, expect } from 'vitest'
import { signRequest } from './sign-request.js'
import { keygen, computeDID } from '../index.js'
import type { DelegationToken } from '../index.js'

describe('signRequest()', () => {
  function makeChain(): DelegationToken[] {
    const { publicKey } = keygen()
    const did = computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey })
    // Minimal stub — only delegate field is used by signRequest for X-AMAP-Agent-DID
    return [{ delegate: did } as unknown as DelegationToken]
  }

  function makeOpts() {
    const { privateKey } = keygen()
    return { privateKey, mandateChain: makeChain() }
  }

  it('X-AMAP-Timestamp is a valid ISO 8601 string close to now', () => {
    const { privateKey, mandateChain } = makeOpts()
    const headers = signRequest({
      method: 'GET',
      path: '/test',
      privateKey,
      mandateChain,
    })
    const ts = new Date(headers['X-AMAP-Timestamp']).getTime()
    expect(Math.abs(Date.now() - ts)).toBeLessThan(1_000)
  })

  it('X-AMAP-Mandate is base64url-encoded JSON of the chain', () => {
    const { privateKey } = keygen()
    const chain = [{ tokenId: 'test' }] as unknown as DelegationToken[]
    const headers = signRequest({
      method: 'GET',
      path: '/test',
      privateKey,
      mandateChain: chain,
    })
    const decoded = JSON.parse(Buffer.from(headers['X-AMAP-Mandate'], 'base64url').toString())
    expect(decoded).toEqual(chain)
  })

  it('different body produces different signature', () => {
    const { privateKey, mandateChain } = makeOpts()
    const a = signRequest({
      method: 'POST',
      path: '/test',
      body: '{"x":1}',
      privateKey,
      mandateChain,
    })
    const b = signRequest({
      method: 'POST',
      path: '/test',
      body: '{"x":2}',
      privateKey,
      mandateChain,
    })
    expect(a['X-AMAP-Signature']).not.toBe(b['X-AMAP-Signature'])
  })

  it('X-AMAP-Agent-DID is derived from the leaf token delegate', () => {
    const { privateKey } = keygen()
    const { publicKey } = keygen()
    const did = computeDID({ type: 'agent', name: 'myagent', version: '1.0', publicKey })
    const chain = [{ delegate: did } as unknown as DelegationToken]
    const headers = signRequest({ method: 'GET', path: '/test', privateKey, mandateChain: chain })
    expect(headers['X-AMAP-Agent-DID']).toBe(did)
  })
})
