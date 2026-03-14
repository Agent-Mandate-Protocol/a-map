import { describe, it, expect } from 'vitest'
import { signRequest } from './sign-request.js'
import { keygen, computeDID } from '../index.js'

describe('signRequest()', () => {
  function makeOpts() {
    const { publicKey, privateKey } = keygen()
    const agentDid = computeDID('agent', '1.0', publicKey)
    return { privateKey, agentDid }
  }

  it('X-AMAP-Timestamp is a valid ISO 8601 string close to now', () => {
    const { privateKey, agentDid } = makeOpts()
    const headers = signRequest({
      method: 'GET',
      path: '/test',
      body: null,
      privateKey,
      agentDid,
      mandateChain: [],
    })
    const ts = new Date(headers['X-AMAP-Timestamp']).getTime()
    expect(Math.abs(Date.now() - ts)).toBeLessThan(1_000)
  })

  it('X-AMAP-Mandate is base64url-encoded JSON of the chain', () => {
    const { privateKey, agentDid } = makeOpts()
    const chain = [{ tokenId: 'test' }] as unknown as never[]
    const headers = signRequest({
      method: 'GET',
      path: '/test',
      body: null,
      privateKey,
      agentDid,
      mandateChain: chain,
    })
    const decoded = JSON.parse(Buffer.from(headers['X-AMAP-Mandate'], 'base64url').toString())
    expect(decoded).toEqual(chain)
  })

  it('different body produces different signature', () => {
    const { privateKey, agentDid } = makeOpts()
    const a = signRequest({
      method: 'POST',
      path: '/test',
      body: { x: 1 },
      privateKey,
      agentDid,
      mandateChain: [],
    })
    const b = signRequest({
      method: 'POST',
      path: '/test',
      body: { x: 2 },
      privateKey,
      agentDid,
      mandateChain: [],
    })
    expect(a['X-AMAP-Signature']).not.toBe(b['X-AMAP-Signature'])
  })
})
