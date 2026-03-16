/**
 * Offline Verification Tests (T-LT1)
 *
 * Proves that verify(), signRequest(), and verifyRequest() make zero network
 * calls when used with a LocalKeyResolver.
 *
 * A-MAP core is a protocol-layer library. The only function that touches the
 * network is amap.register() — everything else must work fully airgapped.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { amap, LocalKeyResolver, InMemoryNonceStore } from './index.js'

describe('offline verification — no network calls', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('verify() works with LocalKeyResolver and makes no fetch calls', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(() => {
      throw new Error('Network call detected — verify() must work fully offline')
    })

    const pk    = amap.keygen()
    const agent = amap.keygen()
    const pkDid    = amap.computeDID({ type: 'human', name: 'alice', publicKey: pk.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'assistant', version: '1.0', publicKey: agent.publicKey })

    const keyResolver = new LocalKeyResolver(new Map([
      [pkDid,    pk.publicKey],
      [agentDid, agent.publicKey],
    ]))

    const token = await amap.issue({
      principal: pkDid,
      delegate: agentDid,
      permissions: ['read_data'],
      expiresIn: '1h',
      privateKey: pk.privateKey,
    })

    const result = await amap.verify({
      chain: [token],
      expectedPermission: 'read_data',
      expectedDelegate: agentDid,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('signRequest() makes no fetch calls', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(() => {
      throw new Error('Network call detected — signRequest() must work fully offline')
    })

    const pk    = amap.keygen()
    const agent = amap.keygen()
    const pkDid    = amap.computeDID({ type: 'human', name: 'alice', publicKey: pk.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'assistant', version: '1.0', publicKey: agent.publicKey })

    const token = await amap.issue({
      principal: pkDid,
      delegate: agentDid,
      permissions: ['read_data'],
      expiresIn: '1h',
      privateKey: pk.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'GET',
      path: '/data',
      privateKey: agent.privateKey,
    })

    expect(typeof headers['X-AMAP-Signature']).toBe('string')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('verifyRequest() works with LocalKeyResolver and makes no fetch calls', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(() => {
      throw new Error('Network call detected — verifyRequest() must work fully offline')
    })

    const pk    = amap.keygen()
    const agent = amap.keygen()
    const pkDid    = amap.computeDID({ type: 'human', name: 'alice', publicKey: pk.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'assistant', version: '1.0', publicKey: agent.publicKey })

    const keyResolver = new LocalKeyResolver(new Map([
      [pkDid,    pk.publicKey],
      [agentDid, agent.publicKey],
    ]))

    const token = await amap.issue({
      principal: pkDid,
      delegate: agentDid,
      permissions: ['read_data'],
      expiresIn: '1h',
      privateKey: pk.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'GET',
      path: '/data',
      privateKey: agent.privateKey,
    })

    const result = await amap.verifyRequest({
      headers,
      method: 'GET',
      path: '/data',
      expectedPermission: 'read_data',
      nonceStore: new InMemoryNonceStore(),
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('a full 5-hop chain verifies offline with no fetch calls', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(() => {
      throw new Error('Network call detected')
    })

    const parties = ['pk', 'a', 'b', 'c', 'd', 'e'].map(name => {
      const keys = amap.keygen()
      const did  = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
      return { keys, did }
    })

    const [pk, a, b, c, d, e] = parties as [typeof parties[0], typeof parties[0], typeof parties[0], typeof parties[0], typeof parties[0], typeof parties[0]]

    const keyResolver = new LocalKeyResolver(
      new Map(parties.map(p => [p.did, p.keys.publicKey])),
    )

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_data'], expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })
    const hop2 = await amap.delegate({ parentToken: root, parentChain: [root], delegate: b.did, permissions: ['read_data'], expiresIn: '50m', privateKey: a.keys.privateKey })
    const hop3 = await amap.delegate({ parentToken: hop2, parentChain: [root, hop2], delegate: c.did, permissions: ['read_data'], expiresIn: '40m', privateKey: b.keys.privateKey })
    const hop4 = await amap.delegate({ parentToken: hop3, parentChain: [root, hop2, hop3], delegate: d.did, permissions: ['read_data'], expiresIn: '30m', privateKey: c.keys.privateKey })
    const hop5 = await amap.delegate({ parentToken: hop4, parentChain: [root, hop2, hop3, hop4], delegate: e.did, permissions: ['read_data'], expiresIn: '15m', privateKey: d.keys.privateKey })

    const result = await amap.verify({
      chain: [root, hop2, hop3, hop4, hop5],
      expectedPermission: 'read_data',
      expectedDelegate: e.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.chain).toHaveLength(5)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
