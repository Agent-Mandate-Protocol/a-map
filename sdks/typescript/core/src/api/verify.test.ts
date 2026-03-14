import { describe, it, expect } from 'vitest'
import { amap, LocalKeyResolver, InMemoryNonceStore, AmapErrorCode } from '../index.js'
import type { RevocationChecker } from '../index.js'

describe('verify() — keyResolver + revocationChecker integration', () => {
  function makeParty(name: string) {
    const keys = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
    return { keys, did }
  }

  it('throws AGENT_REVOKED when issuer is revoked', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: pk.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(
      new Map([
        [pk.did, pk.keys.publicKey],
        [agent.did, agent.keys.publicKey],
      ]),
    )

    const revocationChecker: RevocationChecker = {
      isRevoked: async (did: string) => did === pk.did,
    }

    await expect(
      amap.verify({
        chain: [token],
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        keyResolver,
        revocationChecker,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_REVOKED })
  })

  it('throws AGENT_UNKNOWN when keyResolver returns null', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: pk.keys.privateKey,
    })

    const emptyResolver = new LocalKeyResolver(new Map())

    await expect(
      amap.verify({
        chain: [token],
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        keyResolver: emptyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_UNKNOWN })
  })
})
