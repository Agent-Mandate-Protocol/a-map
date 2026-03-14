import { describe, it, expect } from 'vitest'
import { amap, LocalRegistryClient, InMemoryNonceStore, AmapErrorCode } from '../index.js'

describe('verify() — registry integration', () => {
  it('throws AGENT_REVOKED when issuer is revoked', async () => {
    const pk = amap.keygen()
    const agent = amap.keygen()
    const pkDid = amap.computeDID('pk', '1.0', pk.publicKey)
    const agentDid = amap.computeDID('agent', '1.0', agent.publicKey)

    const token = await amap.issue({
      principal: 'alice@example.com',
      delegate: agentDid,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: pk.privateKey,
      issuerDid: pkDid,
    })

    const registry = new LocalRegistryClient(
      new Map([
        [pkDid, pk.publicKey],
        [agentDid, agent.publicKey],
      ]),
      new Set([pkDid]),
    )

    await expect(
      amap.verify([token], {
        expectedPermission: 'read_email',
        expectedDelegate: agentDid,
        nonceStore: new InMemoryNonceStore(),
        registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_REVOKED })
  })
})
