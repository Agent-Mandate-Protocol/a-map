import { bench, describe } from 'vitest'
import { amap, LocalRegistryClient, InMemoryNonceStore } from '../index.js'

describe('verify() performance', () => {
  bench('<50ms for 10-hop chain', async () => {
    const keys = Array.from({ length: 11 }, () => amap.keygen())
    const dids = keys.map((k, i) => amap.computeDID(`agent-${i}`, '1.0', k.publicKey))
    const registry = new LocalRegistryClient(
      new Map(dids.map((d, i) => [d, keys[i]!.publicKey])),
    )

    const root = await amap.issue({
      principal: 'bench@example.com',
      delegate: dids[1]!,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: keys[0]!.privateKey,
      issuerDid: dids[0]!,
    })

    const chain = [root]
    for (let i = 1; i < 10; i++) {
      chain.push(
        await amap.delegate({
          parentToken: chain[chain.length - 1]!,
          parentChain: [...chain],
          delegate: dids[i + 1]!,
          permissions: ['read'],
          expiresIn: '30m',
          privateKey: keys[i]!.privateKey,
          issuerDid: dids[i]!,
        }),
      )
    }

    await amap.verify(chain, {
      expectedPermission: 'read',
      expectedDelegate: dids[10]!,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })
  }, { time: 500 })
})
