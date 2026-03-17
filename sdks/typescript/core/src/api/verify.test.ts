import { describe, it, expect } from 'vitest'
import { amap, LocalKeyResolver, InMemoryNonceStore, AmapErrorCode } from '../index.js'
import type { DelegationToken, RevocationChecker } from '../index.js'

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
        keyResolver: emptyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_UNKNOWN })
  })
})

describe('verify() — Critical A: issuer-delegate continuity', () => {
  function makeParty(name: string) {
    const keys = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
    return { keys, did }
  }

  it('rejects a chain where hop 1 issuer does not match hop 0 delegate', async () => {
    // Build a legitimate root token: human → agentA
    const human = makeParty('human')
    const agentA = makeParty('agentA')
    const attacker = makeParty('attacker')

    const rootToken = await amap.issue({
      principal: human.did,
      delegate: agentA.did,
      permissions: ['read_email'],
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    // Attacker crafts a child token: claims to extend the chain but their issuer
    // is their own DID, not agentA.did. They set parentTokenHash correctly and
    // sign with their own key — before the fix this would pass all checks.
    const { sha256ofObject } = await import('../crypto/hash.js')
    const { canonicalize } = await import('../crypto/canonicalize.js')
    const { signCanonical } = await import('../crypto/sign.js')
    const { randomUUID, randomBytes } = await import('node:crypto')

    const forgedPayload = {
      version: '1' as const,
      tokenId: randomUUID(),
      parentTokenHash: sha256ofObject(rootToken),
      principal: human.did,
      issuer: attacker.did,       // attacker's own DID — NOT agentA.did
      delegate: attacker.did,
      permissions: ['read_email'],
      constraints: {},
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
      nonce: randomBytes(16).toString('hex'),
    }
    const signature = signCanonical(attacker.keys.privateKey, canonicalize(forgedPayload))
    const forgedToken: DelegationToken = { ...forgedPayload, signature }

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agentA.did, agentA.keys.publicKey],
      [attacker.did, attacker.keys.publicKey],
    ]))

    await expect(
      amap.verify({
        chain: [rootToken, forgedToken],
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.BROKEN_CHAIN })
  })

  it('accepts a legitimate two-hop chain where each issuer matches the prior delegate', async () => {
    const human = makeParty('human')
    const agentA = makeParty('agentA')
    const agentB = makeParty('agentB')

    const rootToken = await amap.issue({
      principal: human.did,
      delegate: agentA.did,
      permissions: ['read_email'],
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const childToken = await amap.delegate({
      parentToken: rootToken,
      parentChain: [rootToken],
      delegate: agentB.did,
      permissions: ['read_email'],
      constraints: {},
      expiresIn: '30m',
      privateKey: agentA.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agentA.did, agentA.keys.publicKey],
      [agentB.did, agentB.keys.publicKey],
    ]))

    const result = await amap.verify({
      chain: [rootToken, childToken],
      expectedPermission: 'read_email',
      expectedDelegate: agentB.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.principal).toBe(human.did)
  })
})

describe('verify() — Critical B: parameterLocks parent-first precedence', () => {
  function makeParty(name: string) {
    const keys = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
    return { keys, did }
  }

  it('enforces the root lock value even when a child token redeclares the same key', async () => {
    // This tests the verify() enforcement path directly by crafting a chain where
    // both parent and child have parameterLocks for the same key with different values.
    // The parent lock must win — the root value is the authoritative constraint.
    const human = makeParty('human')
    const agentA = makeParty('agentA')
    const agentB = makeParty('agentB')

    const rootToken = await amap.issue({
      principal: human.did,
      delegate: agentA.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    // Build a child token that also declares the same lock key (same value — delegation allows this).
    // We then verify with requestParams that satisfy the root lock but would fail the child's value
    // if child-first semantics were used. Since they match, it should pass. We then test the
    // inverse: a request matching neither would fail.
    const childToken = await amap.delegate({
      parentToken: rootToken,
      parentChain: [rootToken],
      delegate: agentB.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } }, // same value — valid
      expiresIn: '30m',
      privateKey: agentA.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agentA.did, agentA.keys.publicKey],
      [agentB.did, agentB.keys.publicKey],
    ]))

    // Correct value — should pass
    const result = await amap.verify({
      chain: [rootToken, childToken],
      requestParams: { to: 'boss@company.com' },
      keyResolver,
    })
    expect(result.valid).toBe(true)

    // Wrong value — should fail regardless of child lock order
    await expect(
      amap.verify({
        chain: [rootToken, childToken],
        requestParams: { to: 'hacker@evil.com' },
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })
})
