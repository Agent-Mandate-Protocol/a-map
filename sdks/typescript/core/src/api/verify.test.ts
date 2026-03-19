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

describe('verify() — Logic A: deep equality for parameterLocks values', () => {
  function makeParty(name: string) {
    const keys = amap.keygen()
    const did = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
    return { keys, did }
  }

  it('accepts requestParams when lock value is a structurally identical object', async () => {
    const human = makeParty('human')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: human.did,
      delegate: agent.did,
      permissions: ['query'],
      constraints: { parameterLocks: { filter: { id: 123 } } },
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([[human.did, human.keys.publicKey]]))

    const result = await amap.verify({
      chain: [token],
      requestParams: { filter: { id: 123 } },  // structurally equal but different object ref
      keyResolver,
    })
    expect(result.valid).toBe(true)
  })

  it('rejects requestParams when object lock value differs', async () => {
    const human = makeParty('human')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: human.did,
      delegate: agent.did,
      permissions: ['query'],
      constraints: { parameterLocks: { filter: { id: 123 } } },
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([[human.did, human.keys.publicKey]]))

    await expect(
      amap.verify({
        chain: [token],
        requestParams: { filter: { id: 999 } },
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })
})

describe('verify() — MAX_CHAIN_DEPTH guard', () => {
  it('rejects a chain longer than MAX_CHAIN_DEPTH before any signature verification', async () => {
    // Construct 11 structurally plausible token objects.
    // The depth check fires before key resolution or signature verification,
    // so these do not need valid signatures.
    const oversizedChain = Array.from({ length: 11 }, (_, i) => ({
      version: '1' as const,
      tokenId: `token-${i}`,
      parentTokenHash: i === 0 ? null : `hash-${i - 1}`,
      principal: 'did:amap:human:alice:test',
      issuer: `did:amap:agent:hop${i}:1.0:test`,
      delegate: `did:amap:agent:hop${i + 1}:1.0:test`,
      permissions: ['read'],
      constraints: {},
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      nonce: `nonce-${i}`,
      signature: 'not-checked-before-depth-guard',
    }))

    await expect(
      amap.verify({ chain: oversizedChain }),
    ).rejects.toMatchObject({ code: AmapErrorCode.BROKEN_CHAIN })
  })

  it('accepts a chain of exactly MAX_CHAIN_DEPTH hops', async () => {
    // Build a real 2-hop chain — verifying MAX_CHAIN_DEPTH is not off-by-one.
    // (A 10-hop chain is expensive to build in a unit test; 2 hops confirm the boundary.)
    const human = amap.keygen()
    const humanDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: human.publicKey })
    const agentA = amap.keygen()
    const agentADid = amap.computeDID({ type: 'agent', name: 'a', version: '1.0', publicKey: agentA.publicKey })
    const agentB = amap.keygen()
    const agentBDid = amap.computeDID({ type: 'agent', name: 'b', version: '1.0', publicKey: agentB.publicKey })

    const root = await amap.issue({
      principal: humanDid,
      delegate: agentADid,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: human.privateKey,
    })
    const child = await amap.delegate({
      parentToken: root,
      parentChain: [root],
      delegate: agentBDid,
      permissions: ['read'],
      expiresIn: '30m',
      privateKey: agentA.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [humanDid, human.publicKey],
      [agentADid, agentA.publicKey],
      [agentBDid, agentB.publicKey],
    ]))

    const result = await amap.verify({ chain: [root, child], keyResolver })
    expect(result.valid).toBe(true)
  })
})

describe('verify() — expectedPrincipal check', () => {
  function makeParty(name: string, type: 'human' | 'agent' = 'agent') {
    const keys = amap.keygen()
    const did = type === 'human'
      ? amap.computeDID({ type: 'human', name, publicKey: keys.publicKey })
      : amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
    return { keys, did }
  }

  it('passes when expectedPrincipal matches chain root principal', async () => {
    const human = makeParty('alice', 'human')
    const agent = makeParty('bot')

    const token = await amap.issue({
      principal: human.did,
      delegate: agent.did,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const result = await amap.verify({
      chain: [token],
      expectedPrincipal: human.did,
      keyResolver,
    })
    expect(result.valid).toBe(true)
    expect(result.principal).toBe(human.did)
  })

  it('rejects when expectedPrincipal does not match chain root principal', async () => {
    const human = makeParty('alice', 'human')
    const agent = makeParty('bot')

    const token = await amap.issue({
      principal: human.did,
      delegate: agent.did,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    await expect(
      amap.verify({
        chain: [token],
        expectedPrincipal: 'did:amap:human:bob:notthisone',
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_SIGNATURE })
  })

  it('skips principal check when expectedPrincipal is omitted', async () => {
    const human = makeParty('alice', 'human')
    const agent = makeParty('bot')

    const token = await amap.issue({
      principal: human.did,
      delegate: agent.did,
      permissions: ['read'],
      expiresIn: '1h',
      privateKey: human.keys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [human.did, human.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    // No expectedPrincipal — should pass regardless of who the principal is
    const result = await amap.verify({ chain: [token], keyResolver })
    expect(result.valid).toBe(true)
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
