/**
 * A-MAP Public API Contract Tests
 *
 * Status: RED — all tests fail with "Not implemented" until T4–T8 complete.
 * These tests are the specification. Implementation tasks make them green.
 *
 * T4 (issue)       → amap.issue() tests pass
 * T5 (delegate)    → amap.delegate() tests pass
 * T6 (verify)      → amap.verify() tests pass
 * T8 (signRequest) → amap.signRequest() + amap.verifyRequest() tests pass
 */

import { describe, it, expect } from 'vitest'
import {
  amap,
  InMemoryNonceStore,
  LocalKeyResolver,
  AmapError,
  AmapErrorCode,
} from './index.js'

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeParty(name: string) {
  const keys = amap.keygen()
  const did = amap.computeDID({ type: 'agent', name, version: '1.0', publicKey: keys.publicKey })
  return { keys, did }
}

// ─── amap.issue() ──────────────────────────────────────────────────────────

describe('amap.issue()', () => {
  it('returns a root DelegationToken with correct shape', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: principal.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
    })

    expect(token.version).toBe('1')
    expect(token.parentTokenHash).toBeNull()
    expect(token.principal).toBe(principal.did)
    expect(token.issuer).toBe(principal.did)
    expect(token.delegate).toBe(agent.did)
    expect(token.permissions).toEqual(['read_email'])
    expect(token.signature).toBeTruthy()
    expect(token.nonce).toMatch(/^[a-f0-9]{32}$/)
    expect(new Date(token.expiresAt) > new Date()).toBe(true)
    expect(new Date(token.issuedAt) <= new Date()).toBe(true)
  })

  it('stores intentHash when provided', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: principal.did,
      delegate: agent.did,
      permissions: ['read_email'],
      intentHash: 'abc123deadbeef',
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
    })

    expect(token.intentHash).toBe('abc123deadbeef')
  })

  it('omits intentHash when not provided', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: principal.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
    })

    expect(token.intentHash).toBeUndefined()
  })

  it('generates a unique tokenId and nonce on each call', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')
    const opts = {
      principal: principal.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
    }

    const a = await amap.issue(opts)
    const b = await amap.issue(opts)
    expect(a.tokenId).not.toBe(b.tokenId)
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('embeds constraints when provided', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: principal.did,
      delegate: agent.did,
      permissions: ['send_email'],
      constraints: { maxCalls: 10, parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
    })

    expect(token.constraints.maxCalls).toBe(10)
    expect(token.constraints.parameterLocks?.['to']).toBe('boss@company.com')
  })
})

// ─── amap.delegate() ───────────────────────────────────────────────────────

describe('amap.delegate()', () => {
  async function makeRoot(overrides?: { permissions?: string[]; constraints?: Record<string, unknown> }) {
    const principal = makeParty('principal')
    const agentA = makeParty('agent-a')
    const root = await amap.issue({
      principal: principal.did,
      delegate: agentA.did,
      permissions: overrides?.permissions ?? ['read_email', 'send_email'],
      constraints: { maxSpend: 500, maxCalls: 100, ...overrides?.constraints },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
    })
    return { principal, agentA, root }
  }

  it('creates a valid child token linked to its parent', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    const child = await amap.delegate({
      parentToken: root,
      parentChain: [root],
      delegate: agentB.did,
      permissions: ['read_email'],
      constraints: { maxCalls: 10 },
      expiresIn: '15m',
      privateKey: agentA.keys.privateKey,
    })

    expect(child.parentTokenHash).toBeTruthy()
    expect(child.parentTokenHash).not.toBeNull()
    expect(child.permissions).toEqual(['read_email'])
    expect(child.issuer).toBe(agentA.did)
    expect(child.delegate).toBe(agentB.did)
    expect(child.signature).toBeTruthy()
  })

  it('sets parentTokenHash to SHA-256 of canonical parent token', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')
    const { sha256ofObject } = await import('./crypto/hash.js')

    const child = await amap.delegate({
      parentToken: root,
      parentChain: [root],
      delegate: agentB.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: agentA.keys.privateKey,
    })

    expect(child.parentTokenHash).toBe(sha256ofObject(root))
  })

  it('carries the root principal through to child tokens', async () => {
    const { principal, agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    const child = await amap.delegate({
      parentToken: root,
      parentChain: [root],
      delegate: agentB.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: agentA.keys.privateKey,
    })

    expect(child.principal).toBe(principal.did)
  })

  // ── Invariant 1: PERMISSION_INFLATION ─────────────────────────────────

  it('throws PERMISSION_INFLATION when child requests a permission not in parent', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['read_email', 'delete_email'],
        expiresIn: '15m',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })

  it('throws PERMISSION_INFLATION for a single extra permission', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['read_email', 'book_flight'],
        expiresIn: '15m',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })

  // ── Invariant 2: EXPIRY_VIOLATION ─────────────────────────────────────

  it('throws EXPIRY_VIOLATION when child expiry exceeds parent', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['read_email'],
        expiresIn: '25h',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.EXPIRY_VIOLATION })
  })

  // ── Invariant 3: CONSTRAINT_RELAXATION ────────────────────────────────

  it('throws CONSTRAINT_RELAXATION when child tries to increase maxSpend', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['read_email'],
        constraints: { maxSpend: 1000 },
        expiresIn: '15m',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('throws CONSTRAINT_RELAXATION when child tries to unset readOnly', async () => {
    const principal = makeParty('principal')
    const agentA = makeParty('agent-a')
    const root = await amap.issue({
      principal: principal.did,
      delegate: agentA.did,
      permissions: ['read_email'],
      constraints: { readOnly: true },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
    })
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['read_email'],
        constraints: { readOnly: false },
        expiresIn: '15m',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('throws CONSTRAINT_RELAXATION when child tries to override a parameterLock', async () => {
    const principal = makeParty('principal')
    const agentA = makeParty('agent-a')
    const root = await amap.issue({
      principal: principal.did,
      delegate: agentA.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
    })
    const agentB = makeParty('agent-b')

    await expect(
      amap.delegate({
        parentToken: root,
        parentChain: [root],
        delegate: agentB.did,
        permissions: ['send_email'],
        constraints: { parameterLocks: { to: 'hacker@evil.com' } },
        expiresIn: '15m',
        privateKey: agentA.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('succeeds for a valid 3-hop chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')

    const root = await amap.issue({
      principal: pk.did,
      delegate: a.did,
      permissions: ['read_email'],
      constraints: { maxSpend: 500, maxCalls: 100 },
      expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root],
      delegate: b.did, permissions: ['read_email'],
      constraints: { maxSpend: 200, maxCalls: 50 },
      expiresIn: '30m',
      privateKey: a.keys.privateKey,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2],
      delegate: c.did, permissions: ['read_email'],
      constraints: { maxCalls: 5 },
      expiresIn: '15m',
      privateKey: b.keys.privateKey,
    })

    expect(hop3.delegate).toBe(c.did)
    expect(hop3.permissions).toEqual(['read_email'])
  })
})

// ─── amap.verify() ─────────────────────────────────────────────────────────

describe('amap.verify()', () => {
  async function make1Hop() {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['read_email'],
      constraints: { maxSpend: 500 },
      expiresIn: '15m',
      privateKey: pk.keys.privateKey,
    })
    return { chain: [token], agent, keyResolver }
  }

  it('returns valid: true for a correct 1-hop chain', async () => {
    const { chain, agent, keyResolver } = await make1Hop()

    const result = await amap.verify({
      chain,
      expectedPermission: 'read_email',
      expectedDelegate: agent.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.principal).toBe(chain[0]!.principal)
    expect(result.effectiveConstraints.maxSpend).toBe(500)
    expect(result.auditId).toBeTruthy()
    expect(result.chain).toHaveLength(1)
  })

  it('returns valid: true for a correct 3-hop chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
      [c.did, c.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_email'], constraints: { maxSpend: 500 },
      expiresIn: '1h', privateKey: pk.keys.privateKey,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], expiresIn: '30m',
      privateKey: a.keys.privateKey,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2], delegate: c.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: b.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [root, hop2, hop3],
      expectedPermission: 'read_email',
      expectedDelegate: c.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.chain).toHaveLength(3)
    expect(result.effectiveConstraints.maxSpend).toBe(500)
  })

  it('returns valid: true for a 5-hop chain and preserves human-issued constraints', async () => {
    const pk = makeParty('pk')
    const a  = makeParty('a')
    const b  = makeParty('b')
    const c  = makeParty('c')
    const d  = makeParty('d')
    const e  = makeParty('e')

    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did,  a.keys.publicKey],
      [b.did,  b.keys.publicKey],
      [c.did,  c.keys.publicKey],
      [d.did,  d.keys.publicKey],
      [e.did,  e.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_data'], constraints: { maxSpend: 100, maxCalls: 50 },
      expiresIn: '1h', privateKey: pk.keys.privateKey,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root],
      delegate: b.did, permissions: ['read_data'],
      expiresIn: '50m', privateKey: a.keys.privateKey,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2],
      delegate: c.did, permissions: ['read_data'],
      expiresIn: '40m', privateKey: b.keys.privateKey,
    })
    const hop4 = await amap.delegate({
      parentToken: hop3, parentChain: [root, hop2, hop3],
      delegate: d.did, permissions: ['read_data'],
      expiresIn: '30m', privateKey: c.keys.privateKey,
    })
    const hop5 = await amap.delegate({
      parentToken: hop4, parentChain: [root, hop2, hop3, hop4],
      delegate: e.did, permissions: ['read_data'],
      expiresIn: '15m', privateKey: d.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [root, hop2, hop3, hop4, hop5],
      expectedPermission: 'read_data',
      expectedDelegate: e.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.chain).toHaveLength(5)
    // Human's constraints survive all 5 hops unchanged
    expect(result.effectiveConstraints.maxSpend).toBe(100)
    expect(result.effectiveConstraints.maxCalls).toBe(50)
  })

  it('returns effective constraints as most restrictive across the chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_email'], constraints: { maxSpend: 500, maxCalls: 100 },
      expiresIn: '1h', privateKey: pk.keys.privateKey,
    })
    const child = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], constraints: { maxSpend: 200, maxCalls: 10 },
      expiresIn: '15m', privateKey: a.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [root, child],
      expectedPermission: 'read_email',
      expectedDelegate: b.did,
      keyResolver,
    })

    expect(result.effectiveConstraints.maxSpend).toBe(200)
    expect(result.effectiveConstraints.maxCalls).toBe(10)
  })

  it('throws INVALID_SIGNATURE when a token is tampered', async () => {
    const { chain, agent, keyResolver } = await make1Hop()
    const tampered = { ...chain[0]!, permissions: ['send_email', 'delete_everything'] }

    await expect(
      amap.verify({
        chain: [tampered],
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_SIGNATURE })
  })

  it('throws BROKEN_CHAIN when parentTokenHash does not match actual parent', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_email'], expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })
    const child = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: a.keys.privateKey,
    })

    const tamperedChild = { ...child, parentTokenHash: 'deadbeef'.repeat(8) }

    await expect(
      amap.verify({
        chain: [root, tamperedChild],
        expectedPermission: 'read_email',
        expectedDelegate: b.did,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.BROKEN_CHAIN })
  })

  it('throws TOKEN_EXPIRED when a token is past its expiresAt', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['read_email'], expiresIn: '1ms',
      privateKey: pk.keys.privateKey,
    })

    await new Promise(r => setTimeout(r, 10))

    await expect(
      amap.verify({
        chain: [token],
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.TOKEN_EXPIRED })
  })

  it('allows the same chain to be verified multiple times (mandates are reusable)', async () => {
    const { chain, agent, keyResolver } = await make1Hop()
    const opts = {
      chain,
      expectedPermission: 'read_email',
      expectedDelegate: agent.did,
      keyResolver,
    }

    // Verifying the same mandate chain twice must succeed — replay protection
    // is enforced at the request level (X-AMAP-Nonce in verifyRequest), not here.
    const r1 = await amap.verify(opts)
    const r2 = await amap.verify(opts)
    expect(r1.valid).toBe(true)
    expect(r2.valid).toBe(true)
  })

  it('throws PARAMETER_LOCK_VIOLATION when requestParams violate a lock', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey,
    })

    await expect(
      amap.verify({
        chain: [token],
        expectedPermission: 'send_email',
        expectedDelegate: agent.did,
        keyResolver,
        requestParams: { to: 'hacker@evil.com' },
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })

  it('passes when requestParams match parameterLocks exactly', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [token],
      expectedPermission: 'send_email',
      expectedDelegate: agent.did,
      keyResolver,
      requestParams: { to: 'boss@company.com' },
    })

    expect(result.valid).toBe(true)
  })

  it('throws AGENT_UNKNOWN when a DID cannot be resolved', async () => {
    const { chain, agent } = await make1Hop()
    const emptyResolver = new LocalKeyResolver(new Map())

    await expect(
      amap.verify({
        chain,
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        keyResolver: emptyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_UNKNOWN })
  })
})

// ─── amap.signRequest() + amap.verifyRequest() ─────────────────────────────

describe('amap.signRequest() + amap.verifyRequest()', () => {
  async function makeSetup() {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: pk.keys.privateKey,
    })
    return { pk, agent, keyResolver, token }
  }

  it('produces all required X-AMAP-* headers', async () => {
    const { agent, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })

    expect(headers['X-AMAP-Agent-DID']).toBe(agent.did)
    expect(headers['X-AMAP-Timestamp']).toBeTruthy()
    expect(headers['X-AMAP-Nonce']).toMatch(/^[a-f0-9]{32}$/)
    expect(headers['X-AMAP-Signature']).toBeTruthy()
    expect(headers['X-AMAP-Mandate']).toBeTruthy()
  })

  it('generates a unique nonce on each call', async () => {
    const { agent, token } = await makeSetup()
    const opts = {
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    }

    const a = amap.signRequest(opts)
    const b = amap.signRequest(opts)
    expect(a['X-AMAP-Nonce']).not.toBe(b['X-AMAP-Nonce'])
  })

  it('full round-trip: signRequest → verifyRequest succeeds', async () => {
    const { agent, keyResolver, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })

    const result = await amap.verifyRequest({
      headers, method: 'GET', path: '/email/inbox',
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.principal).toBe(token.principal)
  })

  it('throws STALE_REQUEST when timestamp is outside ±5 minutes', async () => {
    const { agent, keyResolver, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })
    const staleHeaders = {
      ...headers,
      'X-AMAP-Timestamp': new Date(Date.now() - 10 * 60_000).toISOString(),
    }

    await expect(
      amap.verifyRequest({
        headers: staleHeaders, method: 'GET', path: '/email/inbox',
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.STALE_REQUEST })
  })

  it('throws NONCE_REPLAYED when the same request is submitted twice', async () => {
    const { agent, keyResolver, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })
    const nonceStore = new InMemoryNonceStore()
    const opts = { headers, method: 'GET', path: '/email/inbox', nonceStore, keyResolver }

    await amap.verifyRequest(opts)
    await expect(amap.verifyRequest(opts)).rejects.toMatchObject({
      code: AmapErrorCode.NONCE_REPLAYED,
    })
  })

  it('throws INVALID_REQUEST_SIGNATURE when body is tampered after signing', async () => {
    const { agent, keyResolver, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'POST', path: '/email/send', body: '{"subject":"hello"}',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/email/send',
        body: '{"subject":"TAMPERED"}',
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_REQUEST_SIGNATURE })
  })

  it('throws INVALID_REQUEST_SIGNATURE when X-AMAP-Signature is forged', async () => {
    const { agent, keyResolver, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })
    const badHeaders = { ...headers, 'X-AMAP-Signature': 'AAAAAAAAAAAAAAAA' }

    await expect(
      amap.verifyRequest({
        headers: badHeaders, method: 'GET', path: '/email/inbox',
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_REQUEST_SIGNATURE })
  })

  it('enforces parameterLocks through the full verifyRequest path', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey,
    })

    const headers = amap.signRequest({
      method: 'POST', path: '/send',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/send',
        requestParams: { to: 'hacker@evil.com' },
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })
})

// ─── Core safety guarantees ────────────────────────────────────────────────
// These prove "cannot" rather than "please don't" — the reason A-MAP exists.

describe('core safety guarantees', () => {
  it('"cannot": agent with read_email mandate cannot pass a send_email permission check', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m', privateKey: pk.keys.privateKey,
    })

    await expect(
      amap.verify({
        chain: [token],
        expectedPermission: 'send_email',
        expectedDelegate: agent.did,
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })

  it('"cannot": parameterLock means the agent literally cannot send to a different address', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did, delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey,
    })

    const headers = amap.signRequest({
      method: 'POST', path: '/send',
      privateKey: agent.keys.privateKey,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/send',
        requestParams: { to: 'hacker@evil.com' },
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })

  it('"cannot": maxSpend set by human survives a 3-hop chain unchanged', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
      [c.did, c.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['book_flight'], constraints: { maxSpend: 500 },
      expiresIn: '1h', privateKey: pk.keys.privateKey,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root],
      delegate: b.did, permissions: ['book_flight'],
      expiresIn: '30m', privateKey: a.keys.privateKey,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2],
      delegate: c.did, permissions: ['book_flight'],
      expiresIn: '15m', privateKey: b.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [root, hop2, hop3],
      expectedPermission: 'book_flight',
      expectedDelegate: c.did,
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.effectiveConstraints.maxSpend).toBe(500)
  })

  it('"cannot": a downstream agent cannot inflate permissions mid-chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')

    const root = await amap.issue({
      principal: pk.did, delegate: a.did,
      permissions: ['read_email'],
      expiresIn: '1h', privateKey: pk.keys.privateKey,
    })

    // Agent A tries to grant Agent B more than it has
    await expect(
      amap.delegate({
        parentToken: root, parentChain: [root],
        delegate: b.did,
        permissions: ['read_email', 'send_email', 'delete_email'],
        expiresIn: '15m', privateKey: a.keys.privateKey,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })
})

// ─── Allow/Deny Policy Engine ──────────────────────────────────────────────

describe('allow/deny policy engine — verify() with requestedAction', () => {
  it('throws EXPLICIT_DENY when requestedAction matches deniedActions (Developer preset)', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['shell.exec'],
      constraints: { ...amap.presets.Developer },
      expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })

    await expect(
      amap.verify({
        chain: [token],
        requestedAction: 'rm -rf /',
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.EXPLICIT_DENY })
  })

  it('returns WILDCARD_ALLOW for permitted action under Developer preset', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['shell.exec'],
      constraints: { ...amap.presets.Developer },
      expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [token],
      requestedAction: 'npm install express',
      keyResolver,
    })

    expect(result.valid).toBe(true)
    expect(result.appliedPolicy?.decision).toBe('WILDCARD_ALLOW')
  })

  it('returns IMPLICIT_DENY result for action not in ReadOnly preset', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['shell.exec'],
      constraints: { ...amap.presets.ReadOnly },
      expiresIn: '1h',
      privateKey: pk.keys.privateKey,
    })

    await expect(
      amap.verify({
        chain: [token],
        requestedAction: 'rm -rf /',
        keyResolver,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.EXPLICIT_DENY })
  })

  it('no appliedPolicy when requestedAction is not provided', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const keyResolver = new LocalKeyResolver(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: pk.did,
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: pk.keys.privateKey,
    })

    const result = await amap.verify({
      chain: [token],
      keyResolver,
    })

    expect(result.appliedPolicy).toBeUndefined()
  })

  it('amap.presets is accessible on the amap namespace', () => {
    expect(amap.presets.Developer).toBeDefined()
    expect(amap.presets.ReadOnly).toBeDefined()
    expect(amap.presets.CiCd).toBeDefined()
    expect(amap.presets.GodMode).toBeDefined()
  })
})
