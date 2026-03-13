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
  LocalRegistryClient,
  AmapError,
  AmapErrorCode,
} from './index.js'

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeParty(name: string) {
  const keys = amap.keygen()
  const did = amap.computeDID(name, '1.0', keys.publicKey)
  return { keys, did }
}

// ─── amap.issue() ──────────────────────────────────────────────────────────

describe('amap.issue()', () => {
  it('returns a root DelegationToken with correct shape', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
    })

    expect(token.version).toBe('1')
    expect(token.parentTokenHash).toBeNull()
    expect(token.principal).toBe('alice@example.com')
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
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['read_email'],
      intentHash: 'abc123deadbeef',
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
    })

    expect(token.intentHash).toBe('abc123deadbeef')
  })

  it('omits intentHash when not provided', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')

    const token = await amap.issue({
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
    })

    expect(token.intentHash).toBeUndefined()
  })

  it('generates a unique tokenId and nonce on each call', async () => {
    const principal = makeParty('principal')
    const agent = makeParty('agent')
    const opts = {
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
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
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['send_email'],
      constraints: { maxCalls: 10, parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
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
      principal: 'alice@example.com',
      delegate: agentA.did,
      permissions: overrides?.permissions ?? ['read_email', 'send_email'],
      constraints: { maxSpend: 500, maxCalls: 100, ...overrides?.constraints },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
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
      issuerDid: agentA.did,
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
      issuerDid: agentA.did,
    })

    expect(child.parentTokenHash).toBe(sha256ofObject(root))
  })

  it('carries the root principal through to child tokens', async () => {
    const { agentA, root } = await makeRoot()
    const agentB = makeParty('agent-b')

    const child = await amap.delegate({
      parentToken: root,
      parentChain: [root],
      delegate: agentB.did,
      permissions: ['read_email'],
      expiresIn: '15m',
      privateKey: agentA.keys.privateKey,
      issuerDid: agentA.did,
    })

    expect(child.principal).toBe('alice@example.com')
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
        issuerDid: agentA.did,
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
        issuerDid: agentA.did,
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
        issuerDid: agentA.did,
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
        issuerDid: agentA.did,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('throws CONSTRAINT_RELAXATION when child tries to unset readOnly', async () => {
    const principal = makeParty('principal')
    const agentA = makeParty('agent-a')
    const root = await amap.issue({
      principal: 'alice@example.com',
      delegate: agentA.did,
      permissions: ['read_email'],
      constraints: { readOnly: true },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
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
        issuerDid: agentA.did,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('throws CONSTRAINT_RELAXATION when child tries to override a parameterLock', async () => {
    const principal = makeParty('principal')
    const agentA = makeParty('agent-a')
    const root = await amap.issue({
      principal: 'alice@example.com',
      delegate: agentA.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '1h',
      privateKey: principal.keys.privateKey,
      issuerDid: principal.did,
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
        issuerDid: agentA.did,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.CONSTRAINT_RELAXATION })
  })

  it('succeeds for a valid 3-hop chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')

    const root = await amap.issue({
      principal: 'alice@example.com',
      delegate: a.did,
      permissions: ['read_email'],
      constraints: { maxSpend: 500, maxCalls: 100 },
      expiresIn: '1h',
      privateKey: pk.keys.privateKey,
      issuerDid: pk.did,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root],
      delegate: b.did, permissions: ['read_email'],
      constraints: { maxSpend: 200, maxCalls: 50 },
      expiresIn: '30m',
      privateKey: a.keys.privateKey, issuerDid: a.did,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2],
      delegate: c.did, permissions: ['read_email'],
      constraints: { maxCalls: 5 },
      expiresIn: '15m',
      privateKey: b.keys.privateKey, issuerDid: b.did,
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
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: 'alice@example.com',
      delegate: agent.did,
      permissions: ['read_email'],
      constraints: { maxSpend: 500 },
      expiresIn: '15m',
      privateKey: pk.keys.privateKey,
      issuerDid: pk.did,
    })
    return { chain: [token], agent, registry }
  }

  it('returns valid: true for a correct 1-hop chain', async () => {
    const { chain, agent, registry } = await make1Hop()

    const result = await amap.verify(chain, {
      expectedPermission: 'read_email',
      expectedDelegate: agent.did,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })

    expect(result.valid).toBe(true)
    expect(result.principal).toBe('alice@example.com')
    expect(result.effectiveConstraints.maxSpend).toBe(500)
    expect(result.auditId).toBeTruthy()
    expect(result.chain).toHaveLength(1)
  })

  it('returns valid: true for a correct 3-hop chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
      [c.did, c.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: 'alice@example.com', delegate: a.did,
      permissions: ['read_email'], constraints: { maxSpend: 500 },
      expiresIn: '1h', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], expiresIn: '30m',
      privateKey: a.keys.privateKey, issuerDid: a.did,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2], delegate: c.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: b.keys.privateKey, issuerDid: b.did,
    })

    const result = await amap.verify([root, hop2, hop3], {
      expectedPermission: 'read_email',
      expectedDelegate: c.did,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })

    expect(result.valid).toBe(true)
    expect(result.chain).toHaveLength(3)
    expect(result.effectiveConstraints.maxSpend).toBe(500)
  })

  it('returns effective constraints as most restrictive across the chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: 'alice@example.com', delegate: a.did,
      permissions: ['read_email'], constraints: { maxSpend: 500, maxCalls: 100 },
      expiresIn: '1h', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })
    const child = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], constraints: { maxSpend: 200, maxCalls: 10 },
      expiresIn: '15m', privateKey: a.keys.privateKey, issuerDid: a.did,
    })

    const result = await amap.verify([root, child], {
      expectedPermission: 'read_email',
      expectedDelegate: b.did,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })

    expect(result.effectiveConstraints.maxSpend).toBe(200)
    expect(result.effectiveConstraints.maxCalls).toBe(10)
  })

  it('throws INVALID_SIGNATURE when a token is tampered', async () => {
    const { chain, agent, registry } = await make1Hop()
    const tampered = { ...chain[0]!, permissions: ['send_email', 'delete_everything'] }

    await expect(
      amap.verify([tampered], {
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_SIGNATURE })
  })

  it('throws BROKEN_CHAIN when parentTokenHash does not match actual parent', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: 'alice@example.com', delegate: a.did,
      permissions: ['read_email'], expiresIn: '1h',
      privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })
    const child = await amap.delegate({
      parentToken: root, parentChain: [root], delegate: b.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: a.keys.privateKey, issuerDid: a.did,
    })

    const tamperedChild = { ...child, parentTokenHash: 'deadbeef'.repeat(8) }

    await expect(
      amap.verify([root, tamperedChild], {
        expectedPermission: 'read_email',
        expectedDelegate: b.did,
        nonceStore: new InMemoryNonceStore(),
        registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.BROKEN_CHAIN })
  })

  it('throws TOKEN_EXPIRED when a token is past its expiresAt', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['read_email'], expiresIn: '1ms',
      privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    await new Promise(r => setTimeout(r, 10))

    await expect(
      amap.verify([token], {
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.TOKEN_EXPIRED })
  })

  it('throws NONCE_REPLAYED when the same chain is verified twice', async () => {
    const { chain, agent, registry } = await make1Hop()
    const nonceStore = new InMemoryNonceStore()
    const opts = {
      expectedPermission: 'read_email',
      expectedDelegate: agent.did,
      nonceStore,
      registry,
    }

    await amap.verify(chain, opts)

    await expect(amap.verify(chain, opts)).rejects.toMatchObject({
      code: AmapErrorCode.NONCE_REPLAYED,
    })
  })

  it('throws PARAMETER_LOCK_VIOLATION when requestParams violate a lock', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    await expect(
      amap.verify([token], {
        expectedPermission: 'send_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        registry,
        requestParams: { to: 'hacker@evil.com' },
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })

  it('passes when requestParams match parameterLocks exactly', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    const result = await amap.verify([token], {
      expectedPermission: 'send_email',
      expectedDelegate: agent.did,
      nonceStore: new InMemoryNonceStore(),
      registry,
      requestParams: { to: 'boss@company.com' },
    })

    expect(result.valid).toBe(true)
  })

  it('throws AGENT_UNKNOWN when a DID cannot be resolved', async () => {
    const { chain, agent } = await make1Hop()
    const emptyRegistry = new LocalRegistryClient(new Map()) // no keys

    await expect(
      amap.verify(chain, {
        expectedPermission: 'read_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        registry: emptyRegistry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.AGENT_UNKNOWN })
  })
})

// ─── amap.signRequest() + amap.verifyRequest() ─────────────────────────────

describe('amap.signRequest() + amap.verifyRequest()', () => {
  async function makeSetup() {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['read_email'], expiresIn: '15m',
      privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })
    return { pk, agent, registry, token }
  }

  it('produces all required X-AMAP-* headers', async () => {
    const { agent, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
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
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    }

    const a = amap.signRequest(opts)
    const b = amap.signRequest(opts)
    expect(a['X-AMAP-Nonce']).not.toBe(b['X-AMAP-Nonce'])
  })

  it('full round-trip: signRequest → verifyRequest succeeds', async () => {
    const { agent, registry, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })

    const result = await amap.verifyRequest({
      headers, method: 'GET', path: '/email/inbox', body: null,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })

    expect(result.valid).toBe(true)
    expect(result.principal).toBe('alice@example.com')
  })

  it('throws STALE_REQUEST when timestamp is outside ±5 minutes', async () => {
    const { agent, registry, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })
    const staleHeaders = {
      ...headers,
      'X-AMAP-Timestamp': new Date(Date.now() - 10 * 60_000).toISOString(),
    }

    await expect(
      amap.verifyRequest({
        headers: staleHeaders, method: 'GET', path: '/email/inbox', body: null,
        nonceStore: new InMemoryNonceStore(), registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.STALE_REQUEST })
  })

  it('throws NONCE_REPLAYED when the same request is submitted twice', async () => {
    const { agent, registry, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })
    const nonceStore = new InMemoryNonceStore()
    const opts = { headers, method: 'GET', path: '/email/inbox', body: null, nonceStore, registry }

    await amap.verifyRequest(opts)
    await expect(amap.verifyRequest(opts)).rejects.toMatchObject({
      code: AmapErrorCode.NONCE_REPLAYED,
    })
  })

  it('throws INVALID_REQUEST_SIGNATURE when body is tampered after signing', async () => {
    const { agent, registry, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'POST', path: '/email/send', body: { subject: 'hello' },
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/email/send',
        body: { subject: 'TAMPERED' },
        nonceStore: new InMemoryNonceStore(), registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_REQUEST_SIGNATURE })
  })

  it('throws INVALID_REQUEST_SIGNATURE when X-AMAP-Signature is forged', async () => {
    const { agent, registry, token } = await makeSetup()

    const headers = amap.signRequest({
      method: 'GET', path: '/email/inbox', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })
    const badHeaders = { ...headers, 'X-AMAP-Signature': 'AAAAAAAAAAAAAAAA' }

    await expect(
      amap.verifyRequest({
        headers: badHeaders, method: 'GET', path: '/email/inbox', body: null,
        nonceStore: new InMemoryNonceStore(), registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.INVALID_REQUEST_SIGNATURE })
  })

  it('enforces parameterLocks through the full verifyRequest path', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))
    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    const headers = amap.signRequest({
      method: 'POST', path: '/send', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/send', body: null,
        requestParams: { to: 'hacker@evil.com' },
        nonceStore: new InMemoryNonceStore(), registry,
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
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['read_email'],
      expiresIn: '15m', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    await expect(
      amap.verify([token], {
        expectedPermission: 'send_email',
        expectedDelegate: agent.did,
        nonceStore: new InMemoryNonceStore(),
        registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })

  it('"cannot": parameterLock means the agent literally cannot send to a different address', async () => {
    const pk = makeParty('pk')
    const agent = makeParty('agent')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [agent.did, agent.keys.publicKey],
    ]))

    const token = await amap.issue({
      principal: 'alice@example.com', delegate: agent.did,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '15m', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    const headers = amap.signRequest({
      method: 'POST', path: '/send', body: null,
      privateKey: agent.keys.privateKey, agentDid: agent.did,
      mandateChain: [token],
    })

    await expect(
      amap.verifyRequest({
        headers, method: 'POST', path: '/send', body: null,
        requestParams: { to: 'hacker@evil.com' },
        nonceStore: new InMemoryNonceStore(), registry,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PARAMETER_LOCK_VIOLATION })
  })

  it('"cannot": maxSpend set by human survives a 3-hop chain unchanged', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')
    const c = makeParty('c')
    const registry = new LocalRegistryClient(new Map([
      [pk.did, pk.keys.publicKey],
      [a.did, a.keys.publicKey],
      [b.did, b.keys.publicKey],
      [c.did, c.keys.publicKey],
    ]))

    const root = await amap.issue({
      principal: 'alice@example.com', delegate: a.did,
      permissions: ['book_flight'], constraints: { maxSpend: 500 },
      expiresIn: '1h', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })
    const hop2 = await amap.delegate({
      parentToken: root, parentChain: [root],
      delegate: b.did, permissions: ['book_flight'],
      expiresIn: '30m', privateKey: a.keys.privateKey, issuerDid: a.did,
    })
    const hop3 = await amap.delegate({
      parentToken: hop2, parentChain: [root, hop2],
      delegate: c.did, permissions: ['book_flight'],
      expiresIn: '15m', privateKey: b.keys.privateKey, issuerDid: b.did,
    })

    const result = await amap.verify([root, hop2, hop3], {
      expectedPermission: 'book_flight',
      expectedDelegate: c.did,
      nonceStore: new InMemoryNonceStore(),
      registry,
    })

    expect(result.valid).toBe(true)
    expect(result.effectiveConstraints.maxSpend).toBe(500)
  })

  it('"cannot": a downstream agent cannot inflate permissions mid-chain', async () => {
    const pk = makeParty('pk')
    const a = makeParty('a')
    const b = makeParty('b')

    const root = await amap.issue({
      principal: 'alice@example.com', delegate: a.did,
      permissions: ['read_email'],
      expiresIn: '1h', privateKey: pk.keys.privateKey, issuerDid: pk.did,
    })

    // Agent A tries to grant Agent B more than it has
    await expect(
      amap.delegate({
        parentToken: root, parentChain: [root],
        delegate: b.did,
        permissions: ['read_email', 'send_email', 'delete_email'],
        expiresIn: '15m', privateKey: a.keys.privateKey, issuerDid: a.did,
      }),
    ).rejects.toMatchObject({ code: AmapErrorCode.PERMISSION_INFLATION })
  })
})
