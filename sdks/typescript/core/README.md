# @agentmandateprotocol/core

Capability-based authorization for AI agents.

> "Right now, if you give an agent a GitHub token, it can delete your whole repo. The safety is a system prompt saying *please don't*. A-MAP turns that into *cannot* — the tool sees the mandate and physically rejects a DELETE because the signature only covers READ."

## Install

```bash
npm install @agentmandateprotocol/core
```

Requires Node.js 18+. Zero runtime dependencies — all crypto uses Node built-ins.

## Quick start

```typescript
import { amap, LocalRegistryClient, InMemoryNonceStore } from '@agentmandateprotocol/core'

// 1. Generate keypairs
const humanKeys = amap.keygen()
const agentKeys = amap.keygen()
const humanDid = amap.computeDID('alice', '1.0', humanKeys.publicKey)
const agentDid = amap.computeDID('my-agent', '1.0', agentKeys.publicKey)

// 2. Human issues a mandate (read-only, 1 hour, max 50 calls)
const mandate = await amap.issue({
  principal: 'alice@example.com',
  delegate: agentDid,
  permissions: ['read_email'],
  constraints: { maxCalls: 50 },
  expiresIn: '1h',
  privateKey: humanKeys.privateKey,
  issuerDid: humanDid,
})

// 3. Agent signs each outgoing request
const headers = amap.signRequest({
  method: 'GET',
  path: '/email/inbox',
  body: null,
  privateKey: agentKeys.privateKey,
  agentDid,
  mandateChain: [mandate],
})
// → { 'X-AMAP-Agent-DID': '...', 'X-AMAP-Signature': '...', ... }

// 4. Tool verifies the request (fully offline)
const registry = new LocalRegistryClient(new Map([
  [humanDid, humanKeys.publicKey],
  [agentDid, agentKeys.publicKey],
]))

const result = await amap.verifyRequest({
  headers,
  method: 'GET',
  path: '/email/inbox',
  body: null,
  expectedPermission: 'read_email',
  registry,
  nonceStore: new InMemoryNonceStore(),
})

console.log(result.valid)               // true
console.log(result.principal)           // 'alice@example.com'
console.log(result.effectiveConstraints) // { maxCalls: 50 }
```

## What it does

A-MAP (Agent Mandate Protocol) lets humans cryptographically sign exactly what an AI agent is allowed to do — using Ed25519 asymmetric keys. Tools verify the mandate before executing. The constraint is enforced at the cryptographic layer, not the prompt layer.

**Two-layer auth model:**

```
Layer 1 — Mandate Chain:     "I am authorized to perform this action"
Layer 2 — Request Signature: "I am the authorized agent, making this request right now"
```

Without Layer 1: no human authorization. Without Layer 2: stolen mandates can be replayed. Both together prove origin and authorization on every request.

## Multi-hop delegation

Agents can delegate to sub-agents. Constraints can only narrow — never expand:

```typescript
// Human → Agent A (max $500)
const root = await amap.issue({ ..., constraints: { maxSpend: 500 }, ... })

// Agent A → Agent B (max $200 — must be ≤ parent's $500)
const child = await amap.delegate({
  parentToken: root,
  parentChain: [root],
  constraints: { maxSpend: 200 }, // ← narrower, allowed
  ...
})

// Agent B cannot delegate with maxSpend: 400 — throws CONSTRAINT_RELAXATION at construction time
```

The three invariants enforced cryptographically:
1. **Permissions can only narrow** — child cannot grant what parent didn't grant
2. **Constraints are additive** — most restrictive value wins across the chain
3. **Expiry can only shorten** — child TTL ≤ parent TTL

## API reference

| Function | Description |
|----------|-------------|
| `amap.keygen()` | Generate an Ed25519 keypair (base64url) |
| `amap.computeDID(name, version, publicKey)` | Derive a self-certifying DID from a public key |
| `amap.issue(opts)` | Issue a root delegation token (human → first agent) |
| `amap.delegate(opts)` | Create a child token (enforces all 3 invariants before signing) |
| `amap.verify(chain, opts)` | Verify a full delegation chain recursively — fully offline |
| `amap.signRequest(opts)` | Sign an outgoing HTTP request; returns `X-AMAP-*` headers |
| `amap.verifyRequest(opts)` | Verify an incoming signed request (both layers) |
| `amap.revoke(did, privateKey)` | Produce a signed RevocationNotice |

## Error codes

All errors are `AmapError` with a typed `code`:

| Code | When |
|------|------|
| `PERMISSION_INFLATION` | Agent claims permissions not granted by parent |
| `EXPIRY_VIOLATION` | Child expiry exceeds parent TTL |
| `CONSTRAINT_RELAXATION` | Child tries to relax a parent constraint |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | Request-level signature invalid |
| `BROKEN_CHAIN` | `parentTokenHash` doesn't match actual parent |
| `TOKEN_EXPIRED` | One or more tokens expired |
| `NONCE_REPLAYED` | Nonce already seen — replay attack |
| `AGENT_REVOKED` | An agent in the chain has been revoked |
| `AGENT_UNKNOWN` | DID cannot be resolved to a public key |
| `PARAMETER_LOCK_VIOLATION` | Request param doesn't match value locked in mandate |
| `STALE_REQUEST` | Request timestamp outside ±5 minute window |

## Constraints vocabulary

| Key | Type | Merge rule |
|-----|------|-----------|
| `maxSpend` | `number` | min wins |
| `maxCalls` | `number` | min wins |
| `rateLimit` | `{ count, windowSeconds }` | min(count), max(windowSeconds) |
| `readOnly` | `boolean` | once `true`, always `true` |
| `allowedDomains` | `string[]` | intersection |
| `allowedActions` | `string[]` | intersection |
| `parameterLocks` | `Record<string, unknown>` | union (all locks enforced) |

## Production notes

**⚠️ Distributed deployments:** `InMemoryNonceStore` is not safe behind a load balancer — each instance has separate memory, so replays routed to a different instance will pass. Use a shared store (Redis, Cloudflare KV) in multi-instance production. See `@agentmandateprotocol/middleware` for `CloudflareKVNonceStore`.

**Offline verification:** `verify()` and `verifyRequest()` work fully airgapped with `LocalRegistryClient`. No network call required. Only `amap.register()` touches the network.

## Examples

See [`examples/`](../../examples/) in the monorepo for runnable 1-hop and multi-hop demos.
