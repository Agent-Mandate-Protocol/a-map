# A-MAP — Agent Mandate Protocol

Capability-based authorization for AI agents. Humans cryptographically sign exactly what an agent is allowed to do. Tools verify before executing. The constraint is *cannot*, not *please don't*.

> "Right now, if you give an agent a GitHub token, it can delete your whole repo. The safety is a system prompt saying *please don't*. A-MAP turns that into *cannot* — the tool sees the mandate and physically rejects a DELETE because the signature only covers READ."

---

## The problem

Agents operate with credentials that have no scope enforcement at the tool layer:

- A GitHub token lets an agent push to any branch — the agent's promise not to is a prompt
- A "max $500" constraint lives in a system prompt — there's no cryptographic enforcement
- In multi-agent pipelines, there's no way to prove a human authorized the original action through the whole chain

JWT and OAuth don't solve this. They don't support permission narrowing across delegation hops, constraint inheritance, or chain-of-custody proofs.

## The solution

A-MAP provides two cryptographic layers on every agent request:

```
Layer 1 — Mandate Chain:     "A human authorized me to do this"
Layer 2 — Request Signature: "I am that agent, making this specific request right now"
```

Both are verified before your handler runs. No mandate, no access. Tampered mandate, rejected. Replayed request, rejected.

Three invariants are enforced cryptographically across multi-hop chains:
1. **Permissions can only narrow** — a sub-agent cannot claim what the parent didn't grant
2. **Constraints can only tighten** — most restrictive value wins across all hops
3. **Expiry can only shorten** — sub-agent TTL ≤ parent TTL

---

## Packages

| Package | Description | README |
|---------|-------------|--------|
| `@agentmandateprotocol/core` | Cryptographic primitives: `keygen`, `issue`, `delegate`, `verify`, `signRequest`, `verifyRequest`. Zero runtime dependencies. Works fully offline. | [sdks/typescript/core](sdks/typescript/core/README.md) |
| `@agentmandateprotocol/middleware` | Express and Hono middleware for HTTP APIs. Drop-in mandate enforcement for any endpoint. Also includes `AmapFetchGuard` — client-side enforcement without server cooperation. | [sdks/typescript/middleware](sdks/typescript/middleware/README.md) |
| `@agentmandateprotocol/mcp` | MCP integration: `AmapGuard` (client-side, any MCP server) and `amapProtect()` (server-side, wraps any MCP tool handler). | [sdks/typescript/mcp](sdks/typescript/mcp/README.md) |
| `@agentmandateprotocol/openclaw` | OpenClaw plugin. Installs a `before_tool_call` hook that mandate-verifies every tool call before it reaches your handler. | [sdks/typescript/openclaw](sdks/typescript/openclaw/README.md) |

---

## Quick start

```bash
npm install @agentmandateprotocol/core
```

Requires Node.js 18+. Zero runtime dependencies — all crypto uses Node built-ins.

```typescript
import { amap, LocalKeyResolver, InMemoryNonceStore } from '@agentmandateprotocol/core'

// 1. Generate keypairs
const humanKeys = amap.keygen()
const agentKeys = amap.keygen()
const humanDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: humanKeys.publicKey })
const agentDid = amap.computeDID({ type: 'agent', name: 'my-agent', version: '1.0', publicKey: agentKeys.publicKey })

// 2. Human issues a mandate
const mandate = await amap.issue({
  principal: humanDid,
  delegate: agentDid,
  permissions: ['read_email'],
  constraints: { maxCalls: 50 },
  expiresIn: '1h',
  privateKey: humanKeys.privateKey,
})

// 3. Agent signs each outgoing request
const headers = amap.signRequest({
  mandateChain: [mandate],
  method: 'GET',
  path: '/email/inbox',
  privateKey: agentKeys.privateKey,
})

// 4. Tool verifies — fully offline
const result = await amap.verifyRequest({
  headers,
  method: 'GET',
  path: '/email/inbox',
  expectedPermission: 'read_email',
  keyResolver: new LocalKeyResolver(new Map([
    [humanDid, humanKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ])),
  nonceStore: new InMemoryNonceStore(),
})

console.log(result.principal)            // humanDid
console.log(result.effectiveConstraints) // { maxCalls: 50 }
```

---

## Examples

Runnable demos covering permission blocking, prompt injection defense, developer guardrails, and multi-hop delegation chains:

```bash
# From the monorepo root
cd sdks/typescript && pnpm install && pnpm --filter @agentmandateprotocol/core build
npx tsx examples/1-hop/demo.ts
```

See [`examples/README.md`](examples/README.md) for the full scenario guide.

---

## Repo structure

```
a-map/
  sdks/
    typescript/
      core/         @agentmandateprotocol/core
      middleware/   @agentmandateprotocol/middleware
      mcp/          @agentmandateprotocol/mcp
      openclaw/     @agentmandateprotocol/openclaw
    python/         agent-mandate-protocol (Phase 2)
  apps/
    registry/       Cloudflare Workers hosted registry (Phase 2)
    api/            Cloudflare Workers API (Phase 2)
    dashboard/      Developer dashboard (Phase 3)
  examples/         Runnable demos
  spec/             .well-known/agent.json open standard
  plan/             Design documents and task breakdowns
```

---

## Design principles

- **Private keys never leave the agent.** Signing is local. No server ever sees a private key.
- **Zero network calls for verification.** `verify()` and `verifyRequest()` work fully airgapped with `LocalKeyResolver`.
- **Zero runtime dependencies in core.** All crypto uses Node.js built-ins.
- **Protocol-layer library, not a SaaS product.** Like libsodium or jose — you own the keys and the verification.
