# @agentmandateprotocol/openclaw

OpenClaw tools for [A-MAP (Agent Mandate Protocol)](https://agentmandateprotocol.dev) — cryptographic authorization for AI agents.

```
npm install @agentmandateprotocol/openclaw
```

---

## What this plugin does

This plugin registers four tools into your OpenClaw instance:

| Tool | Who calls it | What it does |
|---|---|---|
| `amap_keygen` | Human (setup) | Generate a keypair + DID — start here |
| `amap_issue` | Human | Sign a mandate authorizing an agent |
| `amap_verify` | Anyone | Verify a mandate chain locally |
| `amap_register_session` | Agent | Cache a mandate for the current session |

## Quickstart

The full flow from zero to a verified mandate, all inside OpenClaw:

**Step 1 — Generate keys for the human issuer and the agent**

```
Call amap_keygen with name="alice", type="human"
→ { publicKey, privateKey, did: "did:amap:human:alice:..." }

Call amap_keygen with name="my-agent", type="agent", version="1.0"
→ { publicKey, privateKey, did: "did:amap:agent:my-agent:1.0:..." }
```

Save both private keys. The public keys are needed in Step 3.

**Step 2 — Issue a mandate (human signs it)**

```
Call amap_issue with:
  principal: "did:amap:human:alice:..."     ← from Step 1
  agentDid:  "did:amap:agent:my-agent:..."  ← from Step 1
  permissions: ["tool:read_file"]
  expiresIn: "1h"
  issuerPrivateKey: "<alice's privateKey>"  ← from Step 1
→ DelegationToken
```

**Step 3 — Verify the mandate is valid**

```
Call amap_verify with:
  chain: [<token from Step 2>]
  publicKeys: { "did:amap:human:alice:...": "<alice's publicKey>" }
  expectedPermission: "tool:read_file"
→ { valid: true, principal: "did:amap:human:alice:...", permissions: [...], ... }
```

The agent now carries this mandate chain. To call an A-MAP-protected service, use `amap.signRequest()` from `@agentmandateprotocol/core` to attach it to outbound HTTP requests.

**What it does not do:** OpenClaw does not expose a tool interception API, so this plugin cannot enforce mandate verification on other tool calls. Server-side enforcement belongs in your API layer — use [`@agentmandateprotocol/middleware`](../middleware) for Express/Hono, or [`@agentmandateprotocol/mcp`](../mcp) for MCP tool handlers.

---

## Setup

In `openclaw.config.ts`:

```typescript
import amapPlugin from '@agentmandateprotocol/openclaw'
export default { plugins: [amapPlugin] }
```

Or with a key resolver for session mandate validation:

```typescript
import amapPlugin from '@agentmandateprotocol/openclaw'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
]))

export default {
  plugins: [amapPlugin],
  amap: { keyResolver },
}
```

---

## Tool reference

### `amap_issue` — sign a mandate

Humans call this to cryptographically authorize an agent. The signed mandate is returned as a `DelegationToken` — the agent carries this and presents it to A-MAP-protected services.

| Input field | Required | Description |
|---|---|---|
| `principal` | yes | Human DID (e.g. `did:amap:human:alice:abc123`) |
| `agentDid` | yes | DID of the agent being authorized |
| `permissions` | yes | Permission strings (e.g. `['tool:read_file']`) |
| `expiresIn` | yes | `15m`, `1h`, `4h`, `24h` |
| `issuerPrivateKey` | yes | base64url Ed25519 private key — signs locally, never transmitted |
| `preset` | no | `'ReadOnly'`, `'Developer'`, `'CiCd'`, `'GodMode'` |
| `maxSpend` | no | Max monetary spend constraint |
| `maxCalls` | no | Max tool call count constraint |
| `allowedActions` | no | Allowlist of tool names |
| `deniedActions` | no | Blocklist of tool names (wins over allowlist) |
| `parameterLocks` | no | Lock specific parameters to exact values |

Returns a `DelegationToken` the agent passes to `amap_register_session` or carries in outbound requests via `amap.signRequest()`.

### `amap_register_session` — register a mandate for this session

Agents call this once per conversation to cache their mandate. The mandate is cryptographically validated at registration time.

> **Note:** Because OpenClaw does not expose a tool interception hook, registering a session mandate does not automatically enforce verification on other tool calls. The registered mandate is available for the agent to reference, pass to sub-agents, or use with `amap.signRequest()` when calling external A-MAP-protected services.

| Input field | Required | Description |
|---|---|---|
| `chain` | yes | Full `DelegationToken[]` — root to leaf |

| Output field | Description |
|---|---|
| `registered` | `true` on success |
| `sessionId` | The session that was registered |
| `chainLength` | Number of hops |
| `principal` | Human DID at the chain root |

---

## For custom frameworks: `createAmapPlugin()`

If you are building a custom agent framework that exposes a tool interception API, `createAmapPlugin()` returns a duck-typed object with a `beforeToolCall` method you can wire into your own hook system.

```typescript
import { createAmapPlugin } from '@agentmandateprotocol/openclaw'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const plugin = createAmapPlugin({ keyResolver })

// Wire into your framework's before-tool hook:
framework.beforeToolCall(async (toolName, input, ctx) => {
  return plugin.beforeToolCall(toolName, input, { sessionId: ctx.sessionId })
})
```

`createAmapPlugin().beforeToolCall` enforces the full A-MAP flow: session store lookup → per-call `_amap` envelope verification → permission check → nonce replay prevention.

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `keyResolver` | `KeyResolver` | *(none)* | Resolves DIDs to public keys |
| `nonceStore` | `NonceStore` | `InMemoryNonceStore` | Replay prevention — use Redis in multi-instance deployments |
| `revocationChecker` | `RevocationChecker` | *(none)* | Optional revocation check per DID |

### ⚠️ Nonce store warning for multi-instance deployments

The default `InMemoryNonceStore` is **not safe behind a load balancer**. Each instance has its own nonce memory — replayed requests routed to a different instance will pass the nonce check.

Use a shared store in production:

```typescript
class RedisNonceStore implements NonceStore {
  constructor(private redis: Redis) {}
  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    const result = await this.redis.set(`amap:nonce:${nonce}`, '1', 'PX', ttlMs, 'NX')
    return result === 'OK'
  }
}

const plugin = createAmapPlugin({ keyResolver, nonceStore: new RedisNonceStore(redis) })
```

---

## Error codes

| Code | Meaning |
|---|---|
| `BROKEN_CHAIN` | No session registered or `parentTokenHash` mismatch |
| `TOKEN_EXPIRED` | A token in the chain has expired |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | Per-call request signature invalid (`_amap` path only) |
| `PERMISSION_INFLATION` | Mandate does not grant the required permission |
| `NONCE_REPLAYED` | This nonce has already been used (`_amap` path only) |
| `STALE_REQUEST` | Request timestamp outside ±5 minute window (`_amap` path only) |

---

## Related packages

- [`@agentmandateprotocol/core`](../core) — `keygen`, `issue`, `delegate`, `verify`, `signRequest`, `verifyRequest`
- [`@agentmandateprotocol/mcp`](../mcp) — `amapProtect` for MCP tool handlers (server-side enforcement)
- [`@agentmandateprotocol/middleware`](../middleware) — Express/Hono middleware for HTTP APIs
