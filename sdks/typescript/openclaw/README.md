# @agentmandateprotocol/openclaw

OpenClaw integration for [A-MAP (Agent Mandate Protocol)](https://agentmandateprotocol.dev) — cryptographic authorization for AI agents.

```
npm install @agentmandateprotocol/openclaw
```

---

## Two roles, two perspectives

### If you run an OpenClaw instance (tool developer)

You host OpenClaw tools that agents call. You want agents to prove they carry a human-signed mandate before any tool executes.

```
Agent → OpenClaw → beforeToolCall hook → your tool handler
                          ↑
                   enforcement here
```

Install `createAmapPlugin()` once. Every tool call is intercepted and mandate-verified before it reaches your handler. No per-tool changes required.

### If you are an agent using OpenClaw tools

You have a mandate issued by a human. You want your tool calls to carry authorization proof — either registered once per session (simple) or included per-call (agent-to-agent flows).

```
Human → amap.issue() → mandate
Agent → amap_register_session → session registered
Agent → callTool('read_file', args) → verified automatically
```

---

## For tool developers: install the plugin

### Quickstart

```typescript
import { createAmapPlugin } from '@agentmandateprotocol/openclaw'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
  ['did:amap:agent:my-agent:1.0:def456', agentPublicKey],
]))

// Install once — all tools are protected automatically
openclaw.use(createAmapPlugin({ keyResolver }))
```

That's it. After installation:
- Every tool call goes through `beforeToolCall` — mandate is verified, unauthorized calls are rejected before your handler runs.
- The `amap_register_session` tool is automatically registered so agents can set up their session.
- A-MAP's own `amap_register_session` calls are never self-verified (no bootstrapping loop).

### `createAmapPlugin(options?)`

```typescript
function createAmapPlugin(options?: AmapPluginOptions): OpenClawPlugin
```

The returned plugin object is duck-typed — no OpenClaw SDK import required.

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `keyResolver` | `KeyResolver` | *(none)* | Resolves DIDs to public keys for mandate chain verification |
| `nonceStore` | `NonceStore` | `InMemoryNonceStore` | Tracks nonces for replay prevention |
| `revocationChecker` | `RevocationChecker` | *(none)* | Optional revocation check per DID |

**Plugin object shape:**

```typescript
{
  name: string
  version: string
  description: string
  tools: ToolDefinition[]          // [ amap_register_session ]
  handleTool(name, input, ctx): Promise<unknown>
  beforeToolCall(name, input, ctx): Promise<Record<string, unknown>>
}
```

`ctx` is `{ sessionId: string }` — OpenClaw passes this per request.

### ⚠️ Nonce store warning for multi-instance deployments

The default `InMemoryNonceStore` is **not safe behind a load balancer**. Each OpenClaw instance has its own nonce memory — a replayed request routed to a different instance will pass the nonce check.

| Deployment | Recommended store |
|---|---|
| Single instance / development | `InMemoryNonceStore` (default) — fine |
| Multiple instances | Redis-backed store (implement `NonceStore`) |

```typescript
class RedisNonceStore implements NonceStore {
  constructor(private redis: Redis) {}
  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    const result = await this.redis.set(`amap:nonce:${nonce}`, '1', 'PX', ttlMs, 'NX')
    return result === 'OK'
  }
}

openclaw.use(createAmapPlugin({
  keyResolver,
  nonceStore: new RedisNonceStore(redis),
}))
```

---

## For agents: how to use A-MAP with OpenClaw

There are two ways to carry authorization in tool calls.

### Option A — Session registration (recommended for single-agent flows)

Register your mandate once at the start of a conversation. All subsequent tool calls in that session are automatically verified — no per-call overhead.

**Step 1: Issue a mandate (human signs it)**

```typescript
import { amap } from '@agentmandateprotocol/core'

const mandate = await amap.issue({
  principal: 'did:amap:human:alice:abc123',
  delegate: myAgentDid,
  permissions: ['tool:read_file', 'tool:list_dir', 'tool:search'],
  expiresIn: '4h',
  privateKey: humanPrivateKey,
})
```

**Step 2: Register at session start**

```typescript
await openclawClient.callTool('amap_register_session', {
  chain: [mandate],   // full DelegationToken[]
})
// → { registered: true, sessionId: '...', chainLength: 1, principal: 'did:amap:human:...' }
```

**Step 3: Call tools normally — no extra args needed**

```typescript
// The plugin verifies 'tool:read_file' is in the registered mandate
await openclawClient.callTool('read_file', { path: './README.md' })

// The plugin verifies 'tool:search' is in the registered mandate
await openclawClient.callTool('search', { query: 'quarterly results' })

// Rejected — 'tool:delete_file' is not in the mandate
await openclawClient.callTool('delete_file', { path: './important.txt' })
// → throws PERMISSION_INFLATION before your handler ever runs
```

**Permission convention:** the plugin checks for `tool:{toolName}` in the mandate's permissions. Issue mandates with permissions in that form.

**Session expiry:** The mandate's own `expiresAt` limits the session. If the chain expires, re-register with a fresh mandate before continuing.

### Option B — Per-call `_amap` envelope (required for agent-to-agent flows)

When Agent A delegates to Agent B and Agent B calls an OpenClaw tool, there is no shared session. Agent B must include a signed `_amap` envelope with each call.

**Step 1: Agent B receives a delegated mandate from Agent A**

```typescript
// Agent A delegates to Agent B
const delegatedToken = await amap.delegate({
  parentToken: agentAToken,
  parentChain: [rootToken, agentAToken],
  delegate: agentBDid,
  permissions: ['tool:read_file'],   // must be subset of agentAToken.permissions
  expiresIn: '15m',
  privateKey: agentAPrivateKey,
})
```

**Step 2: Agent B signs each tool call and includes `_amap`**

```typescript
import { amap } from '@agentmandateprotocol/core'

const mandateChain = [rootToken, agentAToken, delegatedToken]

const headers = amap.signRequest({
  mandateChain,
  method: 'POST',
  path: '/tool/read_file',
  privateKey: agentBPrivateKey,
})

await openclawClient.callTool('read_file', {
  path: './README.md',
  _amap: {
    headers,
    method: 'POST',
    path: '/tool/read_file',
  },
})
```

The plugin sees `_amap`, calls `amap.verifyRequest()` with a fresh nonce, verifies the full chain and request signature, then strips `_amap` before forwarding clean args to the tool handler.

**Why per-call for agent-to-agent?** Agent B has no session with the tool's OpenClaw instance. The `_amap` envelope carries everything needed for verification in a single call — chain, identity, and a fresh signed nonce that prevents replay.

---

## How the plugin decides which path to use

For every tool call (except `amap_register_session` itself):

```
1. Is _amap present in the args?
   → YES: extract headers, call verifyRequest(), check 'tool:{toolName}' permission, strip _amap
   → NO: look up sessionStore[sessionId]
          → NOT FOUND: throw BROKEN_CHAIN
          → FOUND: check 'tool:{toolName}' in cached mandate permissions
```

The per-call path always takes precedence. This lets agent-to-agent flows work even when a session is registered for a different mandate.

---

## `SessionMandateStore`

The session store is in-memory, keyed by `sessionId`. Its lifetime is tied to the OpenClaw process.

```typescript
import { SessionMandateStore } from '@agentmandateprotocol/openclaw'

const store = new SessionMandateStore()
store.set(sessionId, chain, verificationResult)
store.get(sessionId)    // → { chain, verified } | undefined
store.delete(sessionId)
store.has(sessionId)    // → boolean
```

The chain is verified **once** at registration. Subsequent tool calls check permissions from the cached `VerificationResult` — no repeated signature verification.

---

## `beforeToolCall(input, ctx, opts)` (advanced)

Use this directly if you need to integrate with a custom framework rather than using `createAmapPlugin()`.

```typescript
import { beforeToolCall, SessionMandateStore } from '@agentmandateprotocol/openclaw'

const sessionStore = new SessionMandateStore()

// In your tool framework's before-hook:
const cleanInput = await beforeToolCall(
  rawInput,
  { sessionId, toolName },
  { sessionStore, keyResolver, nonceStore },
)
// cleanInput has _amap stripped — forward to your handler
```

---

## Tool reference

### `amap_issue` — interactive mandate wizard

Humans call this to sign a mandate for an agent. The plugin registers this automatically — no setup required.

```typescript
// Agent prompts the human, then calls:
await openclawClient.callTool('amap_issue', {
  principal: 'did:amap:human:alice:abc123',
  agentDid: myAgentDid,
  permissions: ['tool:read_file', 'tool:search'],
  expiresIn: '4h',
  issuerPrivateKey: humanPrivateKey,   // never transmitted — signed locally
})
// → returns DelegationToken (carry this in amap_register_session)
```

| Input field | Required | Description |
|---|---|---|
| `principal` | yes | Human DID (e.g. `did:amap:human:alice:abc123`) |
| `agentDid` | yes | DID of the agent being authorized |
| `permissions` | yes | Permission strings (use `tool:{toolName}` format) |
| `expiresIn` | yes | `15m`, `1h`, `4h`, `24h` |
| `issuerPrivateKey` | yes | base64url Ed25519 private key — signs locally, never transmitted |
| `preset` | no | `'ReadOnly'`, `'Developer'`, `'CiCd'`, or `'GodMode'` |
| `maxSpend` | no | Max monetary spend |
| `maxCalls` | no | Max tool call count |
| `allowedActions` | no | Allowlist of tool names or glob patterns. Use `'*'` to allow all. |
| `deniedActions` | no | Blocklist of tool names or glob patterns. Always wins over `allowedActions`. |
| `parameterLocks` | no | Lock specific parameters to exact values |

`amap_issue` is exempt from mandate verification — it's the tool that creates mandates.

### `amap_register_session` — session mandate registration

Agents call this after `amap_issue` to register the mandate for the current session.

| Input field | Required | Description |
|---|---|---|
| `chain` | yes | Full `DelegationToken[]` — root to leaf |

| Output field | Description |
|---|---|
| `registered` | `true` on success |
| `sessionId` | The session that was registered |
| `chainLength` | Number of hops in the chain |
| `principal` | DID of the human who issued the root mandate |

---

## Allow/deny policy enforcement

In addition to the permission check (`tool:{toolName}` must be in the mandate), the session path evaluates `allowedActions` and `deniedActions` from the mandate's effective constraints on every tool call.

**`deniedActions` — blocklist**

```typescript
// Mandate: deny delete tools, allow everything else
const token = await handleAmapIssue({
  permissions: ['tool:read_file', 'tool:delete_file'],
  deniedActions: ['delete_file', 'delete_*'],
  ...
})
```

`delete_file` is in permissions but explicitly denied — blocked every call, no exceptions. Pattern matching uses glob syntax (`delete_*` matches `delete_file`, `delete_dir`, etc.).

**`allowedActions` — allowlist**

```typescript
// Mandate: only these tools are allowed, everything else is blocked
const token = await handleAmapIssue({
  permissions: ['tool:read_file', 'tool:list_dir', 'tool:search'],
  allowedActions: ['read_file', 'list_dir'],  // search is blocked even though it's in permissions
  ...
})
```

**Both together**

```typescript
// Developer preset (allows most things) with specific denials
const token = await handleAmapIssue({
  permissions: ['tool:*'],
  preset: 'Developer',             // allowedActions: ['*']
  deniedActions: ['delete_*', 'rm*', 'format_disk'],
  ...
})
```

`deniedActions` always wins over `allowedActions`. Useful with `'*'` allowlists to carve out specific exclusions.

**Evaluation semantics:**

| `allowedActions` | `deniedActions` | Result for a tool call |
|---|---|---|
| not set | not set | Permission check only (`tool:{toolName}`) |
| not set | set | Blocklist: denied tools rejected, rest pass |
| set | not set | Allowlist: only listed tools pass |
| set | set | Allowlist filtered by blocklist (deny always wins) |

Policy is evaluated from the **effective constraints** — the most restrictive merge across the entire delegation chain. A parent that blocks `delete_*` cannot be overridden by a child, even if the child doesn't include that denial.

---

## Error codes

| Code | Meaning |
|---|---|
| `BROKEN_CHAIN` | No `_amap` envelope and no session registered, or `parentTokenHash` mismatch |
| `TOKEN_EXPIRED` | A token in the chain has expired |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | The per-call request signature is invalid (per-call path only) |
| `PERMISSION_INFLATION` | Mandate does not grant `tool:{toolName}` for the called tool |
| `EXPLICIT_DENY` | Tool is explicitly denied by `deniedActions`, or not in `allowedActions` |
| `NONCE_REPLAYED` | This nonce has already been used (per-call path only) |
| `STALE_REQUEST` | Request timestamp outside ±5 minute window (per-call path only) |

---

## Related packages

- [`@agentmandateprotocol/core`](../core) — `keygen`, `issue`, `delegate`, `verify`, `signRequest`, `verifyRequest`
- [`@agentmandateprotocol/mcp`](../mcp) — `AmapGuard` (MCP client guard) and `amapProtect` (MCP server protection)
- [`@agentmandateprotocol/middleware`](../middleware) — Express/Hono middleware for HTTP APIs
