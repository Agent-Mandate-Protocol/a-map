# @agentmandateprotocol/mcp

MCP integration for [A-MAP (Agent Mandate Protocol)](https://agentmandateprotocol.dev) — cryptographic authorization for AI agents.

```
npm install @agentmandateprotocol/mcp
```

---

## Two ways to use A-MAP with MCP

### Option A — Client-side guard (works with any MCP server today)

You are an **agent owner**. Your agent uses an MCP client to call tools. You want to enforce limits on what your agent is allowed to call — without any cooperation from the MCP servers it talks to.

```
Agent → AmapGuard → MCP Client → MCP Server
             ↑
     enforcement here
     server never knows
```

`AmapGuard` sits between your agent and the MCP client. If the mandate doesn't cover the tool being called, the call is blocked locally — the MCP server never receives it.

### Option B — Server-side protection (for MCP server authors)

You are building an **MCP server**. You want agents to prove they have a human-signed mandate before your tool runs.

```
Agent → MCP Client → amapProtect() → your handler
                           ↑
                    enforcement here
```

`amapProtect()` wraps your handler. No mandate, no access.

---

## Option A: Client-side guard

### Quickstart

```typescript
import { AmapGuard } from '@agentmandateprotocol/mcp'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

// Your existing MCP client — unchanged
const mcpClient = new MCPClient({ serverUrl: 'https://some-mcp-server.com' })

// Wrap it with the guard
const guarded = new AmapGuard(mcpClient, {
  mandate: currentSessionMandate,   // DelegationToken[] from amap_issue or amap.issue()
  mode: 'enforce',
  rules: {
    'filesystem/readFile':   { requires: ['filesystem:read'] },
    'filesystem/writeFile':  { requires: ['filesystem:write'] },
    'filesystem/deleteFile': { requires: ['filesystem:delete'] },
    'shell/execute':         { requires: ['shell:execute'] },
    '*':                     { requires: ['tools:undeclared:allow'] },
  },
})

// Agent uses guarded instead of mcpClient — exact same API
const result = await guarded.callTool('filesystem/deleteFile', { path: './important-file.txt' })
// → throws PERMISSION_INFLATION if mandate lacks 'filesystem:delete'
// → MCP server never received the call
```

The agent doesn't need to know the guard exists. The API is identical to the underlying MCP client.

### Why this matters

**The MCP server's cooperation is irrelevant.** Whether the server is a simple SQLite wrapper, a complex enterprise API, or a third-party service you have no relationship with — the guard intercepts before the call is made.

**The agent is protected from itself.** Prompt injection tells the agent to delete a file. The agent calls `guarded.callTool('filesystem/deleteFile', ...)`. The guard checks the mandate. The mandate says `filesystem:read` only. The call is rejected locally. The prompt injection fails at the guard, not at the server.

**Audit mode lets you learn before you lock down.** Run with `mode: 'audit'` for a week. Every tool call is logged — allowed or blocked — and the agent is never interrupted. Then write precise rules based on what you observed, not what you guessed upfront.

### `new AmapGuard(client, options)`

```typescript
class AmapGuard {
  constructor(client: McpClientLike, options: AmapGuardOptions)
  async callTool(toolName: string, params: Record<string, unknown>): Promise<unknown>
}
```

`McpClientLike` is duck-typed — any object with `callTool(name, params)` works. No SDK dependency required.

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `mandate` | `DelegationToken[]` | required | The mandate chain the agent is operating under |
| `mode` | `'enforce' \| 'audit' \| 'warn'` | `'enforce'` | Global enforcement mode |
| `rules` | `Record<string, ToolRule>` | `{}` | Per-tool permission requirements. `'*'` is the catch-all |
| `keyResolver` | `KeyResolver` | *(none)* | For mandate chain verification |
| `onAudit` | `(entry: AuditEntry) => void` | *(none)* | Called for every tool call — allowed or blocked |

**`ToolRule`:**

```typescript
interface ToolRule {
  requires: string[]                        // permissions the mandate must include
  policy?: 'enforce' | 'audit' | 'warn'    // per-tool override of global mode
}
```

**`AuditEntry`:**

```typescript
interface AuditEntry {
  event: 'TOOL_ALLOWED' | 'TOOL_BLOCKED'
  tool: string
  timestamp: string
  mandateId: string    // tokenId of the root token
  principal: string    // DID of the human who issued the mandate
  reason?: string      // present when TOOL_BLOCKED
}
```

### Enforcement modes

**`enforce` (default):** Blocked calls throw `AmapError` with code `PERMISSION_INFLATION`. The MCP server never receives the call.

**`audit`:** All calls go through regardless of permissions. Blocked calls are logged via `onAudit` but not interrupted. Use this to observe your agent's behavior before locking it down.

**`warn`:** Same as `audit` — calls go through, violations are logged.

Per-tool `policy` overrides the global `mode`:

```typescript
const guarded = new AmapGuard(mcpClient, {
  mandate,
  mode: 'audit',   // globally: log and pass through
  rules: {
    'filesystem/deleteFile': {
      requires: ['filesystem:delete'],
      policy: 'enforce',   // this specific tool always blocks if unauthorized
    },
    '*': { requires: ['tools:allow'] },
  },
})
```

### Audit logging example

```typescript
const auditLog: AuditEntry[] = []

const guarded = new AmapGuard(mcpClient, {
  mandate,
  mode: 'audit',
  onAudit: (entry) => {
    auditLog.push(entry)
    if (entry.event === 'TOOL_BLOCKED') {
      console.warn(`[AMAP] Blocked: ${entry.tool} — ${entry.reason}`)
    }
  },
})
```

Every call produces a structured entry with the tool name, timestamp, mandate ID, and principal. Blocked entries include the missing permissions as the `reason`. You can forward these to any logging sink — console, file, Datadog, etc.

### Rule resolution

Rules are matched in this order:
1. Exact tool name (`'filesystem/deleteFile'`)
2. Catch-all (`'*'`)
3. No match: the tool name itself is used as the required permission

If a tool has no rule and no catch-all, the guard requires that the tool name appear in the mandate's permissions. This is the safest default — unknown tools are implicitly blocked unless explicitly permitted.

### Three scenarios

**Scenario A — MCP server has no A-MAP support (most servers today)**

Write the rules yourself. You know your agent's intended behavior. Rules live in your codebase.

```typescript
rules: {
  'gmail/listMessages':  { requires: ['email:read'] },
  'gmail/sendMessage':   { requires: ['email:send'] },
  'gmail/deleteMessage': { requires: ['email:delete'] },
  '*': { requires: ['gmail:undeclared:allow'] },
}
```

**Scenario B — MCP server publishes an A-MAP manifest**

The server declares what permissions each tool requires in `/.well-known/agent.json`. *(Phase 2 — manifest auto-loading not yet implemented.)*

**Scenario C — Mixed**

Some tools have manifests, some don't. Use rules as fallback for servers without manifests. *(Phase 2.)*

---

## Option B: Server-side protection

### Quickstart

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { amapProtect, handleAmapIssue, amapIssueToolDefinition } from '@agentmandateprotocol/mcp'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const server = new McpServer({ name: 'my-tools', version: '1.0.0' })

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
  ['did:amap:agent:my-agent:1.0:def456', agentPublicKey],
]))

// Expose mandate issuance so humans can authorize agents
server.tool('amap_issue', amapIssueToolDefinition.inputSchema, handleAmapIssue)

// Protect your tool — one import, one wrap
server.tool('send_email', emailSchema,
  amapProtect('send_email', async ({ to, subject, body }, mandate) => {
    console.log(`Authorized by: ${mandate.principal}`)
    return await sendEmail({ to, subject, body })
  }, { keyResolver })
)
```

### How agents call a protected tool

The agent must sign the request with its private key and include a `_amap` envelope:

```typescript
import { amap } from '@agentmandateprotocol/core'

const headers = amap.signRequest({
  mandateChain: [token],
  method: 'POST',
  path: '/mcp/send_email',
  privateKey: agentPrivateKey,
})

await mcpClient.callTool('send_email', {
  to: 'boss@company.com',
  subject: 'Q1 report',
  body: '...',
  _amap: { headers, method: 'POST', path: '/mcp/send_email' },
})
```

### `amapProtect(toolName, handler, options?)`

```typescript
function amapProtect<TInput, TOutput>(
  toolName: string,
  handler: (args: Omit<TInput, '_amap'>, mandate: VerificationResult) => Promise<TOutput>,
  options?: AmapProtectOptions,
): (input: TInput) => Promise<TOutput>
```

**What it does:**
1. Extracts the `_amap` envelope from the tool input
2. Calls `amap.verifyRequest()` — checks signatures, expiry, chain linkage, permissions, nonces
3. Strips `_amap` from args before passing to your handler
4. Passes `VerificationResult` as the second argument

On failure: throws `AmapError`. The MCP framework converts it to a structured error response.

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `requiredPermission` | `string` | `toolName` | Permission the mandate must include |
| `requestedAction` | `string` | *(none)* | If set, evaluates allow/deny policy against this action |
| `keyResolver` | `KeyResolver` | *(none)* | Resolves DIDs to public keys |
| `nonceStore` | `NonceStore` | new `InMemoryNonceStore` | Tracks nonces for replay prevention |

**`mandate` object** (second arg to your handler):

```typescript
{
  valid: true,
  principal: string,           // DID of the human who issued the root mandate
  effectiveConstraints: { ... },
  chain: VerifiedLink[],
  auditId: string,
  appliedPolicy?: { ... }      // present when requestedAction was passed
}
```

### `handleAmapIssue(input)` / `amapIssueToolDefinition`

Issues a root mandate token. Register this as a tool so humans can authorize agents interactively.

```typescript
server.tool('amap_issue', amapIssueToolDefinition.inputSchema, handleAmapIssue)
```

| Input field | Required | Description |
|---|---|---|
| `principal` | yes | Human DID (e.g. `did:amap:human:alice:abc123`) |
| `agentDid` | yes | DID of the agent being authorized |
| `permissions` | yes | Permission strings |
| `expiresIn` | yes | `15m`, `1h`, `4h`, `24h` |
| `issuerPrivateKey` | yes | base64url Ed25519 private key — signs locally, never transmitted |
| `preset` | no | `'ReadOnly'`, `'Developer'`, `'CiCd'`, or `'GodMode'` |
| `maxSpend` | no | Max monetary spend |
| `maxCalls` | no | Max API calls |
| `parameterLocks` | no | Lock specific parameters to exact values |

### `amapVerifyToolDefinition` / `handleAmapVerify(input, opts?)`

For agents that need to verify a mandate directly. Register as a tool alongside `amap_issue`.

```typescript
server.tool('amap_verify', amapVerifyToolDefinition.inputSchema,
  (input) => handleAmapVerify(input, { keyResolver })
)
```

---

## Constraint presets

Both `handleAmapIssue` and `amap.issue()` accept a `preset` that applies a named base constraint.

| Preset | Allows | Blocks | Use case |
|---|---|---|---|
| `ReadOnly` | `ls`, `cat`, `grep`, `git status/log/diff`, `npm list`, a few others | everything else | Safe inspection agents |
| `Developer` | Everything (`*`) | `rm -rf`, `sudo`, force push, `kubectl delete`, `DROP TABLE`, fork bombs, disk wipes | Trusted coding agents |
| `CiCd` | `npm`, `yarn`, `git`, `docker build/push`, `kubectl apply`, `helm upgrade` | everything else | Pipeline automation |
| `GodMode` | Everything (`*`) | Only `rm -rf /`, `rm -rf ~`, disk format, shutdown | Highly trusted autonomous agents |

Presets can be combined with overrides:

```typescript
{
  preset: 'Developer',
  maxSpend: 100,
  maxCalls: 50,
  parameterLocks: { environment: 'staging' },
}
```

---

## Parameter locks

`parameterLocks` pins specific tool parameters to exact values. The check is a string comparison — no LLM interpretation.

```typescript
// Human issues mandate with parameterLocks
{ parameterLocks: { to: 'boss@company.com' } }

// Agent calls send_email — ACCEPTED
{ to: 'boss@company.com', subject: 'Update', _amap: { ... } }

// Agent calls send_email — REJECTED: PARAMETER_LOCK_VIOLATION
{ to: 'hacker@evil.com', subject: 'Update', _amap: { ... } }
```

Unlocked parameters pass through freely. Only locked ones are checked.

---

## Production deployment

### Replay protection with multiple server instances

The default `InMemoryNonceStore` does not work behind a load balancer — each instance has separate memory and won't see nonces used by other instances. A replayed request will pass on any instance that hasn't seen that nonce.

**If you run more than one instance, you must pass a shared nonce store** to `amapProtect`:

```typescript
class RedisNonceStore {
  constructor(private redis: Redis) {}
  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    const result = await this.redis.set(`amap:nonce:${nonce}`, '1', 'PX', ttlMs, 'NX')
    return result === 'OK'
  }
}

amapProtect('send_email', handler, {
  keyResolver,
  nonceStore: new RedisNonceStore(redis),
})
```

`checkAndStore` must be atomic — a nonce that returns `true` on one instance must return `false` on all others. Redis `SET NX` satisfies this. This applies to `amapProtect` only; `AmapGuard` runs in a single process and is not affected.

### Key resolution

`LocalKeyResolver` works for known-ahead-of-time public keys:

```typescript
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
  ['did:amap:agent:my-agent:1.0:def456', agentPublicKey],
]))
```

For dynamic key resolution, implement `KeyResolver`:

```typescript
import type { KeyResolver } from '@agentmandateprotocol/core'

class DatabaseKeyResolver implements KeyResolver {
  async resolve(did: string): Promise<string | null> {
    const row = await db.query('SELECT public_key FROM agents WHERE did = $1', [did])
    return row?.public_key ?? null
  }
}
```

---

## Error codes

| Code | Meaning |
|---|---|
| `BROKEN_CHAIN` | Missing `_amap` envelope, or `parentTokenHash` mismatch |
| `TOKEN_EXPIRED` | A token in the chain has expired |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | The request-level signature is invalid |
| `PERMISSION_INFLATION` | Agent claims or attempts an action beyond what the mandate grants |
| `NONCE_REPLAYED` | This nonce has already been used |
| `STALE_REQUEST` | Request timestamp is outside the ±5 minute window |
| `MANDATE_HASH_MISMATCH` | The mandate presented doesn't match the signed hash |
| `PARAMETER_LOCK_VIOLATION` | A locked parameter value doesn't match |
| `EXPLICIT_DENY` | Action denied by `deniedActions`, or not in `allowedActions` |
| `AGENT_REVOKED` | An agent in the chain has been revoked |
| `AGENT_UNKNOWN` | A DID cannot be resolved to a public key |

---

## Related packages

- [`@agentmandateprotocol/core`](../core) — `keygen`, `issue`, `delegate`, `verify`, `signRequest`, `verifyRequest`
- [`@agentmandateprotocol/middleware`](../middleware) — Express/Hono middleware for HTTP APIs
