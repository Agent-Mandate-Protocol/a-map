# @agentmandateprotocol/middleware

HTTP middleware for [A-MAP (Agent Mandate Protocol)](https://agentmandateprotocol.dev) — cryptographic authorization for AI agents.

```
npm install @agentmandateprotocol/middleware
```

---

## Two ways to use A-MAP with HTTP

### Option A — Client-side fetch guard (works with any API today)

You are an **agent owner**. Your agent makes HTTP requests to external APIs. You want to enforce limits on what your agent is allowed to call — without any cooperation from those APIs.

```
Agent → AmapFetchGuard → fetch() → API server
              ↑
      enforcement here
      server never knows
```

`AmapFetchGuard` wraps any `fetch`-compatible function. If the mandate doesn't cover the request being made, the call is blocked locally before any network traffic.

### Option B — Server-side middleware (for API and tool developers)

You are building an **HTTP API or tool**. You want agents to prove they have a human-signed mandate before your endpoint runs.

```
Agent → HTTP request → amapVerifier() → your handler
                             ↑
                     enforcement here
```

`amapVerifier()` (Express) and `amapHonoVerifier()` (Hono/Cloudflare Workers) sit in front of your routes. No mandate, no access.

---

## ⚠️ Distributed deployments — nonce store warning

The default `InMemoryNonceStore` is **not safe behind a load balancer**.

Each server instance has its own nonce memory. A replayed request routed to a different instance will pass the nonce check — defeating replay prevention entirely.

**Production with multiple instances: you must provide a shared nonce store.**

| Deployment | Recommended store |
|---|---|
| Single instance / development | `InMemoryNonceStore` (default) — fine |
| Cloudflare Workers | `CloudflareKVNonceStore` (included) |
| Node.js multi-process | Redis-backed store (implement `NonceStore`) |

The middleware logs a console warning when `InMemoryNonceStore` is used outside of test environments.

---

## Option A: Client-side fetch guard

### Quickstart

```typescript
import { AmapFetchGuard } from '@agentmandateprotocol/middleware'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
  ['did:amap:agent:my-agent:1.0:def456', agentPublicKey],
]))

// Wrap the global fetch — agent uses this instead
const guarded = new AmapFetchGuard(fetch, {
  mandate: currentSessionMandate,   // DelegationToken[] from amap.issue()
  keyResolver,
  mode: 'enforce',
  rules: {
    'GET /api/emails':         { requires: ['email:read'] },
    'POST /api/emails/send':   { requires: ['email:send'] },
    'DELETE /api/emails/*':    { requires: ['email:delete'] },
    'POST *':                  { requires: ['api:write'] },
    '*':                       { requires: ['api:allow'] },
  },
})

// Agent uses guarded.fetch instead of fetch — same API
const res = await guarded.fetch('https://api.example.com/api/emails/delete/123', {
  method: 'DELETE',
})
// → throws PERMISSION_INFLATION if mandate lacks 'email:delete'
// → network call never made, API server never receives it
```

### Why this matters

**The API server's cooperation is irrelevant.** Whether the server is a simple REST API, a complex third-party service, or anything in between — the guard intercepts before the network call.

**Prompt injection fails at the guard.** An injected instruction tells the agent to delete files it shouldn't touch. The agent calls `guarded.fetch('/api/critical-data', { method: 'DELETE' })`. The guard checks the mandate. Mandate says `api:read` only. Call rejected locally. No network traffic, no server log entry, no damage.

**Audit mode for observation.** Run in `audit` mode for a week. Every request is logged — allowed or blocked — and the agent runs uninterrupted. Write precise rules based on observed behavior, not guesswork.

### `new AmapFetchGuard(fetchFn, options)`

```typescript
class AmapFetchGuard {
  constructor(
    fetchFn: (url: string | URL, init?: RequestInit) => Promise<Response>,
    options: AmapFetchGuardOptions,
  )
  async fetch(url: string | URL, init?: RequestInit): Promise<Response>
}
```

Pass any `fetch`-compatible function — the global `fetch`, `node-fetch`, an Axios wrapper, etc.

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `mandate` | `DelegationToken[]` | required | The mandate chain the agent is operating under |
| `mode` | `'enforce' \| 'audit' \| 'warn'` | `'enforce'` | Global enforcement mode |
| `rules` | `Record<string, FetchRule>` | `{}` | Per-endpoint rules. `'*'` is the catch-all |
| `keyResolver` | `KeyResolver` | *(none)* | For mandate chain verification |
| `onAudit` | `(entry: FetchAuditEntry) => void` | *(none)* | Called for every request — allowed or blocked |

**`FetchRule`:**

```typescript
interface FetchRule {
  requires: string[]                        // permissions that must be in the mandate
  policy?: 'enforce' | 'audit' | 'warn'    // per-rule override of global mode
}
```

**`FetchAuditEntry`:**

```typescript
interface FetchAuditEntry {
  event: 'FETCH_ALLOWED' | 'FETCH_BLOCKED'
  method: string
  url: string
  path: string
  timestamp: string
  mandateId: string    // tokenId of the root token
  principal: string    // DID of the human who issued the mandate
  reason?: string      // present when FETCH_BLOCKED
}
```

### Rule matching

Rules are matched against the string `"METHOD /path"`. The `'*'` key is the catch-all.

| Rule key | Matches |
|---|---|
| `'GET /api/emails'` | `GET /api/emails` (exact) |
| `'DELETE /api/emails/*'` | `DELETE /api/emails/123`, `DELETE /api/emails/abc` |
| `'POST *'` | Any POST request |
| `'*'` | Any method, any path |

Rule resolution order:
1. First matching pattern in the rules object (non-catch-all)
2. `'*'` catch-all
3. No match: the endpoint string itself (`"METHOD /path"`) is required as a permission

### Enforcement modes

**`enforce` (default):** Blocked requests throw `AmapError` with code `PERMISSION_INFLATION`. No network traffic.

**`audit`:** All requests go through. Blocked ones are logged via `onAudit` without interruption. Use to observe before locking down.

**`warn`:** Same as `audit`.

Per-rule `policy` overrides global `mode`:

```typescript
new AmapFetchGuard(fetch, {
  mandate,
  mode: 'audit',          // globally: observe and pass through
  rules: {
    'DELETE *': {
      requires: ['data:delete'],
      policy: 'enforce',  // DELETE always blocks if unauthorized, even in audit mode
    },
    '*': { requires: ['api:allow'] },
  },
})
```

### Audit logging

```typescript
const guarded = new AmapFetchGuard(fetch, {
  mandate,
  mode: 'audit',
  onAudit: (entry) => {
    if (entry.event === 'FETCH_BLOCKED') {
      console.warn(`[AMAP] Blocked: ${entry.method} ${entry.path} — ${entry.reason}`)
    }
    myLogger.log(entry)
  },
})
```

---

## Option B: Server-side middleware

### Express

```typescript
import express from 'express'
import { amapVerifier } from '@agentmandateprotocol/middleware'
import { LocalKeyResolver } from '@agentmandateprotocol/core'

const app = express()

const keyResolver = new LocalKeyResolver(new Map([
  ['did:amap:human:alice:abc123', alicePublicKey],
  ['did:amap:agent:my-agent:1.0:def456', agentPublicKey],
]))

// Protect a route
app.use('/api/email',
  amapVerifier({ expectedPermission: 'email:read', keyResolver })
)

app.get('/api/email', (req, res) => {
  const { principal, effectiveConstraints } = req.amapVerification!
  res.json({ authorizedBy: principal })
})
```

On success: `req.amapVerification` is set and `next()` is called.
On failure: responds `401` with `{ error: AmapErrorCode, message: string }`.

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `expectedPermission` | `string` | *(none)* | Permission the mandate must include |
| `keyResolver` | `KeyResolver` | *(none)* | DID → public key resolution |
| `revocationChecker` | `RevocationChecker` | *(none)* | Skip to omit revocation checks |
| `nonceStore` | `NonceStore` | `InMemoryNonceStore` | See distributed warning above |
| `requestedAction` | `string` | *(none)* | Evaluate allow/deny policy against this action |
| `getRequestParams` | `(req) => object` | `req.body` (if object) | Extract params for `parameterLocks` checking |

**Body verification:** The middleware passes `req.body` to `verifyRequest` only when it is a `string` or `Buffer` (e.g., using `express.text()` or `express.raw()`). If using `express.json()`, the parsed body is used for `parameterLocks` checking but not for body hash verification. To verify the body hash, use `express.text()` and parse JSON yourself.

**TypeScript — extend the Request type:**

```typescript
// The middleware augments the Express namespace automatically:
// req.amapVerification: VerificationResult | undefined
```

### Hono (Cloudflare Workers)

```typescript
import { Hono } from 'hono'
import { amapHonoVerifier, CloudflareKVNonceStore } from '@agentmandateprotocol/middleware'
import type { AmapHonoVariables } from '@agentmandateprotocol/middleware'

const app = new Hono<{ Variables: AmapHonoVariables }>()

app.use('/api/*', amapHonoVerifier({
  expectedPermission: 'email:read',
  keyResolver,
  nonceStore: new CloudflareKVNonceStore(env.AMAP_NONCES),
}))

app.get('/api/email', (c) => {
  const { principal } = c.get('amapVerification')
  return c.json({ authorizedBy: principal })
})
```

On success: `c.get('amapVerification')` is set and the next handler runs.
On failure: returns `c.json({ error, message }, 401)`.

**Options:** same as Express (no `getRequestParams`).

### `VerificationResult` shape

Both middlewares attach this result:

```typescript
{
  valid: true,
  principal: string,             // DID of the human who issued the root mandate
  effectiveConstraints: { ... }, // most restrictive constraints across the full chain
  chain: VerifiedLink[],         // each hop: { hop, token, issuer, delegate }
  auditId: string,               // UUID for audit logging
  appliedPolicy?: { ... }        // present when requestedAction was passed
}
```

---

## `CloudflareKVNonceStore`

Production nonce store for Cloudflare Workers deployments.

```typescript
import { CloudflareKVNonceStore } from '@agentmandateprotocol/middleware'

// In your Worker handler:
export default {
  async fetch(request: Request, env: Env) {
    // env.AMAP_NONCES is a KV binding declared in wrangler.toml
    const nonceStore = new CloudflareKVNonceStore(env.AMAP_NONCES)
    // pass to amapHonoVerifier or amapFetchGuard
  }
}
```

```toml
# wrangler.toml
[[kv_namespaces]]
binding = "AMAP_NONCES"
id = "your-kv-namespace-id"
```

**Atomicity note:** Cloudflare KV does not support atomic set-if-not-exists. Two simultaneous requests with the same nonce arriving at different Worker instances could theoretically both pass. This window is milliseconds in practice. For strict atomicity, use a Durable Object with a single writer.

### Implementing your own `NonceStore` (Redis example)

```typescript
import type { NonceStore } from '@agentmandateprotocol/core'
import { Redis } from 'ioredis'

class RedisNonceStore implements NonceStore {
  constructor(private redis: Redis) {}

  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    // SET NX with TTL — atomic in Redis
    const result = await this.redis.set(`amap:nonce:${nonce}`, '1', 'PX', ttlMs, 'NX')
    return result === 'OK'
  }
}
```

`checkAndStore` must be atomic. Redis `SET NX` satisfies this. The method returns `true` if the nonce was fresh (first seen), `false` if it was already used.

---

## Error codes

All errors from `amapVerifier` and `amapHonoVerifier` produce a `{ error: code, message }` JSON response with HTTP 401. `AmapFetchGuard` throws `AmapError` with a `.code` property.

| Code | Meaning |
|---|---|
| `BROKEN_CHAIN` | Missing X-AMAP headers, or `parentTokenHash` mismatch |
| `TOKEN_EXPIRED` | A token in the chain has expired |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | The request-level signature is invalid |
| `PERMISSION_INFLATION` | Agent claims an action beyond what the mandate grants |
| `NONCE_REPLAYED` | This nonce has already been used |
| `STALE_REQUEST` | Request timestamp is outside the ±5 minute window |
| `PARAMETER_LOCK_VIOLATION` | A locked parameter value doesn't match |
| `EXPLICIT_DENY` | Action denied by `deniedActions`, or not in `allowedActions` |
| `AGENT_REVOKED` | An agent in the chain has been revoked |
| `AGENT_UNKNOWN` | A DID cannot be resolved to a public key |

---

## Related packages

- [`@agentmandateprotocol/core`](../core) — `keygen`, `issue`, `delegate`, `verify`, `signRequest`, `verifyRequest`
- [`@agentmandateprotocol/mcp`](../mcp) — `AmapGuard` (MCP client guard) and `amapProtect` (MCP server protection)
