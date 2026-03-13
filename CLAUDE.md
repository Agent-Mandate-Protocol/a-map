# A-MAP — CLAUDE.md

This file gives AI coding agents full product context for the A-MAP project. Read this before doing any work.

---

## What This Is

**A-MAP (Agent Mandate Protocol)** is **capability-based authorization for AI agents**.

It is an open-source multi-language library providing cryptographic primitives so that:
- Humans can sign exactly what an agent is allowed to do ("cannot", not "please don't")
- Tools/APIs can verify incoming agent requests are authorized before executing them
- Delegation chains are cryptographically enforced across multi-hop agent workflows

It is a **protocol-layer library** (like libsodium or jose), not a SaaS product. No central server. No key custody. Core verification works fully offline.

### The One-Line Value Proposition

> "Right now, if you give an agent a GitHub token, it can delete your whole repo. The safety is a system prompt saying *please don't*. A-MAP turns that into *cannot* — the tool sees the mandate and physically rejects a DELETE because the signature only covers READ."

---

## The Core Problem

**Single-hop (human → agent → tool):**
- Tools have no way to verify a call was authorized by a real human vs. a rogue agent
- Scope limits ("read email, don't send") live only in a prompt — nothing enforces them
- Long-lived API keys mean a compromised agent has unlimited access, forever
- Humans have no cryptographic record of what they authorized vs. what the agent did

**Multi-hop (human → agent A → agent B → tool):**
- No existing technology can answer "did the human actually authorize this, through the whole chain?"
- Permission inflation: a downstream agent can claim any permission
- Constraint loss: "max $500" set by the human disappears by hop 3

JWT and OAuth fail here: they don't support permission narrowing, constraint inheritance, or chain-of-custody proofs.

---

## Competitive Context

**AgentSign** (launched March 2026) is the closest competitor. Its critical architectural weaknesses:
- Uses **HMAC-SHA256** (symmetric) — requires a shared master key on their central server
- **No delegation chains** — no concept of Agent A delegating to Agent B
- **No permission narrowing** — child agents can claim any permission
- **No offline verification** — requires a network call to their server
- **Single point of failure** — if their server is compromised, all credentials are invalid

A-MAP wins by solving the hard problem AgentSign ignored: **cryptographically provable, multi-hop agent delegation chains** — while also delivering immediate value for the simpler 1-hop case.

---

## The Full Request Model

Every agent API call has two distinct cryptographic layers. Both are required:

```
Layer 1 — Mandate Chain:  "I am authorized to do this"
Layer 2 — Request Signature: "I am the authorized agent, making this request right now"
```

Without Layer 2, a stolen mandate can be replayed by anyone. Without Layer 1, there's no human-issued authorization. Both together prove:
1. This specific agent (keypair) is making this request right now
2. A human authorized this agent for this capability

### Request Headers (standard format)

```
X-AMAP-Agent-DID:   did:amap:my-agent:1.0:abc123
X-AMAP-Timestamp:   2026-03-12T10:00:00Z
X-AMAP-Nonce:       <128-bit random hex>
X-AMAP-Signature:   <Ed25519 sig over canonical(method+path+body+timestamp+nonce)>
X-AMAP-Mandate:     <base64url-encoded JSON array of DelegationToken chain>
```

The middleware verifies: timestamp freshness (±5 min), nonce not replayed, request signature valid, mandate chain valid and covers the requested action.

---

## Core Data Structure: Delegation Token

A Delegation Token is a custom signed structure (NOT a JWT) that embeds a hash reference to its parent, forming a tamper-evident chain:

```typescript
{
  version: '1',
  tokenId: '<uuid>',
  parentTokenHash: '<sha256 of parent token | null for root>',
  principal: '<human or org identifier at chain root>',
  issuer: '<DID of agent issuing this token>',
  delegate: '<DID of agent receiving this delegation>',
  permissions: ['read_email'],         // must be subset of parent
  constraints: {
    maxSpend: 500,                     // numeric: most restrictive wins
    maxCalls: 100,                     // usage budget
    readOnly: true,                    // boolean: true locks in, cannot be unset
    allowedDomains: ['example.com'],   // list: intersection enforced
    allowedActions: ['GET', 'POST'],   // list: intersection enforced
    parameterLocks: {                  // exact param values the tool must match
      to: 'boss@company.com'          // unlocked params pass through freely
    }
  },
  issuedAt: '<ISO8601>',
  expiresAt: '<ISO8601>',              // cannot exceed parent expiry
  nonce: '<128-bit random hex>',       // single-use replay prevention
  signature: '<Ed25519 sig of canonical JSON of all above fields>'
}
```

`intentHash` is optional. When present, the tool verifier hashes the instruction it received and checks it matches. If the agent tries to reuse a mandate for a different intent, the hash mismatch rejects the call.

---

## Constraints Vocabulary

Constraints are typed. The SDK enforces merge semantics at delegation time and re-validates at verification time.

| Constraint key | Type | Merge rule | Example |
|---|---|---|---|
| `maxSpend` | number | most restrictive (min) wins | `500` |
| `maxCalls` | number | most restrictive (min) wins | `10` |
| `rateLimit` | `{ count, windowSeconds }` | most restrictive wins per field | `{ count: 5, windowSeconds: 60 }` |
| `readOnly` | boolean | once `true`, always `true` | `true` |
| `allowedDomains` | string[] | intersection (narrowing only) | `['github.com']` |
| `allowedActions` | string[] | intersection (narrowing only) | `['GET', 'POST']` |
| `parameterLocks` | `Record<string, unknown>` | union of all ancestor locks (all locked keys enforced) | `{ to: 'boss@company.com' }` |

**`parameterLocks` semantics:** Locked params must exactly match the values in the mandate. Unlocked params (not present in `parameterLocks`) pass through freely. If an agent tries to send to `hacker@evil.com` when `to` is locked to `boss@company.com`, the middleware rejects the call with a string comparison — no AI, no NLP, no ambiguity. This is capability-based security at the parameter level.

Unknown constraint keys are preserved and passed through but the SDK cannot enforce merge semantics on them — tool providers handle custom keys themselves.

---

## The Three Invariants (Cryptographically Enforced)

These are enforced at construction time and re-validated at verification time. A malicious agent cannot produce a valid token that violates them.

1. **PERMISSIONS CAN ONLY NARROW** — A child token may only grant permissions that exist in its parent. `[read_email]` cannot delegate `[read_email, send_email]`.

2. **CONSTRAINTS ARE ADDITIVE — MOST RESTRICTIVE WINS** — Constraints merge across the full chain using the rules in the table above. Cannot be relaxed by downstream agents.

3. **EXPIRY CAN ONLY SHORTEN** — A child token's `expiresAt` must be ≤ its parent's. Prefer short TTLs (15 minutes for most use cases). Root: 24h max.

---

## Agent DID Format

```
did:amap:{name}:{version}:{public-key-fingerprint}
```

Self-certifying — derived deterministically from the Ed25519 public key. No central registry needed to verify a DID.

---

## Public API Contract

The namespace in code is always `amap`. Package: `@agentmandateprotocol/core`.

```typescript
import { amap } from '@agentmandateprotocol/core'

// Generate Ed25519 keypair
amap.keygen()
→ { publicKey: string, privateKey: string }  // base64url

// Publish public key to hosted registry (optional)
amap.register({ name, version, publicKey, capabilities, registryUrl? })
→ Promise<{ did: string }>

// Issue root delegation token (human → first agent)
amap.issue({ principal, delegate, permissions, constraints?, intentHash?, expiresIn, privateKey })
→ Promise<DelegationToken>

// Create child delegation token (enforces all 3 invariants before signing)
amap.delegate({ parentToken, parentChain, delegate, permissions, constraints?, expiresIn, privateKey })
→ Promise<DelegationToken>

// Verify full mandate chain recursively (fully offline with local key map)
amap.verify(chain: DelegationToken[], { expectedPermission, expectedDelegate, nonceStore?, registryUrl? })
→ Promise<VerificationResult>

// Sign an outgoing HTTP request with agent identity + fresh nonce
amap.signRequest({ method, path, body, privateKey, agentDid })
→ { headers: Record<string, string> }  // X-AMAP-* headers, ready to spread

// Verify an incoming signed request (mandate + request signature)
amap.verifyRequest({ headers, method, path, body, nonceStore?, registryUrl? })
→ Promise<VerificationResult>

// Publish signed revocation notice
amap.revoke(did, privateKey)
→ Promise<void>
```

---

## Error Codes

All errors are typed `AmapError` with a specific `code`:

| Code | Meaning |
|------|---------|
| `PERMISSION_INFLATION` | Requested permissions exceed parent |
| `EXPIRY_VIOLATION` | Requested expiry exceeds parent TTL |
| `CONSTRAINT_RELAXATION` | Attempted to relax an ancestor constraint |
| `INVALID_SIGNATURE` | Signature verification failed at a hop |
| `INVALID_REQUEST_SIGNATURE` | Request-level signature invalid |
| `BROKEN_CHAIN` | parentTokenHash doesn't match actual parent |
| `TOKEN_EXPIRED` | One or more tokens expired |
| `NONCE_REPLAYED` | Nonce seen before — replay attack |
| `AGENT_REVOKED` | An agent in the chain has been revoked |
| `AGENT_UNKNOWN` | DID cannot be resolved to a public key |
| `PARAMETER_LOCK_VIOLATION` | Request param doesn't match value locked in mandate |
| `STALE_REQUEST` | Request timestamp outside ±5 minute window |

---

## Naming Conventions

| Thing | Name | Convention used |
|-------|------|----------------|
| npm org scope | `@agentmandateprotocol` | Full product name, matches GitHub org |
| Core npm package | `@agentmandateprotocol/core` | scoped package, industry standard |
| MCP integration package | `@agentmandateprotocol/mcp` | scoped, framework name as sub-package |
| OpenClaw integration package | `@agentmandateprotocol/openclaw` | scoped, framework name as sub-package |
| Middleware package | `@agentmandateprotocol/middleware` | scoped |
| React hooks package | `@agentmandateprotocol/react` | scoped, matches @tanstack/react pattern |
| Python package (PyPI) | `agent-mandate-protocol` | kebab-case, PyPI convention |
| Python import name | `amap` | short alias, matches JS namespace |
| GitHub org | `agent-mandate-protocol` | kebab-case, matches npm scope without `@` |
| Error class | `AmapError` | PascalCase, product abbreviation prefix |
| Main code namespace | `amap` | lowercase abbreviation, used in all languages |
| Cloudflare Worker (registry) | `amap-registry` | kebab-case service name |
| Cloudflare Worker (API) | `amap-api` | kebab-case service name |
| Registry URL | `registry.agentmandateprotocol.dev` | subdomain per service |
| API URL | `api.agentmandateprotocol.dev` | subdomain per service |
| Dashboard URL | `app.agentmandateprotocol.dev` | `app.` convention (Vercel, Linear, etc.) |

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| TypeScript SDK | TypeScript, Node.js 18 LTS | MCP/agent ecosystem is TS-first |
| Python SDK | Python 3.11+ | Secondary SDK for ML/data agent use cases |
| Signing | Ed25519 via Node.js `crypto` (TS) / `cryptography` lib (Python) | Asymmetric, private key never shared |
| Hashing | SHA-256 via Node.js `crypto` | For parentTokenHash, intentHash, and payload hashing |
| Token format | Custom JSON (not JWT) | JWT can't represent chain nesting |
| Canonicalization | JCS (RFC 8785) | Deterministic JSON for consistent signatures |
| Nonce store | Pluggable interface | Default: in-memory. Also: Cloudflare KV |
| Hosted registry | Cloudflare Workers + KV | Edge-global, zero server ops |
| Hosted audit log | Cloudflare D1 | SQLite at edge, co-located with Workers |
| Dashboard | Next.js + Tailwind | Cloudflare Pages |
| Auth (developers) | Clerk | Human auth — not A-MAP's problem |
| Billing | Stripe | Metered on verification count |

---

## Monorepo Structure

The repo is **polyglot** — not TypeScript-only. Python and other language SDKs live under `sdks/`. JS/TS packages and apps use pnpm workspaces. Cross-language tasks coordinated with a root `Makefile`.

```
a-map/
  sdks/                              ← all language SDKs (each independently splittable)
    typescript/                      ← JS/TS packages (pnpm workspace)
      core/                          ← @agentmandateprotocol/core
      mcp/                           ← @agentmandateprotocol/mcp
      openclaw/                      ← @agentmandateprotocol/openclaw
      middleware/                    ← @agentmandateprotocol/middleware  ← Phase 1
      react/                         ← @agentmandateprotocol/react
    python/                          ← agent-mandate-protocol (PyPI)
  apps/                              ← deployed applications (pnpm workspace)
    registry/                        ← amap-registry (CF Workers)
    api/                             ← amap-api (CF Workers)
    dashboard/                       ← app.agentmandateprotocol.dev (Next.js)
  docs/                              ← Documentation site + OpenAPI spec
  spec/                              ← .well-known/agent.json open standard
  examples/                          ← Runnable demos (multi-hop, 1-hop, etc.)
  Makefile                           ← Root task runner for cross-language ops
```

---

## Hard Constraints — Non-Negotiable

- **PRIVATE KEYS NEVER LEAVE THE AGENT.** The SDK signs locally. Servers never receive, store, or process private keys.
- **FULLY FUNCTIONAL OFFLINE.** `sdks/typescript/core` must work with zero network calls. `issue()`, `delegate()`, `verify()`, `signRequest()`, `verifyRequest()` all work airgapped with out-of-band public keys.
- **ZERO RUNTIME DEPENDENCIES IN CORE.** `sdks/typescript/core` has zero npm runtime dependencies. All crypto uses Node.js built-ins.
- **5-MINUTE ONBOARDING.** `npm install @agentmandateprotocol/core` to working sign/verify in under 5 minutes, under 10 lines of code.
- **VERIFICATION UNDER 50MS.** `amap.verify()` and `amap.verifyRequest()` must complete in <50ms for a 10-hop chain with locally cached keys.

---

## Two-Sided Network

A-MAP only creates value when both sides adopt it. Phase 1 must ship both:

**Human/Issuer side** — `amap issue` CLI and `amap_issue` MCP tool. A human is walked through "what agent, what actions, what limits, how long?" and signs a mandate interactively. Output is a mandate chain the agent carries.

**Tool/Verifier side** — `sdks/typescript/middleware` with `amapVerifier()` for Express/Hono/fetch. A tool provider adds one line and their API now enforces mandate verification on every incoming agent request.

**Distributed nonce store warning (must document in middleware README):** The default `InMemoryNonceStore` does not work behind a load balancer — each instance has its own nonce memory. Production deployments with multiple instances must use a shared nonce store (Redis, Cloudflare KV). The middleware README must call this out explicitly so developers don't silently lose replay protection in prod.

## Consent Component (Phase 3)

The "Sign in with Google" equivalent for agent authorization — a headless React component (`@agentmandateprotocol/react`) that presents a permission consent screen, the user clicks Allow, and the signed mandate is returned to the agent.

**Deferred to Phase 3.** The blocking reason is browser signing: Ed25519 is not universally supported in WebCrypto across browsers (Firefox support is recent). Options at Phase 3 decision point:
- Use P-256 (ECDSA) for browser contexts — universally supported, but requires handling two signing algorithms in `verify()`
- Ship an audited Ed25519 JS implementation for browsers
- Do not sign in browser — generate mandate server-side, deliver to agent (simpler but requires a server)

Phase 1 and 2 are CLI + server-side signing only. The consent component UX pattern is correct; the browser crypto problem must be resolved before implementation begins.

Without both sides, the protocol has no network effect.

---

## MCP Integration

`sdks/typescript/mcp` provides:
1. **MCP Tool Manifest** for `amap_verify` — description written for LLM semantic search.
2. **`amap_issue` MCP Tool** — interactive mandate issuance for humans inside an MCP-capable agent environment.
3. **Gateway Middleware** — `amap.authorize(mcpTool, mandateChain)` wraps any MCP `call_tool` handler.

---

## OpenClaw Integration

**OpenClaw** (github.com/openclaw/openclaw) is a self-hosted personal AI assistant that runs on any OS and communicates via WhatsApp, Telegram, Slack, Discord, and 20+ other channels. Plugin system built around `AnyAgentTool` and `OpenClawPluginToolFactory`.

`sdks/typescript/openclaw` provides an A-MAP plugin for OpenClaw:
1. **Session-scoped mandate store (primary path)** — at conversation start, agent calls `amap_register_session({ chain })` once. Plugin stores chain keyed by `sessionId`. Every subsequent tool call auto-verified.
2. **Per-call `_amap` envelope override (agent-to-agent path)** — downstream agent passes `_amap: { chain }` as a top-level tool arg. Hook checks this first, falls back to session store, rejects if neither present. Strips `_amap` before forwarding args to the tool.
3. **Before-Tool-Call Hook** — extracts chain, calls `amap.verifyRequest()`, strips `_amap`, forwards clean args.
4. **Plugin manifest** — valid OpenClaw plugin definition for `openclaw plugin install @agentmandateprotocol/openclaw`.

Session store is an in-memory `Map<sessionId, DelegationToken[]>` inside the plugin.

---

## .well-known/agent.json Standard

Every service hosting an A-MAP-protected API serves:

```json
GET /.well-known/agent.json
{
  "amap": "1.0",
  "did": "did:amap:my-service:2.1:a1b2c3",
  "requiresDelegationChain": true,
  "requiredPermissions": ["read_email"],
  "constraints": { "maxCalls": 100 },
  "registryUrl": "https://registry.agentmandateprotocol.dev",
  "publicKey": "<base64url Ed25519 public key>"
}
```

Tools publish required permissions. Agents discover what scope to request from the human before calling. This creates the two-sided ecosystem.

Formal schema lives in `spec/`. Treat it as an IETF submission.

---

## MVP Plan

See `MVP_PLAN.md` for the full phased task breakdown. Phase 1 (Core SDK + Request Signing + Middleware + MCP + OpenClaw + Mandate Portal) is the current focus.

Phase 1 task order:
`T1 Monorepo → T2 Crypto + T3 Types (parallel) → T4 issue() → T5 delegate() → T6 verify() → T7 revoke()/registry → T8 signRequest/verifyRequest → T9 Core polish → [T10 MCP, T10b OpenClaw, T11 Middleware, T12 .well-known spec (parallel)] → T13 Mandate Portal → T14 Demo`

---

## Open Questions (Resolved)

| Question | Answer |
|----------|--------|
| npm package name | `@agentmandateprotocol/core` |
| npm org scope | `@agentmandateprotocol` |
| Node.js minimum version | Node 18 LTS |
| Code namespace | `amap` in all languages |
| Error class name | `AmapError` |
| GitHub org | `agent-mandate-protocol` |
| Python PyPI name | `agent-mandate-protocol` |
| OpenClaw chain transport | Hybrid: session store (primary) + per-call `_amap` envelope (override) |
| Middleware in Phase 1? | Yes — required for two-sided network |

## Open Questions (Unresolved)

- `constraints` vocabulary: is the table above the complete initial set, or are there domain-specific constraints to add?
- `intentHash` enforcement: Phase 1 adds the field to the token schema (optional, SDK validates when present). Phase 2 adds the `amap_issue --intent` flag and UX. Confirm this phasing.
- Production domain confirmed? (assumed: `agentmandateprotocol.dev`)
