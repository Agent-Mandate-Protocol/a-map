---
name: amap-verify
description: >
  Cryptographically verify that an AI agent was authorized by a human to
  perform an action. Detects agent impersonation, forged mandates, and
  replay attacks. Use when receiving a request from another AI agent.
version: 1.0.0
tags:
  - agent-security
  - agent-identity
  - request-signing
  - mandate-verification
  - replay-prevention
  - zero-trust
  - agent-authorization
  - A2A-security
  - delegation-chain
  - MCP-trust
metadata:
  openclaw:
    requires:
      bins:
        - node
    primaryEnv: AMAP_PUBLIC_KEYS
    homepage: https://agentmandateprotocol.dev
---

# A-MAP Verify Skill

Verify that an incoming request from another AI agent is genuine.

This skill uses the Agent Mandate Protocol (A-MAP) to cryptographically prove:
the agent was authorized by a human, the authorization chain is intact, and this
specific request was not replayed.

## When to Use This Skill

Activate this skill when:
- Another agent sends a request claiming authorization to perform an action
- A request includes `X-AMAP-Mandate`, `X-AMAP-Signature`, `X-AMAP-Timestamp`,
  `X-AMAP-Nonce`, or `X-AMAP-Agent-DID` headers
- You need to confirm an agent's identity before granting access
- You need to detect agent impersonation or replay attacks
- You need cryptographic proof of who authorized an agent to act

## What You Need

- The five A-MAP headers from the incoming request
- The expected permission the caller claims to have
- The public keys of all agents in the chain (distribute out-of-band)

## Install

```
npm install @agentmandateprotocol/core@0.1.0
```

## How to Verify

```javascript
import { amap, InMemoryNonceStore, LocalKeyResolver } from '@agentmandateprotocol/core'

// Build key map from known public keys distributed out-of-band
const publicKeyMap = new Map([
  ['did:amap:sender-agent:1.0:abc', process.env.SENDER_PUBKEY],
])
const keyResolver = new LocalKeyResolver(publicKeyMap)

// Use Redis or Cloudflare KV in production — see Guardrails below
const nonceStore = new InMemoryNonceStore()

try {
  const result = await amap.verifyRequest({
    headers: {
      'X-AMAP-Agent-DID': request.headers['x-amap-agent-did'],
      'X-AMAP-Mandate':   request.headers['x-amap-mandate'],
      'X-AMAP-Signature': request.headers['x-amap-signature'],
      'X-AMAP-Timestamp': request.headers['x-amap-timestamp'],
      'X-AMAP-Nonce':     request.headers['x-amap-nonce'],
    },
    method: request.method,
    path:   request.path,
    body:   request.body,
    expectedPermission: 'book_flight',
    keyResolver,
    nonceStore,
  })

  // Safe to proceed
  console.log('Authorized by:', result.principal)
  console.log('Effective limits:', result.effectiveConstraints)
  console.log('Audit ID:', result.auditId)  // log this
} catch (err) {
  // A-MAP throws on any failure — never returns { valid: false }
  console.error(`Authorization failed: [${err.code}] ${err.message}`)
  // Reject the request
}
```

## Interpreting the Result

On success (no error thrown):
- `result.principal` — the human who originally authorized this chain
- `result.effectiveConstraints` — merged limits across all hops (e.g. `maxSpend: 347`)
- `result.chain` — array of verified links, one per hop
- `result.auditId` — UUID for this verification event — log it for audit trail

On failure (`AmapError` thrown):
- `err.code` — specific error code (see `references/error-codes.md`)
- `err.hop` — which link in the chain failed (0 = root), if applicable
- Always reject the request and log the error code

## Guardrails

- Never proceed with an action if `verifyRequest()` throws
- Always log `result.auditId` for audit trail
- The default `InMemoryNonceStore` does not survive server restarts and does
  not work behind a load balancer. Use a shared store (Redis, Cloudflare KV)
  in any multi-instance or production deployment.
- Always check `result.effectiveConstraints` before performing consequential
  actions (e.g. check `maxSpend` before charging a card)
- If an agent presents no A-MAP headers, treat it as unverified — your policy
  decides whether to allow or reject unverified agents

## Fail-Closed Behavior

When in doubt, reject. An `AmapError` means one of:
- The agent was not authorized by a human
- The request is a replay of a captured legitimate request
- The mandate chain was forged or tampered
- The agent's identity is being spoofed

All four cases require rejection.
