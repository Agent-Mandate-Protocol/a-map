---
name: amap-delegate
description: >
  Create cryptographic delegation chains when spawning sub-agents.
  Enforces permission narrowing, constraint inheritance, and expiry
  shortening. Use when an agent needs to authorize another agent to
  act on its behalf with a subset of its own permissions.
version: 1.0.0
tags:
  - agent-security
  - delegation-chain
  - agent-authorization
  - agent-identity
  - multi-agent
  - zero-trust
  - A2A-security
metadata:
  openclaw:
    requires:
      bins:
        - node
    primaryEnv: AMAP_PRIVATE_KEY
    homepage: https://agentmandateprotocol.dev
---

# A-MAP Delegate Skill

Create a delegation chain when spawning a sub-agent. This gives the sub-agent
cryptographic proof of what it is authorized to do, enforcing that it can never
exceed your own permissions.

## When to Use This Skill

Activate this skill when:
- You are spawning a sub-agent to handle part of a task
- A sub-agent needs proof of authorization to call external services
- You want to limit what a sub-agent can do to a safe subset of your permissions
- You need an auditable record of which agent authorized which sub-agent

## Install

```
npm install @agentmandateprotocol/core@0.1.0
```

## How to Delegate

```javascript
import { amap } from '@agentmandateprotocol/core'

// myToken = the DelegationToken you received (from amap.issue or amap.delegate)
// myChain = the full chain including myToken (index 0 = root)

let childToken
try {
  childToken = await amap.delegate({
    parentToken: myToken,
    parentChain: myChain,
    delegate:    'did:amap:sub-agent:1.0:xyz',
    permissions: ['charge_card'],     // must be a subset of myToken.permissions
    constraints: { maxSpend: 347 },   // can only tighten, never relax
    expiresIn:   '15m',               // cannot exceed parent's remaining TTL
    privateKey:  process.env.AMAP_PRIVATE_KEY,
  })
} catch (err) {
  // AmapError thrown BEFORE any signing if an invariant is violated
  // err.code will be one of:
  //   PERMISSION_INFLATION    — requested permissions not in parent
  //   CONSTRAINT_RELAXATION   — constraint would be looser than parent
  //   EXPIRY_VIOLATION        — expiresIn exceeds parent's remaining TTL
  throw err
}

// Pass the full chain (parent + child token) to the sub-agent out-of-band
const subAgentChain = [...myChain, childToken]
```

## What to Send to the Sub-Agent

Always pass `subAgentChain` — the full chain — to the sub-agent, not just the
child token. The sub-agent needs the complete chain to prove authorization to
services that call `amap.verifyRequest()`.

The sub-agent uses `amap.signRequest({ mandateChain: subAgentChain, ... })` to
attach the chain to outgoing requests.

## Expiry Strategy

Use the shortest TTL that covers the task. The SDK will throw `EXPIRY_VIOLATION`
if you request more than the parent's remaining time.

| Task type | Recommended TTL |
|-----------|----------------|
| Single API call | `15s` |
| One-off task | `60s` |
| Short workflow | `5m` |
| Extended session | Match parent — let the SDK enforce the ceiling |

## The Three Rules (Enforced by SDK)

See `references/delegation-invariants.md` for full details.

1. **Permissions can only narrow** — you cannot grant what you do not have
2. **Constraints can only tighten** — you cannot relax a limit set above you
3. **Expiry can only shorten** — sub-agent tokens expire before yours

Violations throw a typed `AmapError` before any signature is produced. The SDK
makes it impossible to accidentally issue an over-privileged token.

## Guardrails

- Never grant permissions you did not receive in your own mandate
- Set the shortest possible `expiresIn` for sub-agents
- Always pass `subAgentChain` (the full chain), not just the new token
- Log `childToken.tokenId` for audit trail
- Never share your `AMAP_PRIVATE_KEY` — each agent has its own keypair
