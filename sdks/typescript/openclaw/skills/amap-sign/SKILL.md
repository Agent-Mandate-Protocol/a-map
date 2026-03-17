---
name: amap-sign
description: >
  Sign outgoing agent requests with A-MAP cryptographic headers to prove
  authorization. Produces X-AMAP-Mandate, X-AMAP-Signature,
  X-AMAP-Timestamp, X-AMAP-Nonce, and X-AMAP-Agent-DID headers. Use before
  calling any service that requires verified agent identity.
version: 1.0.0
tags:
  - agent-security
  - request-signing
  - agent-authorization
  - mandate-verification
  - zero-trust
  - A2A-security
  - delegation-chain
metadata:
  openclaw:
    requires:
      bins:
        - node
    primaryEnv: AMAP_PRIVATE_KEY
    homepage: https://agentmandateprotocol.dev
---

# A-MAP Sign Skill

Sign outgoing HTTP requests with A-MAP security headers so receiving services
can verify your agent's authorization cryptographically.

## When to Use This Skill

Activate this skill when:
- You are about to call a service that uses `amap-verify` to check agents
- You need to prove to a third party that a human authorized your action
- You need to prevent replay attacks on your outgoing requests
- You are forwarding a delegation chain to a sub-agent or downstream service

## Prerequisites

You must have:
- A mandate chain (from `amap.issue()` or `amap.delegate()`)
- Your agent's Ed25519 private key in the `AMAP_PRIVATE_KEY` environment variable

## Install

```
npm install @agentmandateprotocol/core@0.1.0
```

## How to Sign a Request

```javascript
import { amap } from '@agentmandateprotocol/core'

// mandateChain = array of DelegationToken obtained from amap.issue or amap.delegate
const headers = amap.signRequest({
  mandateChain: myMandateChain,
  method:       'POST',
  path:         '/api/book-flight',
  body:         JSON.stringify(requestBody),   // omit if no body
  privateKey:   process.env.AMAP_PRIVATE_KEY,
})

// Attach to your outgoing request
await fetch('https://api.example.com/book-flight', {
  method:  'POST',
  headers: {
    'Content-Type': 'application/json',
    ...headers,   // spreads all five X-AMAP-* headers
  },
  body: JSON.stringify(requestBody),
})
```

## What Gets Signed

The signature covers: `mandate_hash + body_hash + method + path + timestamp + nonce`

This means:
- **Stealing the mandate** cannot forge new requests — the agent's private key is required
- **Replaying a captured request** fails — the nonce is single-use
- **Tampering with the body** fails — body hash is bound in the signature
- **Redirecting to a different endpoint** fails — method and path are bound

## Headers Produced

`amap.signRequest()` returns an object with five headers ready to spread:

| Header | Content |
|--------|---------|
| `X-AMAP-Agent-DID` | DID of the signing agent (derived from private key) |
| `X-AMAP-Mandate` | Base64url-encoded JSON array of DelegationTokens |
| `X-AMAP-Signature` | Ed25519 signature over the canonical signed payload |
| `X-AMAP-Timestamp` | ISO8601 UTC timestamp |
| `X-AMAP-Nonce` | 128-bit random hex string (single-use) |

See `references/signed-request-format.md` for full format details.

## Guardrails

- Never hardcode `AMAP_PRIVATE_KEY` — always use an environment variable
- Never log the private key
- Check mandate expiry before signing — signing an expired mandate produces
  headers the receiver will reject with `TOKEN_EXPIRED`
- Use the `amap-verify` skill on your own end to test the round-trip locally
- A fresh nonce is generated on every `signRequest()` call — never cache headers
  and reuse them across requests

## Environment Variables

Set these in your OpenClaw environment (not shell exports):

| Variable | Purpose |
|----------|---------|
| `AMAP_PRIVATE_KEY` | Your agent's Ed25519 private key (base64url-encoded) |
