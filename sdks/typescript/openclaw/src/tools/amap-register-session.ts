import { amap } from '@agentmandateprotocol/core'
import type { DelegationToken, KeyResolver } from '@agentmandateprotocol/core'
import type { SessionMandateStore } from '../session-store.js'

export const amapRegisterSessionToolDefinition = {
  name: 'amap_register_session',
  description:
    'Register an A-MAP mandate chain for this session. ' +
    'Call once at the start of a conversation to authorize all subsequent tool calls. ' +
    'The agent provides its full DelegationToken chain. ' +
    'After registration, every tool call in this session is automatically checked ' +
    'against the mandate permissions — no per-call overhead required. ' +
    '[A-MAP] [mandate] [authorize] [session] [delegation]',
  inputSchema: {
    type: 'object' as const,
    properties: {
      chain: {
        type: 'array',
        description: 'The full DelegationToken chain (index 0 = root, last = leaf for this agent)',
        items: { type: 'object' },
      },
    },
    required: ['chain'],
  },
}

/**
 * Returns a handler that verifies and registers the mandate chain for a session.
 *
 * The chain is verified once here (signature + expiry + invariants).
 * Subsequent tool calls only check permissions from the cached VerificationResult.
 *
 * Note on delegate identity: `amap.verify()` is called without `expectedDelegate`
 * because OpenClaw has no independent knowledge of the registering agent's DID at
 * registration time — the only identity information comes from the chain itself.
 * The security boundary here is the session ID (UUID v4, cryptographically random):
 * an agent can only register a mandate into its own session, and session IDs are
 * never shared between agents. If your deployment model requires verifying that the
 * leaf delegate matches a known agent DID, pass `expectedDelegate` explicitly via a
 * subclass or by calling `amap.verify()` directly before `sessionStore.set()`.
 */
export function handleAmapRegisterSession(
  sessionId: string,
  sessionStore: SessionMandateStore,
  keyResolver?: KeyResolver,
) {
  return async (input: { chain: DelegationToken[] }) => {
    const verified = await amap.verify({
      chain: input.chain,
      ...(keyResolver !== undefined ? { keyResolver } : {}),
    })

    sessionStore.set(sessionId, input.chain, verified)

    return {
      registered: true,
      sessionId,
      chainLength: input.chain.length,
      principal: verified.principal,
    }
  }
}
