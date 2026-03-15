import { amap, InMemoryNonceStore } from '@agentmandateprotocol/core'
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
 */
export function handleAmapRegisterSession(
  sessionId: string,
  sessionStore: SessionMandateStore,
  keyResolver?: KeyResolver,
) {
  return async (input: { chain: DelegationToken[] }) => {
    const verified = await amap.verify({
      chain: input.chain,
      nonceStore: new InMemoryNonceStore(),
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
