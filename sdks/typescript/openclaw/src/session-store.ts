import type { DelegationToken, VerificationResult } from '@agentmandateprotocol/core'

interface SessionEntry {
  chain: DelegationToken[]
  verified: VerificationResult
}

/**
 * In-memory session-scoped mandate store.
 * Maps sessionId → { chain, verified VerificationResult }.
 *
 * Lifetime: same as the plugin instance (process memory).
 * The chain is verified once at registration; subsequent tool calls
 * only check permissions from the cached VerificationResult.
 */
export class SessionMandateStore {
  private readonly sessions = new Map<string, SessionEntry>()

  set(sessionId: string, chain: DelegationToken[], verified: VerificationResult): void {
    this.sessions.set(sessionId, { chain, verified })
  }

  get(sessionId: string): SessionEntry | undefined {
    return this.sessions.get(sessionId)
  }

  delete(sessionId: string): void {
    this.sessions.delete(sessionId)
  }

  has(sessionId: string): boolean {
    return this.sessions.has(sessionId)
  }
}
