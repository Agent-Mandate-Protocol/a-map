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
 *
 * ⚠️  SESSION ISOLATION DEPENDS ON THE FRAMEWORK'S SESSION ID RANDOMNESS.
 * This store is keyed by `sessionId` strings supplied by OpenClaw. If those IDs
 * are predictable or reused, one session could access another session's mandate.
 * OpenClaw uses UUID v4 session keys, which are cryptographically random — this
 * is acceptable. If you embed this store in a different framework, ensure session
 * IDs are generated with a CSPRNG (≥128 bits of entropy). Do not use sequential
 * integers, timestamps, or other guessable values as session identifiers.
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
