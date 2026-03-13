/**
 * Interface for tracking seen nonces to prevent replay attacks.
 *
 * WARNING: The default InMemoryNonceStore does NOT work correctly behind a
 * load balancer — each process has isolated memory, so a replayed request
 * will pass on a different instance. Production multi-instance deployments
 * MUST use a shared implementation (e.g. Redis, Cloudflare KV) to prevent
 * replay attacks across instances.
 */
export interface NonceStore {
  /**
   * Check if a nonce has been seen before.
   * Returns true if the nonce is new (not yet seen).
   * Returns false if the nonce has already been used.
   */
  check(nonce: string): Promise<boolean>

  /**
   * Mark a nonce as used. Called after check() returns true.
   * Implementations should set a TTL based on the token's expiresAt
   * to prevent unbounded memory/storage growth.
   */
  mark(nonce: string, expiresAt: Date): Promise<void>
}

/**
 * In-memory NonceStore. Safe for single-process use (tests, CLI tools,
 * single-instance services). NOT suitable for production multi-instance deployments.
 *
 * Expired nonces are evicted lazily on each check() call.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, Date>()

  async check(nonce: string): Promise<boolean> {
    this.evict()
    return !this.seen.has(nonce)
  }

  async mark(nonce: string, expiresAt: Date): Promise<void> {
    this.seen.set(nonce, expiresAt)
  }

  /** Remove expired nonces to prevent unbounded memory growth. */
  private evict(): void {
    const now = new Date()
    for (const [nonce, expiry] of this.seen) {
      if (expiry < now) this.seen.delete(nonce)
    }
  }
}
