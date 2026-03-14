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
   * Atomically check and store a nonce.
   * Returns true if the nonce was new (stored successfully).
   * Returns false if the nonce was already seen (replay detected).
   *
   * @param nonce  - the nonce to check and store
   * @param ttlMs  - time-to-live in milliseconds; implementations should evict after this window
   */
  checkAndStore(nonce: string, ttlMs: number): Promise<boolean>
}

/**
 * In-memory NonceStore. Safe for single-process use (tests, CLI tools,
 * single-instance services). NOT suitable for production multi-instance deployments.
 *
 * Expired nonces are evicted lazily on each checkAndStore() call.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>() // nonce → expiry epoch ms

  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    this.evict()
    if (this.seen.has(nonce)) return false
    this.seen.set(nonce, Date.now() + ttlMs)
    return true
  }

  /** Remove expired nonces to prevent unbounded memory growth. */
  private evict(): void {
    const now = Date.now()
    for (const [nonce, expiry] of this.seen) {
      if (expiry < now) this.seen.delete(nonce)
    }
  }
}
