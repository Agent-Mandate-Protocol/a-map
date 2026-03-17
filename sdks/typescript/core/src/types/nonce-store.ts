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
 * Uses a FIFO insertion queue alongside the lookup map. Because verifyRequest()
 * passes a fixed TTL for all nonces, entries expire in the same order they were
 * inserted. On each checkAndStore() call, expired entries are drained from the
 * front of the queue and deleted from the map — O(1) amortized per call, with
 * memory bounded to the live window rather than growing between eviction batches.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>()          // nonce → expiry ms
  private readonly queue: Array<{ nonce: string; expiry: number }> = []

  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now()

    // Drain expired entries from the front of the queue — O(1) amortized because
    // each entry is enqueued once and dequeued once over its lifetime.
    while (this.queue.length > 0 && this.queue[0]!.expiry <= now) {
      this.seen.delete(this.queue.shift()!.nonce)
    }

    if (this.seen.has(nonce)) return false

    const expiry = now + ttlMs
    this.seen.set(nonce, expiry)
    this.queue.push({ nonce, expiry })
    return true
  }
}
