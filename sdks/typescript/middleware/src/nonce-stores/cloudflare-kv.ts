import type { NonceStore } from '@agentmandateprotocol/core'

/**
 * CloudflareKVNonceStore — production NonceStore backed by Cloudflare KV.
 *
 * Safe for multi-worker deployments. KV provides global read-after-write
 * consistency within the same region. For strict cross-region replay prevention,
 * co-locate Workers and KV in the same region.
 *
 * ⚠️  Cloudflare KV does not support atomic set-if-not-exists. In theory, two
 * concurrent requests with the same nonce arriving simultaneously at different
 * Workers could both pass (they both read null before either writes). This window
 * is extremely small in practice but is not cryptographically strict. For
 * environments requiring strict atomicity, use a Durable Object.
 *
 * Usage:
 *   const nonceStore = new CloudflareKVNonceStore(env.AMAP_NONCES)
 *   app.use(amapHonoVerifier({ nonceStore, keyResolver }))
 */
export class CloudflareKVNonceStore implements NonceStore {
  constructor(private readonly kv: KVNamespace) {}

  async checkAndStore(nonce: string, ttlMs: number): Promise<boolean> {
    const existing = await this.kv.get(nonce)
    if (existing !== null) return false
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000))
    await this.kv.put(nonce, '1', { expirationTtl: ttlSeconds })
    return true
  }
}

/**
 * KVNamespace — Cloudflare Workers global.
 * Declared here to avoid requiring @cloudflare/workers-types as a hard dependency.
 */
interface KVNamespace {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}
