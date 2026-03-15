import { amap, InMemoryNonceStore } from '@agentmandateprotocol/core'
import type { VerificationResult, NonceStore, KeyResolver, RevocationChecker } from '@agentmandateprotocol/core'

export interface AmapHonoVerifierOptions {
  /** The permission required to access this route. */
  expectedPermission?: string
  /** Key resolver for DID → public key resolution. */
  keyResolver?: KeyResolver
  /** Revocation checker. Optional. */
  revocationChecker?: RevocationChecker
  /**
   * Nonce store for replay prevention.
   *
   * ⚠️  Cloudflare Workers spawn multiple isolates — InMemoryNonceStore is NOT safe.
   * Use CloudflareKVNonceStore for production Workers deployments.
   */
  nonceStore?: NonceStore
  /** If set, evaluates allow/deny policy against this action string. */
  requestedAction?: string
}

/** Context variable key where the VerificationResult is stored. */
export const AMAP_VERIFICATION_KEY = 'amapVerification' as const

/** Use as the Variables type parameter in Hono: `new Hono<{ Variables: AmapHonoVariables }>()` */
export type AmapHonoVariables = {
  amapVerification: VerificationResult
}

/** Minimal Hono-compatible types — no hard dependency on the hono package. */
interface MinimalHonoRequest {
  raw: {
    headers: { forEach(cb: (value: string, key: string) => void): void }
  }
  method: string
  url: string
}

interface MinimalHonoContext {
  req: MinimalHonoRequest
  get(key: string): unknown
  set(key: string, value: unknown): void
  json(body: unknown, status?: number): Response
}

type HonoNext = () => Promise<void>

/**
 * Hono middleware that verifies A-MAP mandate chains on every request.
 *
 * On success: sets c.get('amapVerification') and calls next().
 * On failure: returns c.json({ error, message }, 401).
 *
 * Usage (Cloudflare Workers):
 *   import type { AmapHonoVariables } from '@agentmandateprotocol/middleware'
 *
 *   const app = new Hono<{ Variables: AmapHonoVariables }>()
 *   app.use('/api/*', amapHonoVerifier({ expectedPermission: 'read_email', nonceStore: kvStore }))
 *
 *   app.get('/api/email', (c) => {
 *     const { principal } = c.get('amapVerification')
 *     return c.json({ authorized: principal })
 *   })
 */
export function amapHonoVerifier(opts: AmapHonoVerifierOptions = {}) {
  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()

  return async (c: MinimalHonoContext, next: HonoNext): Promise<Response | void> => {
    try {
      const amapHeaders: Record<string, string> = {}
      c.req.raw.headers.forEach((value, key) => {
        if (key.toLowerCase().startsWith('x-amap-')) {
          amapHeaders[key] = value
        }
      })

      const pathname = new URL(c.req.url).pathname

      const verification = await amap.verifyRequest({
        headers: amapHeaders,
        method: c.req.method,
        path: pathname,
        nonceStore,
        ...(opts.expectedPermission !== undefined ? { expectedPermission: opts.expectedPermission } : {}),
        ...(opts.requestedAction !== undefined ? { requestedAction: opts.requestedAction } : {}),
        ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
        ...(opts.revocationChecker !== undefined ? { revocationChecker: opts.revocationChecker } : {}),
      })

      c.set(AMAP_VERIFICATION_KEY, verification)
      await next()
    } catch (err: unknown) {
      const code = (err as { code?: string }).code ?? 'UNKNOWN'
      const message = (err as Error).message ?? 'Authorization failed'
      return c.json({ error: code, message }, 401)
    }
  }
}
