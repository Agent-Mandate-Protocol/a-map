import { amap, InMemoryNonceStore } from '@agentmandateprotocol/core'
import type { VerificationResult, NonceStore, KeyResolver, RevocationChecker } from '@agentmandateprotocol/core'

export interface AmapVerifierOptions {
  /**
   * The permission required to access this route.
   * If omitted, no permission check is performed — read result.chain and check yourself.
   */
  expectedPermission?: string
  /** Key resolver for DID → public key resolution. */
  keyResolver?: KeyResolver
  /** Revocation checker. Optional — omit to skip revocation checks. */
  revocationChecker?: RevocationChecker
  /**
   * Nonce store for replay prevention.
   *
   * ⚠️  Not safe behind a load balancer. Each instance has its own nonce memory —
   * a replayed request routed to a different instance will pass.
   * Use a shared store (Redis, Cloudflare KV) for multi-instance deployments.
   *
   * Default: InMemoryNonceStore (safe only for single-instance or development).
   */
  nonceStore?: NonceStore
  /** If set, evaluates allow/deny policy against this action string. */
  requestedAction?: string
  /**
   * Extracts request params for parameterLocks checking.
   * Defaults to req.body when it is a plain object.
   */
  getRequestParams?: (req: MinimalRequest) => Record<string, unknown> | undefined
}

/** Minimal Express-compatible types — no hard dependency on the express package. */
export interface MinimalRequest {
  headers: Record<string, string | string[] | undefined>
  method: string
  path: string
  body?: unknown
}

export interface MinimalResponse {
  status(code: number): MinimalResponse
  json(body: unknown): void
}

export type NextFn = (err?: unknown) => void

// Augment Express Request for users who have @types/express installed
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      amapVerification?: VerificationResult
    }
  }
}

/**
 * Express middleware that verifies A-MAP mandate chains on every request.
 *
 * On success: attaches the VerificationResult to req.amapVerification and calls next().
 * On failure: responds 401 with { error: AmapErrorCode, message: string }.
 *
 * Usage:
 *   app.use('/api/email', amapVerifier({ expectedPermission: 'read_email', keyResolver }))
 *
 *   app.get('/api/email', (req, res) => {
 *     const { principal } = req.amapVerification!
 *     res.json({ authorized: principal })
 *   })
 */
export function amapVerifier(opts: AmapVerifierOptions = {}) {
  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()

  if (opts.nonceStore === undefined && process.env['NODE_ENV'] !== 'test') {
    console.warn(
      '[A-MAP] amapVerifier: using InMemoryNonceStore — not safe behind a load balancer. ' +
        'Provide a shared nonceStore for production multi-instance deployments.',
    )
  }

  return async (
    req: MinimalRequest & Record<string, unknown>,
    res: MinimalResponse,
    next: NextFn,
  ): Promise<void> => {
    try {
      const amapHeaders: Record<string, string> = {}
      for (const [key, value] of Object.entries(req.headers)) {
        if (key.toLowerCase().startsWith('x-amap-') && typeof value === 'string') {
          amapHeaders[key] = value
        }
      }

      // Pass raw body if available as string or Buffer (set by express.text() or express.raw()).
      // Parsed objects (express.json()) are omitted — use express.text() when body verification matters.
      // Warn when express.json() appears to have already run: body is a plain object but a signature
      // header is present, meaning the raw bytes are gone and body integrity cannot be verified.
      const bodyIsParsedObject =
        req.body !== null &&
        typeof req.body === 'object' &&
        !Buffer.isBuffer(req.body)
      if (bodyIsParsedObject && amapHeaders['X-AMAP-Signature']) {
        console.warn(
          '[A-MAP] amapVerifier: req.body is a parsed object — body integrity cannot be verified. ' +
            'Place amapVerifier() before express.json() and use express.text() for routes that require body signing.',
        )
      }
      const rawBody =
        typeof req.body === 'string'
          ? req.body
          : Buffer.isBuffer(req.body)
            ? req.body
            : undefined

      const requestParams: Record<string, unknown> | undefined =
        opts.getRequestParams !== undefined
          ? opts.getRequestParams(req)
          : req.body !== null && typeof req.body === 'object' && !Buffer.isBuffer(req.body)
            ? (req.body as Record<string, unknown>)
            : undefined

      const verification = await amap.verifyRequest({
        headers: amapHeaders,
        method: req.method,
        path: req.path,
        ...(rawBody !== undefined ? { body: rawBody } : {}),
        nonceStore,
        ...(opts.expectedPermission !== undefined ? { expectedPermission: opts.expectedPermission } : {}),
        ...(opts.requestedAction !== undefined ? { requestedAction: opts.requestedAction } : {}),
        ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
        ...(opts.revocationChecker !== undefined ? { revocationChecker: opts.revocationChecker } : {}),
        ...(requestParams !== undefined ? { requestParams } : {}),
      })

      req['amapVerification'] = verification
      next()
    } catch (err: unknown) {
      const code = (err as { code?: string }).code ?? 'UNKNOWN'
      const message = (err as Error).message ?? 'Authorization failed'
      res.status(401).json({ error: code, message })
    }
  }
}
