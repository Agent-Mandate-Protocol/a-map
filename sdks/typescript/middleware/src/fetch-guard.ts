import { amap, AmapError, AmapErrorCode, InMemoryNonceStore, matchesGlob, evaluatePolicy } from '@agentmandateprotocol/core'
import type { DelegationToken, VerificationResult, KeyResolver } from '@agentmandateprotocol/core'

/** Rule for a specific endpoint pattern. */
export interface FetchRule {
  /** Permissions that must appear in the mandate's leaf token. */
  requires: string[]
  /** Per-rule mode override. Falls back to AmapFetchGuardOptions.mode. */
  policy?: 'enforce' | 'audit' | 'warn'
}

export interface FetchAuditEntry {
  event: 'FETCH_ALLOWED' | 'FETCH_BLOCKED'
  method: string
  url: string
  path: string
  timestamp: string
  /** tokenId of the root token */
  mandateId: string
  /** DID of the human who issued the root mandate */
  principal: string
  /** Present when event is FETCH_BLOCKED */
  reason?: string
}

export interface AmapFetchGuardOptions {
  /** The mandate chain the agent is operating under. */
  mandate: DelegationToken[]
  /**
   * Enforcement mode.
   * - 'enforce' (default): blocked requests throw AmapError and never leave the process.
   * - 'audit': all requests go through; blocked ones are logged via onAudit.
   * - 'warn': same as audit — logs the violation but does not block.
   */
  mode?: 'enforce' | 'audit' | 'warn'
  /**
   * Per-endpoint rules. Key is a pattern matched against "METHOD /path".
   * '*' is the catch-all.
   *
   * Pattern examples:
   *   'GET /api/emails'          — exact match
   *   'DELETE /api/emails/*'     — glob path wildcard
   *   'POST *'                   — any POST request
   *   '*'                        — catch-all (any method, any path)
   */
  rules?: Record<string, FetchRule>
  /** Key resolver for mandate chain verification. */
  keyResolver?: KeyResolver
  /** Called for every request — allowed or blocked. Use for audit logging. */
  onAudit?: (entry: FetchAuditEntry) => void
}

/**
 * Client-side A-MAP guard for HTTP fetch. Wraps a fetch function and enforces
 * mandate permissions before any request leaves the process.
 *
 * The API server is completely unaware — it either receives the request or doesn't.
 *
 * Usage:
 *   const guarded = new AmapFetchGuard(fetch, { mandate, rules, mode: 'enforce' })
 *   await guarded.fetch('https://api.example.com/api/emails/delete/123', { method: 'DELETE' })
 *   // → throws PERMISSION_INFLATION if mandate lacks 'email:delete'
 *   // → network call never made
 */
export class AmapFetchGuard {
  private verifiedMandate: VerificationResult | null = null
  private verifyPromise: Promise<VerificationResult> | null = null

  constructor(
    private readonly fetchFn: (url: string | URL, init?: RequestInit) => Promise<Response>,
    private readonly options: AmapFetchGuardOptions,
  ) {}

  private async getVerifiedMandate(): Promise<VerificationResult> {
    if (this.verifiedMandate !== null) return this.verifiedMandate
    if (this.verifyPromise === null) {
      this.verifyPromise = amap.verify({
        chain: this.options.mandate,
        nonceStore: new InMemoryNonceStore(),
        ...(this.options.keyResolver !== undefined ? { keyResolver: this.options.keyResolver } : {}),
      })
    }
    this.verifiedMandate = await this.verifyPromise
    return this.verifiedMandate
  }

  private resolveRule(method: string, path: string): FetchRule {
    const rules = this.options.rules ?? {}
    const target = `${method.toUpperCase()} ${path}`

    for (const [key, rule] of Object.entries(rules)) {
      if (key === '*') continue // handled as fallback
      if (matchesGlob(target, key)) return rule
    }

    if ('*' in rules) return rules['*']!

    // Default: require a permission named after the full endpoint string
    return { requires: [target] }
  }

  async fetch(url: string | URL, init?: RequestInit): Promise<Response> {
    const mandate = await this.getVerifiedMandate()
    const method = (init?.method ?? 'GET').toUpperCase()
    const parsed = new URL(url instanceof URL ? url.href : url, 'http://localhost')
    const path = parsed.pathname
    const hostname = parsed.hostname

    const rule = this.resolveRule(method, path)
    const mode = rule.policy ?? this.options.mode ?? 'enforce'

    const leafToken = mandate.chain[mandate.chain.length - 1]!.token
    const missing = rule.requires.filter(p => !leafToken.permissions.includes(p))

    // Constraint checks (stateless — skip maxSpend/maxCalls/rateLimit which need counters)
    let constraintViolation: string | null = null
    let constraintCode: AmapErrorCode = AmapErrorCode.PERMISSION_INFLATION
    const ec = mandate.effectiveConstraints

    if (ec.readOnly === true && method !== 'GET' && method !== 'HEAD') {
      constraintViolation = `readOnly mandate forbids ${method} requests`
    }

    if (constraintViolation === null && ec.deniedDomains && ec.deniedDomains.length > 0) {
      const matched = ec.deniedDomains.find(p => matchesGlob(hostname, p))
      if (matched) constraintViolation = `Domain "${hostname}" is denied by mandate (pattern: "${matched}")`
    }

    if (constraintViolation === null && ec.allowedDomains && ec.allowedDomains.length > 0) {
      if (!ec.allowedDomains.some(p => matchesGlob(hostname, p))) {
        constraintViolation = `Domain "${hostname}" is not in mandate's allowedDomains`
      }
    }

    if (constraintViolation === null && (ec.allowedActions !== undefined || ec.deniedActions !== undefined)) {
      const decision = evaluatePolicy(method, ec)
      if (decision.decision === 'EXPLICIT_DENY') {
        constraintViolation = `Action "${method}" is explicitly denied by mandate (rule: "${decision.matchedRule}")`
        constraintCode = AmapErrorCode.EXPLICIT_DENY
      } else if (decision.decision === 'IMPLICIT_DENY') {
        constraintViolation = `Action "${method}" is not in mandate's allowedActions (implicit deny)`
        constraintCode = AmapErrorCode.EXPLICIT_DENY
      }
    }

    const allowed = missing.length === 0 && constraintViolation === null
    const reason = missing.length > 0
      ? `Missing permissions: ${missing.join(', ')}`
      : (constraintViolation ?? undefined)

    const entry: FetchAuditEntry = {
      event: allowed ? 'FETCH_ALLOWED' : 'FETCH_BLOCKED',
      method,
      url: url.toString(),
      path,
      timestamp: new Date().toISOString(),
      mandateId: mandate.chain[0]!.token.tokenId,
      principal: mandate.principal,
      ...(allowed ? {} : { reason }),
    }

    this.options.onAudit?.(entry)

    if (!allowed && mode === 'enforce') {
      if (missing.length > 0) {
        throw new AmapError(
          AmapErrorCode.PERMISSION_INFLATION,
          `Request "${method} ${path}" requires permissions not granted by mandate: ${missing.join(', ')}`,
        )
      }
      throw new AmapError(constraintCode, constraintViolation!)
    }

    return this.fetchFn(url, init)
  }
}
