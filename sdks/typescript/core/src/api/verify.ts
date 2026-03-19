import { randomUUID } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { sha256ofObject } from '../crypto/hash.js'
import { verifySignature } from '../crypto/sign.js'
import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'
import { mergeConstraintChain } from '../types/constraints.js'
import type { VerificationResult, VerifiedLink } from '../types/result.js'
import type { VerifyOptions } from './types.js'
import { assertConstraintsNotRelaxed } from './validate-constraints.js'
import { evaluatePolicy } from './policy.js'

/**
 * Maximum number of hops permitted in a mandate chain.
 * Chains longer than this are rejected before any cryptographic work begins,
 * preventing CPU-exhaustion via crafted deep chains (denial-of-service).
 */
export const MAX_CHAIN_DEPTH = 10

export async function verify(opts: VerifyOptions): Promise<VerificationResult> {
  const { chain } = opts
  if (chain.length === 0) {
    throw new AmapError(AmapErrorCode.BROKEN_CHAIN, 'Chain must contain at least one token')
  }
  if (chain.length > MAX_CHAIN_DEPTH) {
    throw new AmapError(
      AmapErrorCode.BROKEN_CHAIN,
      `Chain length ${chain.length} exceeds maximum allowed depth of ${MAX_CHAIN_DEPTH}`,
    )
  }

  const now = new Date()
  const verifiedLinks: VerifiedLink[] = []

  for (let i = 0; i < chain.length; i++) {
    const token = chain[i]!

    // Step 1: Expiry check
    if (new Date(token.expiresAt) < now) {
      throw new AmapError(
        AmapErrorCode.TOKEN_EXPIRED,
        `Token at hop ${i} expired at ${token.expiresAt}`,
        i,
      )
    }

    // Steps 2–3: Chain hash linkage
    if (i === 0) {
      if (token.parentTokenHash !== null) {
        throw new AmapError(
          AmapErrorCode.BROKEN_CHAIN,
          'Root token must have parentTokenHash = null',
          0,
        )
      }
    } else {
      const expectedHash = sha256ofObject(chain[i - 1]!)
      if (token.parentTokenHash !== expectedHash) {
        throw new AmapError(
          AmapErrorCode.BROKEN_CHAIN,
          `parentTokenHash mismatch at hop ${i}`,
          i,
        )
      }

      // Issuer-delegate continuity: the token's issuer must be the previous token's delegate.
      // Without this check an attacker can append their own DID-signed token to any valid chain,
      // satisfying the hash link and their own signature while never having been delegated to.
      if (token.issuer !== chain[i - 1]!.delegate) {
        throw new AmapError(
          AmapErrorCode.BROKEN_CHAIN,
          `Hop ${i} issuer "${token.issuer}" does not match hop ${i - 1} delegate "${chain[i - 1]!.delegate}"`,
          i,
        )
      }
    }

    // Step 4: Resolve issuer public key
    const publicKey = opts.keyResolver ? await opts.keyResolver.resolve(token.issuer) : null
    if (publicKey === null) {
      throw new AmapError(AmapErrorCode.AGENT_UNKNOWN, `Cannot resolve DID: ${token.issuer}`, i)
    }

    // Step 5: Revocation check
    if (opts.revocationChecker && (await opts.revocationChecker.isRevoked(token.issuer))) {
      throw new AmapError(
        AmapErrorCode.AGENT_REVOKED,
        `Agent ${token.issuer} has been revoked`,
        i,
      )
    }

    // Step 6: Signature verification — sign over payload (all fields except signature)
    const { signature, ...payload } = token
    if (!verifySignature(publicKey, canonicalize(payload), signature)) {
      throw new AmapError(AmapErrorCode.INVALID_SIGNATURE, `Invalid signature at hop ${i}`, i)
    }

    // Step 7: Re-enforce invariants vs parent (hops 1+)
    if (i > 0) {
      const parent = chain[i - 1]!

      // Permission narrowing
      const illegalPerms = token.permissions.filter(p => !parent.permissions.includes(p))
      if (illegalPerms.length > 0) {
        throw new AmapError(
          AmapErrorCode.PERMISSION_INFLATION,
          `Hop ${i} claims permissions not granted by parent: ${illegalPerms.join(', ')}`,
          i,
        )
      }

      // Expiry
      if (new Date(token.expiresAt) > new Date(parent.expiresAt)) {
        throw new AmapError(
          AmapErrorCode.EXPIRY_VIOLATION,
          `Hop ${i} expiresAt exceeds parent`,
          i,
        )
      }

      // Constraint non-relaxation
      const mergedParent = mergeConstraintChain(chain.slice(0, i).map(t => t.constraints))
      assertConstraintsNotRelaxed(mergedParent, token.constraints)
    }

    verifiedLinks.push({ hop: i, token, issuer: token.issuer, delegate: token.delegate })
  }

  const leafToken = chain[chain.length - 1]!

  // Step 9: Delegate check — optional
  if (opts.expectedDelegate !== undefined && leafToken.delegate !== opts.expectedDelegate) {
    throw new AmapError(
      AmapErrorCode.INVALID_SIGNATURE,
      `Chain is delegated to ${leafToken.delegate}, not ${opts.expectedDelegate}`,
    )
  }

  // Step 9b: Principal check — optional
  // Useful in multi-tenant gateways: ensures the chain was rooted by a specific human,
  // not just any valid principal.
  if (opts.expectedPrincipal !== undefined && chain[0]!.principal !== opts.expectedPrincipal) {
    throw new AmapError(
      AmapErrorCode.INVALID_SIGNATURE,
      `Chain is rooted to principal ${chain[0]!.principal}, not ${opts.expectedPrincipal}`,
    )
  }

  // Step 10: Permission check — optional
  if (opts.expectedPermission !== undefined && !leafToken.permissions.includes(opts.expectedPermission)) {
    throw new AmapError(
      AmapErrorCode.PERMISSION_INFLATION,
      `Chain does not grant permission "${opts.expectedPermission}"`,
    )
  }

  // Steps 11–12: parameterLocks check
  if (opts.requestParams !== undefined) {
    // Build the effective lock map with parent-first precedence: iterate in reverse so that
    // earlier (parent) tokens overwrite later (child) tokens. This ensures a root lock on
    // e.g. { to: "boss@company.com" } can never be shadowed by a child token that redeclares
    // the same key — parents always win on conflicts.
    const allLocks: Record<string, unknown> = {}
    for (let j = chain.length - 1; j >= 0; j--) {
      const token = chain[j]!
      if (token.constraints.parameterLocks) {
        Object.assign(allLocks, token.constraints.parameterLocks)
      }
    }
    for (const [key, lockedValue] of Object.entries(allLocks)) {
      if (canonicalize(opts.requestParams[key]) !== canonicalize(lockedValue)) {
        throw new AmapError(
          AmapErrorCode.PARAMETER_LOCK_VIOLATION,
          `Parameter "${key}" must be "${String(lockedValue)}" (locked by mandate), got "${String(opts.requestParams[key])}"`,
        )
      }
    }
  }

  // Step 13: Compute effective constraints — most restrictive across all hops
  const effectiveConstraints = mergeConstraintChain(chain.map(t => t.constraints))

  // Step 14: Allow/deny policy evaluation (optional — only when requestedAction is provided)
  let appliedPolicy: VerificationResult['appliedPolicy'] | undefined
  if (opts.requestedAction !== undefined) {
    const decision = evaluatePolicy(opts.requestedAction, effectiveConstraints)
    appliedPolicy = decision

    if (decision.decision === 'EXPLICIT_DENY' || decision.decision === 'IMPLICIT_DENY') {
      throw new AmapError(
        AmapErrorCode.EXPLICIT_DENY,
        decision.decision === 'EXPLICIT_DENY'
          ? `Action "${opts.requestedAction}" is explicitly denied by rule "${decision.matchedRule}"`
          : `Action "${opts.requestedAction}" is not permitted (implicit deny — not in allowedActions)`,
      )
    }
  }

  return {
    valid: true,
    principal: chain[0]!.principal,
    chain: verifiedLinks,
    effectiveConstraints,
    auditId: randomUUID(),
    ...(appliedPolicy !== undefined ? { appliedPolicy } : {}),
  }
}
