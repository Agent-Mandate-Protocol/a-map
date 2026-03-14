import type { DelegationToken } from './token.js'
import type { Constraints } from './constraints.js'
import type { PolicyDecision } from '../api/policy.js'

/** One verified hop in the delegation chain. */
export interface VerifiedLink {
  /** Index in the chain (0 = root). */
  hop: number
  /** The token at this hop. */
  token: DelegationToken
  /** The issuer DID at this hop. */
  issuer: string
  /** The delegate DID at this hop. */
  delegate: string
}

/** Returned by amap.verify() and amap.verifyRequest(). */
export interface VerificationResult {
  /** True if the full chain is cryptographically valid. */
  valid: boolean

  /** Human principal at the root of the chain. */
  principal: string

  /** Full verified chain, one entry per hop. */
  chain: VerifiedLink[]

  /**
   * Merged constraints from the full chain.
   * Applies the most restrictive value for each constraint key across all hops.
   */
  effectiveConstraints: Constraints

  /**
   * UUID generated fresh for each verification event.
   * Use for audit log correlation.
   */
  auditId: string

  /**
   * Allow/deny policy evaluation result. Populated when requestedAction is provided.
   * Absent when no policy was evaluated.
   */
  appliedPolicy?: PolicyDecision

  /** Present when valid is false. */
  error?: {
    code: string
    message: string
    /** Which hop in the chain caused the failure (0-indexed). */
    hop?: number
  }
}
