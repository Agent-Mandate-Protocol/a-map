import type { DelegationToken } from './token.js'
import type { Constraints } from './constraints.js'

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
   * IAM policy evaluation result. Populated by T17 (IAM Policy Engine).
   * Absent when no policy was evaluated (e.g. no requestedAction provided).
   */
  appliedPolicy?: {
    action: string
    decision: 'ALLOW' | 'DENY'
    matchedRule?: string
  }

  /** Present when valid is false. */
  error?: {
    code: string
    message: string
    /** Which hop in the chain caused the failure (0-indexed). */
    hop?: number
  }
}
