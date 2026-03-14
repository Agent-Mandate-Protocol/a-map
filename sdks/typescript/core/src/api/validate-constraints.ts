import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'
import type { Constraints } from '../types/constraints.js'

/**
 * Check that candidate constraints do not relax any value in mergedParent.
 * Throws CONSTRAINT_RELAXATION if a relaxation is detected.
 *
 * @param mergedParent - the effective constraints from the full parent chain
 * @param candidate - the constraints the delegating agent wants to embed
 */
export function assertConstraintsNotRelaxed(
  mergedParent: Constraints,
  candidate: Constraints,
): void {
  if (
    mergedParent.maxSpend !== undefined &&
    candidate.maxSpend !== undefined &&
    candidate.maxSpend > mergedParent.maxSpend
  ) {
    throw new AmapError(
      AmapErrorCode.CONSTRAINT_RELAXATION,
      `maxSpend ${candidate.maxSpend} exceeds parent limit of ${mergedParent.maxSpend}`,
    )
  }

  if (
    mergedParent.maxCalls !== undefined &&
    candidate.maxCalls !== undefined &&
    candidate.maxCalls > mergedParent.maxCalls
  ) {
    throw new AmapError(
      AmapErrorCode.CONSTRAINT_RELAXATION,
      `maxCalls ${candidate.maxCalls} exceeds parent limit of ${mergedParent.maxCalls}`,
    )
  }

  if (mergedParent.rateLimit !== undefined && candidate.rateLimit !== undefined) {
    if (candidate.rateLimit.count > mergedParent.rateLimit.count) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        `rateLimit.count ${candidate.rateLimit.count} exceeds parent limit of ${mergedParent.rateLimit.count}`,
      )
    }
    // Shorter windowSeconds = more calls per unit time = less restrictive.
    // e.g. { count: 5, windowSeconds: 60 } = 5/min is less restrictive than 5/hour.
    if (candidate.rateLimit.windowSeconds < mergedParent.rateLimit.windowSeconds) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        `rateLimit.windowSeconds ${candidate.rateLimit.windowSeconds}s is shorter than parent ${mergedParent.rateLimit.windowSeconds}s (same count in a shorter window = higher rate)`,
      )
    }
  }

  if (mergedParent.readOnly === true && candidate.readOnly !== undefined && candidate.readOnly !== true) {
    throw new AmapError(
      AmapErrorCode.CONSTRAINT_RELAXATION,
      'readOnly is true in parent chain and cannot be unset',
    )
  }

  if (mergedParent.allowedDomains !== undefined && candidate.allowedDomains !== undefined) {
    const parentDomainsArr = mergedParent.allowedDomains as string[]
    const candidateDomainsArr = candidate.allowedDomains as string[]
    if (!parentDomainsArr.includes('*')) {
      const illegal = candidateDomainsArr.filter(d => !parentDomainsArr.includes(d))
      if (illegal.length > 0) {
        throw new AmapError(
          AmapErrorCode.CONSTRAINT_RELAXATION,
          `allowedDomains contains domains not permitted by parent: ${illegal.join(', ')}`,
        )
      }
    }
  }

  if (mergedParent.allowedActions !== undefined && candidate.allowedActions !== undefined) {
    const parentActionsArr = mergedParent.allowedActions as string[]
    const candidateActionsArr = candidate.allowedActions as string[]
    const parentHasWild = parentActionsArr.includes('*')
    const candidateHasWild = candidateActionsArr.includes('*')
    // Child cannot expand to wildcard when parent has an explicit list
    if (!parentHasWild && candidateHasWild) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        'allowedActions: child cannot expand to wildcard when parent has explicit list',
      )
    }
    // When parent has wildcard, any explicit child list is a valid narrowing — skip subset check
    if (!candidateHasWild && !parentHasWild) {
      const illegal = candidateActionsArr.filter(a => !parentActionsArr.includes(a))
      if (illegal.length > 0) {
        throw new AmapError(
          AmapErrorCode.CONSTRAINT_RELAXATION,
          `allowedActions contains actions not permitted by parent: ${illegal.join(', ')}`,
        )
      }
    }
  }

  // deniedActions: child cannot remove a deny entry set by parent
  if (mergedParent.deniedActions !== undefined && candidate.deniedActions !== undefined) {
    for (const denied of mergedParent.deniedActions) {
      if (!candidate.deniedActions.includes(denied)) {
        throw new AmapError(
          AmapErrorCode.CONSTRAINT_RELAXATION,
          `deniedActions: child removed parent deny entry "${denied}"`,
        )
      }
    }
  }

  // deniedDomains: same — child cannot remove a domain deny set by parent
  if (mergedParent.deniedDomains !== undefined && candidate.deniedDomains !== undefined) {
    for (const denied of mergedParent.deniedDomains) {
      if (!candidate.deniedDomains.includes(denied)) {
        throw new AmapError(
          AmapErrorCode.CONSTRAINT_RELAXATION,
          `deniedDomains: child removed parent deny entry "${denied}"`,
        )
      }
    }
  }

  if (mergedParent.parameterLocks !== undefined && candidate.parameterLocks !== undefined) {
    for (const [key, candidateValue] of Object.entries(candidate.parameterLocks)) {
      if (
        key in mergedParent.parameterLocks &&
        mergedParent.parameterLocks[key] !== candidateValue
      ) {
        throw new AmapError(
          AmapErrorCode.CONSTRAINT_RELAXATION,
          `parameterLocks.${key} is locked to "${String(mergedParent.parameterLocks[key])}" by a parent token and cannot be changed`,
        )
      }
    }
  }
}
