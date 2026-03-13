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
        'rateLimit.count is less restrictive than parent',
      )
    }
    if (candidate.rateLimit.windowSeconds > mergedParent.rateLimit.windowSeconds) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        'rateLimit.windowSeconds is less restrictive than parent',
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
    const illegal = candidate.allowedDomains.filter(d => !mergedParent.allowedDomains!.includes(d))
    if (illegal.length > 0) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        `allowedDomains contains domains not permitted by parent: ${illegal.join(', ')}`,
      )
    }
  }

  if (mergedParent.allowedActions !== undefined && candidate.allowedActions !== undefined) {
    const illegal = candidate.allowedActions.filter(a => !mergedParent.allowedActions!.includes(a))
    if (illegal.length > 0) {
      throw new AmapError(
        AmapErrorCode.CONSTRAINT_RELAXATION,
        `allowedActions contains actions not permitted by parent: ${illegal.join(', ')}`,
      )
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
