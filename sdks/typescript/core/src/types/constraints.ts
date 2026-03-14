/**
 * Typed constraints embedded in a DelegationToken.
 * Merge semantics are enforced by the SDK at delegation time and re-validated at verification.
 */
export interface Constraints {
  /**
   * Maximum monetary spend allowed under this mandate. Merge: min() wins.
   */
  maxSpend?: number

  /**
   * Maximum number of tool/API calls allowed under this mandate. Merge: min() wins.
   */
  maxCalls?: number

  /**
   * Rate limit for calls within a time window.
   *
   * Merge semantics:
   * - `count`: min wins (fewer allowed calls is more restrictive)
   * - `windowSeconds`: max wins (longer window at same count = lower rate = more restrictive)
   *
   * Example: parent { count: 5, windowSeconds: 3600 } = 5/hour.
   * Child cannot use { count: 5, windowSeconds: 60 } = 5/minute — that is less restrictive.
   */
  rateLimit?: {
    count: number
    windowSeconds: number
  }

  /**
   * When true, the mandate is read-only for all tools. Merge: once true, always true.
   * A downstream agent cannot unset this.
   */
  readOnly?: boolean

  /**
   * Restricts calls to these domains only. Merge: intersection (narrowing only).
   * An empty intersection is invalid and throws CONSTRAINT_RELAXATION.
   */
  allowedDomains?: string[]

  /**
   * Restricts HTTP methods/actions allowed. Merge: intersection (narrowing only).
   */
  allowedActions?: string[]

  /**
   * Locks specific request parameters to exact values.
   * Merge: union of all ancestor locks — all locked keys are enforced cumulatively.
   *
   * Semantics:
   * - Keys present in parameterLocks MUST exactly match in the incoming request params.
   * - Keys NOT present in parameterLocks pass through freely.
   * - A downstream agent may add new locks but cannot remove or change inherited locks.
   *
   * Example: { to: 'boss@company.com' }
   * If request params contain { to: 'hacker@evil.com' }, the call is rejected
   * with PARAMETER_LOCK_VIOLATION — no AI, no NLP, just a string comparison.
   */
  parameterLocks?: Record<string, unknown>
}

/**
 * Merge two Constraints objects applying the correct merge rule per field.
 * Used internally by delegate() and verify().
 * Result is always the most restrictive combination of the two.
 */
export function mergeConstraints(parent: Constraints, child: Constraints): Constraints {
  const merged: Constraints = {}

  // maxSpend: min wins
  if (parent.maxSpend !== undefined || child.maxSpend !== undefined) {
    merged.maxSpend = Math.min(parent.maxSpend ?? Infinity, child.maxSpend ?? Infinity)
  }

  // maxCalls: min wins
  if (parent.maxCalls !== undefined || child.maxCalls !== undefined) {
    merged.maxCalls = Math.min(parent.maxCalls ?? Infinity, child.maxCalls ?? Infinity)
  }

  // rateLimit: min(count) — fewer calls is more restrictive
  //            max(windowSeconds) — longer window at same count = lower rate = more restrictive
  if (parent.rateLimit !== undefined || child.rateLimit !== undefined) {
    merged.rateLimit = {
      count: Math.min(parent.rateLimit?.count ?? Infinity, child.rateLimit?.count ?? Infinity),
      windowSeconds: Math.max(parent.rateLimit?.windowSeconds ?? 0, child.rateLimit?.windowSeconds ?? 0),
    }
  }

  // readOnly: once true, always true
  if (parent.readOnly === true || child.readOnly === true) {
    merged.readOnly = true
  }

  // allowedDomains: intersection
  if (parent.allowedDomains !== undefined && child.allowedDomains !== undefined) {
    merged.allowedDomains = parent.allowedDomains.filter(d => child.allowedDomains!.includes(d))
  } else if (parent.allowedDomains !== undefined) {
    merged.allowedDomains = parent.allowedDomains
  } else if (child.allowedDomains !== undefined) {
    merged.allowedDomains = child.allowedDomains
  }

  // allowedActions: intersection
  if (parent.allowedActions !== undefined && child.allowedActions !== undefined) {
    merged.allowedActions = parent.allowedActions.filter(a => child.allowedActions!.includes(a))
  } else if (parent.allowedActions !== undefined) {
    merged.allowedActions = parent.allowedActions
  } else if (child.allowedActions !== undefined) {
    merged.allowedActions = child.allowedActions
  }

  // parameterLocks: union — parent locks take precedence, child may only add new keys
  if (parent.parameterLocks !== undefined || child.parameterLocks !== undefined) {
    merged.parameterLocks = {
      ...child.parameterLocks,
      ...parent.parameterLocks, // parent always wins on conflicts
    }
  }

  return merged
}

/**
 * Merge an array of Constraints (full chain) left to right.
 * Index 0 is root (human), last is the leaf agent.
 * Result is the most restrictive combination across all hops.
 */
export function mergeConstraintChain(chain: Constraints[]): Constraints {
  return chain.reduce((acc, cur) => mergeConstraints(acc, cur), {})
}
