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
   * '*' means allow all domains — used as the wildcard base for god-mode patterns.
   */
  allowedDomains?: string[] | ['*']

  /**
   * Explicit domain deny list. ALWAYS wins over allowedDomains.
   * Merge: UNION (grows through the chain — a child cannot remove a parent deny).
   * Supports glob patterns: '~/.ssh/**', '~/.aws/**'.
   */
  deniedDomains?: string[]

  /**
   * Allowed actions. Merge: intersection.
   * '*' means allow all actions — used as the wildcard base for god-mode patterns.
   * Example: ['shell.exec', 'fs.read'] or ['*']
   */
  allowedActions?: string[] | ['*']

  /**
   * Explicit action deny list. ALWAYS wins over allowedActions.
   * Merge: UNION (grows through the chain — a child cannot remove a parent deny).
   * Supports glob patterns: 'rm*', '*delete*', 'kubectl*'.
   * Example: ['rm -rf', 'sudo*', 'kubectl delete']
   */
  deniedActions?: string[]

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

  // Helper: check if a string[] | ['*'] includes the wildcard
  const hasWild = (arr: string[] | ['*'] | undefined): boolean =>
    arr !== undefined && (arr as string[]).includes('*')

  // allowedDomains: intersection with wildcard handling
  // - parent ['*'] + child explicit → child list (narrowing)
  // - parent explicit + child ['*'] → parent list (child can't widen an explicit list)
  // - parent undefined + child ['*'] → ['*'] (child introduces wildcard for first time)
  // - both explicit → intersection
  // - both ['*'] → ['*']
  if (parent.allowedDomains !== undefined || child.allowedDomains !== undefined) {
    const parentWild = hasWild(parent.allowedDomains)
    const childWild = hasWild(child.allowedDomains)
    if (parentWild && childWild) {
      merged.allowedDomains = ['*']
    } else if (parentWild) {
      merged.allowedDomains = child.allowedDomains ?? ['*']
    } else if (childWild) {
      if (parent.allowedDomains !== undefined) {
        merged.allowedDomains = parent.allowedDomains as string[]
      } else {
        merged.allowedDomains = child.allowedDomains as ['*']
      }
    } else if (parent.allowedDomains !== undefined && child.allowedDomains !== undefined) {
      merged.allowedDomains = (parent.allowedDomains as string[]).filter(
        d => (child.allowedDomains as string[]).includes(d),
      )
    } else {
      merged.allowedDomains = (parent.allowedDomains ?? child.allowedDomains) as string[]
    }
  }

  // deniedDomains: union — grows through chain, never shrinks
  if (parent.deniedDomains !== undefined || child.deniedDomains !== undefined) {
    const parentDenied = parent.deniedDomains ?? []
    const childDenied = child.deniedDomains ?? []
    merged.deniedDomains = [...new Set([...parentDenied, ...childDenied])]
  }

  // allowedActions: same wildcard-intersection semantics as allowedDomains
  if (parent.allowedActions !== undefined || child.allowedActions !== undefined) {
    const parentWild = hasWild(parent.allowedActions)
    const childWild = hasWild(child.allowedActions)
    if (parentWild && childWild) {
      merged.allowedActions = ['*']
    } else if (parentWild) {
      merged.allowedActions = child.allowedActions ?? ['*']
    } else if (childWild) {
      if (parent.allowedActions !== undefined) {
        merged.allowedActions = parent.allowedActions as string[]
      } else {
        merged.allowedActions = child.allowedActions as ['*']
      }
    } else if (parent.allowedActions !== undefined && child.allowedActions !== undefined) {
      merged.allowedActions = (parent.allowedActions as string[]).filter(
        a => (child.allowedActions as string[]).includes(a),
      )
    } else {
      merged.allowedActions = (parent.allowedActions ?? child.allowedActions) as string[]
    }
  }

  // deniedActions: union — grows through chain, never shrinks
  if (parent.deniedActions !== undefined || child.deniedActions !== undefined) {
    const parentDenied = parent.deniedActions ?? []
    const childDenied = child.deniedActions ?? []
    merged.deniedActions = [...new Set([...parentDenied, ...childDenied])]
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
