import type { Constraints } from '../types/constraints.js'

export interface PolicyDecision {
  action: string
  decision: 'EXPLICIT_DENY' | 'WILDCARD_ALLOW' | 'EXPLICIT_ALLOW' | 'IMPLICIT_DENY'
  matchedRule?: string
}

/**
 * Evaluate the allow/deny policy for a requested action.
 *
 * Pure function — no I/O, always deterministic.
 *
 * Evaluation order (strict precedence):
 * 1. EXPLICIT_DENY  — matches deniedActions (always wins, cannot be overridden)
 * 2. WILDCARD_ALLOW — allowedActions contains '*'
 * 3. EXPLICIT_ALLOW — matches an entry in allowedActions
 * 4. IMPLICIT_DENY  — nothing matched (default deny)
 */
export function evaluatePolicy(
  requestedAction: string,
  effectiveConstraints: Constraints,
): PolicyDecision {
  const { allowedActions, deniedActions } = effectiveConstraints

  // Step 1: Explicit deny — checked before allow, always wins
  if (deniedActions !== undefined) {
    for (const denied of deniedActions) {
      if (matchesGlob(requestedAction, denied)) {
        return { action: requestedAction, decision: 'EXPLICIT_DENY', matchedRule: denied }
      }
    }
  }

  // Step 2: No allowedActions constraint → implicit deny (must explicitly allow)
  if (allowedActions === undefined || allowedActions.length === 0) {
    return { action: requestedAction, decision: 'IMPLICIT_DENY' }
  }

  // Step 3: Wildcard allow
  if (allowedActions.includes('*')) {
    return { action: requestedAction, decision: 'WILDCARD_ALLOW', matchedRule: '*' }
  }

  // Step 4: Explicit allow — check each entry including glob patterns
  for (const allowed of allowedActions) {
    if (matchesGlob(requestedAction, allowed)) {
      return { action: requestedAction, decision: 'EXPLICIT_ALLOW', matchedRule: allowed }
    }
  }

  // Step 5: Implicit deny — nothing matched
  return { action: requestedAction, decision: 'IMPLICIT_DENY' }
}

/**
 * Glob pattern matching for deny/allow entries.
 * Supports: '*' (any sequence of chars), '?' (exactly one char), exact match, and
 * word-boundary prefix match (so 'npm' matches 'npm install', 'npm run test', etc.).
 * Case-sensitive.
 *
 * Match rules (in order):
 * 1. '*' bare wildcard → matches anything
 * 2. Pattern contains '*' or '?' → glob regex match
 * 3. No wildcards → exact match OR prefix at word boundary (pattern + ' ' prefix of value)
 *
 * Examples:
 *   matchesGlob('rm -rf /', 'rm*')            → true   (glob)
 *   matchesGlob('kubectl delete', '*delete*')  → true   (glob)
 *   matchesGlob('npm install', 'npm')          → true   (prefix: 'npm ' prefix of 'npm install')
 *   matchesGlob('npm', 'npm')                  → true   (exact)
 *   matchesGlob('npm install', 'rm*')          → false
 */
export function matchesGlob(value: string, pattern: string): boolean {
  if (pattern === '*') return true

  if (pattern.includes('*') || pattern.includes('?')) {
    // Convert glob to regex: escape regex specials, then replace * and ?
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.')
    return new RegExp(`^${escaped}$`).test(value)
  }

  // Exact match or word-boundary prefix match
  return value === pattern || value.startsWith(pattern + ' ')
}
