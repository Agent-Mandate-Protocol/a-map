import { describe, it, expect } from 'vitest'
import { assertConstraintsNotRelaxed } from './validate-constraints.js'
import { AmapErrorCode } from '../errors/codes.js'

describe('assertConstraintsNotRelaxed', () => {
  it('passes when candidate is more restrictive', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { maxSpend: 500, maxCalls: 100 },
        { maxSpend: 200, maxCalls: 10 },
      ),
    ).not.toThrow()
  })

  it('passes when candidate adds no constraints', () => {
    expect(() => assertConstraintsNotRelaxed({ maxSpend: 500 }, {})).not.toThrow()
  })

  it('throws CONSTRAINT_RELAXATION for maxSpend increase', () => {
    expect(() => assertConstraintsNotRelaxed({ maxSpend: 500 }, { maxSpend: 1000 })).toThrow(
      expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }),
    )
  })

  it('throws CONSTRAINT_RELAXATION for maxCalls increase', () => {
    expect(() => assertConstraintsNotRelaxed({ maxCalls: 10 }, { maxCalls: 100 })).toThrow(
      expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }),
    )
  })

  it('throws CONSTRAINT_RELAXATION for unsetting readOnly', () => {
    expect(() => assertConstraintsNotRelaxed({ readOnly: true }, { readOnly: false })).toThrow(
      expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }),
    )
    // omitting readOnly is fine — merged result will still be true
    expect(() => assertConstraintsNotRelaxed({ readOnly: true }, {})).not.toThrow()
  })

  it('throws CONSTRAINT_RELAXATION for domain not in parent allowedDomains', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedDomains: ['a.com', 'b.com'] },
        { allowedDomains: ['a.com', 'c.com'] },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('throws CONSTRAINT_RELAXATION for parameterLock override attempt', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { to: 'boss@company.com' } },
        { parameterLocks: { to: 'hacker@evil.com' } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when candidate adds a new parameterLock key', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { to: 'boss@company.com' } },
        { parameterLocks: { to: 'boss@company.com', subject: 'Approved' } },
      ),
    ).not.toThrow()
  })
})

describe('assertConstraintsNotRelaxed — rateLimit', () => {
  it('throws CONSTRAINT_RELAXATION when candidate rateLimit.count exceeds parent', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 60 } },
        { rateLimit: { count: 10, windowSeconds: 60 } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('throws CONSTRAINT_RELAXATION when candidate rateLimit.windowSeconds is shorter than parent (higher rate)', () => {
    // { count: 5, windowSeconds: 60 } = 5/min is LESS restrictive than 5/hour
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 3600 } },
        { rateLimit: { count: 5, windowSeconds: 60 } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when candidate rateLimit.windowSeconds is longer than parent (lower rate)', () => {
    // { count: 5, windowSeconds: 120 } = 5/2min is MORE restrictive than 5/min
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 60 } },
        { rateLimit: { count: 5, windowSeconds: 120 } },
      ),
    ).not.toThrow()
  })

  it('security: cannot bypass hourly limit with a 1-second window', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 3600 } },
        { rateLimit: { count: 5, windowSeconds: 1 } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when candidate rateLimit is absent', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 60 } },
        {},
      ),
    ).not.toThrow()
  })

  it('does NOT throw when candidate rateLimit is equally restrictive', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 5, windowSeconds: 60 } },
        { rateLimit: { count: 5, windowSeconds: 60 } },
      ),
    ).not.toThrow()
  })

  it('does NOT throw when candidate rateLimit is more restrictive on both dimensions', () => {
    // count: 5 < 10 (fewer calls) AND windowSeconds: 240 > 120 (longer window = lower rate)
    expect(() =>
      assertConstraintsNotRelaxed(
        { rateLimit: { count: 10, windowSeconds: 120 } },
        { rateLimit: { count: 5, windowSeconds: 240 } },
      ),
    ).not.toThrow()
  })
})

describe('assertConstraintsNotRelaxed — deniedActions', () => {
  it('throws CONSTRAINT_RELAXATION when child removes a parent deny entry', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { deniedActions: ['rm*', 'sudo*'] },
        { deniedActions: ['rm*'] }, // missing sudo*
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when child adds a new deny entry', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { deniedActions: ['rm*'] },
        { deniedActions: ['rm*', 'sudo*'] },
      ),
    ).not.toThrow()
  })

  it('does NOT throw when child has no deniedActions (merge will union them in)', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { deniedActions: ['rm*'] },
        {},
      ),
    ).not.toThrow()
  })
})

describe('assertConstraintsNotRelaxed — allowedActions wildcard', () => {
  it('throws CONSTRAINT_RELAXATION when child tries to expand allowedActions to wildcard', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedActions: ['npm', 'git'] },
        { allowedActions: ['*'] },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when parent has wildcard and child narrows to explicit list', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedActions: ['*'] },
        { allowedActions: ['npm'] },
      ),
    ).not.toThrow()
  })
})

describe('assertConstraintsNotRelaxed — allowedActions', () => {
  it('throws CONSTRAINT_RELAXATION when candidate adds an action not in parent', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedActions: ['GET', 'POST'] },
        { allowedActions: ['GET', 'DELETE'] },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('does NOT throw when candidate is a strict subset of parent', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedActions: ['GET', 'POST', 'PUT'] },
        { allowedActions: ['GET'] },
      ),
    ).not.toThrow()
  })

  it('does NOT throw when candidate allowedActions is absent', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { allowedActions: ['GET'] },
        {},
      ),
    ).not.toThrow()
  })

  // Logic A: deep equality for parameterLocks values
  it('passes when parameterLocks object value is structurally identical', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { filter: { id: 123 } } },
        { parameterLocks: { filter: { id: 123 } } },
      ),
    ).not.toThrow()
  })

  it('throws CONSTRAINT_RELAXATION when parameterLocks object value differs', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { filter: { id: 123 } } },
        { parameterLocks: { filter: { id: 999 } } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })

  it('passes when parameterLocks array value is structurally identical', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { tags: ['a', 'b'] } },
        { parameterLocks: { tags: ['a', 'b'] } },
      ),
    ).not.toThrow()
  })

  it('throws CONSTRAINT_RELAXATION when parameterLocks array value differs', () => {
    expect(() =>
      assertConstraintsNotRelaxed(
        { parameterLocks: { tags: ['a', 'b'] } },
        { parameterLocks: { tags: ['a', 'c'] } },
      ),
    ).toThrow(expect.objectContaining({ code: AmapErrorCode.CONSTRAINT_RELAXATION }))
  })
})
