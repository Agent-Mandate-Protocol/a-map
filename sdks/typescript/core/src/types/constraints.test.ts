import { describe, it, expect } from 'vitest'
import { mergeConstraints, mergeConstraintChain } from './constraints.js'

describe('mergeConstraints', () => {
  it('maxSpend: min wins', () => {
    expect(mergeConstraints({ maxSpend: 500 }, { maxSpend: 347 }).maxSpend).toBe(347)
    expect(mergeConstraints({ maxSpend: 100 }, { maxSpend: 500 }).maxSpend).toBe(100)
  })

  it('maxSpend: present in only one side is preserved', () => {
    expect(mergeConstraints({ maxSpend: 500 }, {}).maxSpend).toBe(500)
    expect(mergeConstraints({}, { maxSpend: 200 }).maxSpend).toBe(200)
  })

  it('maxCalls: min wins', () => {
    expect(mergeConstraints({ maxCalls: 10 }, { maxCalls: 5 }).maxCalls).toBe(5)
    expect(mergeConstraints({ maxCalls: 3 }, { maxCalls: 100 }).maxCalls).toBe(3)
  })

  it('rateLimit: min(count), max(windowSeconds) — most restrictive rate wins', () => {
    const result = mergeConstraints(
      { rateLimit: { count: 10, windowSeconds: 60 } },
      { rateLimit: { count: 5, windowSeconds: 120 } }
    )
    expect(result.rateLimit?.count).toBe(5)           // min: fewer calls
    expect(result.rateLimit?.windowSeconds).toBe(120) // max: longer window = lower rate
  })

  it('readOnly: once true, always true', () => {
    expect(mergeConstraints({ readOnly: true }, {}).readOnly).toBe(true)
    expect(mergeConstraints({}, { readOnly: true }).readOnly).toBe(true)
    expect(mergeConstraints({ readOnly: true }, { readOnly: false }).readOnly).toBe(true)
    expect(mergeConstraints({}, {}).readOnly).toBeUndefined()
  })

  it('allowedDomains: intersection', () => {
    const result = mergeConstraints(
      { allowedDomains: ['a.com', 'b.com'] },
      { allowedDomains: ['b.com', 'c.com'] }
    )
    expect(result.allowedDomains).toEqual(['b.com'])
  })

  it('allowedDomains: present in only one side is preserved', () => {
    expect(mergeConstraints({ allowedDomains: ['a.com'] }, {}).allowedDomains).toEqual(['a.com'])
    expect(mergeConstraints({}, { allowedDomains: ['b.com'] }).allowedDomains).toEqual(['b.com'])
  })

  it('allowedActions: intersection', () => {
    const result = mergeConstraints(
      { allowedActions: ['GET', 'POST'] },
      { allowedActions: ['GET', 'DELETE'] }
    )
    expect(result.allowedActions).toEqual(['GET'])
  })

  it('parameterLocks: union — all ancestor locks preserved', () => {
    const result = mergeConstraints(
      { parameterLocks: { to: 'boss@company.com' } },
      { parameterLocks: { subject: 'Re: invoice' } }
    )
    expect(result.parameterLocks).toEqual({
      to: 'boss@company.com',
      subject: 'Re: invoice',
    })
  })

  it('parameterLocks: parent lock cannot be overridden by child', () => {
    const result = mergeConstraints(
      { parameterLocks: { to: 'boss@company.com' } },
      { parameterLocks: { to: 'hacker@evil.com' } }
    )
    expect(result.parameterLocks?.['to']).toBe('boss@company.com')
  })

  it('returns empty object when both sides have no constraints', () => {
    expect(mergeConstraints({}, {})).toEqual({})
  })
})

describe('mergeConstraints — deniedActions (union)', () => {
  it('union: both sides merged', () => {
    const result = mergeConstraints(
      { deniedActions: ['rm*'] },
      { deniedActions: ['sudo*'] },
    )
    expect(result.deniedActions).toContain('rm*')
    expect(result.deniedActions).toContain('sudo*')
  })

  it('child adds new deny — allowed', () => {
    const result = mergeConstraints(
      { deniedActions: ['rm*'] },
      { deniedActions: ['rm*', 'sudo*'] },
    )
    expect(result.deniedActions).toHaveLength(2)
  })

  it('absent deniedActions on child side — parent preserved', () => {
    const result = mergeConstraints({ deniedActions: ['rm*'] }, {})
    expect(result.deniedActions).toEqual(['rm*'])
  })

  it('absent deniedActions on parent side — child preserved', () => {
    const result = mergeConstraints({}, { deniedActions: ['sudo*'] })
    expect(result.deniedActions).toEqual(['sudo*'])
  })

  it('deduplicates identical entries', () => {
    const result = mergeConstraints(
      { deniedActions: ['rm*', 'sudo*'] },
      { deniedActions: ['rm*', 'sudo*'] },
    )
    expect(result.deniedActions).toHaveLength(2)
  })
})

describe('mergeConstraints — allowedActions wildcard', () => {
  it('parent wildcard + child explicit list → child list (narrowing)', () => {
    const result = mergeConstraints(
      { allowedActions: ['*'] },
      { allowedActions: ['npm', 'git'] },
    )
    expect(result.allowedActions).toEqual(['npm', 'git'])
  })

  it('both wildcard → wildcard', () => {
    const result = mergeConstraints(
      { allowedActions: ['*'] },
      { allowedActions: ['*'] },
    )
    expect(result.allowedActions).toEqual(['*'])
  })

  it('child wildcard + parent explicit → parent list (child cannot widen)', () => {
    const result = mergeConstraints(
      { allowedActions: ['npm', 'git'] },
      { allowedActions: ['*'] },
    )
    expect(result.allowedActions).toEqual(['npm', 'git'])
  })
})

describe('mergeConstraintChain', () => {
  it('applies most restrictive across multiple hops', () => {
    const result = mergeConstraintChain([
      { maxSpend: 500, maxCalls: 50 },
      { maxSpend: 347, maxCalls: 50 },
      { maxSpend: 347, maxCalls: 10 },
    ])
    expect(result.maxSpend).toBe(347)
    expect(result.maxCalls).toBe(10)
  })

  it('returns empty object for empty chain', () => {
    expect(mergeConstraintChain([])).toEqual({})
  })

  it('returns the single element unchanged for a 1-element chain', () => {
    const result = mergeConstraintChain([{ maxSpend: 100, readOnly: true }])
    expect(result.maxSpend).toBe(100)
    expect(result.readOnly).toBe(true)
  })

  it('accumulates parameterLocks across all hops', () => {
    const result = mergeConstraintChain([
      { parameterLocks: { to: 'boss@company.com' } },
      { parameterLocks: { subject: 'Quarterly Report' } },
      { parameterLocks: { cc: 'audit@company.com' } },
    ])
    expect(result.parameterLocks).toEqual({
      to: 'boss@company.com',
      subject: 'Quarterly Report',
      cc: 'audit@company.com',
    })
  })
})
