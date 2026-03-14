import { describe, it, expect } from 'vitest'
import { evaluatePolicy, matchesGlob } from './policy.js'

describe('matchesGlob()', () => {
  it('exact match', () => {
    expect(matchesGlob('rm -rf /', 'rm -rf /')).toBe(true)
    expect(matchesGlob('npm install', 'rm -rf /')).toBe(false)
  })

  it('wildcard * matches any sequence', () => {
    expect(matchesGlob('rm -rf /', 'rm*')).toBe(true)
    expect(matchesGlob('kubectl delete pods', '*delete*')).toBe(true)
    expect(matchesGlob('npm install', '*delete*')).toBe(false)
  })

  it('bare * matches everything', () => {
    expect(matchesGlob('anything', '*')).toBe(true)
    expect(matchesGlob('', '*')).toBe(true)
  })

  it('? matches exactly one character', () => {
    expect(matchesGlob('abc', 'a?c')).toBe(true)
    expect(matchesGlob('ac', 'a?c')).toBe(false)
  })

  it('does not match partial strings without wildcard', () => {
    expect(matchesGlob('rm -rf /home', 'rm -rf /')).toBe(false)
  })
})

describe('evaluatePolicy()', () => {
  it('EXPLICIT_DENY wins over wildcard allow', () => {
    const result = evaluatePolicy('rm -rf /', {
      allowedActions: ['*'],
      deniedActions: ['rm*'],
    })
    expect(result.decision).toBe('EXPLICIT_DENY')
    expect(result.matchedRule).toBe('rm*')
  })

  it('WILDCARD_ALLOW when allowedActions is ["*"] and no deny matches', () => {
    const result = evaluatePolicy('npm install', {
      allowedActions: ['*'],
      deniedActions: ['rm*'],
    })
    expect(result.decision).toBe('WILDCARD_ALLOW')
    expect(result.matchedRule).toBe('*')
  })

  it('EXPLICIT_ALLOW when action matches entry in allowedActions list', () => {
    const result = evaluatePolicy('npm install', {
      allowedActions: ['npm', 'git'],
    })
    expect(result.decision).toBe('EXPLICIT_ALLOW')
    expect(result.matchedRule).toBe('npm')
  })

  it('IMPLICIT_DENY when action not in allowedActions', () => {
    const result = evaluatePolicy('curl evil.com', {
      allowedActions: ['npm', 'git'],
    })
    expect(result.decision).toBe('IMPLICIT_DENY')
    expect(result.matchedRule).toBeUndefined()
  })

  it('IMPLICIT_DENY when no allowedActions defined', () => {
    const result = evaluatePolicy('npm install', {})
    expect(result.decision).toBe('IMPLICIT_DENY')
  })

  it('IMPLICIT_DENY when allowedActions is empty', () => {
    const result = evaluatePolicy('npm install', { allowedActions: [] })
    expect(result.decision).toBe('IMPLICIT_DENY')
  })

  it('EXPLICIT_DENY via glob pattern on action', () => {
    const result = evaluatePolicy('kubectl delete deployment', {
      allowedActions: ['*'],
      deniedActions: ['kubectl delete*'],
    })
    expect(result.decision).toBe('EXPLICIT_DENY')
  })

  it('EXPLICIT_DENY always checked before allow — order matters', () => {
    // Same action in both lists — deny wins
    const result = evaluatePolicy('npm install', {
      allowedActions: ['npm install'],
      deniedActions: ['npm install'],
    })
    expect(result.decision).toBe('EXPLICIT_DENY')
  })

  it('result contains the requested action', () => {
    const result = evaluatePolicy('git status', { allowedActions: ['git'] })
    expect(result.action).toBe('git status')
  })
})
