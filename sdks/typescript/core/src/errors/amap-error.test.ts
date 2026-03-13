import { describe, it, expect } from 'vitest'
import { AmapError } from './amap-error.js'
import { AmapErrorCode } from './codes.js'

describe('AmapError', () => {
  it('is an instance of Error and AmapError', () => {
    const err = new AmapError(AmapErrorCode.TOKEN_EXPIRED, 'token expired')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(AmapError)
  })

  it('has the correct code, message, and name', () => {
    const err = new AmapError(AmapErrorCode.PERMISSION_INFLATION, 'exceeded permissions')
    expect(err.code).toBe('PERMISSION_INFLATION')
    expect(err.message).toBe('exceeded permissions')
    expect(err.name).toBe('AmapError')
  })

  it('carries hop index when provided', () => {
    const err = new AmapError(AmapErrorCode.INVALID_SIGNATURE, 'bad sig', 2)
    expect(err.hop).toBe(2)
  })

  it('hop is undefined when not provided', () => {
    const err = new AmapError(AmapErrorCode.STALE_REQUEST, 'stale')
    expect(err.hop).toBeUndefined()
  })

  it('all 12 error codes are defined', () => {
    const codes = Object.values(AmapErrorCode)
    expect(codes).toHaveLength(12)
    expect(codes).toContain('PERMISSION_INFLATION')
    expect(codes).toContain('EXPIRY_VIOLATION')
    expect(codes).toContain('CONSTRAINT_RELAXATION')
    expect(codes).toContain('INVALID_SIGNATURE')
    expect(codes).toContain('INVALID_REQUEST_SIGNATURE')
    expect(codes).toContain('BROKEN_CHAIN')
    expect(codes).toContain('TOKEN_EXPIRED')
    expect(codes).toContain('NONCE_REPLAYED')
    expect(codes).toContain('AGENT_REVOKED')
    expect(codes).toContain('AGENT_UNKNOWN')
    expect(codes).toContain('PARAMETER_LOCK_VIOLATION')
    expect(codes).toContain('STALE_REQUEST')
  })

  it('can be caught and narrowed by code', () => {
    const err = new AmapError(AmapErrorCode.NONCE_REPLAYED, 'replay detected')
    try {
      throw err
    } catch (e) {
      expect(e).toBeInstanceOf(AmapError)
      if (e instanceof AmapError) {
        expect(e.code).toBe(AmapErrorCode.NONCE_REPLAYED)
      }
    }
  })
})
