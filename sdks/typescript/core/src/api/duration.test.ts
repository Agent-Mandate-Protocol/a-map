import { describe, it, expect } from 'vitest'
import { parseDurationMs } from './duration.js'
import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'

describe('parseDurationMs', () => {
  it('parses minutes', () => expect(parseDurationMs('15m')).toBe(900_000))
  it('parses hours', () => expect(parseDurationMs('1h')).toBe(3_600_000))
  it('parses days', () => expect(parseDurationMs('7d')).toBe(604_800_000))
  it('parses seconds', () => expect(parseDurationMs('30s')).toBe(30_000))
  it('parses milliseconds', () => expect(parseDurationMs('500ms')).toBe(500))

  it('throws EXPIRY_VIOLATION for invalid format', () => {
    expect(() => parseDurationMs('1hour')).toThrow(AmapError)
    expect(() => parseDurationMs('1hour')).toThrow(
      expect.objectContaining({ code: AmapErrorCode.EXPIRY_VIOLATION }),
    )
    expect(() => parseDurationMs('')).toThrow(AmapError)
    expect(() => parseDurationMs('abc')).toThrow(AmapError)
  })
})
