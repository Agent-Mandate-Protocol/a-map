import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'

const UNIT_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
}

/**
 * Parse a human-friendly duration string to milliseconds.
 * Supported units: ms, s, m, h, d
 * Examples: '15m', '1h', '24h', '7d', '500ms'
 */
export function parseDurationMs(input: string): number {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(input)
  if (!match) {
    throw new AmapError(
      AmapErrorCode.EXPIRY_VIOLATION,
      `Invalid expiresIn format: "${input}". Expected e.g. '15m', '1h', '24h'.`,
    )
  }
  const n = parseInt(match[1]!, 10)
  return n * UNIT_MS[match[2]!]!
}
