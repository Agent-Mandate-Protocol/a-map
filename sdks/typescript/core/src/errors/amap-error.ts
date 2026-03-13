import type { AmapErrorCode } from './codes.js'

/**
 * Typed error thrown by all A-MAP SDK functions.
 * Always has a machine-readable `code` from AmapErrorCode.
 */
export class AmapError extends Error {
  readonly code: AmapErrorCode
  /** The hop index (0-indexed) in the chain that caused the failure, if applicable. */
  readonly hop?: number

  constructor(code: AmapErrorCode, message: string, hop?: number) {
    super(message)
    this.name = 'AmapError'
    this.code = code
    if (hop !== undefined) this.hop = hop
  }
}
