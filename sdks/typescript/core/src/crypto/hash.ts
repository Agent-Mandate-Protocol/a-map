import { createHash } from 'node:crypto'
import { canonicalize } from './canonicalize.js'

/**
 * SHA-256 hash of a string or Buffer. Returns lowercase hex.
 */
export function sha256hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex')
}

/**
 * SHA-256 hash of any value via its JCS canonical JSON representation.
 * Used for parentTokenHash computation — ensures hash is stable regardless
 * of key insertion order in the token object.
 */
export function sha256ofObject(obj: unknown): string {
  return sha256hex(canonicalize(obj))
}
