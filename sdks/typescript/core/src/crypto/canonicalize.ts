/**
 * Inline JCS (RFC 8785) — deterministic JSON canonicalization.
 * No external dependencies.
 *
 * Rules:
 * 1. Object keys are sorted lexicographically (Unicode code point order)
 * 2. No whitespace
 * 3. Strings use \uXXXX escapes only where required by JSON spec
 * 4. Numbers use shortest representation
 * 5. Applied recursively to nested objects and arrays
 *
 * Why this matters: every Ed25519 signature in A-MAP is computed over the
 * canonical form of the token. Two implementations must produce byte-for-byte
 * identical output for the same object regardless of key insertion order —
 * otherwise signatures will not verify across implementations or runtimes.
 */

const MAX_DEPTH = 32

function _canonicalize(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new RangeError(`canonicalize: object nesting exceeds maximum depth of ${MAX_DEPTH}`)
  }

  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }

  if (Array.isArray(value)) {
    return '[' + value.map(v => _canonicalize(v, depth + 1)).join(',') + ']'
  }

  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  const pairs = keys.map(k => JSON.stringify(k) + ':' + _canonicalize(obj[k], depth + 1))
  return '{' + pairs.join(',') + '}'
}

export function canonicalize(value: unknown): string {
  return _canonicalize(value, 0)
}
