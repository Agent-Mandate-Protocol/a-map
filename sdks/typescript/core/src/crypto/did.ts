import { createHash } from 'node:crypto'

/**
 * Derive a deterministic DID from an Ed25519 public key.
 *
 * Format: `did:amap:{name}:{version}:{fingerprint}`
 *
 * Fingerprint = first 16 bytes of SHA-256(publicKey DER bytes), hex-encoded.
 * This gives 32 hex chars — short enough to be readable, long enough to be unique.
 *
 * Self-certifying: the DID is derived deterministically from the public key.
 * No central registry is needed to verify a DID.
 *
 * Invariant: same public key + same name + same version always produces the same DID.
 */
export function computeDID(name: string, version: string, publicKeyBase64url: string): string {
  const keyBytes = Buffer.from(publicKeyBase64url, 'base64url')
  const fingerprint = createHash('sha256')
    .update(keyBytes)
    .digest('hex')
    .slice(0, 32)

  const safeName = name.toLowerCase().replace(/[^a-z0-9-]/g, '-')
  const safeVersion = version.replace(/[^a-z0-9.-]/g, '-')

  return `did:amap:${safeName}:${safeVersion}:${fingerprint}`
}
