import { createHash } from 'node:crypto'

export interface ComputeDIDOptions {
  /** 'human' produces did:amap:human:{name}:{fp}, 'agent' produces did:amap:agent:{name}:{version}:{fp} */
  type: 'human' | 'agent'
  /** Human-readable name component */
  name: string
  /** Required for type='agent'. Ignored for type='human'. */
  version?: string
  /** base64url-encoded Ed25519 public key */
  publicKey: string
}

/**
 * Derive a deterministic DID from an Ed25519 public key.
 *
 * Formats:
 *   Human: `did:amap:human:{name}:{fingerprint}`
 *   Agent: `did:amap:agent:{name}:{version}:{fingerprint}`
 *
 * Fingerprint = first 8 chars of base64url(SHA-256(publicKey bytes)).
 *
 * Self-certifying: the DID is derived deterministically from the public key.
 * No central registry is needed to verify a DID.
 */
export function computeDID(opts: ComputeDIDOptions): string {
  const keyBytes = Buffer.from(opts.publicKey, 'base64url')
  const fp = createHash('sha256')
    .update(keyBytes)
    .digest('base64url')
    .slice(0, 8)

  const safeName = opts.name.toLowerCase().replace(/[^a-z0-9-]/g, '-')

  if (opts.type === 'human') {
    return `did:amap:human:${safeName}:${fp}`
  }

  const safeVersion = (opts.version ?? '1.0').replace(/[^a-z0-9.-]/g, '-')
  return `did:amap:agent:${safeName}:${safeVersion}:${fp}`
}
