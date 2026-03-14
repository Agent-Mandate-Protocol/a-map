import { canonicalize } from '../crypto/canonicalize.js'
import { signCanonical } from '../crypto/sign.js'

export interface RevokeOptions {
  /** The DID to revoke */
  did: string
  /** base64url-encoded Ed25519 private key corresponding to the DID */
  privateKey: string
  /** Optional human-readable reason for revocation */
  reason?: string
}

export interface RevocationNotice {
  /** The DID being revoked */
  did: string
  /** ISO 8601 timestamp of revocation */
  revokedAt: string
  /** Optional reason for revocation */
  reason?: string
  /** Ed25519 signature over canonical({ did, revokedAt, reason? }) — signed by the DID's private key */
  signature: string
}

/**
 * Produce a signed RevocationNotice for a DID.
 *
 * In Phase 1, this returns the notice but does NOT publish it — the caller
 * is responsible for submitting it to a registry. Phase 2 adds hosted publishing.
 */
export async function revoke(opts: RevokeOptions): Promise<RevocationNotice> {
  const revokedAt = new Date().toISOString()
  const payload: Record<string, string> = { did: opts.did, revokedAt }
  if (opts.reason !== undefined) payload['reason'] = opts.reason
  const signature = signCanonical(opts.privateKey, canonicalize(payload))
  return { did: opts.did, revokedAt, ...(opts.reason !== undefined ? { reason: opts.reason } : {}), signature }
}
