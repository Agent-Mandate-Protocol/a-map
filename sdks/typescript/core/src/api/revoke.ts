import { canonicalize } from '../crypto/canonicalize.js'
import { signCanonical } from '../crypto/sign.js'

export interface RevocationNotice {
  /** The DID being revoked */
  did: string
  /** ISO 8601 timestamp of revocation */
  revokedAt: string
  /** Ed25519 signature over canonical({ did, revokedAt }) — signed by the DID's private key */
  signature: string
}

/**
 * Produce a signed RevocationNotice for a DID.
 *
 * In Phase 1, this returns the notice but does NOT publish it — the caller
 * is responsible for submitting it to a registry. Phase 2 adds hosted publishing.
 *
 * @param did - the DID to revoke
 * @param privateKey - base64url-encoded Ed25519 private key corresponding to the DID
 * @returns a signed RevocationNotice
 */
export async function revoke(did: string, privateKey: string): Promise<RevocationNotice> {
  const revokedAt = new Date().toISOString()
  const payload = { did, revokedAt }
  const signature = signCanonical(privateKey, canonicalize(payload))
  return { did, revokedAt, signature }
}
