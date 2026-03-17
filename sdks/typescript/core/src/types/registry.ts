import { createHash } from 'node:crypto'

/**
 * Verify that a public key matches the fingerprint embedded in a DID.
 *
 * DID format: did:amap:{...segments...}:{fingerprint}
 * Fingerprint = first 8 chars of base64url(SHA-256(publicKey bytes))
 *
 * Returns true only if the computed fingerprint matches the DID's last segment.
 * A false result means the registry returned a key that does not correspond to
 * this DID — either a compromised registry or a MITM substitution.
 */
function didFingerprintMatches(did: string, publicKeyBase64url: string): boolean {
  const expectedFingerprint = did.split(':').pop()
  if (!expectedFingerprint) return false
  const actualFingerprint = createHash('sha256')
    .update(Buffer.from(publicKeyBase64url, 'base64url'))
    .digest('base64url')
    .slice(0, 8)
  return actualFingerprint === expectedFingerprint
}

/**
 * Interface for resolving agent DIDs to public keys.
 * Abstracted so the offline (LocalKeyResolver) and hosted (HostedRegistryClient)
 * implementations are swappable without changing verify() logic.
 */
export interface KeyResolver {
  /**
   * Resolve a DID to a base64url-encoded Ed25519 public key.
   * Returns null if the DID is unknown.
   */
  resolve(did: string): Promise<string | null>
}

/**
 * Interface for checking whether an agent has been revoked.
 * Separated from KeyResolver so each concern can be swapped independently.
 */
export interface RevocationChecker {
  /**
   * Check if an agent has been revoked.
   * Returns true if the agent is revoked and should be rejected.
   */
  isRevoked(did: string): Promise<boolean>
}

/**
 * Offline key resolver backed by a local Map<did, publicKey>.
 * Use for tests, CLI tools, and airgapped deployments where public keys
 * are distributed out-of-band.
 */
export class LocalKeyResolver implements KeyResolver {
  constructor(private readonly keys: Map<string, string>) {}

  async resolve(did: string): Promise<string | null> {
    return this.keys.get(did) ?? null
  }
}

/**
 * Key resolver and revocation checker backed by a hosted A-MAP registry.
 *
 * Resolves DIDs and checks revocations via HTTP. Use in production deployments
 * where agents register their public keys with the registry.
 *
 * For airgapped or test deployments, use LocalKeyResolver instead.
 *
 * @example
 * ```ts
 * const resolver = new HostedRegistryClient('https://registry.agentmandateprotocol.dev')
 * const result = await amap.verify(chain, { keyResolver: resolver, revocationChecker: resolver })
 * ```
 */
export class HostedRegistryClient implements KeyResolver, RevocationChecker {
  constructor(
    private readonly registryUrl: string = 'https://registry.agentmandateprotocol.dev',
  ) {}

  async resolve(did: string): Promise<string | null> {
    try {
      const res = await fetch(`${this.registryUrl}/resolve/${encodeURIComponent(did)}`)
      if (!res.ok) return null
      const body = await res.json() as { publicKey: string }
      // Self-certifying check: the returned public key must produce a fingerprint
      // that matches the one embedded in the DID. A compromised or MITM'd registry
      // cannot substitute a different key without failing this check.
      if (!didFingerprintMatches(did, body.publicKey)) return null
      return body.publicKey
    } catch {
      return null
    }
  }

  async isRevoked(did: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.registryUrl}/revoked/${encodeURIComponent(did)}`)
      if (!res.ok) return false
      const body = await res.json() as { revoked: boolean }
      return body.revoked
    } catch {
      return false
    }
  }
}
