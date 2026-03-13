/**
 * Interface for resolving agent DIDs to public keys and checking revocations.
 * Abstracted so the offline (LocalRegistryClient) and hosted (HostedRegistryClient)
 * implementations are swappable without changing verify() logic.
 */
export interface AgentRegistry {
  /**
   * Resolve a DID to a base64url-encoded Ed25519 public key.
   * Returns null if the DID is unknown.
   */
  resolve(did: string): Promise<string | null>

  /**
   * Check if an agent has been revoked.
   * Returns true if the agent is revoked and should be rejected.
   */
  isRevoked(did: string): Promise<boolean>
}

/**
 * Offline registry backed by a local Map<did, publicKey>.
 * Use for tests, CLI tools, and airgapped deployments where public keys
 * are distributed out-of-band.
 *
 * Has no revocation list — all agents are considered active.
 */
export class LocalRegistryClient implements AgentRegistry {
  constructor(private readonly keys: Map<string, string>) {}

  async resolve(did: string): Promise<string | null> {
    return this.keys.get(did) ?? null
  }

  async isRevoked(_did: string): Promise<boolean> {
    return false
  }
}
