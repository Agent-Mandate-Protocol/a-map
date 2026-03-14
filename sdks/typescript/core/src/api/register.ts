import { computeDID } from '../crypto/did.js'

export interface RegisterOptions {
  /** Agent name — used in DID construction */
  name: string
  /** Agent version string, e.g. '1.0' */
  version: string
  /** base64url-encoded Ed25519 public key */
  publicKey: string
  /** Optional capability strings to publish alongside the key */
  capabilities?: string[]
  /**
   * Registry URL to publish to. Required in Phase 1 — the hosted registry
   * (registry.agentmandateprotocol.dev) does not exist yet. Use your own
   * registry or set up a local one. Phase 2 will add a default hosted URL.
   *
   * NOTE: register() is the ONLY function in @agentmandateprotocol/core that
   * makes a network call. All other functions (issue, delegate, verify,
   * signRequest, verifyRequest, revoke) work fully offline. register() is
   * optional — use LocalKeyResolver for fully airgapped deployments.
   */
  registryUrl: string
}

/**
 * Publish an agent's public key to an A-MAP registry.
 *
 * Enables other parties to resolve your DID to your public key for mandate
 * chain verification. Optional — the core protocol works fully offline with
 * LocalKeyResolver.
 *
 * @returns The DID derived from the public key. Deterministic: same key always
 *   produces the same DID regardless of whether register() is called.
 */
export async function register(opts: RegisterOptions): Promise<{ did: string }> {
  const did = computeDID({ type: 'agent', name: opts.name, version: opts.version, publicKey: opts.publicKey })
  const url = `${opts.registryUrl}/register`

  const body: Record<string, unknown> = { did, publicKey: opts.publicKey }
  if (opts.capabilities !== undefined) body['capabilities'] = opts.capabilities

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText)
    throw new Error(`Registry registration failed (${response.status}): ${text}`)
  }

  return { did }
}
