import type { Constraints } from './constraints.js'

export interface DelegationToken {
  /** Schema version. Always '1' for now. */
  version: '1'

  /** UUID v4 — unique per token. */
  tokenId: string

  /**
   * SHA-256 hex of the canonical JSON of the parent token.
   * null for the root token (issued directly by a human principal).
   * Forms the tamper-evident hash chain — any modification to a parent
   * token breaks all child token hashes downstream.
   */
  parentTokenHash: string | null

  /**
   * Human or org identifier at the root of this chain.
   * Carried through unchanged in every child token.
   * Examples: 'alice@example.com', 'org:acme'
   */
  principal: string

  /**
   * DID of the agent issuing this token.
   * Format: did:amap:{name}:{version}:{fingerprint}
   * For root tokens, this is the human principal's DID (or a well-known issuer identifier).
   */
  issuer: string

  /**
   * DID of the agent receiving this delegation.
   * This agent's private key must be used to sign any child tokens.
   */
  delegate: string

  /**
   * Capabilities granted to the delegate.
   * Must be a strict subset of the parent token's permissions.
   * Examples: ['read_email', 'book_flight']
   */
  permissions: string[]

  /** Typed constraints. See Constraints for per-field merge semantics. */
  constraints: Constraints

  /** ISO 8601 datetime when this token was created. */
  issuedAt: string

  /**
   * ISO 8601 datetime when this token expires.
   * Must be <= parent token's expiresAt.
   * Prefer short TTLs — 15 minutes for most use cases, 24h max for root.
   */
  expiresAt: string

  /**
   * 128-bit random hex string. Single-use — replay prevention.
   * The NonceStore tracks seen nonces and rejects duplicates.
   */
  nonce: string

  /**
   * Optional SHA-256 hex of the instruction the agent received.
   * When present, the tool verifier hashes the instruction it received
   * and checks it matches. If the agent tries to reuse a mandate for a
   * different intent, the hash mismatch rejects the call.
   */
  intentHash?: string

  /**
   * Ed25519 signature of the canonical JSON of all fields above (excluding signature itself).
   * Signed by the issuer's private key. base64url-encoded.
   */
  signature: string
}

/** The fields that are signed — everything except `signature`. */
export type DelegationTokenPayload = Omit<DelegationToken, 'signature'>
