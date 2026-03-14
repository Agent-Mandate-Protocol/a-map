import type { DelegationToken, Constraints, NonceStore, KeyResolver, RevocationChecker } from '../types/index.js'

export interface IssueOptions {
  /** Human or org DID at the root of the chain. Becomes the token issuer for root tokens. */
  principal: string
  /** DID of the agent receiving this root delegation. */
  delegate: string
  /** Capabilities granted. */
  permissions: string[]
  /** Optional constraints on what the agent may do. */
  constraints?: Constraints
  /**
   * Optional SHA-256 hex of the instruction the agent received.
   * When present, the tool verifier can confirm the agent is acting on
   * the correct instruction — reusing a mandate for a different intent is rejected.
   */
  intentHash?: string
  /** Duration string, e.g. '15m', '1h', '24h'. */
  expiresIn: string
  /** base64url-encoded Ed25519 private key of the issuer. */
  privateKey: string
}

export interface DelegateOptions {
  /** The parent token being delegated from. */
  parentToken: DelegationToken
  /** Full chain up to and including parentToken (index 0 = root). */
  parentChain: DelegationToken[]
  /** DID of the agent receiving this delegation. */
  delegate: string
  /** Must be a subset of parentToken.permissions. */
  permissions: string[]
  /** Must be at least as restrictive as merged constraints across parentChain. */
  constraints?: Constraints
  /** Duration string — cannot exceed parent's remaining TTL. */
  expiresIn: string
  /** base64url-encoded Ed25519 private key of the delegating agent. */
  privateKey: string
}

export interface VerifyOptions {
  /** The mandate chain to verify (index 0 = root). */
  chain: DelegationToken[]
  /**
   * The permission the tool requires. If omitted, no permission check is performed —
   * the caller reads result.chain[last].token.permissions and checks itself.
   */
  expectedPermission?: string
  /**
   * DID of the agent presenting the chain. If omitted, no delegate check is performed.
   */
  expectedDelegate?: string
  /** Nonce store for replay prevention. Defaults to a new InMemoryNonceStore if omitted. */
  nonceStore?: NonceStore
  /** Key resolver for DID → public key resolution. */
  keyResolver?: KeyResolver
  /** Revocation checker. Optional — omit to skip revocation checks. */
  revocationChecker?: RevocationChecker
  /**
   * Request parameters to check against any parameterLocks in the chain.
   * If any token has parameterLocks, each locked key is compared against these.
   */
  requestParams?: Record<string, unknown>
  /**
   * Action string for IAM policy evaluation (T17).
   * If provided, the IAM policy engine evaluates the action against the chain.
   */
  requestedAction?: string
}

export interface SignRequestOptions {
  method: string
  path: string
  /** Request body as string or Buffer. Omit for requests with no body. */
  body?: string | Buffer
  /** base64url-encoded Ed25519 private key of the agent making the request. */
  privateKey: string
  /** The full mandate chain the agent carries. Agent DID is derived from the leaf delegate. */
  mandateChain: DelegationToken[]
}

export interface SignedRequestHeaders {
  'X-AMAP-Agent-DID': string
  'X-AMAP-Timestamp': string
  'X-AMAP-Nonce': string
  'X-AMAP-Signature': string
  'X-AMAP-Mandate': string
  [key: string]: string
}

export interface VerifyRequestOptions {
  headers: Record<string, string>
  method: string
  path: string
  /** Request body as string or Buffer. Omit for requests with no body. */
  body?: string | Buffer
  /** Request parameters to check against parameterLocks. */
  requestParams?: Record<string, unknown>
  nonceStore?: NonceStore
  /** Key resolver for DID → public key resolution. */
  keyResolver?: KeyResolver
  /** Revocation checker. Optional — omit to skip revocation checks. */
  revocationChecker?: RevocationChecker
  /**
   * If provided, verify() will check this permission is in the chain's leaf permissions.
   * If absent, no permission check is performed.
   */
  expectedPermission?: string
  /**
   * Action string for IAM policy evaluation (T17).
   */
  requestedAction?: string
}
