import type { DelegationToken, Constraints, NonceStore, AgentRegistry } from '../types/index.js'

export interface IssueOptions {
  /** Human or org identifier — carried through every child token. */
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
  /** DID of the issuer. */
  issuerDid: string
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
  /** DID of the delegating agent. */
  issuerDid: string
}

export interface VerifyOptions {
  /** The permission the tool requires for this action. */
  expectedPermission: string
  /** DID of the agent presenting the chain. */
  expectedDelegate: string
  /** Nonce store for replay prevention. Defaults to a new InMemoryNonceStore if omitted. */
  nonceStore?: NonceStore
  /** Registry for DID → public key resolution. */
  registry?: AgentRegistry
  /**
   * Request parameters to check against any parameterLocks in the chain.
   * If any token has parameterLocks, each locked key is compared against these.
   */
  requestParams?: Record<string, unknown>
}

export interface SignRequestOptions {
  method: string
  path: string
  body: unknown
  /** base64url-encoded Ed25519 private key of the agent making the request. */
  privateKey: string
  /** DID of the agent making the request. */
  agentDid: string
  /** The full mandate chain the agent carries. */
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
  body: unknown
  /** Request parameters to check against parameterLocks. */
  requestParams?: Record<string, unknown>
  nonceStore?: NonceStore
  registry?: AgentRegistry
}
