import { keygen } from './crypto/keygen.js'
import { computeDID } from './crypto/did.js'
import { issue } from './api/issue.js'
import { delegate } from './api/delegate.js'
import { verify, signRequest, verifyRequest, revoke } from './api/stubs.js'

/**
 * The amap namespace — the primary public API surface.
 * Import the whole namespace: `import { amap } from '@agentmandateprotocol/core'`
 */
export const amap = {
  keygen,
  computeDID,
  issue,
  delegate,
  verify,
  signRequest,
  verifyRequest,
  revoke,
}

// Named exports for consumers who prefer them
export { keygen, computeDID, issue, delegate, verify, signRequest, verifyRequest, revoke }

// Crypto primitives (T2)
export { canonicalize } from './crypto/canonicalize.js'
export { sha256hex, sha256ofObject } from './crypto/hash.js'

// Types (T3)
export type { Keypair } from './crypto/keygen.js'
export type { DelegationToken, DelegationTokenPayload } from './types/token.js'
export type { Constraints } from './types/constraints.js'
export { mergeConstraints, mergeConstraintChain } from './types/constraints.js'
export type { VerificationResult, VerifiedLink } from './types/result.js'
export type { NonceStore } from './types/nonce-store.js'
export { InMemoryNonceStore } from './types/nonce-store.js'
export type { AgentRegistry } from './types/registry.js'
export { LocalRegistryClient } from './types/registry.js'

// Errors (T3)
export { AmapError } from './errors/amap-error.js'
export { AmapErrorCode } from './errors/codes.js'
export type { AmapErrorCode as AmapErrorCodeType } from './errors/codes.js'

// API types (T3b)
export type {
  IssueOptions,
  DelegateOptions,
  VerifyOptions,
  SignRequestOptions,
  SignedRequestHeaders,
  VerifyRequestOptions,
} from './api/types.js'
