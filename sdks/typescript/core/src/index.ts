// Crypto primitives (T2)
export { keygen, type Keypair } from './crypto/keygen.js'
export { computeDID } from './crypto/did.js'
export { canonicalize } from './crypto/canonicalize.js'
export { sha256hex, sha256ofObject } from './crypto/hash.js'

// Types (T3)
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
