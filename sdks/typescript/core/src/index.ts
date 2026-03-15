import { keygen } from './crypto/keygen.js'
import { computeDID } from './crypto/did.js'
import { register } from './api/register.js'
import { issue } from './api/issue.js'
import { delegate } from './api/delegate.js'
import { verify } from './api/verify.js'
import { revoke } from './api/revoke.js'
import { signRequest } from './api/sign-request.js'
import { verifyRequest } from './api/verify-request.js'
import { AmapPresets } from './api/presets.js'

/**
 * The amap namespace — the primary public API surface.
 * Import the whole namespace: `import { amap } from '@agentmandateprotocol/core'`
 */
export const amap = {
  keygen,
  computeDID,
  register,
  issue,
  delegate,
  verify,
  signRequest,
  verifyRequest,
  revoke,
  presets: AmapPresets,
}

// Named exports for consumers who prefer them
export { keygen, computeDID, register, issue, delegate, verify, signRequest, verifyRequest, revoke }

// Crypto primitives (T2)
export { canonicalize } from './crypto/canonicalize.js'
export { sha256hex, sha256ofObject } from './crypto/hash.js'

// Types (T3)
export type { Keypair } from './crypto/keygen.js'
export type { ComputeDIDOptions } from './crypto/did.js'
export type { DelegationToken, DelegationTokenPayload } from './types/token.js'
export type { Constraints } from './types/constraints.js'
export { mergeConstraints, mergeConstraintChain } from './types/constraints.js'
export type { VerificationResult, VerifiedLink } from './types/result.js'
export type { NonceStore } from './types/nonce-store.js'
export { InMemoryNonceStore } from './types/nonce-store.js'
export type { KeyResolver, RevocationChecker } from './types/registry.js'
export { LocalKeyResolver } from './types/registry.js'

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

// Revocation (T7)
export type { RevocationNotice, RevokeOptions } from './api/revoke.js'

// Registry (T15)
export type { RegisterOptions } from './api/register.js'

// Spec (T12) — /.well-known/agent.json
export type { AgentJson } from './spec/agent-json.js'
export { createAgentJson, fetchAgentJson } from './spec/agent-json.js'

// Policy (T17)
export { evaluatePolicy, matchesGlob } from './api/policy.js'
export type { PolicyDecision } from './api/policy.js'

// Presets (T17)
export { AmapPresets } from './api/presets.js'

/**
 * Build a permission string in OAuth 2.1 `resource:action` format.
 *
 * @example scope('email', 'send')   // → 'email:send'
 * @example scope('github', 'push')  // → 'github:push'
 */
export const scope = (resource: string, action: string): string => `${resource}:${action}`
