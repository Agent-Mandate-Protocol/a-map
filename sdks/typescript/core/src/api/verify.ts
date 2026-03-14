import { randomUUID } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { sha256ofObject } from '../crypto/hash.js'
import { verifySignature } from '../crypto/sign.js'
import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'
import { mergeConstraintChain } from '../types/constraints.js'
import { InMemoryNonceStore } from '../types/nonce-store.js'
import type { DelegationToken } from '../types/token.js'
import type { VerificationResult, VerifiedLink } from '../types/result.js'
import type { VerifyOptions } from './types.js'
import { assertConstraintsNotRelaxed } from './validate-constraints.js'

export async function verify(
  chain: DelegationToken[],
  opts: VerifyOptions,
): Promise<VerificationResult> {
  if (chain.length === 0) {
    throw new AmapError(AmapErrorCode.BROKEN_CHAIN, 'Chain must contain at least one token')
  }

  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()
  const now = new Date()
  const verifiedLinks: VerifiedLink[] = []

  for (let i = 0; i < chain.length; i++) {
    const token = chain[i]!

    // Step 1: Expiry check
    if (new Date(token.expiresAt) < now) {
      throw new AmapError(
        AmapErrorCode.TOKEN_EXPIRED,
        `Token at hop ${i} expired at ${token.expiresAt}`,
        i,
      )
    }

    // Steps 2–3: Chain hash linkage
    if (i === 0) {
      if (token.parentTokenHash !== null) {
        throw new AmapError(
          AmapErrorCode.BROKEN_CHAIN,
          'Root token must have parentTokenHash = null',
          0,
        )
      }
    } else {
      const expectedHash = sha256ofObject(chain[i - 1]!)
      if (token.parentTokenHash !== expectedHash) {
        throw new AmapError(
          AmapErrorCode.BROKEN_CHAIN,
          `parentTokenHash mismatch at hop ${i}`,
          i,
        )
      }
    }

    // Step 4: Resolve issuer public key
    const publicKey = opts.registry ? await opts.registry.resolve(token.issuer) : null
    if (publicKey === null) {
      throw new AmapError(AmapErrorCode.AGENT_UNKNOWN, `Cannot resolve DID: ${token.issuer}`, i)
    }

    // Step 5: Revocation check
    if (opts.registry && (await opts.registry.isRevoked(token.issuer))) {
      throw new AmapError(
        AmapErrorCode.AGENT_REVOKED,
        `Agent ${token.issuer} has been revoked`,
        i,
      )
    }

    // Step 6: Signature verification — sign over payload (all fields except signature)
    const { signature, ...payload } = token
    if (!verifySignature(publicKey, canonicalize(payload), signature)) {
      throw new AmapError(AmapErrorCode.INVALID_SIGNATURE, `Invalid signature at hop ${i}`, i)
    }

    // Step 7: Re-enforce invariants vs parent (hops 1+)
    if (i > 0) {
      const parent = chain[i - 1]!

      // Permission narrowing
      const illegalPerms = token.permissions.filter(p => !parent.permissions.includes(p))
      if (illegalPerms.length > 0) {
        throw new AmapError(
          AmapErrorCode.PERMISSION_INFLATION,
          `Hop ${i} claims permissions not granted by parent: ${illegalPerms.join(', ')}`,
          i,
        )
      }

      // Expiry
      if (new Date(token.expiresAt) > new Date(parent.expiresAt)) {
        throw new AmapError(
          AmapErrorCode.EXPIRY_VIOLATION,
          `Hop ${i} expiresAt exceeds parent`,
          i,
        )
      }

      // Constraint non-relaxation
      const mergedParent = mergeConstraintChain(chain.slice(0, i).map(t => t.constraints))
      assertConstraintsNotRelaxed(mergedParent, token.constraints)
    }

    // Step 8: Nonce replay check
    if (!(await nonceStore.check(token.nonce))) {
      throw new AmapError(AmapErrorCode.NONCE_REPLAYED, `Nonce already seen at hop ${i}`, i)
    }

    // Step 9: Mark nonce as used
    await nonceStore.mark(token.nonce, new Date(token.expiresAt))

    verifiedLinks.push({ hop: i, token, issuer: token.issuer, delegate: token.delegate })
  }

  const leafToken = chain[chain.length - 1]!

  // Step 10: Delegate check — the leaf must delegate to the expected agent
  if (leafToken.delegate !== opts.expectedDelegate) {
    throw new AmapError(
      AmapErrorCode.INVALID_SIGNATURE,
      `Chain is delegated to ${leafToken.delegate}, not ${opts.expectedDelegate}`,
    )
  }

  // Step 11: Permission check
  if (!leafToken.permissions.includes(opts.expectedPermission)) {
    throw new AmapError(
      AmapErrorCode.PERMISSION_INFLATION,
      `Chain does not grant permission "${opts.expectedPermission}"`,
    )
  }

  // Steps 12–13: parameterLocks check
  if (opts.requestParams !== undefined) {
    const allLocks: Record<string, unknown> = {}
    for (const token of chain) {
      if (token.constraints.parameterLocks) {
        Object.assign(allLocks, token.constraints.parameterLocks)
      }
    }
    for (const [key, lockedValue] of Object.entries(allLocks)) {
      if (opts.requestParams[key] !== lockedValue) {
        throw new AmapError(
          AmapErrorCode.PARAMETER_LOCK_VIOLATION,
          `Parameter "${key}" must be "${String(lockedValue)}" (locked by mandate), got "${String(opts.requestParams[key])}"`,
        )
      }
    }
  }

  // Step 14: Compute effective constraints — most restrictive across all hops
  const effectiveConstraints = mergeConstraintChain(chain.map(t => t.constraints))

  // Step 15: Return result
  return {
    valid: true,
    principal: chain[0]!.principal,
    chain: verifiedLinks,
    effectiveConstraints,
    auditId: randomUUID(),
  }
}
