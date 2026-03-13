import { randomBytes, randomUUID } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { sha256ofObject } from '../crypto/hash.js'
import { signCanonical } from '../crypto/sign.js'
import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'
import { mergeConstraintChain } from '../types/constraints.js'
import type { DelegationToken, DelegationTokenPayload } from '../types/token.js'
import type { DelegateOptions } from './types.js'
import { parseDurationMs } from './duration.js'
import { assertConstraintsNotRelaxed } from './validate-constraints.js'

/**
 * Create a child delegation token that narrows the capabilities of its parent.
 * Enforces all three invariants before signing:
 *   1. Permissions can only narrow (PERMISSION_INFLATION)
 *   2. Expiry can only shorten (EXPIRY_VIOLATION)
 *   3. Constraints are additive — most restrictive wins (CONSTRAINT_RELAXATION)
 */
export async function delegate(opts: DelegateOptions): Promise<DelegationToken> {
  const parentToken = opts.parentToken

  // ── Invariant 1: Permission narrowing ──────────────────────────────────────
  const illegalPermissions = opts.permissions.filter(p => !parentToken.permissions.includes(p))
  if (illegalPermissions.length > 0) {
    throw new AmapError(
      AmapErrorCode.PERMISSION_INFLATION,
      `Requested permissions not in parent token: ${illegalPermissions.join(', ')}`,
    )
  }

  // ── Invariant 2: Expiry shortening ────────────────────────────────────────
  const now = new Date()
  const expiresAt = new Date(now.getTime() + parseDurationMs(opts.expiresIn))
  const parentExpiresAt = new Date(parentToken.expiresAt)

  if (expiresAt > parentExpiresAt) {
    throw new AmapError(
      AmapErrorCode.EXPIRY_VIOLATION,
      `Child expiresAt (${expiresAt.toISOString()}) exceeds parent expiresAt (${parentToken.expiresAt})`,
    )
  }

  // ── Invariant 3: Constraint non-relaxation ────────────────────────────────
  const mergedParentConstraints = mergeConstraintChain(opts.parentChain.map(t => t.constraints))
  if (opts.constraints !== undefined) {
    assertConstraintsNotRelaxed(mergedParentConstraints, opts.constraints)
  }

  // ── Build and sign payload ─────────────────────────────────────────────────
  const payload: DelegationTokenPayload = {
    version: '1',
    tokenId: randomUUID(),
    parentTokenHash: sha256ofObject(parentToken),
    principal: parentToken.principal,
    issuer: opts.issuerDid,
    delegate: opts.delegate,
    permissions: opts.permissions,
    constraints: opts.constraints ?? {},
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: randomBytes(16).toString('hex'),
  }

  const signature = signCanonical(opts.privateKey, canonicalize(payload))

  return { ...payload, signature }
}
