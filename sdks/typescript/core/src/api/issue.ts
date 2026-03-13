import { randomBytes, randomUUID } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { signCanonical } from '../crypto/sign.js'
import type { DelegationToken, DelegationTokenPayload } from '../types/token.js'
import type { IssueOptions } from './types.js'
import { parseDurationMs } from './duration.js'

/**
 * Issue a root delegation token — the first token in a mandate chain.
 * Signed by the human principal's Ed25519 private key.
 *
 * The token has parentTokenHash = null, identifying it as the chain root.
 * All child tokens (via delegate()) hash back to this token.
 */
export async function issue(opts: IssueOptions): Promise<DelegationToken> {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + parseDurationMs(opts.expiresIn))

  const payload: DelegationTokenPayload = {
    version: '1',
    tokenId: randomUUID(),
    parentTokenHash: null,
    principal: opts.principal,
    issuer: opts.issuerDid,
    delegate: opts.delegate,
    permissions: opts.permissions,
    constraints: opts.constraints ?? {},
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    nonce: randomBytes(16).toString('hex'),
    ...(opts.intentHash !== undefined ? { intentHash: opts.intentHash } : {}),
  }

  const signature = signCanonical(opts.privateKey, canonicalize(payload))

  return { ...payload, signature }
}
