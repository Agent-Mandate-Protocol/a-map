import { createHash } from 'node:crypto'
import { AmapError } from '../errors/amap-error.js'
import { AmapErrorCode } from '../errors/codes.js'
import { canonicalize } from '../crypto/canonicalize.js'
import { verifySignature } from '../crypto/sign.js'
import { InMemoryNonceStore } from '../types/nonce-store.js'
import type { DelegationToken } from '../types/token.js'
import type { VerificationResult } from '../types/result.js'
import type { VerifyRequestOptions } from './types.js'
import { verify } from './verify.js'

const FIVE_MINUTES_MS = 5 * 60 * 1_000

/**
 * Verify an incoming signed request (both layers: mandate chain + request signature).
 *
 * Checks in order:
 * 1. X-AMAP-Timestamp within ±5 minutes             → STALE_REQUEST
 * 2. Parse X-AMAP-Mandate chain
 * 3. X-AMAP-Nonce not replayed (request-level)       → NONCE_REPLAYED
 * 4. X-AMAP-Signature valid over { mandateHash, bodyHash, method, path, timestamp, nonce }
 *                                                    → INVALID_REQUEST_SIGNATURE
 * 5. Mandate chain valid (via verify())              → any chain error
 */
export async function verifyRequest(opts: VerifyRequestOptions): Promise<VerificationResult> {
  const { headers, method, path, body, requestParams } = opts
  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()

  // Step 1: Timestamp freshness
  const timestampStr = headers['X-AMAP-Timestamp']
  if (!timestampStr) {
    throw new AmapError(AmapErrorCode.STALE_REQUEST, 'Missing X-AMAP-Timestamp header')
  }
  const timestampMs = new Date(timestampStr).getTime()
  if (isNaN(timestampMs) || Math.abs(Date.now() - timestampMs) > FIVE_MINUTES_MS) {
    throw new AmapError(
      AmapErrorCode.STALE_REQUEST,
      `Request timestamp is outside the ±5 minute window: ${timestampStr}`,
    )
  }

  // Step 2: Parse mandate chain
  const mandateHeader = headers['X-AMAP-Mandate']
  if (!mandateHeader) {
    throw new AmapError(AmapErrorCode.BROKEN_CHAIN, 'Missing X-AMAP-Mandate header')
  }
  let chain: DelegationToken[]
  try {
    chain = JSON.parse(
      Buffer.from(mandateHeader, 'base64url').toString('utf8'),
    ) as DelegationToken[]
  } catch {
    throw new AmapError(
      AmapErrorCode.BROKEN_CHAIN,
      'X-AMAP-Mandate is not valid base64url-encoded JSON',
    )
  }
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new AmapError(
      AmapErrorCode.BROKEN_CHAIN,
      'X-AMAP-Mandate must be a non-empty array of DelegationTokens',
    )
  }

  // Step 3: Request nonce replay check (atomic)
  const nonce = headers['X-AMAP-Nonce']
  if (!nonce) {
    throw new AmapError(AmapErrorCode.NONCE_REPLAYED, 'Missing X-AMAP-Nonce header')
  }
  // Fixed nonce TTL: 2× the timestamp freshness window (10 minutes).
  // The timestamp check already rejects any request older than ±5 minutes, so a nonce
  // cannot be replayed after that window regardless. Using the token's remaining lifetime
  // (which can be hours or days) would cause the nonce store to accumulate entries far
  // longer than necessary, wasting memory and slowing eviction.
  const requestTtlMs = 2 * FIVE_MINUTES_MS
  if (!(await nonceStore.checkAndStore(nonce, requestTtlMs))) {
    throw new AmapError(
      AmapErrorCode.NONCE_REPLAYED,
      'X-AMAP-Nonce has already been used (replay detected)',
    )
  }

  // Step 4: Request signature verification
  const agentDid = headers['X-AMAP-Agent-DID']
  if (!agentDid) {
    throw new AmapError(
      AmapErrorCode.INVALID_REQUEST_SIGNATURE,
      'Missing X-AMAP-Agent-DID header',
    )
  }
  const signatureHeader = headers['X-AMAP-Signature']
  if (!signatureHeader) {
    throw new AmapError(
      AmapErrorCode.INVALID_REQUEST_SIGNATURE,
      'Missing X-AMAP-Signature header',
    )
  }

  const agentPublicKey = opts.keyResolver ? await opts.keyResolver.resolve(agentDid) : null
  if (agentPublicKey === null) {
    throw new AmapError(
      AmapErrorCode.AGENT_UNKNOWN,
      `Cannot resolve agent DID for request signature verification: ${agentDid}`,
    )
  }

  // Compute mandateHash and bodyHash to match signRequest()
  const mandateHash = createHash('sha256').update(mandateHeader).digest('hex')
  const bHash = createHash('sha256').update(body ?? '').digest('hex')

  const signedPayload = canonicalize({
    mandateHash,
    bodyHash: bHash,
    method,
    path,
    timestamp: timestampStr,
    nonce,
  })
  if (!verifySignature(agentPublicKey, signedPayload, signatureHeader)) {
    throw new AmapError(AmapErrorCode.INVALID_REQUEST_SIGNATURE, 'X-AMAP-Signature is invalid')
  }

  // Step 5: Verify full mandate chain
  return verify({
    chain,
    ...(opts.expectedPermission !== undefined ? { expectedPermission: opts.expectedPermission } : {}),
    ...(opts.expectedPrincipal !== undefined ? { expectedPrincipal: opts.expectedPrincipal } : {}),
    expectedDelegate: agentDid,
    ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
    ...(opts.revocationChecker !== undefined ? { revocationChecker: opts.revocationChecker } : {}),
    ...(requestParams !== undefined ? { requestParams } : {}),
    ...(opts.requestedAction !== undefined ? { requestedAction: opts.requestedAction } : {}),
  })
}
