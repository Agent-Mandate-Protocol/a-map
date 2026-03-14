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
 * 1. X-AMAP-Timestamp within ±5 minutes          → STALE_REQUEST
 * 2. Parse X-AMAP-Mandate chain
 * 3. X-AMAP-Nonce not replayed                   → NONCE_REPLAYED
 * 4. X-AMAP-Signature valid over request payload → INVALID_REQUEST_SIGNATURE
 * 5. Mark request nonce (only after valid sig — prevents nonce burning on forged requests)
 * 6. Mandate chain valid (via verify())           → any chain error
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

  // Step 3: Request nonce replay check
  const nonce = headers['X-AMAP-Nonce']
  if (!nonce) {
    throw new AmapError(AmapErrorCode.NONCE_REPLAYED, 'Missing X-AMAP-Nonce header')
  }
  if (!(await nonceStore.check(nonce))) {
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

  const agentPublicKey = opts.registry ? await opts.registry.resolve(agentDid) : null
  if (agentPublicKey === null) {
    throw new AmapError(
      AmapErrorCode.AGENT_UNKNOWN,
      `Cannot resolve agent DID for request signature verification: ${agentDid}`,
    )
  }

  const signedPayload = canonicalize({ method, path, body, timestamp: timestampStr, nonce })
  if (!verifySignature(agentPublicKey, signedPayload, signatureHeader)) {
    throw new AmapError(AmapErrorCode.INVALID_REQUEST_SIGNATURE, 'X-AMAP-Signature is invalid')
  }

  // Step 5: Mark request nonce — only after signature is verified
  const leafToken = chain[chain.length - 1]!
  await nonceStore.mark(nonce, new Date(leafToken.expiresAt))

  // Step 6: Verify full mandate chain
  return verify(chain, {
    expectedPermission: opts.expectedPermission ?? leafToken.permissions[0] ?? '',
    expectedDelegate: agentDid,
    nonceStore,
    ...(opts.registry !== undefined ? { registry: opts.registry } : {}),
    ...(requestParams !== undefined ? { requestParams } : {}),
  })
}
