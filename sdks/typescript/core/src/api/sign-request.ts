import { createHash, randomBytes } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { signCanonical } from '../crypto/sign.js'
import type { SignRequestOptions, SignedRequestHeaders } from './types.js'

/**
 * Hash a body value (string | Buffer | undefined) to a hex SHA-256 string.
 * Empty body hashes to SHA-256('').
 */
function bodyHash(body: string | Buffer | undefined): string {
  const input = body ?? ''
  return createHash('sha256').update(input).digest('hex')
}

/**
 * Sign an outgoing HTTP request with the agent's Ed25519 identity and a fresh nonce.
 * Returns X-AMAP-* headers ready to spread into a fetch() call or any HTTP client.
 *
 * The mandate chain is base64url-encoded JSON and carried in X-AMAP-Mandate.
 * Agent DID is derived from the leaf token's delegate field — no explicit agentDid param needed.
 *
 * Signed payload: { mandateHash, bodyHash, method, path, timestamp, nonce }
 *   - mandateHash: SHA-256 of the X-AMAP-Mandate header string
 *   - bodyHash: SHA-256 of the body bytes (SHA-256('') for no body)
 *
 * This binds the signature to both the mandate and the body, preventing:
 *   - Mandate swap attacks (swapping mandate without invalidating signature)
 *   - Body tampering after signing
 */
export function signRequest(opts: SignRequestOptions): SignedRequestHeaders {
  const timestamp = new Date().toISOString()
  const nonce = randomBytes(16).toString('hex')

  const mandate = Buffer.from(JSON.stringify(opts.mandateChain), 'utf8').toString('base64url')
  const mandateHash = createHash('sha256').update(mandate).digest('hex')
  const bHash = bodyHash(opts.body)

  const signedPayload = canonicalize({
    mandateHash,
    bodyHash: bHash,
    method: opts.method,
    path: opts.path,
    timestamp,
    nonce,
  })

  const signature = signCanonical(opts.privateKey, signedPayload)

  // Derive agent DID from the leaf token's delegate field
  const leafToken = opts.mandateChain[opts.mandateChain.length - 1]
  const agentDid = leafToken?.delegate ?? ''

  return {
    'X-AMAP-Agent-DID': agentDid,
    'X-AMAP-Timestamp': timestamp,
    'X-AMAP-Nonce': nonce,
    'X-AMAP-Signature': signature,
    'X-AMAP-Mandate': mandate,
  }
}
