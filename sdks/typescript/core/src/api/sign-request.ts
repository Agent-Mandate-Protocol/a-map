import { randomBytes } from 'node:crypto'
import { canonicalize } from '../crypto/canonicalize.js'
import { signCanonical } from '../crypto/sign.js'
import type { SignRequestOptions, SignedRequestHeaders } from './types.js'

/**
 * Sign an outgoing HTTP request with the agent's Ed25519 identity and a fresh nonce.
 * Returns X-AMAP-* headers ready to spread into a fetch() call or any HTTP client.
 *
 * The mandate chain is base64url-encoded JSON and carried in X-AMAP-Mandate.
 * The request signature covers: method, path, body, timestamp, nonce.
 *
 * This function is synchronous — all crypto is synchronous, no I/O.
 */
export function signRequest(opts: SignRequestOptions): SignedRequestHeaders {
  const timestamp = new Date().toISOString()
  const nonce = randomBytes(16).toString('hex')

  const signedPayload = canonicalize({
    method: opts.method,
    path: opts.path,
    body: opts.body,
    timestamp,
    nonce,
  })

  const signature = signCanonical(opts.privateKey, signedPayload)
  const mandate = Buffer.from(JSON.stringify(opts.mandateChain), 'utf8').toString('base64url')

  return {
    'X-AMAP-Agent-DID': opts.agentDid,
    'X-AMAP-Timestamp': timestamp,
    'X-AMAP-Nonce': nonce,
    'X-AMAP-Signature': signature,
    'X-AMAP-Mandate': mandate,
  }
}
