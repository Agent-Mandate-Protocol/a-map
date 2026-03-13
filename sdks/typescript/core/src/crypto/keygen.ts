import { generateKeyPairSync } from 'node:crypto'

export interface Keypair {
  /** base64url-encoded Ed25519 public key (SPKI DER format) */
  publicKey: string
  /** base64url-encoded Ed25519 private key (PKCS8 DER format) */
  privateKey: string
}

/**
 * Generate a fresh Ed25519 keypair.
 * Keys are base64url-encoded (no padding, URL-safe) — consistent with JWT conventions.
 * Uses Node.js built-in `node:crypto` only — zero npm dependencies.
 */
export function keygen(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  })

  return {
    publicKey: publicKey.toString('base64url'),
    privateKey: privateKey.toString('base64url'),
  }
}
