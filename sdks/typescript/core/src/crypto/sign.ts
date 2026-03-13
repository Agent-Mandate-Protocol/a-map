import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'

/**
 * Sign a canonical JSON string with an Ed25519 private key.
 * @param privateKeyBase64url - base64url-encoded PKCS8 DER private key (from keygen())
 * @param canonicalMessage - canonical JSON string to sign
 * @returns base64url-encoded Ed25519 signature
 */
export function signCanonical(privateKeyBase64url: string, canonicalMessage: string): string {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyBase64url, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  })
  return sign(null, Buffer.from(canonicalMessage, 'utf8'), key).toString('base64url')
}

/**
 * Verify an Ed25519 signature over a canonical JSON string.
 * @param publicKeyBase64url - base64url-encoded SPKI DER public key (from keygen())
 * @param canonicalMessage - the message that was signed
 * @param signatureBase64url - the signature to verify
 * @returns true if signature is valid
 */
export function verifySignature(
  publicKeyBase64url: string,
  canonicalMessage: string,
  signatureBase64url: string,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKeyBase64url, 'base64url'),
      format: 'der',
      type: 'spki',
    })
    return verify(
      null,
      Buffer.from(canonicalMessage, 'utf8'),
      key,
      Buffer.from(signatureBase64url, 'base64url'),
    )
  } catch {
    return false
  }
}
