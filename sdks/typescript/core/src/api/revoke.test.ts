import { describe, it, expect } from 'vitest'
import { revoke } from './revoke.js'
import { keygen } from '../index.js'
import { verifySignature } from '../crypto/sign.js'
import { canonicalize } from '../crypto/canonicalize.js'

describe('amap.revoke()', () => {
  it('returns a RevocationNotice with correct shape', async () => {
    const { privateKey } = keygen()
    const did = 'did:amap:agent:agent:1.0:abc12345'
    const notice = await revoke({ did, privateKey })

    expect(notice.did).toBe(did)
    expect(notice.revokedAt).toBeTruthy()
    expect(new Date(notice.revokedAt)).toBeInstanceOf(Date)
    expect(notice.signature).toBeTruthy()
  })

  it('includes reason when provided', async () => {
    const { privateKey } = keygen()
    const notice = await revoke({ did: 'did:amap:agent:agent:1.0:abc12345', privateKey, reason: 'compromised' })
    expect(notice.reason).toBe('compromised')
  })

  it('omits reason when not provided', async () => {
    const { privateKey } = keygen()
    const notice = await revoke({ did: 'did:amap:agent:agent:1.0:abc12345', privateKey })
    expect(notice.reason).toBeUndefined()
  })

  it('signature verifies over canonical({ did, revokedAt })', async () => {
    const { publicKey, privateKey } = keygen()
    const did = 'did:amap:agent:agent:1.0:abc12345'
    const notice = await revoke({ did, privateKey })

    const payload = canonicalize({ did: notice.did, revokedAt: notice.revokedAt })
    expect(verifySignature(publicKey, payload, notice.signature)).toBe(true)
  })
})
