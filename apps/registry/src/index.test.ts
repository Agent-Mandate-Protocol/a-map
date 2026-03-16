import { describe, it, expect, beforeEach } from 'vitest'
import app from './index.js'

class FakeKV {
  private store = new Map<string, string>()
  async get(key: string) { return this.store.get(key) ?? null }
  async put(key: string, value: string) { this.store.set(key, value) }
  async delete(key: string) { this.store.delete(key) }
}

function makeEnv(overrides?: Partial<{ REGISTRY_DID: string; REGISTRY_PUBLIC_KEY: string }>) {
  return {
    AMAP_KEYS: new FakeKV(),
    AMAP_REVOKED: new FakeKV(),
    ...overrides,
  }
}

const TEST_DID = 'did:amap:test-agent:1.0:abc123'
const TEST_PUBLIC_KEY = 'MCowBQYDK2VwAyEAabc123fakePublicKeyBase64urlEncoded'

describe('GET /.well-known/agent.json', () => {
  it('returns agent.json with default did when REGISTRY_DID not set', async () => {
    const res = await app.request('/.well-known/agent.json', {}, makeEnv())
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['amap']).toBe('1.0')
    expect(body['did']).toBe('did:amap:registry:1.0:unknown')
    expect(body['requiresDelegationChain']).toBe(false)
    expect(body['name']).toBe('A-MAP Registry')
  })

  it('returns configured REGISTRY_DID when set', async () => {
    const env = makeEnv({ REGISTRY_DID: 'did:amap:registry:1.0:customkey' })
    const res = await app.request('/.well-known/agent.json', {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['did']).toBe('did:amap:registry:1.0:customkey')
  })

  it('includes publicKey when REGISTRY_PUBLIC_KEY is set', async () => {
    const env = makeEnv({ REGISTRY_PUBLIC_KEY: TEST_PUBLIC_KEY })
    const res = await app.request('/.well-known/agent.json', {}, env)
    const body = await res.json() as Record<string, unknown>
    expect(body['publicKey']).toBe(TEST_PUBLIC_KEY)
  })

  it('omits publicKey when REGISTRY_PUBLIC_KEY is not set', async () => {
    const res = await app.request('/.well-known/agent.json', {}, makeEnv())
    const body = await res.json() as Record<string, unknown>
    expect('publicKey' in body).toBe(false)
  })
})

describe('POST /register', () => {
  let env: ReturnType<typeof makeEnv>

  beforeEach(() => {
    env = makeEnv()
  })

  it('registers a DID successfully', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, publicKey: TEST_PUBLIC_KEY }),
    }, env)
    expect(res.status).toBe(201)
    const body = await res.json() as Record<string, unknown>
    expect(body['did']).toBe(TEST_DID)
    expect(body['registered']).toBe(true)
  })

  it('registers with capabilities', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, publicKey: TEST_PUBLIC_KEY, capabilities: ['email:read'] }),
    }, env)
    expect(res.status).toBe(201)
  })

  it('rejects missing did', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKey: TEST_PUBLIC_KEY }),
    }, env)
    expect(res.status).toBe(400)
    const body = await res.json() as Record<string, unknown>
    expect(typeof body['error']).toBe('string')
  })

  it('rejects empty did', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: '  ', publicKey: TEST_PUBLIC_KEY }),
    }, env)
    expect(res.status).toBe(400)
  })

  it('rejects missing publicKey', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID }),
    }, env)
    expect(res.status).toBe(400)
    const body = await res.json() as Record<string, unknown>
    expect(typeof body['error']).toBe('string')
  })

  it('rejects did not in did:amap format', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: 'did:web:example.com', publicKey: TEST_PUBLIC_KEY }),
    }, env)
    expect(res.status).toBe(400)
    const body = await res.json() as Record<string, unknown>
    expect(body['error']).toContain('did:amap')
  })

  it('rejects invalid JSON body', async () => {
    const res = await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    }, env)
    expect(res.status).toBe(400)
  })
})

describe('GET /resolve/:did', () => {
  let env: ReturnType<typeof makeEnv>

  beforeEach(() => {
    env = makeEnv()
  })

  it('resolves a registered DID', async () => {
    // First register
    await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, publicKey: TEST_PUBLIC_KEY, capabilities: ['email:read'] }),
    }, env)

    // Then resolve
    const res = await app.request(`/resolve/${TEST_DID}`, {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['did']).toBe(TEST_DID)
    expect(body['publicKey']).toBe(TEST_PUBLIC_KEY)
    expect(body['capabilities']).toEqual(['email:read'])
    expect(typeof body['registeredAt']).toBe('string')
  })

  it('returns 404 for unknown DID', async () => {
    const res = await app.request('/resolve/did:amap:unknown:1.0:xyz', {}, env)
    expect(res.status).toBe(404)
    const body = await res.json() as Record<string, unknown>
    expect(typeof body['error']).toBe('string')
  })

  it('stores empty capabilities array when none provided', async () => {
    await app.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, publicKey: TEST_PUBLIC_KEY }),
    }, env)

    const res = await app.request(`/resolve/${TEST_DID}`, {}, env)
    const body = await res.json() as Record<string, unknown>
    expect(body['capabilities']).toEqual([])
  })
})

describe('GET /revoked/:did', () => {
  let env: ReturnType<typeof makeEnv>

  beforeEach(() => {
    env = makeEnv()
  })

  it('returns revoked: false for non-revoked DID', async () => {
    const res = await app.request(`/revoked/${TEST_DID}`, {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['revoked']).toBe(false)
    expect(body['did']).toBe(TEST_DID)
  })

  it('returns revoked: true with notice for revoked DID', async () => {
    // Revoke first
    await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, signature: 'fakesig123' }),
    }, env)

    // Then check
    const res = await app.request(`/revoked/${TEST_DID}`, {}, env)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['revoked']).toBe(true)
    expect(body['did']).toBe(TEST_DID)
    expect(body['notice']).toBeDefined()
  })
})

describe('POST /revoke', () => {
  let env: ReturnType<typeof makeEnv>

  beforeEach(() => {
    env = makeEnv()
  })

  it('accepts a valid revocation notice', async () => {
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, signature: 'fakesig123' }),
    }, env)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body['did']).toBe(TEST_DID)
    expect(body['revoked']).toBe(true)
  })

  it('stores revokedAt timestamp on the notice', async () => {
    await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID, signature: 'fakesig123' }),
    }, env)

    const res = await app.request(`/revoked/${TEST_DID}`, {}, env)
    const body = await res.json() as Record<string, unknown>
    const notice = body['notice'] as Record<string, unknown>
    expect(typeof notice['revokedAt']).toBe('string')
  })

  it('rejects missing did', async () => {
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signature: 'fakesig123' }),
    }, env)
    expect(res.status).toBe(400)
    const body = await res.json() as Record<string, unknown>
    expect(typeof body['error']).toBe('string')
  })

  it('rejects missing signature', async () => {
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did: TEST_DID }),
    }, env)
    expect(res.status).toBe(400)
    const body = await res.json() as Record<string, unknown>
    expect(typeof body['error']).toBe('string')
  })

  it('rejects invalid JSON', async () => {
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    }, env)
    expect(res.status).toBe(400)
  })
})
