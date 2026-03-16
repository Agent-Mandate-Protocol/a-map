import { Hono } from 'hono'
import { createAgentJson } from '@agentmandateprotocol/core'

/** Minimal KVNamespace interface — avoids @cloudflare/workers-types dependency */
interface KVNamespace {
  get(key: string): Promise<string | null>
  put(key: string, value: string): Promise<void>
  delete(key: string): Promise<void>
}

interface Env {
  AMAP_KEYS: KVNamespace       // DID → { publicKey, capabilities, registeredAt }
  AMAP_REVOKED: KVNamespace    // did → RevocationNotice JSON
  REGISTRY_DID?: string        // optional: set in wrangler.toml
  REGISTRY_PUBLIC_KEY?: string // optional: set in wrangler.toml
}

const app = new Hono<{ Bindings: Env }>()

// ── Service discovery ─────────────────────────────────────────────────────────

app.get('/.well-known/agent.json', (c) => {
  return c.json(createAgentJson({
    did: c.env.REGISTRY_DID ?? 'did:amap:registry:1.0:unknown',
    name: 'A-MAP Registry',
    description: 'Public key registry for the Agent Mandate Protocol.',
    requiresDelegationChain: false, // registry is open — no mandate needed to register
    ...(c.env.REGISTRY_PUBLIC_KEY !== undefined ? { publicKey: c.env.REGISTRY_PUBLIC_KEY } : {}),
    docsUrl: 'https://docs.agentmandateprotocol.dev/registry',
    contact: 'security@agentmandateprotocol.dev',
  }))
})

// ── Registration ──────────────────────────────────────────────────────────────

app.post('/register', async (c) => {
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  const { did, publicKey, capabilities } = body as Record<string, unknown>

  if (typeof did !== 'string' || did.trim() === '') {
    return c.json({ error: '"did" is required and must be a non-empty string' }, 400)
  }
  if (typeof publicKey !== 'string' || publicKey.trim() === '') {
    return c.json({ error: '"publicKey" is required and must be a non-empty string' }, 400)
  }
  if (!did.startsWith('did:amap:')) {
    return c.json({ error: '"did" must be in did:amap format' }, 400)
  }

  const entry = {
    publicKey,
    capabilities: Array.isArray(capabilities) ? capabilities : [],
    registeredAt: new Date().toISOString(),
  }

  await c.env.AMAP_KEYS.put(did, JSON.stringify(entry))
  return c.json({ did, registered: true }, 201)
})

// ── Resolution ────────────────────────────────────────────────────────────────

app.get('/resolve/:did', async (c) => {
  const did = c.req.param('did')
  const raw = await c.env.AMAP_KEYS.get(did)
  if (raw === null) {
    return c.json({ error: 'DID not found' }, 404)
  }

  const { publicKey, capabilities, registeredAt } = JSON.parse(raw) as {
    publicKey: string
    capabilities: string[]
    registeredAt: string
  }

  return c.json({ did, publicKey, capabilities, registeredAt })
})

// ── Revocation check ──────────────────────────────────────────────────────────

app.get('/revoked/:did', async (c) => {
  const did = c.req.param('did')
  const raw = await c.env.AMAP_REVOKED.get(did)
  if (raw === null) {
    return c.json({ did, revoked: false })
  }
  const notice = JSON.parse(raw) as Record<string, unknown>
  return c.json({ did, revoked: true, notice })
})

// ── Revocation submission ─────────────────────────────────────────────────────

app.post('/revoke', async (c) => {
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  const notice = body as Record<string, unknown>
  if (typeof notice['did'] !== 'string' || notice['did'].trim() === '') {
    return c.json({ error: '"did" is required' }, 400)
  }
  if (typeof notice['signature'] !== 'string') {
    return c.json({ error: '"signature" is required' }, 400)
  }

  // Phase 1: accept revocations without verifying signature (Phase 2 adds verification)
  const did = notice['did'] as string
  await c.env.AMAP_REVOKED.put(did, JSON.stringify({ ...notice, revokedAt: new Date().toISOString() }))
  return c.json({ did, revoked: true })
})

export default app
