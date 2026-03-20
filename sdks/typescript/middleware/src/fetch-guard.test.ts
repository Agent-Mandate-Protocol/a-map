import { describe, it, expect, vi } from 'vitest'
import { AmapFetchGuard } from './fetch-guard.js'
import { amap, LocalKeyResolver } from '@agentmandateprotocol/core'
import type { FetchAuditEntry } from './fetch-guard.js'

function mockFetch(status = 200) {
  return vi.fn().mockResolvedValue(new Response('ok', { status }))
}

async function makeMandateWithConstraints(permissions: string[], constraints: Record<string, unknown>) {
  const issuerKeys = amap.keygen()
  const agentKeys = amap.keygen()
  const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
  const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

  const token = await amap.issue({
    principal: issuerDid,
    delegate: agentDid,
    permissions,
    constraints: constraints as Parameters<typeof amap.issue>[0]['constraints'],
    expiresIn: '1h',
    privateKey: issuerKeys.privateKey,
  })

  const keyResolver = new LocalKeyResolver(new Map([
    [issuerDid, issuerKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ]))

  return { token, keyResolver, issuerDid }
}

async function makeMandate(permissions: string[]) {
  const issuerKeys = amap.keygen()
  const agentKeys = amap.keygen()
  const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
  const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

  const token = await amap.issue({
    principal: issuerDid,
    delegate: agentDid,
    permissions,
    expiresIn: '1h',
    privateKey: issuerKeys.privateKey,
  })

  const keyResolver = new LocalKeyResolver(new Map([
    [issuerDid, issuerKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ]))

  return { token, keyResolver, issuerDid }
}

describe('AmapFetchGuard', () => {
  describe('enforce mode (default)', () => {
    it('allows requests when mandate includes required permission', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { 'GET /api/emails': { requires: ['email:read'] } },
      })

      const res = await guard.fetch('https://api.example.com/api/emails')
      expect(res.status).toBe(200)
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('blocks requests when mandate lacks required permission', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { 'DELETE /api/emails/*': { requires: ['email:delete'] } },
      })

      await expect(guard.fetch('https://api.example.com/api/emails/123', { method: 'DELETE' }))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('uses catch-all rule when no specific rule matches', async () => {
      const { token, keyResolver } = await makeMandate(['api:allow'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:allow'] } },
      })

      await guard.fetch('https://api.example.com/anything', { method: 'POST' })
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('matches glob path patterns', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { 'GET /api/emails/*': { requires: ['email:read'] } },
      })

      // should match 'GET /api/emails/123'
      await guard.fetch('https://api.example.com/api/emails/123')
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('blocks when no rule matches and default permission not in mandate', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, { mandate: [token], keyResolver })

      // No rules, no catch-all — default requires 'GET /api/unknown' as permission
      await expect(guard.fetch('https://api.example.com/api/unknown'))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
    })
  })

  describe('audit mode', () => {
    it('allows blocked requests through in audit mode', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()
      const auditLog: FetchAuditEntry[] = []

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        mode: 'audit',
        rules: { 'DELETE /api/emails/*': { requires: ['email:delete'] } },
        onAudit: entry => auditLog.push(entry),
      })

      await guard.fetch('https://api.example.com/api/emails/123', { method: 'DELETE' })
      expect(fetch).toHaveBeenCalledOnce()
      expect(auditLog[0]!.event).toBe('FETCH_BLOCKED')
      expect(auditLog[0]!.reason).toContain('email:delete')
    })

    it('per-rule policy overrides global mode', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        mode: 'audit',
        rules: {
          'DELETE /api/emails/*': { requires: ['email:delete'], policy: 'enforce' },
        },
      })

      await expect(guard.fetch('https://api.example.com/api/emails/123', { method: 'DELETE' }))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(fetch).not.toHaveBeenCalled()
    })
  })

  describe('audit logging', () => {
    it('logs allowed requests via onAudit', async () => {
      const { token, keyResolver, issuerDid } = await makeMandate(['email:read'])
      const fetch = mockFetch()
      const auditLog: FetchAuditEntry[] = []

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { 'GET /api/emails': { requires: ['email:read'] } },
        onAudit: entry => auditLog.push(entry),
      })

      await guard.fetch('https://api.example.com/api/emails')

      expect(auditLog).toHaveLength(1)
      expect(auditLog[0]!.event).toBe('FETCH_ALLOWED')
      expect(auditLog[0]!.method).toBe('GET')
      expect(auditLog[0]!.path).toBe('/api/emails')
      expect(auditLog[0]!.principal).toBe(issuerDid)
    })
  })

  describe('constraint enforcement', () => {
    it('blocks non-GET/HEAD requests when readOnly is true', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:write'], { readOnly: true })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:write'] } },
      })

      await expect(guard.fetch('https://api.example.com/data', { method: 'POST' }))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('allows GET requests when readOnly is true', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], { readOnly: true })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await guard.fetch('https://api.example.com/data')
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('blocks requests to denied domains', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        deniedDomains: ['evil.com', '*.malicious.org'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await expect(guard.fetch('https://evil.com/data'))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('allows requests to non-denied domains', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        deniedDomains: ['evil.com'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await guard.fetch('https://api.example.com/data')
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('blocks requests to domains not in allowedDomains', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        allowedDomains: ['api.example.com'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await expect(guard.fetch('https://other.example.com/data'))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('allows requests to domains in allowedDomains', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        allowedDomains: ['api.example.com', '*.trusted.io'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await guard.fetch('https://api.example.com/data')
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('blocks actions denied by deniedActions policy', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:write'], {
        deniedActions: ['DELETE'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:write'] } },
      })

      await expect(guard.fetch('https://api.example.com/data', { method: 'DELETE' }))
        .rejects.toMatchObject({ code: 'EXPLICIT_DENY' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('blocks actions not in allowedActions (implicit deny)', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        allowedActions: ['GET', 'HEAD'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await expect(guard.fetch('https://api.example.com/data', { method: 'POST' }))
        .rejects.toMatchObject({ code: 'EXPLICIT_DENY' })
      expect(fetch).not.toHaveBeenCalled()
    })

    it('allows actions in allowedActions', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], {
        allowedActions: ['GET', 'POST'],
      })
      const fetch = mockFetch()

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['api:read'] } },
      })

      await guard.fetch('https://api.example.com/data', { method: 'POST' })
      expect(fetch).toHaveBeenCalledOnce()
    })

    it('constraint violations are logged in audit mode instead of throwing', async () => {
      const { token, keyResolver } = await makeMandateWithConstraints(['api:read'], { readOnly: true })
      const fetch = mockFetch()
      const auditLog: FetchAuditEntry[] = []

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        mode: 'audit',
        rules: { '*': { requires: ['api:read'] } },
        onAudit: entry => auditLog.push(entry),
      })

      await guard.fetch('https://api.example.com/data', { method: 'DELETE' })
      expect(fetch).toHaveBeenCalledOnce()
      expect(auditLog[0]!.event).toBe('FETCH_BLOCKED')
      expect(auditLog[0]!.reason).toContain('readOnly')
    })
  })

  describe('mandate verification', () => {
    it('verifies the mandate chain only once across multiple requests', async () => {
      const { token, keyResolver } = await makeMandate(['email:read', 'email:write'])
      const fetch = mockFetch()
      const verifySpy = vi.spyOn(amap, 'verify')

      const guard = new AmapFetchGuard(fetch, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['email:read'] } },
      })

      await guard.fetch('https://api.example.com/api/emails')
      await guard.fetch('https://api.example.com/api/emails')
      await guard.fetch('https://api.example.com/api/emails')

      expect(verifySpy).toHaveBeenCalledOnce()
      verifySpy.mockRestore()
    })
  })
})
