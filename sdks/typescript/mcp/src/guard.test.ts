import { describe, it, expect, vi } from 'vitest'
import { AmapGuard } from './guard.js'
import { amap, LocalKeyResolver } from '@agentmandateprotocol/core'
import type { AuditEntry } from './guard.js'

// Minimal mock MCP client
function makeMockClient(result: unknown = { ok: true }) {
  return {
    callTool: vi.fn().mockResolvedValue(result),
  }
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

  return { token, keyResolver, issuerDid, agentDid }
}

describe('AmapGuard', () => {
  describe('enforce mode (default)', () => {
    it('allows calls when mandate includes the required permission', async () => {
      const { token, keyResolver } = await makeMandate(['filesystem/readFile'])
      const client = makeMockClient({ content: 'hello' })

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        rules: { 'filesystem/readFile': { requires: ['filesystem/readFile'] } },
      })

      const result = await guard.callTool('filesystem/readFile', { path: './readme.md' })
      expect(result).toEqual({ content: 'hello' })
      expect(client.callTool).toHaveBeenCalledWith('filesystem/readFile', { path: './readme.md' })
    })

    it('blocks calls when mandate lacks the required permission', async () => {
      const { token, keyResolver } = await makeMandate(['filesystem/readFile'])
      const client = makeMockClient()

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        rules: { 'filesystem/deleteFile': { requires: ['filesystem/deleteFile'] } },
      })

      await expect(guard.callTool('filesystem/deleteFile', { path: './readme.md' }))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })

      expect(client.callTool).not.toHaveBeenCalled()
    })

    it('defaults required permission to the tool name when no rule is set', async () => {
      const { token, keyResolver } = await makeMandate(['tool:shell/execute'])
      const client = makeMockClient()

      const guard = new AmapGuard(client, { mandate: [token], keyResolver })

      // 'tool:shell/execute' is in permissions — should pass
      await guard.callTool('shell/execute', { cmd: 'ls' })
      expect(client.callTool).toHaveBeenCalledOnce()
    })

    it('uses catch-all rule when no specific rule matches', async () => {
      const { token, keyResolver } = await makeMandate(['tools:allow'])
      const client = makeMockClient()

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        rules: { '*': { requires: ['tools:allow'] } },
      })

      await guard.callTool('some/unknown/tool', { x: 1 })
      expect(client.callTool).toHaveBeenCalledWith('some/unknown/tool', { x: 1 })
    })

    it('requires ALL permissions in the rule', async () => {
      const { token, keyResolver } = await makeMandate(['email:read'])  // missing email:send
      const client = makeMockClient()

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        rules: { 'gmail/sendMessage': { requires: ['email:read', 'email:send'] } },
      })

      await expect(guard.callTool('gmail/sendMessage', {}))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
    })
  })

  describe('audit mode', () => {
    it('allows blocked calls through in audit mode', async () => {
      const { token, keyResolver } = await makeMandate(['filesystem/readFile'])
      const client = makeMockClient()
      const auditLog: AuditEntry[] = []

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        mode: 'audit',
        rules: { 'filesystem/deleteFile': { requires: ['filesystem/deleteFile'] } },
        onAudit: entry => auditLog.push(entry),
      })

      await guard.callTool('filesystem/deleteFile', { path: './readme.md' })
      expect(client.callTool).toHaveBeenCalledOnce()
      expect(auditLog).toHaveLength(1)
      expect(auditLog[0]!.event).toBe('TOOL_BLOCKED')
      expect(auditLog[0]!.reason).toContain('filesystem/deleteFile')
    })

    it('per-tool policy overrides global mode', async () => {
      const { token, keyResolver } = await makeMandate(['safe:tool'])
      const client = makeMockClient()

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        mode: 'audit',  // global: audit
        rules: {
          'dangerous/tool': { requires: ['dangerous:permission'], policy: 'enforce' },
        },
      })

      // dangerous/tool enforces even though global mode is audit
      await expect(guard.callTool('dangerous/tool', {}))
        .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
      expect(client.callTool).not.toHaveBeenCalled()
    })
  })

  describe('audit logging', () => {
    it('calls onAudit for every allowed call', async () => {
      const { token, keyResolver, issuerDid } = await makeMandate(['tool:my/tool'])
      const client = makeMockClient()
      const auditLog: AuditEntry[] = []

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        onAudit: entry => auditLog.push(entry),
      })

      await guard.callTool('my/tool', {})
      expect(auditLog).toHaveLength(1)
      expect(auditLog[0]!.event).toBe('TOOL_ALLOWED')
      expect(auditLog[0]!.tool).toBe('my/tool')
      expect(auditLog[0]!.principal).toBe(issuerDid)
      expect(auditLog[0]!.mandateId).toBe(token.tokenId)
    })

    it('calls onAudit for every blocked call', async () => {
      const { token, keyResolver } = await makeMandate(['read:only'])
      const client = makeMockClient()
      const auditLog: AuditEntry[] = []

      const guard = new AmapGuard(client, {
        mandate: [token],
        keyResolver,
        mode: 'audit',
        rules: { 'write/tool': { requires: ['write:access'] } },
        onAudit: entry => auditLog.push(entry),
      })

      await guard.callTool('write/tool', {})
      expect(auditLog[0]!.event).toBe('TOOL_BLOCKED')
      expect(auditLog[0]!.reason).toBeDefined()
    })
  })

  describe('mandate verification', () => {
    it('verifies the mandate chain only once across multiple calls', async () => {
      const { token, keyResolver } = await makeMandate(['tool:readFile', 'tool:writeFile'])
      const client = makeMockClient()
      const verifySpy = vi.spyOn(amap, 'verify')

      const guard = new AmapGuard(client, { mandate: [token], keyResolver })

      await guard.callTool('readFile', {})
      await guard.callTool('writeFile', {})
      await guard.callTool('readFile', {})

      expect(verifySpy).toHaveBeenCalledOnce()
      verifySpy.mockRestore()
    })
  })
})
