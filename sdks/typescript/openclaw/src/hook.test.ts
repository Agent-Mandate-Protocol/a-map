import { describe, it, expect } from 'vitest'
import { amap, LocalKeyResolver, InMemoryNonceStore } from '@agentmandateprotocol/core'
import { SessionMandateStore } from './session-store.js'
import { beforeToolCall } from './hook.js'
import { handleAmapRegisterSession } from './tools/amap-register-session.js'
import { handleAmapIssue } from './tools/amap-issue.js'

async function makeChainAndKeys(permissions: string[]) {
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

  return { chain: [token], issuerKeys, agentKeys, issuerDid, agentDid, keyResolver }
}

describe('beforeToolCall()', () => {
  describe('per-call _amap envelope (agent-to-agent path)', () => {
    it('passes and strips _amap when envelope is valid', async () => {
      const { chain, agentKeys, keyResolver } = await makeChainAndKeys(['tool:read_file'])

      const headers = amap.signRequest({
        mandateChain: chain,
        method: 'POST',
        path: '/tool/read_file',
        privateKey: agentKeys.privateKey,
      })

      const input = {
        path: '/home/docs',
        _amap: { headers, method: 'POST', path: '/tool/read_file' },
      }

      const sessionStore = new SessionMandateStore()
      const result = await beforeToolCall(
        input,
        { sessionId: 'session-1', toolName: 'read_file' },
        { sessionStore, keyResolver, nonceStore: new InMemoryNonceStore() },
      )

      expect(result).not.toHaveProperty('_amap')
      expect(result).toHaveProperty('path', '/home/docs')
    })

    it('throws PERMISSION_INFLATION when mandate lacks the required permission', async () => {
      const { chain, agentKeys, keyResolver } = await makeChainAndKeys(['tool:read_file'])

      const headers = amap.signRequest({
        mandateChain: chain,
        method: 'POST',
        path: '/tool/delete_file',
        privateKey: agentKeys.privateKey,
      })

      const input = { _amap: { headers, method: 'POST', path: '/tool/delete_file' } }

      const sessionStore = new SessionMandateStore()
      await expect(
        beforeToolCall(
          input,
          { sessionId: 'session-1', toolName: 'delete_file' },
          { sessionStore, keyResolver, nonceStore: new InMemoryNonceStore() },
        ),
      ).rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
    })
  })

  describe('session-scoped path', () => {
    it('throws BROKEN_CHAIN when no _amap and no session registered', async () => {
      const sessionStore = new SessionMandateStore()

      await expect(
        beforeToolCall(
          { someArg: 1 },
          { sessionId: 'session-1', toolName: 'read_file' },
          { sessionStore },
        ),
      ).rejects.toMatchObject({ code: 'BROKEN_CHAIN' })
    })

    it('passes when session has the required permission', async () => {
      const { chain, keyResolver } = await makeChainAndKeys(['tool:read_file', 'tool:list_dir'])
      const sessionStore = new SessionMandateStore()

      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain })

      const result = await beforeToolCall(
        { path: '/home' },
        { sessionId: 'session-1', toolName: 'read_file' },
        { sessionStore },
      )

      expect(result).toEqual({ path: '/home' })
    })

    it('throws PERMISSION_INFLATION when session mandate lacks the required permission', async () => {
      const { chain, keyResolver } = await makeChainAndKeys(['tool:read_file'])
      const sessionStore = new SessionMandateStore()

      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain })

      await expect(
        beforeToolCall(
          { path: '/home/file.txt' },
          { sessionId: 'session-1', toolName: 'delete_file' },
          { sessionStore },
        ),
      ).rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
    })

    it('throws TOKEN_EXPIRED when session mandate has expired', async () => {
      const issuerKeys = amap.keygen()
      const agentKeys = amap.keygen()
      const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
      const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

      const token = await amap.issue({
        principal: issuerDid,
        delegate: agentDid,
        permissions: ['tool:read_file'],
        expiresIn: '1s',
        privateKey: issuerKeys.privateKey,
      })

      const keyResolver = new LocalKeyResolver(new Map([
        [issuerDid, issuerKeys.publicKey],
        [agentDid, agentKeys.publicKey],
      ]))
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: [token] })

      await new Promise(resolve => setTimeout(resolve, 1100))

      await expect(
        beforeToolCall({ path: '/home' }, { sessionId: 'session-1', toolName: 'read_file' }, { sessionStore }),
      ).rejects.toMatchObject({ code: 'TOKEN_EXPIRED' })
    })

    it('uses different sessions independently', async () => {
      const { chain: chainA, keyResolver: krA } = await makeChainAndKeys(['tool:email:send'])
      const { chain: chainB, keyResolver: krB } = await makeChainAndKeys(['tool:calendar:read'])
      const sessionStore = new SessionMandateStore()

      await handleAmapRegisterSession('session-A', sessionStore, krA)({ chain: chainA })
      await handleAmapRegisterSession('session-B', sessionStore, krB)({ chain: chainB })

      // session-A can send email, not read calendar
      await expect(
        beforeToolCall({}, { sessionId: 'session-A', toolName: 'email:send' }, { sessionStore }),
      ).resolves.toBeDefined()

      await expect(
        beforeToolCall({}, { sessionId: 'session-A', toolName: 'calendar:read' }, { sessionStore }),
      ).rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
    })
  })

  describe('allow/deny policy evaluation', () => {
    it('blocks a tool explicitly denied by deniedActions even when permission is present', async () => {
      const issuerKeys = amap.keygen()
      const agentKeys = amap.keygen()
      const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
      const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

      const token = await amap.issue({
        principal: issuerDid,
        delegate: agentDid,
        permissions: ['tool:delete_file', 'tool:read_file'],
        constraints: { deniedActions: ['delete_file'] },  // deny the delete tool by name
        expiresIn: '1h',
        privateKey: issuerKeys.privateKey,
      })

      const keyResolver = new LocalKeyResolver(new Map([
        [issuerDid, issuerKeys.publicKey],
        [agentDid, agentKeys.publicKey],
      ]))
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: [token] })

      // delete_file is in permissions but explicitly denied — must be blocked
      await expect(
        beforeToolCall({ path: '/important' }, { sessionId: 'session-1', toolName: 'delete_file' }, { sessionStore }),
      ).rejects.toMatchObject({ code: 'EXPLICIT_DENY' })

      // read_file is allowed (not denied, has permission)
      await expect(
        beforeToolCall({ path: '/readme' }, { sessionId: 'session-1', toolName: 'read_file' }, { sessionStore }),
      ).resolves.toBeDefined()
    })

    it('blocks tools not in allowedActions even when permission is present', async () => {
      const issuerKeys = amap.keygen()
      const agentKeys = amap.keygen()
      const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
      const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

      const token = await amap.issue({
        principal: issuerDid,
        delegate: agentDid,
        permissions: ['tool:read_file', 'tool:list_dir', 'tool:delete_file'],
        constraints: { allowedActions: ['read_file', 'list_dir'] },  // allowlist
        expiresIn: '1h',
        privateKey: issuerKeys.privateKey,
      })

      const keyResolver = new LocalKeyResolver(new Map([
        [issuerDid, issuerKeys.publicKey],
        [agentDid, agentKeys.publicKey],
      ]))
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: [token] })

      // in allowedActions — passes
      await expect(
        beforeToolCall({}, { sessionId: 'session-1', toolName: 'read_file' }, { sessionStore }),
      ).resolves.toBeDefined()

      // NOT in allowedActions — blocked even though it's in permissions
      await expect(
        beforeToolCall({}, { sessionId: 'session-1', toolName: 'delete_file' }, { sessionStore }),
      ).rejects.toMatchObject({ code: 'EXPLICIT_DENY' })
    })

    it('does not apply policy when no allowedActions or deniedActions are set', async () => {
      const { chain, keyResolver } = await makeChainAndKeys(['tool:read_file'])
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain })

      // No policy constraints — permission check only
      await expect(
        beforeToolCall({}, { sessionId: 'session-1', toolName: 'read_file' }, { sessionStore }),
      ).resolves.toBeDefined()
    })
  })

  describe('parameterLock checking (session path)', () => {
    it('passes when locked parameters match', async () => {
      const issuerKeys = amap.keygen()
      const agentKeys = amap.keygen()
      const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
      const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

      const token = await amap.issue({
        principal: issuerDid,
        delegate: agentDid,
        permissions: ['tool:send_email'],
        constraints: { parameterLocks: { to: 'boss@company.com' } },
        expiresIn: '1h',
        privateKey: issuerKeys.privateKey,
      })

      const keyResolver = new LocalKeyResolver(new Map([
        [issuerDid, issuerKeys.publicKey],
        [agentDid, agentKeys.publicKey],
      ]))
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: [token] })

      await expect(
        beforeToolCall(
          { to: 'boss@company.com', subject: 'Hello' },
          { sessionId: 'session-1', toolName: 'send_email' },
          { sessionStore },
        ),
      ).resolves.toBeDefined()
    })

    it('throws PARAMETER_LOCK_VIOLATION when a locked parameter does not match', async () => {
      const issuerKeys = amap.keygen()
      const agentKeys = amap.keygen()
      const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
      const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

      const token = await amap.issue({
        principal: issuerDid,
        delegate: agentDid,
        permissions: ['tool:send_email'],
        constraints: { parameterLocks: { to: 'boss@company.com' } },
        expiresIn: '1h',
        privateKey: issuerKeys.privateKey,
      })

      const keyResolver = new LocalKeyResolver(new Map([
        [issuerDid, issuerKeys.publicKey],
        [agentDid, agentKeys.publicKey],
      ]))
      const sessionStore = new SessionMandateStore()
      await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: [token] })

      await expect(
        beforeToolCall(
          { to: 'hacker@evil.com', subject: 'Hello' },
          { sessionId: 'session-1', toolName: 'send_email' },
          { sessionStore },
        ),
      ).rejects.toMatchObject({ code: 'PARAMETER_LOCK_VIOLATION' })
    })
  })
})

describe('handleAmapIssue()', () => {
  it('returns a signed DelegationToken', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['tool:read_file', 'tool:search'],
      expiresIn: '1h',
      issuerPrivateKey: issuerKeys.privateKey,
    })

    expect(token.principal).toBe(issuerDid)
    expect(token.delegate).toBe(agentDid)
    expect(token.permissions).toEqual(['tool:read_file', 'tool:search'])
    expect(token.signature).toBeTruthy()
  })

  it('applies deniedActions when provided', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['tool:read_file'],
      expiresIn: '1h',
      deniedActions: ['delete_*'],
      issuerPrivateKey: issuerKeys.privateKey,
    })

    expect(token.constraints.deniedActions).toEqual(['delete_*'])
  })
})

describe('handleAmapRegisterSession()', () => {
  it('verifies chain and stores the result', async () => {
    const { chain, keyResolver } = await makeChainAndKeys(['tool:read_file'])
    const sessionStore = new SessionMandateStore()

    const result = await handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain })

    expect(result.registered).toBe(true)
    expect(result.chainLength).toBe(1)
    expect(result.principal).toMatch(/^did:amap:/)
    expect(sessionStore.has('session-1')).toBe(true)
  })

  it('throws on an invalid chain', async () => {
    const { chain, keyResolver } = await makeChainAndKeys(['tool:read_file'])
    const sessionStore = new SessionMandateStore()

    // Tamper with the chain
    const tampered = [{ ...chain[0]!, permissions: ['tool:delete_everything'] }]

    await expect(
      handleAmapRegisterSession('session-1', sessionStore, keyResolver)({ chain: tampered }),
    ).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })
})
