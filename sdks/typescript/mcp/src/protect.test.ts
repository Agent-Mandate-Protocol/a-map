import { describe, it, expect } from 'vitest'
import { amapProtect, toMcpErrorResponse, mcpToolHandler } from './protect.js'
import { amap, LocalKeyResolver, InMemoryNonceStore, AmapError, AmapErrorCode } from '@agentmandateprotocol/core'

function makeKeys() {
  const keys = amap.keygen()
  return keys
}

describe('amapProtect()', () => {
  it('rejects calls missing _amap envelope', async () => {
    const handler = amapProtect('test_tool', async () => ({ ok: true }))
    await expect(handler({})).rejects.toMatchObject({ code: 'BROKEN_CHAIN' })
  })

  it('rejects calls where _amap has no headers', async () => {
    const handler = amapProtect('test_tool', async () => ({ ok: true }))
    await expect(handler({ _amap: {} })).rejects.toMatchObject({ code: 'BROKEN_CHAIN' })
  })

  it('calls handler with clean args and mandate on success', async () => {
    const issuerKeys = makeKeys()
    const agentKeys = makeKeys()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid,
      delegate: agentDid,
      permissions: ['tool:test_tool'],
      expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/mcp/test_tool',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = amapProtect(
      'test_tool',
      async (args, mandate) => ({ principal: mandate.principal, args }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    const result = await handler({
      someArg: 'value',
      _amap: { headers, method: 'POST', path: '/mcp/test_tool' },
    })

    expect(result.principal).toBe(issuerDid)
    expect(result.args).toEqual({ someArg: 'value' }) // _amap stripped
  })

  it('enforces parameterLocks — rejects when locked param does not match', async () => {
    const issuerKeys = makeKeys()
    const agentKeys = makeKeys()
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

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/mcp/send_email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = amapProtect(
      'send_email',
      async () => ({ ok: true }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    // Locked to boss@company.com — hacker@evil.com must be rejected
    await expect(handler({ to: 'hacker@evil.com', _amap: { headers, method: 'POST', path: '/mcp/send_email' } }))
      .rejects.toMatchObject({ code: 'PARAMETER_LOCK_VIOLATION' })
  })

  it('allows call when locked param matches', async () => {
    const issuerKeys = makeKeys()
    const agentKeys = makeKeys()
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

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/mcp/send_email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = amapProtect(
      'send_email',
      async (args) => ({ sent: true }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    await expect(handler({ to: 'boss@company.com', _amap: { headers, method: 'POST', path: '/mcp/send_email' } }))
      .resolves.toEqual({ sent: true })
  })

  it('rejects a replayed nonce on a second call with the same headers', async () => {
    const issuerKeys = makeKeys()
    const agentKeys = makeKeys()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid,
      delegate: agentDid,
      permissions: ['tool:test_tool'],
      expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/mcp/test_tool',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    // No explicit nonceStore — handler must create and reuse one internally
    const handler = amapProtect(
      'test_tool',
      async () => ({ ok: true }),
      { keyResolver },
    )

    // First call — succeeds
    await expect(handler({ _amap: { headers, method: 'POST', path: '/mcp/test_tool' } }))
      .resolves.toEqual({ ok: true })

    // Second call with the same headers (same nonce) — must be rejected as replay
    await expect(handler({ _amap: { headers, method: 'POST', path: '/mcp/test_tool' } }))
      .rejects.toMatchObject({ code: 'NONCE_REPLAYED' })
  })

  it('rejects when agent lacks the required permission', async () => {
    const issuerKeys = makeKeys()
    const agentKeys = makeKeys()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid,
      delegate: agentDid,
      permissions: ['read_only'],  // does not include 'send_email'
      expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/mcp/send_email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = amapProtect(
      'send_email',
      async () => ({ ok: true }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    await expect(handler({ _amap: { headers, method: 'POST', path: '/mcp/send_email' } }))
      .rejects.toMatchObject({ code: 'PERMISSION_INFLATION' })
  })
})

describe('toMcpErrorResponse()', () => {
  it('formats AmapError as { isError: true } with code in message', () => {
    const err = new AmapError(AmapErrorCode.PERMISSION_INFLATION, 'agent tried to escalate')
    const result = toMcpErrorResponse(err)
    expect(result.isError).toBe(true)
    expect(result.content).toHaveLength(1)
    expect(result.content[0]?.type).toBe('text')
    expect(result.content[0]?.text).toContain('PERMISSION_INFLATION')
    expect(result.content[0]?.text).toContain('agent tried to escalate')
  })

  it('formats a generic Error as { isError: true }', () => {
    const result = toMcpErrorResponse(new Error('something broke'))
    expect(result.isError).toBe(true)
    expect(result.content[0]?.text).toBe('something broke')
  })

  it('formats non-Error thrown values', () => {
    const result = toMcpErrorResponse('string error')
    expect(result.isError).toBe(true)
    expect(result.content[0]?.text).toBe('string error')
  })
})

describe('mcpToolHandler()', () => {
  it('returns { isError: false } with JSON result on success', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid  = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid, delegate: agentDid,
      permissions: ['tool:send_email'], expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token], method: 'POST', path: '/mcp/send_email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = mcpToolHandler(
      'send_email',
      async (args) => ({ sent: true, to: (args as { to: string }).to }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    const result = await handler({ to: 'boss@acme.com', _amap: { headers, method: 'POST', path: '/mcp/send_email' } })

    expect(result.isError).toBe(false)
    expect(result.content[0]?.type).toBe('text')
    const parsed = JSON.parse(result.content[0]!.text)
    expect(parsed.sent).toBe(true)
  })

  it('returns { isError: true } with BROKEN_CHAIN when _amap is missing', async () => {
    const handler = mcpToolHandler('send_email', async () => ({ ok: true }))
    const result = await handler({})
    expect(result.isError).toBe(true)
    expect(result.content[0]?.text).toContain('BROKEN_CHAIN')
  })

  it('returns { isError: true } with PERMISSION_INFLATION when permission is wrong', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys  = amap.keygen()
    const issuerDid  = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid   = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid, delegate: agentDid,
      permissions: ['tool:read_only'], expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token], method: 'POST', path: '/mcp/send_email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const handler = mcpToolHandler(
      'send_email',
      async () => ({ ok: true }),
      { keyResolver, nonceStore: new InMemoryNonceStore() },
    )

    const result = await handler({ _amap: { headers, method: 'POST', path: '/mcp/send_email' } })

    expect(result.isError).toBe(true)
    expect(result.content[0]?.text).toContain('PERMISSION_INFLATION')
  })
})
