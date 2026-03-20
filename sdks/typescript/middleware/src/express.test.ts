import { describe, it, expect, vi } from 'vitest'
import { amapVerifier } from './express.js'
import { amap, LocalKeyResolver, InMemoryNonceStore } from '@agentmandateprotocol/core'
import type { MinimalRequest, MinimalResponse } from './express.js'

async function makeSignedRequest(permissions: string[], method = 'GET', path = '/api/data') {
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

  const headers = amap.signRequest({
    mandateChain: [token],
    method,
    path,
    privateKey: agentKeys.privateKey,
  })

  const keyResolver = new LocalKeyResolver(new Map([
    [issuerDid, issuerKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ]))

  return { headers, keyResolver, issuerDid, agentDid }
}

function mockReq(headers: Record<string, string>, method = 'GET', path = '/api/data'): MinimalRequest & Record<string, unknown> {
  return { headers, method, path, body: undefined }
}

function mockRes() {
  let statusCode = 200
  let responseBody: unknown
  const res: MinimalResponse = {
    status(code) { statusCode = code; return res },
    json(body) { responseBody = body },
  }
  return { res, getStatus: () => statusCode, getBody: () => responseBody }
}

describe('amapVerifier() — Express middleware', () => {
  it('calls next() and attaches verification result for valid request', async () => {
    const { headers, keyResolver, issuerDid } = await makeSignedRequest(['read_email'])
    const req = mockReq(headers)
    const { res } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({
      expectedPermission: 'read_email',
      keyResolver,
      nonceStore: new InMemoryNonceStore(),
    })

    await middleware(req, res, next)

    expect(next).toHaveBeenCalledOnce()
    expect(next).toHaveBeenCalledWith()           // no error arg
    expect(req['amapVerification']).toBeDefined()
    expect((req['amapVerification'] as { principal: string }).principal).toBe(issuerDid)
  })

  it('responds 401 with error code when headers are missing', async () => {
    const req = mockReq({})
    const { res, getStatus, getBody } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({ nonceStore: new InMemoryNonceStore() })
    await middleware(req, res, next)

    expect(next).not.toHaveBeenCalled()
    expect(getStatus()).toBe(401)
    expect(getBody()).toMatchObject({ error: expect.any(String) })
  })

  it('responds 401 when mandate lacks required permission', async () => {
    const { headers, keyResolver } = await makeSignedRequest(['read_email'])
    const req = mockReq(headers)
    const { res, getStatus, getBody } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({
      expectedPermission: 'send_email',   // not in mandate
      keyResolver,
      nonceStore: new InMemoryNonceStore(),
    })

    await middleware(req, res, next)

    expect(next).not.toHaveBeenCalled()
    expect(getStatus()).toBe(401)
    expect((getBody() as { error: string }).error).toBe('PERMISSION_INFLATION')
  })

  it('warns when req.body is a parsed object and a signature header is present', async () => {
    const { headers, keyResolver } = await makeSignedRequest(['read_email'])
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    // Simulate express.json() having already run — body is a parsed object
    const req = { headers, method: 'GET', path: '/api/data', body: { key: 'value' } }
    const { res } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({ keyResolver, nonceStore: new InMemoryNonceStore() })
    await middleware(req, res, next)

    expect(warnSpy).toHaveBeenCalledOnce()
    expect(warnSpy.mock.calls[0]![0]).toContain('express.json()')
    warnSpy.mockRestore()
  })

  it('does not warn when req.body is a string', async () => {
    const { headers, keyResolver } = await makeSignedRequest(['read_email'])
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const req = { headers, method: 'GET', path: '/api/data', body: 'raw body string' }
    const { res } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({ keyResolver, nonceStore: new InMemoryNonceStore() })
    await middleware(req, res, next)

    expect(warnSpy).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })

  it('passes requestParams from req.body object for parameterLock checking', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await amap.issue({
      principal: issuerDid,
      delegate: agentDid,
      permissions: ['send_email'],
      constraints: { parameterLocks: { to: 'boss@company.com' } },
      expiresIn: '1h',
      privateKey: issuerKeys.privateKey,
    })

    const headers = amap.signRequest({
      mandateChain: [token],
      method: 'POST',
      path: '/api/email',
      privateKey: agentKeys.privateKey,
    })

    const keyResolver = new LocalKeyResolver(new Map([
      [issuerDid, issuerKeys.publicKey],
      [agentDid, agentKeys.publicKey],
    ]))

    const req = { headers, method: 'POST', path: '/api/email', body: { to: 'hacker@evil.com' } }
    const { res, getStatus, getBody } = mockRes()
    const next = vi.fn()

    const middleware = amapVerifier({ keyResolver, nonceStore: new InMemoryNonceStore() })
    await middleware(req, res, next)

    expect(getStatus()).toBe(401)
    expect((getBody() as { error: string }).error).toBe('PARAMETER_LOCK_VIOLATION')
    vi.restoreAllMocks()
  })
})
