import { describe, it, expect } from 'vitest'
import { handleAmapIssue } from './amap-issue.js'
import { amap } from '@agentmandateprotocol/core'

describe('handleAmapIssue()', () => {
  it('returns a valid DelegationToken', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['send_email'],
      expiresIn: '1h',
      issuerPrivateKey: issuerKeys.privateKey,
    })

    expect(token.principal).toBe(issuerDid)
    expect(token.delegate).toBe(agentDid)
    expect(token.permissions).toEqual(['send_email'])
    expect(token.parentTokenHash).toBeNull()
  })

  it('applies preset constraints', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['read_files'],
      expiresIn: '1h',
      preset: 'ReadOnly',
      issuerPrivateKey: issuerKeys.privateKey,
    })

    expect(token.constraints.readOnly).toBe(true)
  })

  it('overrides merge on top of preset', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['read_files'],
      expiresIn: '1h',
      preset: 'Developer',
      maxSpend: 50,
      maxCalls: 10,
      issuerPrivateKey: issuerKeys.privateKey,
    })

    expect(token.constraints.maxSpend).toBe(50)
    expect(token.constraints.maxCalls).toBe(10)
  })

  it('issues token with no constraints when none specified', async () => {
    const issuerKeys = amap.keygen()
    const agentKeys = amap.keygen()
    const issuerDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: issuerKeys.publicKey })
    const agentDid = amap.computeDID({ type: 'agent', name: 'agent', version: '1.0', publicKey: agentKeys.publicKey })

    const token = await handleAmapIssue({
      principal: issuerDid,
      agentDid,
      permissions: ['read_files'],
      expiresIn: '1h',
      issuerPrivateKey: issuerKeys.privateKey,
    })

    // constraints is always present on token (empty object at minimum)
    expect(token.constraints).toEqual({})
  })
})
