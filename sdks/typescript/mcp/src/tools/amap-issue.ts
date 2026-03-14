import { amap } from '@agentmandateprotocol/core'
import type { DelegationToken, Constraints } from '@agentmandateprotocol/core'

export const amapIssueToolDefinition = {
  name: 'amap_issue',
  description:
    'Issue a cryptographically signed mandate that authorizes an AI agent to perform ' +
    'specific actions with specific constraints. Use this when a human wants to grant ' +
    'an agent permission to act on their behalf with explicit limits. The human provides: ' +
    'which agent (DID), what permissions, optional constraints (maxSpend, maxCalls, ' +
    'parameterLocks, allowedActions, deniedActions), and how long. Returns a signed ' +
    'DelegationToken the agent carries in every subsequent request. ' +
    'The private key never leaves this tool — signing happens locally.',
  inputSchema: {
    type: 'object',
    properties: {
      principal: {
        type: 'string',
        description: 'Human DID or identifier (e.g. did:amap:human:alice:abc123)',
      },
      agentDid: {
        type: 'string',
        description: 'DID of the agent receiving this mandate',
      },
      permissions: {
        type: 'array',
        items: { type: 'string' },
        description: 'Permission strings (e.g. ["send_email", "read_email"])',
      },
      expiresIn: {
        type: 'string',
        description: 'Duration: 15m, 1h, 4h, 24h. Max recommended: 24h.',
      },
      preset: {
        type: 'string',
        enum: ['ReadOnly', 'Developer', 'CiCd', 'GodMode'],
        description: 'Optional: apply a named constraint preset as the base',
      },
      maxSpend: { type: 'number', description: 'Optional: maximum monetary spend' },
      maxCalls: { type: 'number', description: 'Optional: maximum API call count' },
      parameterLocks: {
        type: 'object',
        description: 'Optional: lock parameters to exact values (e.g. { "to": "boss@company.com" })',
      },
      issuerPrivateKey: {
        type: 'string',
        description: 'base64url-encoded Ed25519 private key of the issuer',
      },
    },
    required: ['principal', 'agentDid', 'permissions', 'expiresIn', 'issuerPrivateKey'],
  },
} as const

export async function handleAmapIssue(input: {
  principal: string
  agentDid: string
  permissions: string[]
  expiresIn: string
  preset?: 'ReadOnly' | 'Developer' | 'CiCd' | 'GodMode'
  maxSpend?: number
  maxCalls?: number
  parameterLocks?: Record<string, unknown>
  issuerPrivateKey: string
}): Promise<DelegationToken> {
  const base: Constraints = input.preset !== undefined ? { ...amap.presets[input.preset] } : {}
  const overrides: Constraints = {}
  if (input.maxSpend !== undefined) overrides.maxSpend = input.maxSpend
  if (input.maxCalls !== undefined) overrides.maxCalls = input.maxCalls
  if (input.parameterLocks !== undefined) overrides.parameterLocks = input.parameterLocks

  const constraints: Constraints = { ...base, ...overrides }

  return amap.issue({
    principal: input.principal,
    delegate: input.agentDid,
    permissions: input.permissions,
    expiresIn: input.expiresIn,
    ...(Object.keys(constraints).length > 0 ? { constraints } : {}),
    privateKey: input.issuerPrivateKey,
  })
}
