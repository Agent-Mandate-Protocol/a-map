import { amap, LocalKeyResolver } from '@agentmandateprotocol/core'
import type { DelegationToken, VerificationResult } from '@agentmandateprotocol/core'

export const amapVerifyToolDefinition = {
  name: 'amap_verify',
  description:
    'Verify an A-MAP mandate chain without making an HTTP request. ' +
    'Use this to confirm a mandate is cryptographically valid, not expired, and grants a specific permission. ' +
    'Requires the public keys of all issuers in the chain — pass them as a { DID: publicKey } map. ' +
    'Returns the principal (human who issued), effective constraints, and chain length on success. ' +
    'Throws a typed AmapError on any failure (expired, bad signature, broken chain, etc.). ' +
    '[A-MAP] [verify] [validate] [mandate] [check] [inspect]',
  inputSchema: {
    type: 'object' as const,
    properties: {
      chain: {
        type: 'array',
        items: { type: 'object' },
        description: 'Full DelegationToken[] array — root token first, leaf last',
      },
      publicKeys: {
        type: 'object',
        description:
          'Map of DID → base64url public key for every issuer in the chain. ' +
          'e.g. { "did:amap:human:alice:abc123": "<publicKey>" }',
      },
      expectedPermission: {
        type: 'string',
        description: 'Optional: assert this permission is granted by the chain (e.g. "tool:read_file")',
      },
    },
    required: ['chain', 'publicKeys'],
  },
}

export async function handleAmapVerify(input: {
  chain: DelegationToken[]
  publicKeys: Record<string, string>
  expectedPermission?: string
}): Promise<{
  valid: true
  principal: string
  chainLength: number
  permissions: string[]
  effectiveConstraints: VerificationResult['effectiveConstraints']
  auditId: string
}> {
  const keyResolver = new LocalKeyResolver(new Map(Object.entries(input.publicKeys)))

  const result = await amap.verify({
    chain: input.chain,
    keyResolver,
    ...(input.expectedPermission !== undefined ? { expectedPermission: input.expectedPermission } : {}),
  })

  return {
    valid: true,
    principal: result.principal,
    chainLength: result.chain.length,
    permissions: input.chain[input.chain.length - 1]!.permissions,
    effectiveConstraints: result.effectiveConstraints,
    auditId: result.auditId,
  }
}
