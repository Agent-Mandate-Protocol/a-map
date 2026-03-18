import { amap } from '@agentmandateprotocol/core'

export const amapKeygenToolDefinition = {
  name: 'amap_keygen',
  description:
    'Generate an Ed25519 keypair and derive a self-certifying DID for use with A-MAP. ' +
    'Call this first — before amap_issue — to create keys for a human issuer or an agent. ' +
    'Returns publicKey, privateKey (base64url), and the derived DID. ' +
    'IMPORTANT: save the privateKey securely — it cannot be recovered. Never share it. ' +
    '[A-MAP] [keygen] [keypair] [DID] [setup] [onboarding]',
  inputSchema: {
    type: 'object' as const,
    properties: {
      name: {
        type: 'string',
        description: 'Human-readable name for this identity (e.g. "alice", "my-agent")',
      },
      type: {
        type: 'string',
        enum: ['human', 'agent'],
        description: '"human" for the mandate issuer, "agent" for the agent being authorized',
      },
      version: {
        type: 'string',
        description: 'Required when type="agent". Semantic version string (e.g. "1.0")',
      },
    },
    required: ['name', 'type'],
  },
}

export function handleAmapKeygen(input: {
  name: string
  type: 'human' | 'agent'
  version?: string
}): { publicKey: string; privateKey: string; did: string } {
  const { publicKey, privateKey } = amap.keygen()
  const did = amap.computeDID({ type: input.type, name: input.name, version: input.version, publicKey })
  return { publicKey, privateKey, did }
}
