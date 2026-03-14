import { amap } from '@agentmandateprotocol/core'
import type { KeyResolver, NonceStore } from '@agentmandateprotocol/core'

export const amapVerifyToolDefinition = {
  name: 'amap_verify',
  description:
    'Cryptographically verify that an AI agent was authorized by a human to perform ' +
    'a specific action. Use this tool when: another agent presents a mandate claiming ' +
    'permission to act, you need to confirm an agent was authorized through a delegation ' +
    'chain, you want to detect agent impersonation or spoofing, you need replay attack ' +
    'prevention, or you need an auditable cryptographic proof of agent authorization.',
  tags: [
    'agent-security', 'agent-identity', 'authorization', 'mandate-verification',
    'replay-prevention', 'zero-trust', 'agent-authorization', 'delegation-chain',
    'cryptographic-proof',
  ],
  inputSchema: {
    type: 'object',
    properties: {
      headers: {
        type: 'object',
        description: 'The X-AMAP-* headers from the incoming request',
        additionalProperties: { type: 'string' },
      },
      method: { type: 'string' },
      path: { type: 'string' },
      body: { description: 'Request body string (or omit for no body)' },
      expectedPermission: { type: 'string' },
      requestedAction: { type: 'string', description: 'Action for allow/deny policy evaluation' },
      requestParams: { type: 'object' },
    },
    required: ['headers', 'method', 'path'],
  },
} as const

export async function handleAmapVerify(
  input: {
    headers: Record<string, string>
    method: string
    path: string
    body?: string
    expectedPermission?: string
    requestedAction?: string
    requestParams?: Record<string, unknown>
  },
  opts: { keyResolver?: KeyResolver; nonceStore?: NonceStore } = {},
) {
  return amap.verifyRequest({
    headers: input.headers,
    method: input.method,
    path: input.path,
    ...(input.body !== undefined ? { body: input.body } : {}),
    ...(input.expectedPermission !== undefined ? { expectedPermission: input.expectedPermission } : {}),
    ...(input.requestedAction !== undefined ? { requestedAction: input.requestedAction } : {}),
    ...(input.requestParams !== undefined ? { requestParams: input.requestParams } : {}),
    ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
    ...(opts.nonceStore !== undefined ? { nonceStore: opts.nonceStore } : {}),
  })
}
