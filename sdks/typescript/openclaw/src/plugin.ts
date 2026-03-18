import { InMemoryNonceStore } from '@agentmandateprotocol/core'
import { SessionMandateStore } from './session-store.js'
import { amapRegisterSessionToolDefinition, handleAmapRegisterSession } from './tools/amap-register-session.js'
import { amapIssueToolDefinition, handleAmapIssue } from './tools/amap-issue.js'
import { amapKeygenToolDefinition, handleAmapKeygen } from './tools/amap-keygen.js'
import { amapVerifyToolDefinition, handleAmapVerify } from './tools/amap-verify.js'
import { beforeToolCall } from './hook.js'
import type { HookOptions } from './hook.js'
import type { DelegationToken } from '@agentmandateprotocol/core'

export interface AmapPluginOptions extends Omit<HookOptions, 'sessionStore'> {}

// OpenClaw plugin API — duck-typed so we don't require @openclaw/sdk as a hard dependency
type PluginApi = {
  config?: { amap?: AmapPluginOptions }
  logger?: { warn(msg: string): void }
  registerTool(def: {
    name: string
    description: string
    parameters: object
    execute(id: string, params: Record<string, unknown>, ctx: { sessionKey: string }): Promise<unknown>
  }): void
}

const AMAP_TOOL_NAMES = new Set([
  amapIssueToolDefinition.name,
  amapRegisterSessionToolDefinition.name,
  amapKeygenToolDefinition.name,
  amapVerifyToolDefinition.name,
])

/**
 * OpenClaw plugin entry point.
 *
 * OpenClaw discovers and loads this plugin by calling the default export.
 * Configuration is read from api.config.amap (set in openclaw.config.ts).
 *
 * Usage in openclaw.config.ts:
 *   import amapPlugin from '@agentmandateprotocol/openclaw'
 *   export default { plugins: [amapPlugin] }
 */
export default {
  id: 'agentmandateprotocol-openclaw',
  name: 'Agent Mandate Protocol',
  register(api: PluginApi): void {
  const sessionStore = new SessionMandateStore()
  const config: AmapPluginOptions = api.config?.amap ?? {}
  const { keyResolver } = config

  // amap_issue — humans call this to sign a mandate for an agent
  api.registerTool({
    name: amapIssueToolDefinition.name,
    description: amapIssueToolDefinition.description,
    parameters: amapIssueToolDefinition.inputSchema,
    async execute(_id, params) {
      try {
        const result = await handleAmapIssue(params as Parameters<typeof handleAmapIssue>[0])
        return { content: [{ type: 'text', text: JSON.stringify(result) }] }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        return { content: [{ type: 'text', text: `Mandate issuance failed: ${msg}` }], isError: true }
      }
    },
  })

  // amap_register_session — agents call this once to register their mandate for the session
  api.registerTool({
    name: amapRegisterSessionToolDefinition.name,
    description: amapRegisterSessionToolDefinition.description,
    parameters: amapRegisterSessionToolDefinition.inputSchema,
    async execute(_id, params, ctx) {
      try {
        const result = await handleAmapRegisterSession(
          ctx.sessionKey,
          sessionStore,
          keyResolver,
        )(params as { chain: DelegationToken[] })
        return { content: [{ type: 'text', text: JSON.stringify(result) }] }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        return { content: [{ type: 'text', text: `Session registration failed: ${msg}` }], isError: true }
      }
    },
  })

  // amap_keygen — generate a keypair and DID (first step of onboarding)
  api.registerTool({
    name: amapKeygenToolDefinition.name,
    description: amapKeygenToolDefinition.description,
    parameters: amapKeygenToolDefinition.inputSchema,
    async execute(_id, params) {
      const result = handleAmapKeygen(params as Parameters<typeof handleAmapKeygen>[0])
      return { content: [{ type: 'text', text: JSON.stringify(result) }] }
    },
  })

  // amap_verify — verify a mandate chain locally without an HTTP request
  api.registerTool({
    name: amapVerifyToolDefinition.name,
    description: amapVerifyToolDefinition.description,
    parameters: amapVerifyToolDefinition.inputSchema,
    async execute(_id, params) {
      try {
        const result = await handleAmapVerify(params as Parameters<typeof handleAmapVerify>[0])
        return { content: [{ type: 'text', text: JSON.stringify(result) }] }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        const code = (err as { code?: string }).code ?? 'UNKNOWN'
        return { content: [{ type: 'text', text: `Verification failed: [${code}] ${msg}` }], isError: true }
      }
    },
  })
  },
}

/**
 * Factory that returns a duck-typed plugin object for custom frameworks.
 *
 * Use this when your agent framework exposes a tool interception API that you
 * can wire `beforeToolCall` into. OpenClaw itself does not expose such a hook,
 * so `createAmapPlugin()` is not used in the standard OpenClaw plugin path.
 *
 * The returned object's `beforeToolCall` enforces the full A-MAP flow:
 * session store lookup → per-call `_amap` envelope verification → permission
 * check → nonce replay prevention.
 */
export function createAmapPlugin(opts: AmapPluginOptions = {}) {
  const sessionStore = new SessionMandateStore()
  // Create the nonce store once per plugin instance, not per call.
  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()

  return {
    name: '@agentmandateprotocol/openclaw',
    version: '0.0.1',
    description: 'A-MAP mandate verification for OpenClaw — cryptographic agent authorization',

    tools: [amapIssueToolDefinition, amapRegisterSessionToolDefinition, amapKeygenToolDefinition, amapVerifyToolDefinition],

    handleTool: async (
      name: string,
      input: Record<string, unknown>,
      ctx: { sessionId: string },
    ): Promise<unknown> => {
      if (name === 'amap_issue') {
        return handleAmapIssue(input as Parameters<typeof handleAmapIssue>[0])
      }
      if (name === 'amap_register_session') {
        return handleAmapRegisterSession(ctx.sessionId, sessionStore, opts.keyResolver)(
          input as { chain: DelegationToken[] },
        )
      }
      if (name === 'amap_keygen') {
        return handleAmapKeygen(input as Parameters<typeof handleAmapKeygen>[0])
      }
      if (name === 'amap_verify') {
        return handleAmapVerify(input as Parameters<typeof handleAmapVerify>[0])
      }
      return undefined
    },

    beforeToolCall: async (
      name: string,
      input: Record<string, unknown>,
      ctx: { sessionId: string },
    ): Promise<Record<string, unknown>> => {
      if (AMAP_TOOL_NAMES.has(name)) return input

      return beforeToolCall(input, { sessionId: ctx.sessionId, toolName: name }, {
        sessionStore,
        nonceStore,
        ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
        ...(opts.revocationChecker !== undefined ? { revocationChecker: opts.revocationChecker } : {}),
      })
    },
  }
}
