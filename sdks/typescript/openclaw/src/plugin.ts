import { InMemoryNonceStore } from '@agentmandateprotocol/core'
import { SessionMandateStore } from './session-store.js'
import { amapRegisterSessionToolDefinition, handleAmapRegisterSession } from './tools/amap-register-session.js'
import { amapIssueToolDefinition, handleAmapIssue } from './tools/amap-issue.js'
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
  on(
    event: 'before_tool_call',
    handler: (
      event: unknown,
      ctx: { toolName: string; sessionKey: string; args: Record<string, unknown> },
    ) => Promise<{ abort: boolean; error?: string }>,
  ): void
}

const AMAP_TOOL_NAMES = new Set([amapIssueToolDefinition.name, amapRegisterSessionToolDefinition.name])

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
export default function register(api: PluginApi): void {
  const sessionStore = new SessionMandateStore()
  const config: AmapPluginOptions = api.config?.amap ?? {}
  const { keyResolver, revocationChecker } = config
  // Create the nonce store once per plugin instance, not per call.
  // A per-call store starts empty every time, making replay prevention ineffective.
  // For multi-instance deployments, pass a shared nonceStore in config (e.g. Redis, CF KV).
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore()

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

  // Guard hook — intercepts every tool call before it reaches the handler
  api.on('before_tool_call', async (_event, ctx) => {
    // Skip A-MAP's own tools — they bootstrap the mandate flow
    if (AMAP_TOOL_NAMES.has(ctx.toolName)) return { abort: false }

    try {
      const cleanArgs = await beforeToolCall(
        ctx.args,
        { sessionId: ctx.sessionKey, toolName: ctx.toolName },
        {
          sessionStore,
          nonceStore,
          ...(keyResolver !== undefined ? { keyResolver } : {}),
          ...(revocationChecker !== undefined ? { revocationChecker } : {}),
        },
      )
      // Replace args with clean version (_amap stripped if present)
      ctx.args = cleanArgs
      return { abort: false }
    } catch (err: unknown) {
      const code = (err as { code?: string }).code ?? 'UNKNOWN'
      const msg = err instanceof Error ? err.message : String(err)
      api.logger?.warn(`[A-MAP] Unauthorized tool call blocked: ${msg}`)
      return { abort: true, error: `A-MAP Authorization Failed: [${code}] ${msg}` }
    }
  })
}

/**
 * Factory that returns a duck-typed plugin object.
 * Useful for testing and for frameworks that use a different plugin registration model.
 * The primary entry point for OpenClaw is the default export `register`.
 */
export function createAmapPlugin(opts: AmapPluginOptions = {}) {
  const sessionStore = new SessionMandateStore()
  // Create the nonce store once per plugin instance, not per call.
  const nonceStore = opts.nonceStore ?? new InMemoryNonceStore()

  return {
    name: '@agentmandateprotocol/openclaw',
    version: '0.0.1',
    description: 'A-MAP mandate verification for OpenClaw — cryptographic agent authorization',

    tools: [amapIssueToolDefinition, amapRegisterSessionToolDefinition],

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
