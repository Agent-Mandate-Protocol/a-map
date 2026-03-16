import { amap, AmapError, AmapErrorCode } from '@agentmandateprotocol/core'
import type { VerificationResult, KeyResolver, NonceStore } from '@agentmandateprotocol/core'

// ─── MCP response types ───────────────────────────────────────────────────────

export interface McpTextContent {
  type: 'text'
  text: string
}

/** MCP tool call result — success or error */
export interface McpToolResult {
  isError: boolean
  content: McpTextContent[]
}

/**
 * Convert any thrown error to a structured MCP tool error response.
 *
 * MCP servers that catch errors rather than letting the framework handle them
 * can use this to produce a spec-compliant `{ isError: true, content: [...] }`
 * response. AmapErrors include the error code in the text for easy diagnosis.
 *
 * @example
 * ```ts
 * try {
 *   const result = await protectedHandler(input)
 *   return { isError: false, content: [{ type: 'text', text: JSON.stringify(result) }] }
 * } catch (err) {
 *   return toMcpErrorResponse(err)
 * }
 * ```
 */
export function toMcpErrorResponse(err: unknown): McpToolResult {
  if (err instanceof AmapError) {
    return {
      isError: true,
      content: [{ type: 'text', text: `[${err.code}] ${err.message}` }],
    }
  }
  const message = err instanceof Error ? err.message : String(err)
  return {
    isError: true,
    content: [{ type: 'text', text: message }],
  }
}

/**
 * Wrap an amapProtect handler to return MCP tool results instead of throwing.
 *
 * Use this when you want explicit control over the MCP response format,
 * or when the framework does not automatically convert thrown errors.
 *
 * @example
 * ```ts
 * const sendEmail = mcpToolHandler('send_email', handler, opts)
 * // Returns { isError: false, content: [...] } or { isError: true, content: [...] }
 * const result = await sendEmail(input)
 * ```
 */
export function mcpToolHandler<TInput extends Record<string, unknown>, TOutput>(
  toolName: string,
  handler: AmapToolHandler<Omit<TInput, '_amap'>, TOutput>,
  options: AmapProtectOptions = {},
): (input: TInput) => Promise<McpToolResult> {
  const protectedHandler = amapProtect(toolName, handler, options)
  return async (input: TInput): Promise<McpToolResult> => {
    try {
      const result = await protectedHandler(input)
      return { isError: false, content: [{ type: 'text', text: JSON.stringify(result) }] }
    } catch (err) {
      return toMcpErrorResponse(err)
    }
  }
}

export interface AmapProtectOptions {
  /** The permission required to call this tool. Defaults to `tool:{toolName}`. */
  requiredPermission?: string
  /** The action string for allow/deny policy evaluation. Defaults to the toolName argument. */
  requestedAction?: string
  /** Key resolver for DID → public key resolution. */
  keyResolver?: KeyResolver
  /** Nonce store — MUST be shared across requests in multi-instance deployments. */
  nonceStore?: NonceStore
}

export type AmapToolHandler<TInput, TOutput> = (
  args: TInput,
  mandate: VerificationResult,
) => Promise<TOutput>

interface AmapEnvelope {
  headers: Record<string, string>
  method?: string
  path?: string
  body?: string | Buffer
}

/**
 * Wrap an MCP tool handler with A-MAP authorization.
 *
 * Extracts X-AMAP-* headers from the _amap envelope in the tool arguments,
 * calls verifyRequest(), and passes the VerificationResult to the handler.
 *
 * On failure: throws AmapError — MCP framework converts to a structured error.
 * On success: calls the handler with clean args (no _amap field) + VerificationResult.
 *
 * @param toolName  - used as default requiredPermission and requestedAction
 * @param handler   - the actual tool implementation
 * @param options   - optional overrides for permission, action, keyResolver, nonceStore
 */
export function amapProtect<TInput extends Record<string, unknown>, TOutput>(
  toolName: string,
  handler: AmapToolHandler<Omit<TInput, '_amap'>, TOutput>,
  options: AmapProtectOptions = {},
): (input: TInput) => Promise<TOutput> {
  return async (input: TInput) => {
    const envelope = input['_amap'] as AmapEnvelope | undefined
    if (!envelope?.headers) {
      throw new AmapError(
        AmapErrorCode.BROKEN_CHAIN,
        `Tool "${toolName}" requires A-MAP authorization. Include _amap envelope with X-AMAP-* headers.`,
      )
    }

    const mandate = await amap.verifyRequest({
      headers: envelope.headers,
      method: envelope.method ?? 'POST',
      path: envelope.path ?? `/mcp/${toolName}`,
      ...(envelope.body !== undefined ? { body: envelope.body } : {}),
      expectedPermission: options.requiredPermission ?? `tool:${toolName}`,
      ...(options.requestedAction !== undefined ? { requestedAction: options.requestedAction } : {}),
      ...(options.keyResolver !== undefined ? { keyResolver: options.keyResolver } : {}),
      ...(options.nonceStore !== undefined ? { nonceStore: options.nonceStore } : {}),
    })

    const { _amap: _, ...cleanArgs } = input

    return handler(cleanArgs as Omit<TInput, '_amap'>, mandate)
  }
}
